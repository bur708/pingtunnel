package pingtunnel

import (
	"bytes"
	"fmt"
	"math/rand"
	"net"
	"sync"
	"testing"
	"time"
)

// lossyPipe wires two KCPSessions together through an in-memory channel
// that randomly drops a fraction of the "packets" crossing it, simulating
// the kind of link this whole project targets (satellite, airport wifi).
type lossyPipe struct {
	lossPercent int
	rng         *rand.Rand
	mu          sync.Mutex
}

func newLossyPipe(lossPercent int, seed int64) *lossyPipe {
	return &lossyPipe{lossPercent: lossPercent, rng: rand.New(rand.NewSource(seed))}
}

func (p *lossyPipe) shouldDrop() bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.rng.Intn(100) < p.lossPercent
}

// newConnectedSessions builds two KCPSessions, A and B, whose output is fed
// into each other's Input through lossyPipe (dropping lossPercent% of
// segments in each direction independently).
func newConnectedSessions(t *testing.T, cfg *KCPConfig, lossPercent int) (a, b *KCPSession) {
	t.Helper()

	pipeAB := newLossyPipe(lossPercent, 1)
	pipeBA := newLossyPipe(lossPercent, 2)

	var bRef *KCPSession
	a = NewKCPSession(cfg, func(segment []byte) {
		if pipeAB.shouldDrop() {
			return
		}
		cp := append([]byte(nil), segment...)
		go bRef.Input(cp)
	})
	b = NewKCPSession(cfg, func(segment []byte) {
		if pipeBA.shouldDrop() {
			return
		}
		cp := append([]byte(nil), segment...)
		go a.Input(cp)
	})
	bRef = b

	return a, b
}

func fastTestKCPConfig() *KCPConfig {
	return &KCPConfig{
		NoDelay: 1, Interval: 10, Resend: 2, NoCongestion: 1,
		SndWnd: 128, RcvWnd: 128, MTU: 1200,
	}
}

func TestKCPSessionReliableDeliveryNoLoss(t *testing.T) {
	a, b := newConnectedSessions(t, fastTestKCPConfig(), 0)
	defer a.Close()
	defer b.Close()

	const n = 50
	want := make([][]byte, n)
	for i := range want {
		want[i] = []byte(fmt.Sprintf("message-%03d-%s", i, bytes.Repeat([]byte("x"), i%40)))
		if err := a.Send(want[i]); err != nil {
			t.Fatalf("Send(%d): %v", i, err)
		}
	}

	got := collectMessages(t, b, n, 5*time.Second)
	assertMessagesEqual(t, want, got)
}

func TestKCPSessionReliableDeliveryWithLoss(t *testing.T) {
	// A fairly hostile 15% loss in both directions - well above the
	// occasional-packet-loss FEC targets, deliberately chosen to exercise
	// KCP's own retransmission rather than just "got lucky".
	a, b := newConnectedSessions(t, fastTestKCPConfig(), 15)
	defer a.Close()
	defer b.Close()

	const n = 80
	want := make([][]byte, n)
	for i := range want {
		want[i] = []byte(fmt.Sprintf("payload-%04d", i))
		if err := a.Send(want[i]); err != nil {
			t.Fatalf("Send(%d): %v", i, err)
		}
	}

	// Under 15% loss with a small window, delivery takes longer than the
	// no-loss case but must still complete: that is the entire point of
	// using KCP's ARQ instead of a fire-and-forget send.
	got := collectMessages(t, b, n, 20*time.Second)
	assertMessagesEqual(t, want, got)
}

func TestKCPSessionBidirectional(t *testing.T) {
	a, b := newConnectedSessions(t, fastTestKCPConfig(), 5)
	defer a.Close()
	defer b.Close()

	const n = 30
	wantAtoB := make([][]byte, n)
	wantBtoA := make([][]byte, n)
	for i := range wantAtoB {
		wantAtoB[i] = []byte(fmt.Sprintf("a->b-%d", i))
		wantBtoA[i] = []byte(fmt.Sprintf("b->a-%d", i))
		if err := a.Send(wantAtoB[i]); err != nil {
			t.Fatalf("a.Send(%d): %v", i, err)
		}
		if err := b.Send(wantBtoA[i]); err != nil {
			t.Fatalf("b.Send(%d): %v", i, err)
		}
	}

	gotAtB := collectMessages(t, b, n, 10*time.Second)
	gotBtA := collectMessages(t, a, n, 10*time.Second)
	assertMessagesEqual(t, wantAtoB, gotAtB)
	assertMessagesEqual(t, wantBtoA, gotBtA)
}

func TestKCPTransportPerDestKeySessions(t *testing.T) {
	transport := NewKCPTransport(fastTestKCPConfig(), nil, nil)
	defer transport.Close()

	var sent []byte
	s1 := transport.Session("peerA", nil, 0, func(segment []byte) { sent = append(sent, segment...) })
	s2 := transport.Session("peerA", nil, 0, func(segment []byte) { t.Fatal("should reuse existing session, not build a new one") })
	if s1 != s2 {
		t.Fatalf("expected the same session for the same destKey")
	}

	s3 := transport.Session("peerB", nil, 0, func(segment []byte) {})
	if s1 == s3 {
		t.Fatalf("expected a distinct session for a different destKey")
	}
}

// TestKCPTransportDeliversAcrossTwoTransports wires two KCPTransports
// together (one per "peer") through a lossy in-memory channel, the same
// way sendICMP/recvICMP will in the real pingtunnel wiring: each side's
// Session sendRaw writes into the other's Input, and each transport's
// deliver callback is what a real recvICMP would hand off to
// deliverPayload.
func TestKCPTransportDeliversAcrossTwoTransports(t *testing.T) {
	const destKeyAtoB = "b"
	const destKeyBtoA = "a"

	// Messages flow A -> B (sessionA.Send below), so it is B's transport
	// that should ever see inbound application data; A only ever gets
	// bare ACKs from KCP's own protocol, never handed to deliver.
	delivered := make(chan []byte, 100)
	var transportA, transportB *KCPTransport
	transportA = NewKCPTransport(fastTestKCPConfig(), nil, func(msg []byte, peer *net.IPAddr, id int) {
		t.Errorf("unexpected inbound message on A: %q", msg)
	})
	transportB = NewKCPTransport(fastTestKCPConfig(), nil, func(msg []byte, peer *net.IPAddr, id int) {
		delivered <- msg
	})
	defer transportA.Close()
	defer transportB.Close()

	pipe := newLossyPipe(10, 42)

	var sessionB *KCPSession
	sessionA := transportA.Session(destKeyAtoB, nil, 0, func(segment []byte) {
		if pipe.shouldDrop() {
			return
		}
		cp := append([]byte(nil), segment...)
		go sessionB.Input(cp)
	})
	sessionB = transportB.Session(destKeyBtoA, nil, 0, func(segment []byte) {
		if pipe.shouldDrop() {
			return
		}
		cp := append([]byte(nil), segment...)
		go sessionA.Input(cp)
	})

	const n = 20
	want := make([][]byte, n)
	for i := range want {
		want[i] = []byte(fmt.Sprintf("hello-%d", i))
		if err := sessionA.Send(want[i]); err != nil {
			t.Fatalf("Send(%d): %v", i, err)
		}
	}

	got := make([][]byte, 0, n)
	deadline := time.After(10 * time.Second)
	for len(got) < n {
		select {
		case m := <-delivered:
			got = append(got, m)
		case <-deadline:
			t.Fatalf("timed out after receiving %d/%d messages via deliver callback", len(got), n)
		}
	}
	assertMessagesEqual(t, want, got)
}

func TestKCPWireFraming(t *testing.T) {
	macKey := []byte("test-mac-key")
	segment := []byte{1, 2, 3, 4, 5}
	const flowID uint16 = 42
	pkt := buildKCPPacket(flowID, segment, macKey)

	if !IsKCPPacket(pkt) {
		t.Fatalf("expected IsKCPPacket to be true")
	}
	if IsKCPPacket(segment) {
		t.Fatalf("raw segment without marker should not look like a KCP packet")
	}

	gotFlowID, got, err := ParseKCPPacket(pkt, macKey)
	if err != nil {
		t.Fatalf("ParseKCPPacket: %v", err)
	}
	if gotFlowID != flowID {
		t.Fatalf("flowID round-trip mismatch: want %d got %d", flowID, gotFlowID)
	}
	if !bytes.Equal(got, segment) {
		t.Fatalf("round-trip mismatch: want %v got %v", segment, got)
	}

	if _, _, err := ParseKCPPacket([]byte{}, macKey); err == nil {
		t.Fatalf("expected error parsing an empty packet")
	}
}

// Regression test for the KCP ACK-injection finding: a segment forged (or
// tagged with the wrong key) by someone who doesn't know macKey must be
// rejected before ever reaching (*KCPSession).Input, even if it carries a
// well-formed version byte and a plausible-looking KCP segment body.
func TestKCPWireFramingRejectsWrongMacKey(t *testing.T) {
	segment := []byte{1, 2, 3, 4, 5}
	pkt := buildKCPPacket(7, segment, []byte("real-key"))

	if _, _, err := ParseKCPPacket(pkt, []byte("wrong-key")); err == nil {
		t.Fatalf("expected error parsing a packet tagged with a different key")
	}

	forged := append([]byte(nil), pkt...)
	forged[len(forged)-1] ^= 0xFF // flip a byte in the segment after tagging
	if _, _, err := ParseKCPPacket(forged, []byte("real-key")); err == nil {
		t.Fatalf("expected error parsing a tampered segment")
	}
}

// Regression test for the head-of-line-blocking fix: tampering with just
// the flowID byte (leaving the MAC and segment untouched) must also be
// rejected - otherwise an off-path attacker could redirect a valid segment
// into a different flow's session by flipping this one field.
func TestKCPWireFramingRejectsTamperedFlowID(t *testing.T) {
	macKey := []byte("real-key")
	pkt := buildKCPPacket(7, []byte{1, 2, 3, 4, 5}, macKey)

	forged := append([]byte(nil), pkt...)
	forged[1+kcpMacSize] ^= 0xFF // flip a bit in the flowID field only
	if _, _, err := ParseKCPPacket(forged, macKey); err == nil {
		t.Fatalf("expected error parsing a packet with a tampered flowID")
	}
}

func collectMessages(t *testing.T, s *KCPSession, n int, timeout time.Duration) [][]byte {
	t.Helper()
	deadline := time.After(timeout)
	got := make([][]byte, 0, n)
	for len(got) < n {
		select {
		case m := <-s.RecvChan():
			got = append(got, m)
		case <-deadline:
			t.Fatalf("timed out after receiving %d/%d messages", len(got), n)
		}
	}
	return got
}

func assertMessagesEqual(t *testing.T, want, got [][]byte) {
	t.Helper()
	if len(want) != len(got) {
		t.Fatalf("message count mismatch: want %d got %d", len(want), len(got))
	}
	for i := range want {
		if !bytes.Equal(want[i], got[i]) {
			t.Fatalf("message %d mismatch: want %q got %q", i, want[i], got[i])
		}
	}
}

// Regression test for the KCP send-queue growing without bound: a sender
// feeding data faster than the real link drains it (e.g. a system-wide VPN
// client routing far more traffic than a narrow ICMP path can carry) used
// to have kcp.KCP.Send accept every message unconditionally - the library
// enforces no cap of its own (see KCPConfig.MaxWaitSnd's doc comment), and
// with NoCongestion=1 nothing else throttled ingestion either. Simulates
// the worst case, a completely stalled peer (sendRaw is a black hole, so
// nothing is ever acked and the backlog can never drain), and asserts Send
// eventually refuses rather than buffering forever.
func TestKCPSessionSendBackpressureDropsWhenLinkStalled(t *testing.T) {
	cfg := &KCPConfig{
		NoDelay: 1, Interval: 10, Resend: 2, NoCongestion: 1,
		SndWnd: 16, RcvWnd: 16, MTU: 1200,
		MaxWaitSnd:                8,
		SendBackpressureTimeoutMs: 30,
	}
	s := NewKCPSession(cfg, func(segment []byte) {
		// Black hole: simulates a peer that never receives anything, so
		// nothing is ever acked and WaitSnd can never drop.
	})
	defer s.Close()

	msg := []byte("some application data that needs to go out")

	done := make(chan error, 1)
	go func() {
		var err error
		for i := 0; i < 200; i++ {
			if err = s.Send(msg); err != nil {
				break
			}
		}
		done <- err
	}()

	select {
	case err := <-done:
		if err == nil {
			t.Fatal("expected Send to eventually refuse once the backlog cap is hit, but it accepted 200 messages into a session whose peer never acks anything")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Send blocked far longer than SendBackpressureTimeoutMs*iterations should allow - looks like it's buffering unboundedly instead of dropping")
	}
}

// Companion to the stalled-link test above: a healthy (if lossy) link must
// still be able to push a send volume well past MaxWaitSnd's cap over time,
// since the backlog keeps draining as ACKs arrive. The backpressure fix
// must not turn into a throughput regression for ordinary operation.
func TestKCPSessionSendDoesNotSpuriouslyDropOnHealthyLink(t *testing.T) {
	cfg := fastTestKCPConfig()
	cfg.MaxWaitSnd = 8
	cfg.SendBackpressureTimeoutMs = 2000

	a, b := newConnectedSessions(t, cfg, 0)
	defer a.Close()
	defer b.Close()

	const n = 500
	want := make([][]byte, n)
	for i := 0; i < n; i++ {
		want[i] = []byte(fmt.Sprintf("msg-%d", i))
		if err := a.Send(want[i]); err != nil {
			t.Fatalf("Send %d unexpectedly failed on a healthy link: %v", i, err)
		}
	}

	got := collectMessages(t, b, n, 10*time.Second)
	assertMessagesEqual(t, want, got)
}

// Regression test for the head-of-line-blocking fix: before this, every
// non-tcpmode packet a peer sent - PING, KICK, and critically every
// independent SOCKS5-UDP-relay flow (every DNS lookup a browser makes) -
// shared exactly one KCP session, since sendICMP/recvICMP's destKey was
// only (peer address, ICMP echo id), constant per peer. KCP's in-order
// delivery meant one stuck flow blocked every other flow multiplexed onto
// it. kcpFlowID gives each connId its own slot in the destKey instead.
func TestKCPFlowIDBucketing(t *testing.T) {
	// Same connId must always map to the same flow id, or the two ends of
	// one flow's traffic would land on different KCP sessions and never
	// converge.
	first := kcpFlowID("conn-uuid-aaaa")
	if got := kcpFlowID("conn-uuid-aaaa"); got != first {
		t.Fatalf("kcpFlowID not stable across calls: got %d and %d for the same connId", got, first)
	}

	// PING/KICK-before-a-real-connId-exists (connId == "") get the
	// reserved control bucket, kept out of the range real flows hash into.
	if got := kcpFlowID(""); got != kcpControlFlowID {
		t.Fatalf("expected kcpFlowID(\"\") == kcpControlFlowID (%d), got %d", kcpControlFlowID, got)
	}

	// With a fixed bucket pool (kcpFlowBuckets), any two arbitrary connIds
	// may legitimately collide onto the same bucket - that's the accepted
	// tradeoff (see kcpFlowID's doc comment), not something to assert
	// against for any single pair. What must hold is: every real connId
	// stays out of the reserved control bucket, every id stays in range,
	// and a large enough set of distinct connIds actually spreads across
	// more than one bucket (i.e. this isn't secretly collapsing everything
	// onto one id).
	seen := map[uint16]bool{}
	for i := 0; i < 500; i++ {
		id := kcpFlowID(fmt.Sprintf("conn-uuid-%d", i))
		if id == kcpControlFlowID {
			t.Fatalf("real connId %q hashed onto the reserved control bucket", fmt.Sprintf("conn-uuid-%d", i))
		}
		if id >= kcpFlowBuckets {
			t.Fatalf("flow id %d out of range [0, %d)", id, kcpFlowBuckets)
		}
		seen[id] = true
	}
	if len(seen) < 2 {
		t.Fatalf("500 distinct connIds all hashed onto a single bucket - kcpFlowID isn't actually distributing flows")
	}
}

// Companion to TestKCPFlowIDBucketing at the KCPTransport level: two flows
// to the same peer that land in different buckets (same destKey prefix,
// different flowID-derived suffix, matching how pingtunnel.go builds
// destKey) must get independent sessions - i.e. one being completely
// stalled cannot prevent the other from being created and used. With a
// fixed bucket pool any two arbitrary connIds might collide onto the same
// bucket (an accepted tradeoff - see kcpFlowID), so this scans a small set
// for a pair that doesn't, rather than asserting it of any two fixed
// names.
func TestKCPTransportSeparateFlowsGetIndependentSessions(t *testing.T) {
	transport := NewKCPTransport(fastTestKCPConfig(), nil, nil)
	defer transport.Close()

	peer := "1.2.3.4"
	echoId := 100

	var flowA, flowB uint16
	for i := 0; ; i++ {
		if i > kcpFlowBuckets*4 {
			t.Fatal("could not find two connIds landing in different buckets - kcpFlowID may be broken")
		}
		flowA = kcpFlowID(fmt.Sprintf("scan-flow-%d", i))
		flowB = kcpFlowID(fmt.Sprintf("scan-flow-%d", i+1))
		if flowA != flowB {
			break
		}
	}

	keyA := fmt.Sprintf("%s|%d|%d", peer, echoId, flowA)
	keyB := fmt.Sprintf("%s|%d|%d", peer, echoId, flowB)

	// flowA's session is a black hole - simulates a stuck/lossy lookup
	// that, pre-fix, would have head-of-line-blocked flowB behind it.
	sessionA := transport.Session(keyA, nil, echoId, func(segment []byte) {})
	sessionB := transport.Session(keyB, nil, echoId, func(segment []byte) {})

	if sessionA == sessionB {
		t.Fatal("expected independent sessions for independent flows to the same peer")
	}

	done := make(chan error, 1)
	go func() { done <- sessionB.Send([]byte("this must not wait behind flow A")) }()

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("flow B's Send failed: %v", err)
		}
	case <-time.After(1 * time.Second):
		t.Fatal("flow B's Send blocked - it appears to be sharing state with flow A's stalled session")
	}
}

// Regression test for the per-flow session leak: per-flow sessions (see
// TestKCPFlowIDSeparatesIndependentFlows) are created far more often than
// the old one-per-peer scheme - one per DNS lookup - and each holds a
// goroutine ticking every Interval ms until Close'd, so leaving every one
// of them running forever over a long browsing session is a real leak, not
// a theoretical one. Drives reapIdle directly (rather than waiting out the
// real kcpSessionIdleTimeout) by backdating a session's activity clock.
func TestKCPTransportReapsIdleSessions(t *testing.T) {
	transport := NewKCPTransport(fastTestKCPConfig(), nil, nil)
	defer transport.Close()

	idle := transport.Session("idle-flow", nil, 0, func(segment []byte) {})
	fresh := transport.Session("fresh-flow", nil, 0, func(segment []byte) {})

	idle.lastActivityUnixNano.Store(time.Now().Add(-2 * kcpSessionIdleTimeout).UnixNano())

	transport.reapIdle()

	transport.mu.Lock()
	_, idleStillTracked := transport.sessions["idle-flow"]
	_, freshStillTracked := transport.sessions["fresh-flow"]
	transport.mu.Unlock()

	if idleStillTracked {
		t.Fatal("expected the idle session to be reaped")
	}
	if !freshStillTracked {
		t.Fatal("expected the recently-active session to survive reaping")
	}

	select {
	case <-idle.Done():
	default:
		t.Fatal("expected the reaped session to be Close'd (Done channel closed)")
	}
	select {
	case <-fresh.Done():
		t.Fatal("expected the surviving session to still be open")
	default:
	}
}

// Regression test for the resource-overhead problem found live-testing the
// first (unbounded, one session per connId) version of this fix 2026-08-24:
// a phone's background apps alone sustain on the order of 170-185
// concurrent SOCKS5-UDP-relay flows (mostly DNS), and with one KCPSession
// per flow each running its own 20ms-interval goroutine, that's ~8500
// ticks/sec of pure idle-session bookkeeping - a real, measured CPU cost.
// Bucketing (kcpFlowID) must keep the number of live sessions for a peer
// bounded by kcpFlowBuckets, however many distinct flows are actually
// multiplexed onto it.
func TestKCPTransportSessionCountBoundedByFlowBuckets(t *testing.T) {
	transport := NewKCPTransport(fastTestKCPConfig(), nil, nil)
	defer transport.Close()

	peer := "5.6.7.8"
	echoId := 200
	const simulatedFlows = 500 // comfortably more than a real phone's peak

	for i := 0; i < simulatedFlows; i++ {
		flowID := kcpFlowID(fmt.Sprintf("flow-%d", i))
		key := fmt.Sprintf("%s|%d|%d", peer, echoId, flowID)
		transport.Session(key, nil, echoId, func(segment []byte) {})
	}

	transport.mu.Lock()
	sessionCount := len(transport.sessions)
	transport.mu.Unlock()

	if sessionCount > kcpFlowBuckets {
		t.Fatalf("%d simulated flows produced %d live sessions, want at most kcpFlowBuckets (%d)", simulatedFlows, sessionCount, kcpFlowBuckets)
	}
}
