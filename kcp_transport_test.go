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
	transport := NewKCPTransport(fastTestKCPConfig(), nil)
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
	transportA = NewKCPTransport(fastTestKCPConfig(), func(msg []byte, peer *net.IPAddr, id int) {
		t.Errorf("unexpected inbound message on A: %q", msg)
	})
	transportB = NewKCPTransport(fastTestKCPConfig(), func(msg []byte, peer *net.IPAddr, id int) {
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
	segment := []byte{1, 2, 3, 4, 5}
	pkt := buildKCPPacket(segment)

	if !IsKCPPacket(pkt) {
		t.Fatalf("expected IsKCPPacket to be true")
	}
	if IsKCPPacket(segment) {
		t.Fatalf("raw segment without marker should not look like a KCP packet")
	}

	got, err := ParseKCPPacket(pkt)
	if err != nil {
		t.Fatalf("ParseKCPPacket: %v", err)
	}
	if !bytes.Equal(got, segment) {
		t.Fatalf("round-trip mismatch: want %v got %v", segment, got)
	}

	if _, err := ParseKCPPacket([]byte{}); err == nil {
		t.Fatalf("expected error parsing an empty packet")
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
