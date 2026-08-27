package pingtunnel

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"hash/fnv"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/esrrhs/gohome/loggo"
	kcp "github.com/xtaci/kcp-go"
)

// Wire format of a KCP-framed packet, prepended before the raw bytes a
// kcp.KCP engine's output callback hands us. Mirrors fec.go's FECVersion
// scheme so recvICMP can tell legacy / FEC / KCP packets apart from byte 0
// alone, before parsing further.
//
//	[0]     version/flag byte, always KCPVersion for a valid KCP packet
//	[1:9]   truncated HMAC-SHA256(macKey, flowID||segment)
//	[9:11]  flowID, big-endian uint16 - see kcpFlowID's doc comment
//	[11:]   raw kcp.KCP segment bytes, passed to (*KCPSession).Input as-is
//
// The MAC exists because kcp.KCP's Input() has no authentication of its
// own: routing to a session is keyed only by (source IP, ICMP echo id,
// flowID), all attacker-observable/spoofable, and the "conv" field kcp-go
// uses to disambiguate conversations is a fixed constant here (see kcpConv
// below), not a secret. Without a MAC, an off-path attacker could forge
// segments (e.g. an ACK claiming already-sent data was delivered) directly
// into an established session's retransmit bookkeeping, or redirect a
// segment into the wrong flow's session by tampering with flowID - which is
// why the MAC covers flowID too, not just the segment. Tying the tag to the
// same key material that already gates the tunnel (the encryption key, or
// the fallback numeric -key) means forging a valid segment requires knowing
// that secret, same as everywhere else in this protocol.
const (
	KCPVersion    byte = 2
	kcpMacSize         = 8
	kcpFlowIDSize      = 2
	KCPHeaderSize      = 1 + kcpMacSize + kcpFlowIDSize
)

// kcpFlowID hashes connId (the same UUID sendICMP/recvICMP already thread
// through as the MyMsg.Id for this packet) into one of a fixed pool of
// kcpFlowBuckets session slots. Two problems, found in that order live-
// testing 2026-08-24, shaped this design:
//
//  1. Originally every non-tcpmode packet a peer sent - PING, KICK, and
//     critically every independent SOCKS5-UDP-relay flow, including every
//     DNS lookup a browser makes - shared exactly one KCP session (keyed
//     only by source address + ICMP echo id, both constant per peer). KCP
//     guarantees in-order delivery within a session, so one lost/slow-to-
//     retransmit flow head-of-line-blocked every other flow multiplexed
//     onto that session behind it: a single stuck DNS lookup stalled every
//     subsequent lookup (any new site/video), while already-established
//     connections (no fresh lookup needed) kept working - exactly what
//     pointed here.
//  2. The first fix for (1) gave every connId its own session outright (no
//     bucketing). That traded head-of-line blocking for a different real
//     cost: a phone's background apps alone sustain on the order of 170-185
//     concurrent SOCKS5-UDP-relay flows (measured live, mostly DNS,
//     mostly unrelated to whatever page the user is actively loading), and
//     each KCPSession runs its own goroutine ticking every Interval ms
//     (20ms default) until closed - that's ~8500 ticks/sec of pure
//     bookkeeping overhead just from idle-session upkeep, enough to show
//     up as sustained CPU load competing with the traffic it's supposed to
//     be moving.
//
// Bucketing bounds the session count to kcpFlowBuckets regardless of how
// many concurrent flows exist, while still keeping any one stuck flow's
// head-of-line blocking radius to roughly 1/kcpFlowBuckets of all flows
// instead of all of them - not a perfect fix for (1), but a real, bounded
// improvement that also fixes (2). connId == "" (PING, and KICK before a
// connection with a real id exists) maps to a fixed reserved bucket, kept
// out of the hashed range so control traffic never shares a session with -
// or gets head-of-line-blocked by - a real flow.
const (
	kcpControlFlowID uint16 = 0
	kcpFlowBuckets          = 32
)

func kcpFlowID(connId string) uint16 {
	if connId == "" {
		return kcpControlFlowID
	}
	h := fnv.New32a()
	_, _ = h.Write([]byte(connId))
	// +1 keeps real flows out of bucket 0, reserved for control traffic.
	return uint16(1 + h.Sum32()%(kcpFlowBuckets-1))
}

// kcpConv is the KCP "conversation id" every session on both sides uses.
// kcp.KCP.Input rejects any segment whose conv does not match, but our own
// destKey-based routing (one *KCPSession per peer, chosen before a single
// byte reaches the engine - see KCPTransport) already disambiguates
// sessions, so the conv field itself only needs to agree between the two
// ends of one session, not be globally unique. A fixed shared constant is
// sufficient and avoids an extra handshake to negotiate one.
const kcpConv uint32 = 1

// IsKCPPacket reports whether b starts with a valid KCP version byte.
func IsKCPPacket(b []byte) bool {
	return len(b) >= KCPHeaderSize && b[0] == KCPVersion
}

// deriveKCPMacKey derives the key used to authenticate KCP segments (see
// KCPHeaderSize's doc comment) from whatever secret already gates this
// tunnel: the encryption key when -encrypt is set, otherwise the numeric
// -key. Both are run through SHA-256 with a fixed domain-separation
// prefix rather than used directly, so this key is never the same bytes
// as the AEAD key itself even when -encrypt is also enabled.
func deriveKCPMacKey(cryptoConfig *CryptoConfig, key int) []byte {
	h := sha256.New()
	h.Write([]byte("pingtunnel-kcp-mac|"))
	if cryptoConfig != nil && len(cryptoConfig.Key) > 0 {
		h.Write(cryptoConfig.Key)
	} else {
		h.Write([]byte(fmt.Sprintf("%d", key)))
	}
	return h.Sum(nil)
}

// kcpTag computes the truncated HMAC-SHA256 tag for (flowID, segment) under
// macKey. Covering flowID (not just segment) stops an off-path attacker
// from redirecting an otherwise-valid segment into a different flow's
// session by tampering with the flowID byte alone.
func kcpTag(macKey []byte, flowID uint16, segment []byte) []byte {
	mac := hmac.New(sha256.New, macKey)
	var flowIDBytes [kcpFlowIDSize]byte
	binary.BigEndian.PutUint16(flowIDBytes[:], flowID)
	mac.Write(flowIDBytes[:])
	mac.Write(segment)
	return mac.Sum(nil)[:kcpMacSize]
}

// buildKCPPacket prepends the KCP marker byte, an HMAC tag (keyed by
// macKey), and flowID to a raw segment produced by a kcp.KCP engine's
// output callback. See kcpFlowID's doc comment for what flowID is for.
func buildKCPPacket(flowID uint16, segment []byte, macKey []byte) []byte {
	out := make([]byte, KCPHeaderSize+len(segment))
	out[0] = KCPVersion
	copy(out[1:1+kcpMacSize], kcpTag(macKey, flowID, segment))
	binary.BigEndian.PutUint16(out[1+kcpMacSize:KCPHeaderSize], flowID)
	copy(out[KCPHeaderSize:], segment)
	return out
}

// ParseKCPPacket verifies the HMAC tag (keyed by macKey) and strips the
// header, returning the flowID and raw segment bytes ready for
// (*KCPSession).Input. A missing/wrong-key/forged tag is indistinguishable
// from network corruption from the caller's point of view - both are just
// dropped.
func ParseKCPPacket(b []byte, macKey []byte) (uint16, []byte, error) {
	if len(b) < KCPHeaderSize {
		return 0, nil, fmt.Errorf("kcp: packet too short for header: %d bytes", len(b))
	}
	if b[0] != KCPVersion {
		return 0, nil, fmt.Errorf("kcp: unsupported version byte %d", b[0])
	}
	flowID := binary.BigEndian.Uint16(b[1+kcpMacSize : KCPHeaderSize])
	segment := b[KCPHeaderSize:]
	if !hmac.Equal(b[1:1+kcpMacSize], kcpTag(macKey, flowID, segment)) {
		return 0, nil, fmt.Errorf("kcp: invalid packet tag")
	}
	return flowID, segment, nil
}

// KCPConfig tunes the underlying KCP engine. Defaults roughly match kcp-go's
// own "fast2" preset: low latency, higher bandwidth cost, no congestion
// control (we are already tunnelling through ICMP on top of whatever the
// real network is doing; a second layer of TCP-style backoff underneath
// our own resend logic just adds latency without much benefit here).
type KCPConfig struct {
	NoDelay      int // 0: disabled, 1: enabled (lower min RTO)
	Interval     int // internal update interval, ms
	Resend       int // 0: disabled, 1+: fast-resend after this many out-of-order ACKs
	NoCongestion int // 0: congestion control on, 1: off
	SndWnd       int // send window, in segments
	RcvWnd       int // receive window, in segments
	MTU          int // max size of one KCP segment on the wire (excludes our 1-byte marker)
	// MaxWaitSnd caps how many segments (kcp.KCP.WaitSnd(): unacked +
	// still-queued) a session may hold before Send blocks. kcp.KCP.Send
	// itself never enforces any such limit - see the vendored
	// github.com/xtaci/kcp-go's KCP.Send, which unconditionally appends to
	// snd_queue - and with NoCongestion=1 nothing else throttles ingestion
	// either, so a sender feeding data faster than the real link drains
	// (routine for a system-wide VPN client tunnelling over an ICMP path
	// far narrower than local traffic) would otherwise grow this queue
	// without bound until the process is OOM-killed. 0 defaults to 4x
	// SndWnd: enough headroom to absorb a burst without stalling every
	// send, small enough to bound memory to a few MB.
	MaxWaitSnd int
	// SendBackpressureTimeoutMs bounds how long Send waits for the backlog
	// to drop below MaxWaitSnd before giving up and dropping the message.
	// 0 defaults to 1000ms.
	SendBackpressureTimeoutMs int
}

// DefaultKCPConfig returns sane defaults for a lossy, low-bandwidth link.
func DefaultKCPConfig() *KCPConfig {
	return &KCPConfig{
		NoDelay:      1,
		Interval:     20,
		Resend:       2,
		NoCongestion: 1,
		SndWnd:       256,
		RcvWnd:       256,
		MTU:          FECMaxPayload, // keep KCP segments within the same safe budget FEC uses
		// A real device tunnels far more than just the user's own traffic
		// (background app/ad-SDK chatter shares the same session/bucket -
		// live-tested 2026-08-27: 25-86 concurrent flows), so the default
		// 4x-SndWnd backlog cap (1024) was routinely maxed out, silently
		// dropping new messages - including the user's own DNS lookups -
		// well before the real link's throughput was the limiting factor.
		MaxWaitSnd: 4096,
	}
}

func (c *KCPConfig) updateInterval() time.Duration {
	interval := c.Interval
	if interval <= 0 {
		interval = 20
	}
	return time.Duration(interval) * time.Millisecond
}

func (c *KCPConfig) maxWaitSnd(sndWnd int) int {
	if c.MaxWaitSnd > 0 {
		return c.MaxWaitSnd
	}
	return sndWnd * 4
}

func (c *KCPConfig) sendBackpressureTimeout() time.Duration {
	if c.SendBackpressureTimeoutMs > 0 {
		return time.Duration(c.SendBackpressureTimeoutMs) * time.Millisecond
	}
	return time.Second
}

// KCPSession is one reliable, ordered, message-boundary-preserving pipe
// over an unreliable packet carrier, backed by a raw kcp.KCP engine (not
// kcp-go's UDPSession/Listener, which insist on owning a net.PacketConn
// outright - incompatible with pingtunnel's single shared ICMP socket
// serving many peers). The caller drives all I/O explicitly:
//
//   - Send(msg) queues an application message; whatever bytes are passed
//     arrive as one slice from RecvChan on the other side (one Send = one
//     message, matching the existing one-MyMsg-per-packet model).
//   - Input(pkt) feeds raw bytes read off the wire (after stripping the
//     KCPVersion marker) into the engine.
//   - sendRaw (given at construction) is called - from a background
//     goroutine, concurrently with everything else - whenever the engine
//     has a raw segment ready to transmit; the caller is responsible for
//     actually writing it to the wire (with the KCPVersion marker
//     prepended via buildKCPPacket).
type KCPSession struct {
	mu     sync.Mutex
	engine *kcp.KCP
	recv   chan []byte
	exit   chan struct{}
	once   sync.Once

	// destKey identifies this session for diagnostic logging only (see
	// Input's first-receive log) - not used for routing, which is entirely
	// KCPTransport's t.sessions map's job.
	destKey string

	maxWaitSnd          int
	backpressureTimeout time.Duration

	// lastActivityUnixNano is touched on every Send/Input, read by
	// KCPTransport's idle reaper - see kcpSessionIdleTimeout.
	lastActivityUnixNano atomic.Int64

	// createdUnixNano and lastRecvUnixNano (0 until the first Input call)
	// back the deadlock detector - see isDeadlocked's doc comment. Unlike
	// lastActivityUnixNano, lastRecvUnixNano is deliberately NOT touched by
	// Send: a session can have Send called on it forever (e.g. one shared
	// bucket - see kcpFlowID - keeps receiving new unrelated flows' traffic)
	// while never once hearing back from the peer, and that distinction is
	// exactly what the idle reaper (keyed on lastActivityUnixNano) cannot
	// see.
	createdUnixNano  int64
	lastRecvUnixNano atomic.Int64

	// TEMP forensic instrumentation for the 2026-08-24 KCP/DNS investigation,
	// populated by the write-site capture in pingtunnel.go (sendICMP/recvICMP's
	// sendRaw closures) immediately after the real conn.WriteTo call. Not read
	// anywhere in this file - deliberately no watchdog/poller lives here.
	diag kcpDiagState
}

// kcpDiagState holds the actual ICMP write-site result for a session's most
// recent KCP output, captured by the caller-supplied sendRaw closure, plus a
// few in-place timing samples taken at existing lock/goroutine boundaries in
// this file (updateLoop's tick, the Output callback). All fields are
// lock-free atomics, written only by the goroutine already doing the
// corresponding work - nothing in this file reads them (see DiagSnapshot).
type kcpDiagState struct {
	writeStart, writeEnd, writeNS atomic.Int64
	writeErr                      atomic.Int64

	// updateNS is engine.Update()'s duration alone (excludes drainLocked),
	// sampled once per updateLoop tick under the tick's own s.mu.
	updateNS atomic.Int64
	// waitSnd is engine.WaitSnd(), sampled immediately after Update() in the
	// same tick, still under the same already-held s.mu - no new lock.
	waitSnd atomic.Int64
	// outputNS is the complete Output callback's duration (copy + sendRaw,
	// i.e. including writeICMP) - outputNS minus writeNS isolates non-write
	// overhead (BuildPacket/HMAC, buffer copy) from the write span itself.
	outputNS atomic.Int64
}

// DiagSnapshot returns a point-in-time read of this session's diagnostic
// state. Atomic loads only - no lock, no side effects, not called from
// anywhere in this codebase yet.
func (s *KCPSession) DiagSnapshot() (updateNS, waitSnd, outputNS, writeNS, writeErr int64) {
	return s.diag.updateNS.Load(), s.diag.waitSnd.Load(), s.diag.outputNS.Load(),
		s.diag.writeNS.Load(), s.diag.writeErr.Load()
}

// lastActivity returns when this session last saw Send or Input activity.
func (s *KCPSession) lastActivity() time.Time {
	return time.Unix(0, s.lastActivityUnixNano.Load())
}

func (s *KCPSession) touchActivity() {
	s.lastActivityUnixNano.Store(time.Now().UnixNano())
}

// kcpDeadlockTimeout bounds how long a session may keep an outstanding send
// backlog (kcp.KCP.WaitSnd() > 0) without ever once hearing back from the
// peer (Input never called) before isDeadlocked reports it dead. kcp-go
// itself detects this internally (segment.xmit >= dead_link, kcp.go:831)
// but only sets an unexported state field nothing else in the vendored
// library or this project ever reads - live-tested 2026-08-27: a session
// wedged this way (its very first exchange corrupted by the ICMP-reflection
// mechanism 5eedf7c guards against - or by a rejected/uninitiated peer that
// never replies) retransmits forever, and because kcpFlowID buckets many
// unrelated flows onto one session, every new flow hashed into that same
// bucket keeps calling Send - which touches lastActivityUnixNano - so the
// existing idle reaper (kcpSessionIdleTimeout) never fires; one bad bucket
// stayed permanently wedged and silently ate roughly 1/kcpFlowBuckets of
// all traffic through it. 10s comfortably outlives any real round trip
// (including the artificial ~60ms RTT this was verified under) while still
// recovering promptly.
const kcpDeadlockTimeout = 10 * time.Second

func (s *KCPSession) touchRecv() {
	s.lastRecvUnixNano.Store(time.Now().UnixNano())
}

// isDeadlocked reports whether this session has an outstanding send backlog
// but has never once received anything from the peer, for at least
// kcpDeadlockTimeout since creation - see kcpDeadlockTimeout's doc comment.
// A session that has received at least one real reply is never considered
// deadlocked by this check, no matter how stale: ordinary loss/recovery is
// already handled by KCP's own retransmit logic and Send's backpressure
// timeout, and conflating the two would risk killing a healthy-but-quiet
// session.
func (s *KCPSession) isDeadlocked(now time.Time) bool {
	if s.lastRecvUnixNano.Load() != 0 {
		return false
	}
	if now.Sub(time.Unix(0, s.createdUnixNano)) < kcpDeadlockTimeout {
		return false
	}
	s.mu.Lock()
	waiting := s.engine.WaitSnd()
	s.mu.Unlock()
	return waiting > 0
}

// NewKCPSession creates a session and starts its background update loop.
// Call Close when done to stop that goroutine.
func NewKCPSession(cfg *KCPConfig, sendRaw func(segment []byte)) *KCPSession {
	if cfg == nil {
		cfg = DefaultKCPConfig()
	}

	s := &KCPSession{
		recv: make(chan []byte, 1024),
		exit: make(chan struct{}),
	}
	s.touchActivity()
	s.createdUnixNano = time.Now().UnixNano()

	s.engine = kcp.NewKCP(kcpConv, func(buf []byte, size int) {
		outputStart := time.Now()
		cp := make([]byte, size)
		copy(cp, buf[:size])
		sendRaw(cp)
		s.diag.outputNS.Store(time.Since(outputStart).Nanoseconds())
	})

	nodelay, interval, resend, nc := cfg.NoDelay, cfg.Interval, cfg.Resend, cfg.NoCongestion
	if interval <= 0 {
		interval = 20
	}
	s.engine.NoDelay(nodelay, interval, resend, nc)

	sndWnd, rcvWnd := cfg.SndWnd, cfg.RcvWnd
	if sndWnd <= 0 {
		sndWnd = 256
	}
	if rcvWnd <= 0 {
		rcvWnd = 256
	}
	s.engine.WndSize(sndWnd, rcvWnd)

	mtu := cfg.MTU
	if mtu <= 0 {
		mtu = FECMaxPayload
	}
	s.engine.SetMtu(mtu)

	s.maxWaitSnd = cfg.maxWaitSnd(sndWnd)
	s.backpressureTimeout = cfg.sendBackpressureTimeout()

	go s.updateLoop(cfg.updateInterval())

	return s
}

func (s *KCPSession) updateLoop(interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-s.exit:
			return
		case <-ticker.C:
			s.mu.Lock()
			updateStart := time.Now()
			s.engine.Update()
			s.diag.updateNS.Store(time.Since(updateStart).Nanoseconds())
			s.diag.waitSnd.Store(int64(s.engine.WaitSnd()))
			msgs := s.drainLocked()
			s.mu.Unlock()
			s.deliver(msgs)
		}
	}
}

// drainLocked pulls every fully-reassembled message currently sitting in
// the engine's receive queue. Must be called with s.mu held.
func (s *KCPSession) drainLocked() [][]byte {
	var msgs [][]byte
	for {
		size := s.engine.PeekSize()
		if size <= 0 {
			break
		}
		buf := make([]byte, size)
		n := s.engine.Recv(buf)
		if n <= 0 {
			break
		}
		msgs = append(msgs, buf[:n])
	}
	return msgs
}

func (s *KCPSession) deliver(msgs [][]byte) {
	for _, m := range msgs {
		select {
		case s.recv <- m:
		case <-s.exit:
			return
		}
	}
}

// Send queues msg for reliable delivery. Safe for concurrent use.
//
// Blocks while the session's outstanding backlog (kcp.KCP.WaitSnd(): segments
// either in flight or still queued behind the send window) is at or above
// maxWaitSnd, giving the background updateLoop goroutine (which isn't
// blocked by this - it only needs s.mu, released while waiting here) a
// chance to drain it as ACKs arrive. If the backlog is still full after
// backpressureTimeout - meaning the real link genuinely can't keep up, not
// just a momentary burst - the message is dropped rather than buffered
// forever. Without this, a sender feeding data faster than the tunnel's
// real throughput (e.g. a system-wide VPN client routing far more traffic
// than a narrow ICMP path can carry) would grow the backlog in memory
// without bound, since neither kcp.KCP.Send nor NoCongestion=1 imposes any
// cap of their own - see MaxWaitSnd's doc comment.
func (s *KCPSession) Send(msg []byte) error {
	s.touchActivity()

	if err := s.waitForRoom(); err != nil {
		return err
	}

	s.mu.Lock()
	ret := s.engine.Send(msg)
	if ret == 0 {
		// Nudge an immediate flush so small/interactive messages don't sit
		// waiting for the next update tick.
		s.engine.Update()
	}
	s.mu.Unlock()
	if ret < 0 {
		return fmt.Errorf("kcp: send failed, code %d", ret)
	}
	return nil
}

// waitForRoom blocks until the session's backlog drops below maxWaitSnd, the
// session is closed, or backpressureTimeout elapses (whichever comes first).
func (s *KCPSession) waitForRoom() error {
	deadline := time.Now().Add(s.backpressureTimeout)
	for {
		s.mu.Lock()
		waiting := s.engine.WaitSnd()
		s.mu.Unlock()

		if waiting < s.maxWaitSnd {
			return nil
		}
		if !time.Now().Before(deadline) {
			return fmt.Errorf("kcp: send queue backlog too high (%d segments >= cap %d), dropping message", waiting, s.maxWaitSnd)
		}

		select {
		case <-time.After(5 * time.Millisecond):
		case <-s.exit:
			return fmt.Errorf("kcp: session closed while waiting for send backlog to drain")
		}
	}
}

// Input feeds raw bytes received from the wire (already stripped of the
// KCPVersion marker) into the engine, delivering any newly-complete
// messages to RecvChan immediately rather than waiting for the next
// update tick.
func (s *KCPSession) Input(pkt []byte) {
	if s.lastRecvUnixNano.Load() == 0 {
		loggo.Debug("DIAG FIRSTRECV destKey=%s bytes=%d", s.destKey, len(pkt))
	}
	s.touchActivity()
	s.touchRecv()

	s.mu.Lock()
	s.engine.Input(pkt, true, false)
	msgs := s.drainLocked()
	s.mu.Unlock()
	s.deliver(msgs)
}

// RecvChan returns the channel of reassembled application messages, in
// order. Closed once Close is called (after any already-queued messages
// are drained... in practice: stops receiving new ones, existing readers
// should treat a receive-on-closed-exit race as "session gone").
func (s *KCPSession) RecvChan() <-chan []byte {
	return s.recv
}

// Close stops the session's background update loop. Idempotent.
func (s *KCPSession) Close() {
	s.once.Do(func() { close(s.exit) })
}

// Done returns a channel closed once Close has been called, so callers
// range-reading RecvChan in a select can stop cleanly instead of blocking
// forever on a channel nothing sends to again.
func (s *KCPSession) Done() <-chan struct{} {
	return s.exit
}

// KCPTransport manages one KCPSession per (destination, flow) - destKey
// already folds in kcpFlowID (see its doc comment for why per-flow, not
// just per-peer, matters: head-of-line blocking between unrelated flows
// multiplexed onto one session). A single transport is shared for both
// directions of traffic to a given peer - sendICMP and recvICMP both call
// Session for the same destKey, and whichever happens first creates it;
// KCP is bidirectional within one engine, so outbound application data and
// inbound ACKs (and vice versa) must flow through the very same *kcp.KCP
// or its retransmit/ack bookkeeping never converges.
type KCPTransport struct {
	cfg *KCPConfig
	// macKey authenticates every KCP segment on the wire (see KCPHeaderSize's
	// doc comment on kcp_transport.go); both peers must derive the same key,
	// which client.go/server.go do from the same secret that already gates
	// the tunnel (the encryption key, or the numeric -key as a fallback).
	macKey []byte
	// deliver is called, from a dedicated per-session goroutine, for every
	// fully-reassembled inbound application message. peer/id identify
	// which destKey it came from, so the caller can tag it the same way a
	// directly-received (non-KCP) packet would be.
	deliver func(msg []byte, peer *net.IPAddr, id int)

	mu       sync.Mutex
	sessions map[string]*KCPSession

	reaperStop chan struct{}
	reaperDone chan struct{}
}

// kcpSessionIdleTimeout bounds how long an idle (no Send/Input activity)
// session is kept before Reap closes and drops it. Per-flow sessions (see
// kcpFlowID) are created far more often than the old one-per-peer scheme -
// e.g. one per DNS lookup - and each holds a goroutine ticking every
// Interval ms (default 20ms) until closed, so leaving them all running
// forever is a real, not just theoretical, goroutine/memory leak over a
// long browsing session. 30s comfortably outlives a single lookup's
// request/response round trip while still reclaiming promptly.
const kcpSessionIdleTimeout = 30 * time.Second

// kcpReapInterval is how often KCPTransport scans for idle sessions to
// close - doesn't need to be frequent, idle sessions are cheap to leave
// around for up to one extra interval past their timeout.
const kcpReapInterval = 10 * time.Second

// NewKCPTransport creates an (initially empty) per-destination session
// manager for the given tuning parameters, and starts its background idle-
// session reaper (see kcpSessionIdleTimeout). deliver may be nil if the
// caller only ever sends (never expects inbound application data on these
// sessions) - not a realistic pingtunnel setup, but convenient for tests.
func NewKCPTransport(cfg *KCPConfig, macKey []byte, deliver func(msg []byte, peer *net.IPAddr, id int)) *KCPTransport {
	if cfg == nil {
		cfg = DefaultKCPConfig()
	}
	t := &KCPTransport{
		cfg: cfg, macKey: macKey, deliver: deliver,
		sessions:   make(map[string]*KCPSession),
		reaperStop: make(chan struct{}),
		reaperDone: make(chan struct{}),
	}
	go t.reapLoop()
	return t
}

func (t *KCPTransport) reapLoop() {
	defer close(t.reaperDone)
	ticker := time.NewTicker(kcpReapInterval)
	defer ticker.Stop()
	for {
		select {
		case <-t.reaperStop:
			return
		case <-ticker.C:
			t.reapIdle()
		}
	}
}

func (t *KCPTransport) reapIdle() {
	now := time.Now()
	t.mu.Lock()
	var idle []*KCPSession
	var deadlocked []*KCPSession
	for destKey, s := range t.sessions {
		switch {
		case now.Sub(s.lastActivity()) >= kcpSessionIdleTimeout:
			idle = append(idle, s)
			delete(t.sessions, destKey)
		case s.isDeadlocked(now):
			// Still "active" (Send keeps getting called - see
			// isDeadlocked's doc comment) so the idle branch above never
			// catches this; close and drop it here instead so the next
			// Send/Input for this destKey starts a fresh session rather
			// than piling onto one that can never make progress.
			deadlocked = append(deadlocked, s)
			delete(t.sessions, destKey)
		}
	}
	t.mu.Unlock()

	for _, s := range idle {
		s.Close()
	}
	for _, s := range deadlocked {
		loggo.Info("kcp session deadlocked (never received anything from peer after %s with a pending backlog), closing so a fresh session can take over", kcpDeadlockTimeout)
		s.Close()
	}
}

// BuildPacket frames a raw segment for the wire, tagged with this
// transport's macKey and flowID.
func (t *KCPTransport) BuildPacket(flowID uint16, segment []byte) []byte {
	return buildKCPPacket(flowID, segment, t.macKey)
}

// ParsePacket verifies and strips a wire-framed packet's header, using this
// transport's macKey, returning the flowID it was tagged with.
func (t *KCPTransport) ParsePacket(b []byte) (uint16, []byte, error) {
	return ParseKCPPacket(b, t.macKey)
}

// Session returns the session for destKey, creating one via sendRaw (and
// starting a goroutine that feeds every message it ever receives to
// t.deliver) if none exists yet. peer/id are only used to tag messages
// handed to deliver - both sendICMP and recvICMP already compute the same
// destKey (peer + ICMP echo id + kcpFlowID) for a given flow, so whichever
// of them creates the session passes the peer/id that later drives every
// deliver call for it.
func (t *KCPTransport) Session(destKey string, peer *net.IPAddr, id int, sendRaw func(segment []byte)) *KCPSession {
	t.mu.Lock()
	if s, ok := t.sessions[destKey]; ok {
		t.mu.Unlock()
		return s
	}
	loggo.Debug("DIAG NEWSESSION destKey=%s peer=%v id=%d", destKey, peer, id)
	s := NewKCPSession(t.cfg, sendRaw)
	s.destKey = destKey
	t.sessions[destKey] = s
	t.mu.Unlock()

	go func() {
		for {
			select {
			case msg := <-s.RecvChan():
				if t.deliver != nil {
					t.deliver(msg, peer, id)
				}
			case <-s.Done():
				return
			}
		}
	}()

	return s
}

// Close shuts down every tracked session and stops the idle-session reaper.
func (t *KCPTransport) Close() {
	close(t.reaperStop)
	<-t.reaperDone

	t.mu.Lock()
	defer t.mu.Unlock()
	for _, s := range t.sessions {
		s.Close()
	}
	t.sessions = make(map[string]*KCPSession)
}
