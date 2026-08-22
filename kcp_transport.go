package pingtunnel

import (
	"fmt"
	"net"
	"sync"
	"time"

	kcp "github.com/xtaci/kcp-go"
)

// Wire format of a KCP-framed packet, prepended before the raw bytes a
// kcp.KCP engine's output callback hands us. Mirrors fec.go's FECVersion
// scheme so recvICMP can tell legacy / FEC / KCP packets apart from byte 0
// alone, before parsing further.
//
//	[0]  version/flag byte, always KCPVersion for a valid KCP packet
//	[1:] raw kcp.KCP segment bytes, passed to (*KCPSession).Input as-is
const (
	KCPVersion    byte = 2
	KCPHeaderSize      = 1
)

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

// buildKCPPacket prepends the KCP marker byte to a raw segment produced by
// a kcp.KCP engine's output callback.
func buildKCPPacket(segment []byte) []byte {
	out := make([]byte, KCPHeaderSize+len(segment))
	out[0] = KCPVersion
	copy(out[KCPHeaderSize:], segment)
	return out
}

// ParseKCPPacket strips the KCP marker byte, returning the raw segment
// bytes ready for (*KCPSession).Input.
func ParseKCPPacket(b []byte) ([]byte, error) {
	if len(b) < KCPHeaderSize {
		return nil, fmt.Errorf("kcp: packet too short for header: %d bytes", len(b))
	}
	if b[0] != KCPVersion {
		return nil, fmt.Errorf("kcp: unsupported version byte %d", b[0])
	}
	return b[KCPHeaderSize:], nil
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
	}
}

func (c *KCPConfig) updateInterval() time.Duration {
	interval := c.Interval
	if interval <= 0 {
		interval = 20
	}
	return time.Duration(interval) * time.Millisecond
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

	s.engine = kcp.NewKCP(kcpConv, func(buf []byte, size int) {
		cp := make([]byte, size)
		copy(cp, buf[:size])
		sendRaw(cp)
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
			s.engine.Update()
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
func (s *KCPSession) Send(msg []byte) error {
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

// Input feeds raw bytes received from the wire (already stripped of the
// KCPVersion marker) into the engine, delivering any newly-complete
// messages to RecvChan immediately rather than waiting for the next
// update tick.
func (s *KCPSession) Input(pkt []byte) {
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

// KCPTransport manages one KCPSession per destination (peer), the same
// destKey granularity fec.go's FECSender/FECReceiver already use (one
// session per (remote address, ICMP echo id) pair). A single transport is
// shared for both directions of traffic to a given peer - sendICMP and
// recvICMP both call Session for the same destKey, and whichever happens
// first creates it; KCP is bidirectional within one engine, so outbound
// application data and inbound ACKs (and vice versa) must flow through
// the very same *kcp.KCP or its retransmit/ack bookkeeping never
// converges.
type KCPTransport struct {
	cfg *KCPConfig
	// deliver is called, from a dedicated per-session goroutine, for every
	// fully-reassembled inbound application message. peer/id identify
	// which destKey it came from, so the caller can tag it the same way a
	// directly-received (non-KCP) packet would be.
	deliver func(msg []byte, peer *net.IPAddr, id int)

	mu       sync.Mutex
	sessions map[string]*KCPSession
}

// NewKCPTransport creates an (initially empty) per-destination session
// manager for the given tuning parameters. deliver may be nil if the
// caller only ever sends (never expects inbound application data on these
// sessions) - not a realistic pingtunnel setup, but convenient for tests.
func NewKCPTransport(cfg *KCPConfig, deliver func(msg []byte, peer *net.IPAddr, id int)) *KCPTransport {
	if cfg == nil {
		cfg = DefaultKCPConfig()
	}
	return &KCPTransport{cfg: cfg, deliver: deliver, sessions: make(map[string]*KCPSession)}
}

// Session returns the session for destKey, creating one via sendRaw (and
// starting a goroutine that feeds every message it ever receives to
// t.deliver) if none exists yet. peer/id are only used to tag messages
// handed to deliver - both sendICMP and recvICMP already compute the same
// destKey for a given peer, so whichever of them creates the session
// passes the peer/id that later drives every deliver call for it.
func (t *KCPTransport) Session(destKey string, peer *net.IPAddr, id int, sendRaw func(segment []byte)) *KCPSession {
	t.mu.Lock()
	if s, ok := t.sessions[destKey]; ok {
		t.mu.Unlock()
		return s
	}
	s := NewKCPSession(t.cfg, sendRaw)
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

// Close shuts down every tracked session.
func (t *KCPTransport) Close() {
	t.mu.Lock()
	defer t.mu.Unlock()
	for _, s := range t.sessions {
		s.Close()
	}
	t.sessions = make(map[string]*KCPSession)
}
