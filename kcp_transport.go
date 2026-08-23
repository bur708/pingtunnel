package pingtunnel

import (
	"crypto/hmac"
	"crypto/sha256"
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
//	[0]    version/flag byte, always KCPVersion for a valid KCP packet
//	[1:9]  truncated HMAC-SHA256(macKey, segment)
//	[9:]   raw kcp.KCP segment bytes, passed to (*KCPSession).Input as-is
//
// The MAC exists because kcp.KCP's Input() has no authentication of its
// own: routing to a session is keyed only by (source IP, ICMP echo id),
// both attacker-observable/spoofable, and the "conv" field kcp-go uses to
// disambiguate conversations is a fixed constant here (see kcpConv below),
// not a secret. Without a MAC, an off-path attacker could forge segments
// (e.g. an ACK claiming already-sent data was delivered) directly into an
// established session's retransmit bookkeeping. Tying the tag to the same
// key material that already gates the tunnel (the encryption key, or the
// fallback numeric -key) means forging a valid segment requires knowing
// that secret, same as everywhere else in this protocol.
const (
	KCPVersion    byte = 2
	kcpMacSize         = 8
	KCPHeaderSize      = 1 + kcpMacSize
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

// kcpTag computes the truncated HMAC-SHA256 tag for segment under macKey.
func kcpTag(macKey, segment []byte) []byte {
	mac := hmac.New(sha256.New, macKey)
	mac.Write(segment)
	return mac.Sum(nil)[:kcpMacSize]
}

// buildKCPPacket prepends the KCP marker byte and an HMAC tag (keyed by
// macKey) to a raw segment produced by a kcp.KCP engine's output callback.
func buildKCPPacket(segment []byte, macKey []byte) []byte {
	out := make([]byte, KCPHeaderSize+len(segment))
	out[0] = KCPVersion
	copy(out[1:KCPHeaderSize], kcpTag(macKey, segment))
	copy(out[KCPHeaderSize:], segment)
	return out
}

// ParseKCPPacket verifies the HMAC tag (keyed by macKey) and strips the
// header, returning the raw segment bytes ready for (*KCPSession).Input.
// A missing/wrong-key/forged tag is indistinguishable from network
// corruption from the caller's point of view - both are just dropped.
func ParseKCPPacket(b []byte, macKey []byte) ([]byte, error) {
	if len(b) < KCPHeaderSize {
		return nil, fmt.Errorf("kcp: packet too short for header: %d bytes", len(b))
	}
	if b[0] != KCPVersion {
		return nil, fmt.Errorf("kcp: unsupported version byte %d", b[0])
	}
	segment := b[KCPHeaderSize:]
	if !hmac.Equal(b[1:KCPHeaderSize], kcpTag(macKey, segment)) {
		return nil, fmt.Errorf("kcp: invalid packet tag")
	}
	return segment, nil
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

	maxWaitSnd          int
	backpressureTimeout time.Duration
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
}

// NewKCPTransport creates an (initially empty) per-destination session
// manager for the given tuning parameters. deliver may be nil if the
// caller only ever sends (never expects inbound application data on these
// sessions) - not a realistic pingtunnel setup, but convenient for tests.
func NewKCPTransport(cfg *KCPConfig, macKey []byte, deliver func(msg []byte, peer *net.IPAddr, id int)) *KCPTransport {
	if cfg == nil {
		cfg = DefaultKCPConfig()
	}
	return &KCPTransport{cfg: cfg, macKey: macKey, deliver: deliver, sessions: make(map[string]*KCPSession)}
}

// BuildPacket frames a raw segment for the wire, tagged with this
// transport's macKey.
func (t *KCPTransport) BuildPacket(segment []byte) []byte {
	return buildKCPPacket(segment, t.macKey)
}

// ParsePacket verifies and strips a wire-framed packet's header, using this
// transport's macKey.
func (t *KCPTransport) ParsePacket(b []byte) ([]byte, error) {
	return ParseKCPPacket(b, t.macKey)
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
