package pingtunnel

import (
	"sync"
	"time"
)

// DefaultMaxPPS is the outbound packet-rate cap used when -max-pps isn't
// set (or is <= 0). Originally set to 400 from live measurements against a
// real residential Wi-Fi link (2026-08-24): raw ICMP floods stayed under
// ~1% loss and low RTT up to ~70-100pps once the link was "warm", but a
// cold burst at 100pps saw 8.5% loss and RTT spiking to 477ms - 400 was
// meant purely as a safety net against runaway amplification, not a
// throughput tune, and far below the 3000+pps the tunnel reached during
// the resend storm that motivated adding this limiter at all.
//
// Raised to 2000 the same day once that safety net turned out to have a
// real cost of its own: a phone's background apps alone sustain on the
// order of 170-185 concurrent SOCKS5-UDP-relay flows (mostly DNS), all
// sharing this one budget. At 400pps that's only ~2pps per flow on
// average, and -kcp needs more round trips per exchange (data + ACK
// segments) than -fec/none's one-packet-each-way, so KCP flows were the
// first to fall behind their local proxy's own reply timeout under that
// contention - observed live as ERR_NAME_NOT_RESOLVED in the browser even
// though the tunnel itself was healthy (no drops, no crash, steady
// resource use). The resend-storm risk this limiter exists to cap is
// itself now bounded by other means too (KCP's own backpressure in
// kcp_transport.go, per-flow session bucketing there), so raising the
// ceiling is safer than it would have been when 400 was first chosen.
const DefaultMaxPPS = 2000

// RateLimiter caps a Client/Server instance's total outbound packet rate,
// shared across every connection multiplexed onto its one ICMP socket -
// see writeICMP's call site for why a per-connection limit isn't enough.
// Without a single shared budget, many connections' independent FrameMgr
// resend timers (400ms each, uncoordinated) can all come due in the same
// instant once real loss/latency ticks up even slightly, and nothing stops
// the resulting burst from itself being the thing that causes more loss -
// a runaway feedback loop observed in practice (live-tested 2026-08-24: a
// speedtest-triggered burst pushed send rate to 3000+pps while incoming ACK
// traffic dropped to ~0pps for several seconds, and the tunnel never
// recovered on its own). A simple shared token bucket, applied at the one
// choke point every outgoing packet already passes through regardless of
// mode (writeICMP), bounds the worst case without needing to touch
// FrameMgr's or KCP's own per-connection retry logic at all.
type RateLimiter struct {
	mu         sync.Mutex
	tokens     float64
	maxTokens  float64
	perSec     float64
	lastRefill time.Time
}

// NewRateLimiter creates a limiter allowing pps packets/sec on average,
// with burst capacity equal to one second's worth of tokens. pps <= 0
// falls back to DefaultMaxPPS.
func NewRateLimiter(pps int) *RateLimiter {
	if pps <= 0 {
		pps = DefaultMaxPPS
	}
	return &RateLimiter{
		tokens:     float64(pps),
		maxTokens:  float64(pps),
		perSec:     float64(pps),
		lastRefill: time.Now(),
	}
}

// allowTimeout bounds how long Allow blocks waiting for a token before
// giving up. Kept short and fixed (rather than threaded through as a
// parameter to every writeICMP call site) since this is purely a
// self-imposed local throttle against a budget we control, not a wait on
// uncertain network/peer state the way KCPSession's backpressure is -
// tokens reliably become available within perSec regardless of what the
// remote end is doing, so a long timeout would only delay noticing a
// genuinely misconfigured (pps <= 0 elsewhere) or shut-down limiter.
const allowTimeout = 2 * time.Second

// Allow blocks until a token is available or allowTimeout elapses,
// returning false in the latter case - callers should drop the packet
// rather than send it, matching KCPSession.Send's backpressure pattern. A
// nil receiver always allows immediately (rate limiting disabled), so
// passing a nil *RateLimiter is a valid, unlimited-throughput default.
func (r *RateLimiter) Allow() bool {
	if r == nil {
		return true
	}

	deadline := time.Now().Add(allowTimeout)
	for {
		r.mu.Lock()
		r.refillLocked()
		if r.tokens >= 1 {
			r.tokens--
			r.mu.Unlock()
			return true
		}
		r.mu.Unlock()

		if !time.Now().Before(deadline) {
			return false
		}
		time.Sleep(2 * time.Millisecond)
	}
}

// refillLocked adds tokens for elapsed time since the last refill. Must be
// called with r.mu held.
func (r *RateLimiter) refillLocked() {
	now := time.Now()
	elapsed := now.Sub(r.lastRefill).Seconds()
	r.lastRefill = now
	r.tokens += elapsed * r.perSec
	if r.tokens > r.maxTokens {
		r.tokens = r.maxTokens
	}
}
