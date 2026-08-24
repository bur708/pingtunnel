package pingtunnel

import (
	"testing"
	"time"
)

// A nil *RateLimiter (the default when -max-pps rate limiting isn't
// wanted, e.g. tests constructing a Client/Server directly) must never
// block - see writeICMP's call site, which always calls Allow() even when
// no limiter was configured.
func TestRateLimiterNilAlwaysAllows(t *testing.T) {
	var r *RateLimiter
	for i := 0; i < 1000; i++ {
		if !r.Allow() {
			t.Fatalf("nil RateLimiter refused on iteration %d, expected unlimited throughput", i)
		}
	}
}

// A fresh limiter must allow a full burst (its configured pps, taken as
// the burst capacity too) without any waiting.
func TestRateLimiterAllowsInitialBurstWithoutBlocking(t *testing.T) {
	r := NewRateLimiter(10)
	start := time.Now()
	for i := 0; i < 10; i++ {
		if !r.Allow() {
			t.Fatalf("burst call %d unexpectedly refused", i)
		}
	}
	if elapsed := time.Since(start); elapsed > 50*time.Millisecond {
		t.Fatalf("burst of 10 within a 10pps budget took %v, expected near-instant", elapsed)
	}
}

// Regression test for the resend-storm fix itself: once the burst budget
// is exhausted, further calls must actually wait for refill rather than
// being granted immediately - this is the mechanism that stops many
// connections' independent FrameMgr resend timers from all landing on the
// wire in the same instant (live-tested 2026-08-24: send rate hit
// 3000+pps with ~0pps of matching incoming ACK traffic, and the tunnel
// never recovered on its own).
func TestRateLimiterThrottlesBeyondBurst(t *testing.T) {
	r := NewRateLimiter(5) // 5 tokens/sec, refills one every ~200ms
	for i := 0; i < 5; i++ {
		if !r.Allow() {
			t.Fatalf("initial burst call %d unexpectedly refused", i)
		}
	}

	start := time.Now()
	if !r.Allow() {
		t.Fatal("6th call within allowTimeout should eventually succeed once a token refills")
	}
	if elapsed := time.Since(start); elapsed < 100*time.Millisecond {
		t.Fatalf("6th call returned after only %v, expected it to wait for refill (~200ms at 5pps)", elapsed)
	}
}

// Over a sustained period, throughput must stay close to the configured
// cap rather than drifting - i.e. this is a real rate limiter, not just a
// one-off burst allowance.
func TestRateLimiterCapsSustainedRate(t *testing.T) {
	const pps = 50
	r := NewRateLimiter(pps)

	deadline := time.Now().Add(500 * time.Millisecond)
	count := 0
	for time.Now().Before(deadline) {
		if r.Allow() {
			count++
		}
	}

	// Half a second at 50pps should allow roughly 25, plus the initial
	// burst of 50 - generous bounds since this is real-time and CPU-load
	// dependent, but a runaway (e.g. thousands) would still be caught.
	if count > pps+50 {
		t.Fatalf("got %d allowed calls in 500ms at %dpps - rate limiting isn't actually capping throughput", count, pps)
	}
}
