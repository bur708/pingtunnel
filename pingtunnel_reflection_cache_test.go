package pingtunnel

import (
	"testing"
	"time"
)

// Regression tests for the reflection-cache performance fix: rememberEchoRequest
// used to scan the entire recentEchoRequests map (an O(map size) sweep) on
// every single call, inline on this project's per-packet send hot path.
// Cleanup was moved to a separate periodic background loop instead - these
// tests pin down that isEchoReplyReflection's actual matching behavior
// (which is what correctness depends on) is unchanged by that move.

func TestRememberEchoRequestMatchesWithinWindow(t *testing.T) {
	icmpBytes := []byte{0, 0, 0, 0, 0xAB, 0xCD, 1, 2, 3, 4, 5}
	rememberEchoRequest(icmpBytes)
	if !isEchoReplyReflection(icmpBytes) {
		t.Fatal("expected a just-remembered request to be reported as a reflection match")
	}
}

func TestIsEchoReplyReflectionFalseForNeverSentBytes(t *testing.T) {
	neverSent := []byte{0, 0, 0, 0, 0x11, 0x22, 9, 9, 9, 9}
	if isEchoReplyReflection(neverSent) {
		t.Fatal("expected bytes never passed to rememberEchoRequest to never match")
	}
}

// Correctness (not just performance) must not depend on the background
// cleanup loop's timing: an entry old enough to be outside
// echoReflectionWindow must stop matching immediately once queried, whether
// or not the periodic sweep has actually gotten around to deleting it yet.
func TestIsEchoReplyReflectionFalseOnceExpiredEvenBeforeSwept(t *testing.T) {
	icmpBytes := []byte{0, 0, 0, 0, 0x33, 0x44, 7, 7, 7}
	key := string(icmpBytes[4:])

	recentEchoRequestsMu.Lock()
	recentEchoRequests[key] = time.Now().Add(-2 * echoReflectionWindow)
	recentEchoRequestsMu.Unlock()

	if isEchoReplyReflection(icmpBytes) {
		t.Fatal("expected an entry older than echoReflectionWindow to be treated as expired, regardless of whether the background sweep has run yet")
	}
}
