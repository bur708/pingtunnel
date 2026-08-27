package pingtunnel

import (
	"testing"
	"time"
)

// Regression test for the "many parallel connections through one adaptive
// server" failure mode: NekoBox-style system-wide proxying opens 10+
// tcpmode connections at once, and the previously-hardcoded 5s handshake-
// ack wait was too tight for all of them to complete under that load
// before the client/server each gave up. -connect-timeout must actually
// reach both sides' wait loops.
func TestNewClientConnectTimeout(t *testing.T) {
	c, err := NewClient("127.0.0.1:0", "127.0.0.1", "", 60, 1, "0.0.0.0",
		0, 0, 0, 0, 0,
		0, 1, 0, nil, nil,
		"", "", nil, nil, 20, 0)
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	if c.connectTimeout != 20*time.Second {
		t.Fatalf("expected connectTimeout=20s, got %v", c.connectTimeout)
	}
}

func TestNewClientConnectTimeoutFallsBackWhenZero(t *testing.T) {
	c, err := NewClient("127.0.0.1:0", "127.0.0.1", "", 60, 1, "0.0.0.0",
		0, 0, 0, 0, 0,
		0, 1, 0, nil, nil,
		"", "", nil, nil, 0, 0)
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	if c.connectTimeout != 5*time.Second {
		t.Fatalf("expected default connectTimeout=5s when 0 is passed, got %v", c.connectTimeout)
	}
}

func TestNewServerConnectTimeout(t *testing.T) {
	s, err := NewServer("0.0.0.0", 1, 0, 0, 0, 3000, nil, nil, nil, nil, 20, 0, 0, 0, false)
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	if s.connectTimeout != 20*time.Second {
		t.Fatalf("expected connectTimeout=20s, got %v", s.connectTimeout)
	}
}

func TestNewServerConnectTimeoutFallsBackWhenZero(t *testing.T) {
	s, err := NewServer("0.0.0.0", 1, 0, 0, 0, 3000, nil, nil, nil, nil, 0, 0, 0, 0, false)
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	if s.connectTimeout != 5*time.Second {
		t.Fatalf("expected default connectTimeout=5s when 0 is passed, got %v", s.connectTimeout)
	}
}

// Regression test for -kcp-sndwnd/-kcp-rcvwnd: a real deployment
// recommended to run without -fec/-kcp (adaptive mode, see
// infra-and-access memory) must still be able to tune the KCP window for a
// high-bandwidth-delay-product link (e.g. satellite) - these flags must not
// be silently ignored just because no -kcp/-fec was pinned.
func TestNewServerAdaptiveModeAppliesKCPWindowOverrides(t *testing.T) {
	s, err := NewServer("0.0.0.0", 1, 0, 0, 0, 3000, nil, nil, nil, nil, 0, 0, 1024, 2048, false)
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	if s.kcpConfig == nil {
		t.Fatalf("expected adaptive mode to still build a kcpConfig")
	}
	if s.kcpConfig.SndWnd != 1024 {
		t.Fatalf("expected SndWnd override 1024 to apply in adaptive mode, got %d", s.kcpConfig.SndWnd)
	}
	if s.kcpConfig.RcvWnd != 2048 {
		t.Fatalf("expected RcvWnd override 2048 to apply in adaptive mode, got %d", s.kcpConfig.RcvWnd)
	}
}

// Companion: passing 0 (the flag default, meaning "not overridden") must
// leave the built-in default window size intact rather than zeroing it out.
func TestNewServerAdaptiveModeKeepsDefaultWindowWhenOverrideIsZero(t *testing.T) {
	s, err := NewServer("0.0.0.0", 1, 0, 0, 0, 3000, nil, nil, nil, nil, 0, 0, 0, 0, false)
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	if s.kcpConfig.SndWnd != 256 || s.kcpConfig.RcvWnd != 256 {
		t.Fatalf("expected default 256/256 window when overrides are 0, got sndwnd=%d rcvwnd=%d", s.kcpConfig.SndWnd, s.kcpConfig.RcvWnd)
	}
}

// Regression test for -kcp-congestion: NoCongestion defaults to 1 (kcp-go's
// built-in TCP-Reno-style congestion control disabled, matching this
// project's original behavior) unless explicitly requested, including in
// adaptive mode - same reasoning as the window-override tests above.
func TestNewServerAdaptiveModeAppliesCongestionControlFlag(t *testing.T) {
	s, err := NewServer("0.0.0.0", 1, 0, 0, 0, 3000, nil, nil, nil, nil, 0, 0, 0, 0, true)
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	if s.kcpConfig.NoCongestion != 0 {
		t.Fatalf("expected -kcp-congestion=true to set NoCongestion=0, got %d", s.kcpConfig.NoCongestion)
	}
}

func TestNewServerAdaptiveModeKeepsCongestionDisabledByDefault(t *testing.T) {
	s, err := NewServer("0.0.0.0", 1, 0, 0, 0, 3000, nil, nil, nil, nil, 0, 0, 0, 0, false)
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	if s.kcpConfig.NoCongestion != 1 {
		t.Fatalf("expected NoCongestion=1 (unchanged default) when -kcp-congestion is false, got %d", s.kcpConfig.NoCongestion)
	}
}
