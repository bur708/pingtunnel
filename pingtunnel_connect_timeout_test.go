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
		"", "", nil, nil, 20)
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
		"", "", nil, nil, 0)
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	if c.connectTimeout != 5*time.Second {
		t.Fatalf("expected default connectTimeout=5s when 0 is passed, got %v", c.connectTimeout)
	}
}

func TestNewServerConnectTimeout(t *testing.T) {
	s, err := NewServer("0.0.0.0", 1, 0, 0, 0, 3000, nil, nil, nil, nil, 20)
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	if s.connectTimeout != 20*time.Second {
		t.Fatalf("expected connectTimeout=20s, got %v", s.connectTimeout)
	}
}

func TestNewServerConnectTimeoutFallsBackWhenZero(t *testing.T) {
	s, err := NewServer("0.0.0.0", 1, 0, 0, 0, 3000, nil, nil, nil, nil, 0)
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	if s.connectTimeout != 5*time.Second {
		t.Fatalf("expected default connectTimeout=5s when 0 is passed, got %v", s.connectTimeout)
	}
}
