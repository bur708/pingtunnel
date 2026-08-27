package pingtunnel

import (
	"net"
	"testing"
)

func TestPeerModeTrackerDefaultsToNone(t *testing.T) {
	tr := NewPeerModeTracker()
	if mode := tr.Mode("never-seen"); mode != PeerModeNone {
		t.Fatalf("expected PeerModeNone for an unobserved peer, got %v", mode)
	}
	if _, _, ok := tr.FECParams("never-seen"); ok {
		t.Fatalf("expected FECParams to report ok=false for an unobserved peer")
	}
}

func TestPeerModeTrackerObserveAndFECParams(t *testing.T) {
	tr := NewPeerModeTracker()
	tr.Observe("peerA", PeerModeFEC, 10, 3)
	tr.Observe("peerB", PeerModeKCP, 0, 0)

	if mode := tr.Mode("peerA"); mode != PeerModeFEC {
		t.Fatalf("expected PeerModeFEC for peerA, got %v", mode)
	}
	if mode := tr.Mode("peerB"); mode != PeerModeKCP {
		t.Fatalf("expected PeerModeKCP for peerB, got %v", mode)
	}

	data, parity, ok := tr.FECParams("peerA")
	if !ok || data != 10 || parity != 3 {
		t.Fatalf("expected FECParams(peerA) = (10, 3, true), got (%d, %d, %v)", data, parity, ok)
	}

	// A KCP peer has no FEC params to report, even though it has been observed.
	if _, _, ok := tr.FECParams("peerB"); ok {
		t.Fatalf("expected FECParams to report ok=false for a KCP peer")
	}
}

func TestPeerModeTrackerObserveOverwritesPreviousMode(t *testing.T) {
	tr := NewPeerModeTracker()
	tr.Observe("peer", PeerModeFEC, 10, 3)
	tr.Observe("peer", PeerModeKCP, 0, 0)

	if mode := tr.Mode("peer"); mode != PeerModeKCP {
		t.Fatalf("expected the later observation to win, got %v", mode)
	}
}

// TestServerPeerTransportPinnedModeIgnoresTracker mirrors production
// construction: when a server is pinned (-fec or -kcp given explicitly),
// peerModes stays nil and peerTransport must return the pinned
// fecSender/kcpTransport unconditionally, regardless of any peer's actual
// traffic - this is the "hard pin, don't auto-adapt" guarantee.
func TestServerPeerTransportPinnedModeIgnoresTracker(t *testing.T) {
	cfg, err := NewFECConfig(10, 3)
	if err != nil {
		t.Fatalf("NewFECConfig: %v", err)
	}
	pinnedFEC := NewFECSender(cfg, []byte("test-mac-key"))

	s := &Server{fecSender: pinnedFEC, peerModes: nil}
	fecSender, kcpTransport := s.peerTransport(nil, 1)
	if fecSender != pinnedFEC {
		t.Fatalf("expected pinned mode to return the server's fixed FECSender")
	}
	if kcpTransport != nil {
		t.Fatalf("expected pinned FEC mode to return a nil KCPTransport")
	}
}

// TestServerPeerTransportAdaptiveModeFollowsTracker exercises the
// per-destKey dispatch that lets two simultaneously-connected clients use
// different modes: each destKey must get back exactly the transport
// matching its own last-observed mode, independent of the others.
func TestServerPeerTransportAdaptiveModeFollowsTracker(t *testing.T) {
	tracker := NewPeerModeTracker()
	tracker.Observe("1.2.3.4|10", PeerModeFEC, 10, 3)
	tracker.Observe("5.6.7.8|20", PeerModeKCP, 0, 0)
	// "9.9.9.9|30" deliberately left unobserved: a brand new peer.

	fecSender := NewAdaptiveFECSender(tracker.FECParams, []byte("test-mac-key"))
	kcpTransport := NewKCPTransport(DefaultKCPConfig(), nil, nil)
	defer kcpTransport.Close()

	s := &Server{fecSender: fecSender, kcpTransport: kcpTransport, peerModes: tracker}

	if fs, kt := s.peerTransport(&net.IPAddr{IP: net.ParseIP("1.2.3.4")}, 10); fs != fecSender || kt != nil {
		t.Fatalf("expected FEC-tracked peer to get (fecSender, nil), got (%v, %v)", fs, kt)
	}
	if fs, kt := s.peerTransport(&net.IPAddr{IP: net.ParseIP("5.6.7.8")}, 20); fs != nil || kt != kcpTransport {
		t.Fatalf("expected KCP-tracked peer to get (nil, kcpTransport), got (%v, %v)", fs, kt)
	}
	if fs, kt := s.peerTransport(&net.IPAddr{IP: net.ParseIP("9.9.9.9")}, 30); fs != nil || kt != nil {
		t.Fatalf("expected an unobserved peer to get (nil, nil) - plain reply, got (%v, %v)", fs, kt)
	}
}
