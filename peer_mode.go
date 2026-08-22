package pingtunnel

import "sync"

// PeerMode is which reliability layer (if any) a given peer's own traffic
// was last observed using.
type PeerMode int

const (
	PeerModeNone PeerMode = iota
	PeerModeFEC
	PeerModeKCP
)

// PeerModeTracker records, per destKey, which reliability layer a peer's
// incoming traffic is using, so an adaptive server (one not pinned to a
// single -fec/-kcp mode) can reply in the same mode without the operator
// having to configure it. recvICMP updates this as it classifies incoming
// packets; the server's send call sites read it to pick which transport (if
// any) to hand to sendICMP.
//
// This is the only piece of adaptive-mode state that isn't already
// destKey-scoped inside FECReceiver/FECSender/KCPTransport themselves - it
// exists because, unlike incoming packets (self-describing via their
// version-marker byte and, for FEC, their own header), an outgoing packet
// needs someone to have already decided which format the peer expects.
type PeerModeTracker struct {
	mu    sync.RWMutex
	peers map[string]*peerModeInfo
}

type peerModeInfo struct {
	mode         PeerMode
	dataShards   int // only meaningful when mode == PeerModeFEC
	parityShards int
}

// NewPeerModeTracker creates an empty tracker.
func NewPeerModeTracker() *PeerModeTracker {
	return &PeerModeTracker{peers: make(map[string]*peerModeInfo)}
}

// Observe records that destKey's most recent incoming packet used mode.
// dataShards/parityShards are only meaningful (and only stored) when mode
// is PeerModeFEC.
func (t *PeerModeTracker) Observe(destKey string, mode PeerMode, dataShards, parityShards int) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.peers[destKey] = &peerModeInfo{mode: mode, dataShards: dataShards, parityShards: parityShards}
}

// Mode returns the last-observed mode for destKey, defaulting to
// PeerModeNone for a destKey that has never been observed (the correct
// behavior for a brand new peer: send it a plain, unwrapped reply until we
// see what it actually sends).
func (t *PeerModeTracker) Mode(destKey string) PeerMode {
	t.mu.RLock()
	defer t.mu.RUnlock()
	info, ok := t.peers[destKey]
	if !ok {
		return PeerModeNone
	}
	return info.mode
}

// FECParams returns the FEC shard counts last observed for destKey. ok is
// false if destKey has never been observed using FEC, in which case the
// caller (FECSender.WrapData in adaptive mode) has no basis to encode a
// reply and should fall back to sending unprotected. Matches the
// func(destKey string) (int, int, bool) shape NewAdaptiveFECSender expects.
func (t *PeerModeTracker) FECParams(destKey string) (dataShards, parityShards int, ok bool) {
	t.mu.RLock()
	defer t.mu.RUnlock()
	info, exists := t.peers[destKey]
	if !exists || info.mode != PeerModeFEC {
		return 0, 0, false
	}
	return info.dataShards, info.parityShards, true
}
