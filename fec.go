package pingtunnel

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/esrrhs/gohome/loggo"
	"github.com/klauspost/reedsolomon"
)

// Wire format of an FEC packet, prepended before the (already encrypted) frame
// bytes whenever FEC is enabled:
//
//	[0]      version/flag byte, always FECVersion for a valid FEC packet
//	[1:9]    truncated HMAC-SHA256 tag over everything from [9:] (see fecTag)
//	[9:13]   group number, uint32 big-endian
//	[13]     shard index within the group, uint8
//	[14]     number of data shards in the group, uint8
//	[15]     number of parity shards in the group, uint8
//	[16:18]  original length of this data shard, uint16 big-endian (0 for parity shards)
//	[18:]    shard payload, zero-padded so every shard in a group is the same length
//
// The tag authenticates the header fields as well as the payload - not just
// the payload - so an attacker can't redirect an otherwise-valid shard into
// a different group/index by tampering with those bytes alone. Added
// 2026-08-27: unlike KCP segments (kcp_transport.go's kcpTag, added in the
// 2026-08-22 security review specifically to stop off-path ACK forgery),
// FEC packets originally had zero authentication - anyone who could inject
// spoofed packets carrying the FECVersion byte, without knowing the tunnel's
// shared secret at all, could feed forged shards into a real peer's
// in-flight Reed-Solomon reconstruction (FECReceiver.Feed keys groups purely
// by destKey = src|echoId, both directly observable on the wire, not
// secret) and corrupt what a legitimate message reconstructs to. This tag
// closes that gap the same way the KCP one already did.
const (
	FECVersion    byte = 1
	fecMacSize         = 8 // truncated HMAC-SHA256, matches kcpMacSize's convention
	fecFieldsSize      = 4 + 1 + 1 + 1 + 2
	FECHeaderSize      = 1 + fecMacSize + fecFieldsSize
)

// deriveFECMacKey derives the key used to authenticate FEC packets from
// whatever secret already gates this tunnel (the encryption key when
// -encrypt is set, otherwise the numeric -key) - mirrors
// deriveKCPMacKey (kcp_transport.go) exactly except for the
// domain-separation prefix, so the two derived keys can never collide or be
// mistaken for one another even though both ultimately stem from the same
// underlying secret.
func deriveFECMacKey(cryptoConfig *CryptoConfig, key int) []byte {
	h := sha256.New()
	h.Write([]byte("pingtunnel-fec-mac|"))
	if cryptoConfig != nil && len(cryptoConfig.Key) > 0 {
		h.Write(cryptoConfig.Key)
	} else {
		h.Write([]byte(fmt.Sprintf("%d", key)))
	}
	return h.Sum(nil)
}

// fecTag computes the truncated HMAC-SHA256 tag for one shard's header
// fields plus its content, keyed by macKey.
func fecTag(macKey []byte, group uint32, shardIndex, dataShards, parityShards uint8, origLen uint16, content []byte) []byte {
	mac := hmac.New(sha256.New, macKey)
	var fields [fecFieldsSize]byte
	binary.BigEndian.PutUint32(fields[0:4], group)
	fields[4] = shardIndex
	fields[5] = dataShards
	fields[6] = parityShards
	binary.BigEndian.PutUint16(fields[7:9], origLen)
	mac.Write(fields[:])
	mac.Write(content)
	return mac.Sum(nil)[:fecMacSize]
}

// FECMaxPayload is the largest already-encrypted frame (mb) that FEC will
// protect. Every FEC shard, data or parity, is padded to this size (plus a
// 2-byte embedded length prefix) so that a data shard can be sent the moment
// it arrives without waiting to see the rest of its group - the padded size
// has to be fixed up front rather than computed from the group's actual
// contents. Kept low (well under low-MTU paths like Starlink ~1400,
// Cloudflare WARP ~1420, or the IPv6 minimum MTU of 1280) so a full FEC
// packet - 18 header + 2 prefix + FECMaxPayload shard + 8 ICMP + 20 IPv4 =
// 1048 bytes at 1000 - never gets fragmented and dropped by a strict link,
// which would defeat the point of adding FEC. Measured worst case for a
// MyMsg (max-length id/target strings, FRAME_MAX_SIZE data, ChaCha20-
// Poly1305 overhead) is ~1022 bytes, just over this cap: WrapData falls
// back to sending such a rare oversized frame unprotected (see its ok
// return value) rather than protecting it at the cost of fragmentation.
const FECMaxPayload = 1000

// FECGroupStaleTimeout is how long a receiver waits for more shards of a
// group before giving up on packets that never showed a reconstructable
// group (e.g. the tail of a session that stops sending). recvICMP's read
// loop already wakes up roughly every 100ms, so this is checked on a
// similar cadence.
const FECGroupStaleTimeout = 2 * time.Second

// FECConfig holds the Reed-Solomon erasure coding parameters used to protect
// outgoing frames against packet loss. One group is DataShards data frames
// plus ParityShards computed parity frames; a group survives the loss of up
// to ParityShards packets out of DataShards+ParityShards.
type FECConfig struct {
	DataShards   int
	ParityShards int
	encoder      reedsolomon.Encoder
}

// NewFECConfig builds an FECConfig for the given shard counts.
func NewFECConfig(dataShards int, parityShards int) (*FECConfig, error) {
	if dataShards <= 0 {
		return nil, fmt.Errorf("fec: dataShards must be > 0, got %d", dataShards)
	}
	if parityShards <= 0 {
		return nil, fmt.Errorf("fec: parityShards must be > 0, got %d", parityShards)
	}

	enc, err := reedsolomon.New(dataShards, parityShards)
	if err != nil {
		return nil, fmt.Errorf("fec: create encoder: %w", err)
	}

	return &FECConfig{
		DataShards:   dataShards,
		ParityShards: parityShards,
		encoder:      enc,
	}, nil
}

// TotalShards returns DataShards+ParityShards.
func (f *FECConfig) TotalShards() int {
	return f.DataShards + f.ParityShards
}

// maxAdaptiveFECTotalShards bounds how large a (DataShards+ParityShards)
// pair adaptive mode (see NewAdaptiveFECReceiver/NewAdaptiveFECSender) will
// honor from a peer-supplied header field, so a peer can't force large
// per-group memory allocation (TotalShards * fecShardSize() bytes, i.e.
// ~1KB per shard) just by claiming an enormous shard count. Well above any
// sane real configuration (defaults are 10/3).
const maxAdaptiveFECTotalShards = 64

// fecConfigCache lazily builds and reuses *FECConfig instances (each
// wrapping a reedsolomon.Encoder, which is safe to reuse across many
// groups/peers) for whatever (dataShards, parityShards) pairs are actually
// observed in adaptive mode, instead of requiring every peer to share one
// preconfigured shard count.
type fecConfigCache struct {
	mu    sync.Mutex
	cache map[[2]int]*FECConfig
}

func newFECConfigCache() *fecConfigCache {
	return &fecConfigCache{cache: make(map[[2]int]*FECConfig)}
}

func (c *fecConfigCache) get(dataShards, parityShards int) (*FECConfig, error) {
	if dataShards <= 0 || parityShards <= 0 || dataShards+parityShards > maxAdaptiveFECTotalShards {
		return nil, fmt.Errorf("fec: adaptive shard counts out of range: data=%d parity=%d", dataShards, parityShards)
	}
	key := [2]int{dataShards, parityShards}

	c.mu.Lock()
	defer c.mu.Unlock()
	if cfg, ok := c.cache[key]; ok {
		return cfg, nil
	}
	cfg, err := NewFECConfig(dataShards, parityShards)
	if err != nil {
		return nil, err
	}
	c.cache[key] = cfg
	return cfg, nil
}

// EncodeGroup takes exactly f.DataShards payloads (already encrypted frame
// bytes) belonging to a single group and returns f.TotalShards() wire-ready
// packets: the DataShards original payloads followed by ParityShards parity
// payloads, each prefixed with the FEC header described above.
//
// The original length of each data payload is stored inside the two-byte
// prefix of the shard's own coded content (not only in the header), so it
// survives reconstruction on the receive side even when the packet carrying
// that header was itself lost.
func (f *FECConfig) EncodeGroup(macKey []byte, group uint32, payloads [][]byte) ([][]byte, error) {
	if len(payloads) != f.DataShards {
		return nil, fmt.Errorf("fec: EncodeGroup expected %d payloads, got %d", f.DataShards, len(payloads))
	}

	shards := make([][]byte, f.TotalShards())
	for i, p := range payloads {
		s, err := fecShardContent(p)
		if err != nil {
			return nil, err
		}
		shards[i] = s
	}
	for i := f.DataShards; i < f.TotalShards(); i++ {
		shards[i] = make([]byte, fecShardSize())
	}

	if err := f.encoder.Encode(shards); err != nil {
		return nil, fmt.Errorf("fec: encode: %w", err)
	}

	out := make([][]byte, f.TotalShards())
	for i, s := range shards {
		var origLen uint16
		if i < f.DataShards {
			origLen = uint16(len(payloads[i]))
		}
		out[i] = buildFECPacket(macKey, group, uint8(i), uint8(f.DataShards), uint8(f.ParityShards), origLen, s)
	}

	return out, nil
}

// DecodeGroup reconstructs the original data payloads of a group given the
// raw (header-stripped) shard contents. shards must have length
// f.TotalShards(); missing shards (packets that were lost) must be nil.
// Returns the f.DataShards original payloads in order.
func (f *FECConfig) DecodeGroup(shards [][]byte) ([][]byte, error) {
	if len(shards) != f.TotalShards() {
		return nil, fmt.Errorf("fec: DecodeGroup expected %d shards, got %d", f.TotalShards(), len(shards))
	}

	if err := f.encoder.ReconstructData(shards); err != nil {
		return nil, fmt.Errorf("fec: reconstruct: %w", err)
	}

	out := make([][]byte, f.DataShards)
	for i := 0; i < f.DataShards; i++ {
		s := shards[i]
		if len(s) < 2 {
			return nil, fmt.Errorf("fec: reconstructed shard %d too short", i)
		}
		origLen := binary.BigEndian.Uint16(s[0:2])
		if int(origLen)+2 > len(s) {
			return nil, fmt.Errorf("fec: reconstructed shard %d length %d exceeds shard size", i, origLen)
		}
		out[i] = s[2 : 2+int(origLen)]
	}

	return out, nil
}

// FECHeader is the parsed form of the per-packet FEC header.
type FECHeader struct {
	Group        uint32
	ShardIndex   uint8
	DataShards   uint8
	ParityShards uint8
	OrigLen      uint16
}

func buildFECPacket(macKey []byte, group uint32, shardIndex uint8, dataShards uint8, parityShards uint8, origLen uint16, shard []byte) []byte {
	out := make([]byte, FECHeaderSize+len(shard))
	out[0] = FECVersion
	copy(out[1:1+fecMacSize], fecTag(macKey, group, shardIndex, dataShards, parityShards, origLen, shard))
	fieldsOff := 1 + fecMacSize
	binary.BigEndian.PutUint32(out[fieldsOff:fieldsOff+4], group)
	out[fieldsOff+4] = shardIndex
	out[fieldsOff+5] = dataShards
	out[fieldsOff+6] = parityShards
	binary.BigEndian.PutUint16(out[fieldsOff+7:fieldsOff+9], origLen)
	copy(out[FECHeaderSize:], shard)
	return out
}

// IsFECPacket reports whether b starts with a valid FEC version byte.
func IsFECPacket(b []byte) bool {
	return len(b) >= FECHeaderSize && b[0] == FECVersion
}

// ParseFECHeader verifies the HMAC tag (keyed by macKey) and parses the FEC
// header from a received packet, returning it along with the remaining
// shard payload (the RS-coded content, still carrying its embedded 2-byte
// length prefix). A missing/wrong-key/forged tag is indistinguishable from
// network corruption from the caller's point of view - both are just
// rejected - mirroring ParseKCPPacket's contract exactly.
func ParseFECHeader(macKey []byte, b []byte) (*FECHeader, []byte, error) {
	if len(b) < FECHeaderSize {
		return nil, nil, fmt.Errorf("fec: packet too short for fec header: %d bytes", len(b))
	}
	if b[0] != FECVersion {
		return nil, nil, fmt.Errorf("fec: unsupported fec version %d", b[0])
	}

	fieldsOff := 1 + fecMacSize
	group := binary.BigEndian.Uint32(b[fieldsOff : fieldsOff+4])
	shardIndex := b[fieldsOff+4]
	dataShards := b[fieldsOff+5]
	parityShards := b[fieldsOff+6]
	origLen := binary.BigEndian.Uint16(b[fieldsOff+7 : fieldsOff+9])
	content := b[FECHeaderSize:]

	if !hmac.Equal(b[1:1+fecMacSize], fecTag(macKey, group, shardIndex, dataShards, parityShards, origLen, content)) {
		return nil, nil, fmt.Errorf("fec: invalid packet tag")
	}

	h := &FECHeader{
		Group:        group,
		ShardIndex:   shardIndex,
		DataShards:   dataShards,
		ParityShards: parityShards,
		OrigLen:      origLen,
	}

	return h, content, nil
}

// fecShardSize is the fixed length of a shard's RS-coded content (the part
// after the 10-byte FEC header): a 2-byte embedded length prefix plus
// FECMaxPayload bytes of (possibly zero-padded) data.
func fecShardSize() int {
	return 2 + FECMaxPayload
}

// fecShardContent builds the fixed-size RS-coded content for a single data
// shard: a 2-byte big-endian length prefix (so the original length survives
// even if this shard has to be reconstructed from parity) followed by the
// payload and zero padding up to fecShardSize().
func fecShardContent(payload []byte) ([]byte, error) {
	if len(payload) > FECMaxPayload {
		return nil, fmt.Errorf("fec: payload too large for fec: %d bytes (max %d)", len(payload), FECMaxPayload)
	}
	s := make([]byte, fecShardSize())
	binary.BigEndian.PutUint16(s[0:2], uint16(len(payload)))
	copy(s[2:], payload)
	return s, nil
}

// fecExtractFrame reverses fecShardContent, reading the embedded length
// prefix and slicing off the real payload.
func fecExtractFrame(content []byte) ([]byte, error) {
	if len(content) < 2 {
		return nil, fmt.Errorf("fec: shard content too short: %d bytes", len(content))
	}
	origLen := binary.BigEndian.Uint16(content[0:2])
	if int(origLen)+2 > len(content) {
		return nil, fmt.Errorf("fec: embedded length %d exceeds shard size %d", origLen, len(content))
	}
	return content[2 : 2+int(origLen)], nil
}

// FECSender buffers outgoing frames per destination (one buffer per remote
// peer, since parity computed over one peer's packets must never mix with
// another peer's traffic) and emits the extra parity packets to send once a
// block of DataShards frames has gone out.
//
// In "pinned" mode (cfg set) every destination is encoded with cfg's shard
// counts, matching the pre-adaptive behavior. In "adaptive" mode (cfg nil,
// resolve set) each destKey is encoded with whatever shard counts resolve
// reports for it - see NewAdaptiveFECSender. resolve is how the sender
// finds out what a given peer's own FEC params are: fec.go has no
// knowledge of peers or how their params were observed, so this is
// supplied as a closure (in practice, a PeerModeTracker.FECParams method)
// rather than fec.go depending on a peer-tracking type directly.
type FECSender struct {
	cfg      *FECConfig
	adaptive *fecConfigCache
	resolve  func(destKey string) (dataShards, parityShards int, ok bool)
	macKey   []byte
	mu       sync.Mutex
	state    map[string]*fecSendGroup
}

type fecSendGroup struct {
	cfg    *FECConfig // the config this group's shards are being encoded with
	group  uint32
	shards [][]byte // raw (unpadded) payloads collected so far for this group
	filled int
}

// NewFECSender creates a sender-side buffer for the given FEC parameters,
// authenticating every packet it builds with macKey (see deriveFECMacKey).
func NewFECSender(cfg *FECConfig, macKey []byte) *FECSender {
	return &FECSender{cfg: cfg, macKey: macKey, state: make(map[string]*fecSendGroup)}
}

// NewAdaptiveFECSender creates a sender that encodes each destination with
// whatever FEC params resolve reports for it, instead of one fixed
// preconfigured shard count. Used by a server that was not pinned to -fec,
// so a reply to an FEC-using client is encoded with that client's own
// -fec-data/-fec-parity choice (which resolve looks up from what was last
// observed on packets received from that same destKey).
func NewAdaptiveFECSender(resolve func(destKey string) (dataShards, parityShards int, ok bool), macKey []byte) *FECSender {
	return &FECSender{adaptive: newFECConfigCache(), resolve: resolve, macKey: macKey, state: make(map[string]*fecSendGroup)}
}

// WrapData assigns payload the next (group, shardIndex) slot for destKey and
// returns the FEC-framed packet to send in place of payload. If this call
// completes a block of DataShards frames, it also returns the parity packets
// that must be sent right after (their relative order does not matter).
//
// If payload is larger than FECMaxPayload, or (in adaptive mode) destKey's
// FEC params are not yet known, FEC framing is skipped for this one packet
// (ok is false) and the caller should send payload unprotected, exactly as
// it would with FEC disabled.
func (s *FECSender) WrapData(destKey string, payload []byte) (framed []byte, parityPackets [][]byte, ok bool) {
	if len(payload) > FECMaxPayload {
		return nil, nil, false
	}

	cfg := s.cfg
	if cfg == nil {
		dataShards, parityShards, found := s.resolve(destKey)
		if !found {
			return nil, nil, false
		}
		var err error
		cfg, err = s.adaptive.get(dataShards, parityShards)
		if err != nil {
			return nil, nil, false
		}
	}

	content, err := fecShardContent(payload)
	if err != nil {
		return nil, nil, false
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	g, exists := s.state[destKey]
	if !exists || g.cfg != cfg {
		// Either the first packet ever sent to destKey, or its FEC params
		// changed since the last one (adaptive mode only) - start a fresh
		// group rather than mixing shards encoded under two configs.
		g = &fecSendGroup{cfg: cfg, shards: make([][]byte, cfg.DataShards)}
		s.state[destKey] = g
	}

	idx := g.filled
	cp := make([]byte, len(payload))
	copy(cp, payload)
	g.shards[idx] = cp
	g.filled++

	framed = buildFECPacket(s.macKey, g.group, uint8(idx), uint8(cfg.DataShards), uint8(cfg.ParityShards), uint16(len(payload)), content)

	if g.filled == cfg.DataShards {
		all, err := cfg.EncodeGroup(s.macKey, g.group, g.shards)
		if err != nil {
			loggo.Error("FECSender EncodeGroup error dest %s group %d: %s", destKey, g.group, err)
		} else {
			parityPackets = all[cfg.DataShards:]
		}
		s.state[destKey] = &fecSendGroup{cfg: cfg, shards: make([][]byte, cfg.DataShards), group: g.group + 1}
	}

	return framed, parityPackets, true
}

// fecDeliverable is a frame recovered by an FECReceiver, tagged with the
// context (source address, ICMP echo id/seq) it should be delivered with -
// the same context the original packet would have carried had it not been
// lost and reconstructed from parity instead.
type fecDeliverable struct {
	mb      []byte
	src     *net.IPAddr
	echoId  int
	echoSeq int
}

type fecRecvGroup struct {
	cfg      *FECConfig // the config this group's shards were encoded with
	group    uint32
	shards   [][]byte // len == cfg.TotalShards(); nil entries are missing
	present  int
	emitted  []bool // len == cfg.DataShards; true once delivered (directly or reconstructed)
	src      *net.IPAddr
	echoId   int
	echoSeq  int
	lastSeen time.Time
}

// FECReceiver reassembles FEC groups per source peer, delivering data shards
// as soon as they arrive directly and reconstructing any that were lost
// (up to ParityShards per group) once enough of the group has been seen.
//
// In "pinned" mode (cfg set), every peer must use exactly cfg's shard
// counts, matching the pre-adaptive behavior. In "adaptive" mode (cfg nil,
// adaptive set) each group is decoded with whatever (DataShards,
// ParityShards) its own header claims, via adaptive's cache of
// lazily-built decoders - see NewAdaptiveFECReceiver.
type FECReceiver struct {
	cfg      *FECConfig
	adaptive *fecConfigCache
	macKey   []byte
	mu       sync.Mutex
	state    map[string]*fecRecvGroup
}

// NewFECReceiver creates a receiver-side reassembly buffer for the given FEC
// parameters, verifying every packet's tag against macKey (see
// deriveFECMacKey) before it's ever fed to Feed.
func NewFECReceiver(cfg *FECConfig, macKey []byte) *FECReceiver {
	return &FECReceiver{cfg: cfg, macKey: macKey, state: make(map[string]*fecRecvGroup)}
}

// ParseHeader verifies and parses one received FEC packet using this
// receiver's own macKey - mirrors KCPTransport.ParsePacket exactly, so
// callers never need to reach for the standalone ParseFECHeader/macKey pair
// directly.
func (r *FECReceiver) ParseHeader(b []byte) (*FECHeader, []byte, error) {
	return ParseFECHeader(r.macKey, b)
}

// NewAdaptiveFECReceiver creates a receiver that accepts any FEC parameters
// a peer presents (within maxAdaptiveFECTotalShards), instead of requiring a
// single preconfigured shard count. Used by a server that was not pinned to
// -fec, so each connecting client's own -fec-data/-fec-parity choice is
// honored automatically rather than having to match a fixed server setting.
func NewAdaptiveFECReceiver(macKey []byte) *FECReceiver {
	return &FECReceiver{adaptive: newFECConfigCache(), macKey: macKey, state: make(map[string]*fecRecvGroup)}
}

// Feed processes one received FEC packet (already header-parsed) for
// destKey and returns any frames now available for delivery: the frame
// carried by this packet itself (if it is a data shard, delivered
// immediately without waiting for the rest of the group), plus any frames
// recovered by reconstructing a previous group that destKey has now moved
// on from.
//
// In pinned mode, a header whose DataShards/ParityShards do not match the
// local configuration indicates the peer is using different FEC parameters
// (or is not running FEC at all and this is a false-positive version byte
// match); the packet is logged and dropped rather than causing a crash. In
// adaptive mode, only maxAdaptiveFECTotalShards bounds and an in-progress
// group's own established params are enforced.
func (r *FECReceiver) Feed(destKey string, h *FECHeader, content []byte, src *net.IPAddr, echoId int, echoSeq int) []fecDeliverable {
	cfg := r.cfg
	if cfg == nil {
		var err error
		cfg, err = r.adaptive.get(int(h.DataShards), int(h.ParityShards))
		if err != nil {
			loggo.Info("FECReceiver: rejecting packet from %s: %s", destKey, err)
			return nil
		}
	} else if int(h.DataShards) != cfg.DataShards || int(h.ParityShards) != cfg.ParityShards {
		loggo.Info("FECReceiver: fec parameter mismatch from %s (got data=%d parity=%d, want data=%d parity=%d), dropping packet",
			destKey, h.DataShards, h.ParityShards, cfg.DataShards, cfg.ParityShards)
		return nil
	}
	if int(h.ShardIndex) >= cfg.TotalShards() {
		loggo.Info("FECReceiver: invalid shard index %d from %s, dropping packet", h.ShardIndex, destKey)
		return nil
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	var out []fecDeliverable

	g := r.state[destKey]
	if g != nil && g.cfg != cfg {
		// The peer changed FEC params mid-group (or a stale group from
		// before a restart is still tracked). Finalize/discard whatever
		// the old group had and start fresh under the new params rather
		// than mixing shards encoded with two different configs.
		out = append(out, r.finalizeLocked(g)...)
		g = nil
	}
	if g == nil || h.Group != g.group {
		if g != nil && h.Group > g.group {
			out = append(out, r.finalizeLocked(g)...)
		} else if g != nil && h.Group < g.group {
			// Stale or duplicate packet for an already-finalized group.
			return nil
		}
		g = &fecRecvGroup{
			cfg:     cfg,
			group:   h.Group,
			shards:  make([][]byte, cfg.TotalShards()),
			emitted: make([]bool, cfg.DataShards),
		}
		r.state[destKey] = g
	}

	idx := int(h.ShardIndex)
	g.src = src
	g.echoId = echoId
	g.echoSeq = echoSeq
	g.lastSeen = time.Now()

	if g.shards[idx] != nil {
		return out // duplicate packet, ignore
	}
	g.shards[idx] = content
	g.present++

	if idx < cfg.DataShards && !g.emitted[idx] {
		frame, err := fecExtractFrame(content)
		if err != nil {
			loggo.Info("FECReceiver: bad shard content from %s group %d shard %d: %s", destKey, h.Group, idx, err)
		} else {
			g.emitted[idx] = true
			out = append(out, fecDeliverable{mb: frame, src: src, echoId: echoId, echoSeq: echoSeq})
		}
	}

	if g.present == cfg.TotalShards() {
		delete(r.state, destKey)
	}

	return out
}

// FlushStale finalizes (attempting reconstruction, then discarding) any
// tracked group that has not seen a new shard in at least staleAfter. Call
// this periodically so the tail of a session - fewer than DataShards frames
// followed by silence - is not held forever waiting for a group that will
// never fill.
func (r *FECReceiver) FlushStale(staleAfter time.Duration) []fecDeliverable {
	r.mu.Lock()
	defer r.mu.Unlock()

	var out []fecDeliverable
	now := time.Now()
	for key, g := range r.state {
		if now.Sub(g.lastSeen) >= staleAfter {
			out = append(out, r.finalizeLocked(g)...)
			delete(r.state, key)
		}
	}
	return out
}

// finalizeLocked attempts to reconstruct any data shards of g that were
// never received directly. Must be called with r.mu held; does not remove g
// from r.state itself (callers do that once they decide to move on from g).
func (r *FECReceiver) finalizeLocked(g *fecRecvGroup) []fecDeliverable {
	missingData := 0
	for i := 0; i < g.cfg.DataShards; i++ {
		if !g.emitted[i] {
			missingData++
		}
	}
	if missingData == 0 {
		return nil
	}

	totalMissing := g.cfg.TotalShards() - g.present
	if totalMissing > g.cfg.ParityShards {
		loggo.Info("FECReceiver: group %d unrecoverable, lost %d/%d shards (tolerate %d)",
			g.group, totalMissing, g.cfg.TotalShards(), g.cfg.ParityShards)
		return nil
	}

	decoded, err := g.cfg.DecodeGroup(g.shards)
	if err != nil {
		loggo.Info("FECReceiver: group %d reconstruction failed: %s", g.group, err)
		return nil
	}

	loggo.Info("FECReceiver: group %d recovered %d/%d missing data shard(s) from %d/%d received shards",
		g.group, missingData, g.cfg.DataShards, g.present, g.cfg.TotalShards())

	var out []fecDeliverable
	for i := 0; i < g.cfg.DataShards; i++ {
		if !g.emitted[i] {
			out = append(out, fecDeliverable{mb: decoded[i], src: g.src, echoId: g.echoId, echoSeq: g.echoSeq})
		}
	}
	return out
}
