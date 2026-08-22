package pingtunnel

import (
	"bytes"
	"math/rand"
	"testing"
)

func TestFECEncodeDecodeNoLoss(t *testing.T) {
	cfg, err := NewFECConfig(10, 3)
	if err != nil {
		t.Fatalf("NewFECConfig: %v", err)
	}

	payloads := make([][]byte, cfg.DataShards)
	for i := range payloads {
		payloads[i] = randPayload(i + 1)
	}

	packets, err := cfg.EncodeGroup(42, payloads)
	if err != nil {
		t.Fatalf("EncodeGroup: %v", err)
	}
	if len(packets) != cfg.TotalShards() {
		t.Fatalf("expected %d packets, got %d", cfg.TotalShards(), len(packets))
	}

	shards := make([][]byte, cfg.TotalShards())
	for i, pkt := range packets {
		h, content, err := ParseFECHeader(pkt)
		if err != nil {
			t.Fatalf("ParseFECHeader: %v", err)
		}
		if h.Group != 42 {
			t.Fatalf("group mismatch: got %d", h.Group)
		}
		if int(h.ShardIndex) != i {
			t.Fatalf("shard index mismatch: want %d got %d", i, h.ShardIndex)
		}
		shards[h.ShardIndex] = content
	}

	decoded, err := cfg.DecodeGroup(shards)
	if err != nil {
		t.Fatalf("DecodeGroup: %v", err)
	}

	assertPayloadsEqual(t, payloads, decoded)
}

func TestFECEncodeDecodeWithMaxLoss(t *testing.T) {
	dataShards, parityShards := 10, 3
	cfg, err := NewFECConfig(dataShards, parityShards)
	if err != nil {
		t.Fatalf("NewFECConfig: %v", err)
	}

	payloads := make([][]byte, dataShards)
	for i := range payloads {
		payloads[i] = randPayload(50 + i*7)
	}

	packets, err := cfg.EncodeGroup(7, payloads)
	if err != nil {
		t.Fatalf("EncodeGroup: %v", err)
	}

	// Drop exactly parityShards packets at random distinct indices,
	// mixing data and parity losses.
	dropped := map[int]bool{}
	perm := rand.Perm(len(packets))
	for _, idx := range perm[:parityShards] {
		dropped[idx] = true
	}

	shards := make([][]byte, cfg.TotalShards())
	for i, pkt := range packets {
		if dropped[i] {
			continue
		}
		h, content, err := ParseFECHeader(pkt)
		if err != nil {
			t.Fatalf("ParseFECHeader: %v", err)
		}
		shards[h.ShardIndex] = content
	}

	decoded, err := cfg.DecodeGroup(shards)
	if err != nil {
		t.Fatalf("DecodeGroup with %d losses: %v", parityShards, err)
	}

	assertPayloadsEqual(t, payloads, decoded)
}

func TestFECDecodeFailsWithTooManyLosses(t *testing.T) {
	dataShards, parityShards := 10, 3
	cfg, err := NewFECConfig(dataShards, parityShards)
	if err != nil {
		t.Fatalf("NewFECConfig: %v", err)
	}

	payloads := make([][]byte, dataShards)
	for i := range payloads {
		payloads[i] = randPayload(20 + i)
	}

	packets, err := cfg.EncodeGroup(1, payloads)
	if err != nil {
		t.Fatalf("EncodeGroup: %v", err)
	}

	// Drop parityShards+1 packets: reconstruction should fail.
	shards := make([][]byte, cfg.TotalShards())
	for i, pkt := range packets {
		if i < parityShards+1 {
			continue
		}
		h, content, err := ParseFECHeader(pkt)
		if err != nil {
			t.Fatalf("ParseFECHeader: %v", err)
		}
		shards[h.ShardIndex] = content
	}

	if _, err := cfg.DecodeGroup(shards); err == nil {
		t.Fatalf("expected DecodeGroup to fail with %d losses, but it succeeded", parityShards+1)
	}
}

func TestFECHeaderRoundTrip(t *testing.T) {
	pkt := buildFECPacket(123456, 5, 10, 3, 888, []byte("hello world"))

	if !IsFECPacket(pkt) {
		t.Fatalf("expected IsFECPacket to be true")
	}

	h, content, err := ParseFECHeader(pkt)
	if err != nil {
		t.Fatalf("ParseFECHeader: %v", err)
	}
	if h.Group != 123456 || h.ShardIndex != 5 || h.DataShards != 10 || h.ParityShards != 3 || h.OrigLen != 888 {
		t.Fatalf("header mismatch: %+v", h)
	}
	if string(content) != "hello world" {
		t.Fatalf("content mismatch: %q", content)
	}
}

func assertPayloadsEqual(t *testing.T, want, got [][]byte) {
	t.Helper()
	if len(want) != len(got) {
		t.Fatalf("payload count mismatch: want %d got %d", len(want), len(got))
	}
	for i := range want {
		if !bytes.Equal(want[i], got[i]) {
			t.Fatalf("payload %d mismatch: want %d bytes, got %d bytes", i, len(want[i]), len(got[i]))
		}
	}
}

func randPayload(n int) []byte {
	b := make([]byte, n)
	rand.Read(b)
	return b
}

func TestFECSenderReceiverStreamingNoLoss(t *testing.T) {
	cfg, err := NewFECConfig(10, 3)
	if err != nil {
		t.Fatalf("NewFECConfig: %v", err)
	}
	sender := NewFECSender(cfg)
	receiver := NewFECReceiver(cfg)

	const total = 25 // 2 full groups + a partial one
	payloads := make([][]byte, total)
	for i := range payloads {
		payloads[i] = randPayload(10 + i)
	}

	var delivered [][]byte
	for i, p := range payloads {
		framed, parity, ok := sender.WrapData("peer", p)
		if !ok {
			t.Fatalf("WrapData(%d): expected ok=true", i)
		}
		h, content, err := ParseFECHeader(framed)
		if err != nil {
			t.Fatalf("ParseFECHeader(%d): %v", i, err)
		}
		for _, d := range receiver.Feed("peer", h, content, nil, 1, i) {
			delivered = append(delivered, d.mb)
		}
		for _, pkt := range parity {
			ph, pcontent, err := ParseFECHeader(pkt)
			if err != nil {
				t.Fatalf("ParseFECHeader(parity): %v", err)
			}
			for _, d := range receiver.Feed("peer", ph, pcontent, nil, 1, i) {
				delivered = append(delivered, d.mb)
			}
		}
	}

	// Every data shard is delivered the moment it is received directly -
	// including the trailing partial group's frames - since the fast path
	// never waits for a group to fill when nothing was lost.
	assertPayloadsEqual(t, payloads, delivered)
}

func TestFECSenderReceiverStreamingWithLoss(t *testing.T) {
	cfg, err := NewFECConfig(10, 3)
	if err != nil {
		t.Fatalf("NewFECConfig: %v", err)
	}
	sender := NewFECSender(cfg)
	receiver := NewFECReceiver(cfg)

	const groups = 3
	total := cfg.DataShards * groups
	payloads := make([][]byte, total)
	for i := range payloads {
		payloads[i] = randPayload(20 + i%50)
	}

	type pkt struct {
		h       *FECHeader
		content []byte
	}
	var wire []pkt
	for _, p := range payloads {
		framed, parity, ok := sender.WrapData("peer", p)
		if !ok {
			t.Fatalf("WrapData: expected ok=true")
		}
		h, content, err := ParseFECHeader(framed)
		if err != nil {
			t.Fatalf("ParseFECHeader: %v", err)
		}
		wire = append(wire, pkt{h, content})
		for _, pp := range parity {
			ph, pcontent, err := ParseFECHeader(pp)
			if err != nil {
				t.Fatalf("ParseFECHeader(parity): %v", err)
			}
			wire = append(wire, pkt{ph, pcontent})
		}
	}

	// Drop exactly ParityShards packets from each group (mixing data and
	// parity losses within the group), feed the rest to the receiver in
	// order, and confirm every original payload still comes out in order.
	dropped := map[uint32]map[uint8]bool{}
	for g := uint32(0); g < groups; g++ {
		dropped[g] = map[uint8]bool{}
		perm := rand.Perm(cfg.TotalShards())
		for _, idx := range perm[:cfg.ParityShards] {
			dropped[g][uint8(idx)] = true
		}
	}

	var delivered [][]byte
	for i, w := range wire {
		if dropped[w.h.Group][w.h.ShardIndex] {
			continue
		}
		for _, d := range receiver.Feed("peer", w.h, w.content, nil, 1, i) {
			delivered = append(delivered, d.mb)
		}
	}
	// Flush the last group, which never sees a "next group" transition.
	for _, d := range receiver.FlushStale(0) {
		delivered = append(delivered, d.mb)
	}

	if len(delivered) != len(payloads) {
		t.Fatalf("expected %d delivered payloads, got %d", len(payloads), len(delivered))
	}

	// Reconstructed frames arrive out of the original stream order (they
	// surface only once their group is finalized), so compare as sets
	// grouped by shard rather than assuming strict ordering.
	deliveredSet := map[string]bool{}
	for _, d := range delivered {
		deliveredSet[string(d)] = true
	}
	for i, p := range payloads {
		if !deliveredSet[string(p)] {
			t.Fatalf("payload %d never delivered", i)
		}
	}
}

func TestFECReceiverParamMismatchDropsWithoutPanic(t *testing.T) {
	cfg, err := NewFECConfig(10, 3)
	if err != nil {
		t.Fatalf("NewFECConfig: %v", err)
	}
	receiver := NewFECReceiver(cfg)

	h := &FECHeader{Group: 0, ShardIndex: 0, DataShards: 8, ParityShards: 2, OrigLen: 5}
	content, _ := fecShardContent([]byte("hello"))

	out := receiver.Feed("peer", h, content, nil, 1, 1)
	if len(out) != 0 {
		t.Fatalf("expected mismatched fec params to be dropped, got %d deliverables", len(out))
	}
}
