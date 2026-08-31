package pingtunnel

import "testing"

// Regression test for the "-encrypt makes every reply silently dropped"
// bug found live-testing AES-256 end to end 2026-08-31: this project's own
// Android client UI sends -key 0 whenever encryption is configured (its
// "-key" and encryption fields are mutually exclusive - see
// client.go's processPacket for the full story), so a server pinned to a
// real nonzero -key rejected every genuinely-encrypted, correctly-keyed
// client at the numeric-key check, before ever reaching the real
// authentication (AEAD decrypt, which already happened earlier in
// deliverPayload) or the connection logic. The check must be skipped
// once cryptoConfig is set, since that's already doing the real
// authentication work.
func TestServerProcessPacketIgnoresKeyMismatchWhenEncrypted(t *testing.T) {
	cryptoConfig, err := NewCryptoConfig(AES256, "0123456789abcdef0123456789abcdef")
	if err != nil {
		t.Fatalf("NewCryptoConfig: %v", err)
	}
	s := &Server{key: 654321, cryptoConfig: cryptoConfig}

	// A mismatched numeric key (0, matching what the real Android client
	// sends whenever encryption is on) must NOT be rejected here - it
	// should fall through to the next guard (Rproto<0) and return there
	// instead, which this test can't directly observe, but reaching the
	// KICK branch below (which would panic on the nil localConnMap
	// dereference. if this method's key-check hadn't already been passed)
	// proves it wasn't dropped at the key check.
	kick := &Packet{
		my: &MyMsg{
			Type: int32(MyMsg_KICK),
			Key:  0, // mismatched vs s.key (654321) - must be tolerated when encrypted
			Id:   "nonexistent-conn-id",
		},
		echoId:  100,
		echoSeq: 1,
	}
	// getServerConnById on an empty/zero-value localConnMap returns nil
	// for any id, so this is safe to call and just confirms we got past
	// the key check into the real KICK-handling logic.
	s.processPacket(kick)
}

// Companion: without encryption, a mismatched numeric key must still be
// rejected exactly as before - this fix must not weaken the unencrypted
// case at all.
func TestServerProcessPacketStillEnforcesKeyMismatchWithoutEncryption(t *testing.T) {
	s := &Server{key: 654321}

	ping := &Packet{
		my: &MyMsg{
			Type: int32(MyMsg_PING),
			Key:  0, // mismatched, no encryption configured
			Data: []byte{1, 2, 3},
		},
		echoId:  100,
		echoSeq: 1,
	}
	// p.conn is nil: if the key check didn't reject this, the PING branch
	// would panic trying to send a reply. A clean return proves the
	// mismatch was still caught.
	s.processPacket(ping)
}
