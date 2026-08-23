package pingtunnel

import "testing"

// Regression test for the self-reflection flood: a negative Rproto is a
// sentinel the server itself embeds in its own replies (see the sendICMP
// calls throughout server.go, all of which pass -1 for it) and no
// legitimate client ever sends one. If the server's own reply gets
// delivered back to its own raw ICMP socket - routine when client and
// server are the same host, since the loopback interface delivers a sent
// packet to every matching local socket including the sender's own -
// processPacket must drop it immediately rather than treating it as a
// fresh request and replying again (which would itself loop back the
// same way: an unbounded, self-sustaining flood, observed in practice at
// upward of 1500 packets/sec before this guard existed).
//
// p.conn is deliberately left nil: if the guard didn't return before
// reaching any code path that sends a reply, this test would panic on a
// nil dereference instead of passing, so a passing test proves no reply
// was attempted.
func TestServerProcessPacketDropsNegativeRproto(t *testing.T) {
	s := &Server{key: 42}

	ping := &Packet{
		my: &MyMsg{
			Type:   int32(MyMsg_PING),
			Key:    42,
			Rproto: -1,
			Data:   []byte{1, 2, 3},
		},
		echoId:  100,
		echoSeq: 1,
	}
	s.processPacket(ping) // must return early; would panic on nil p.conn otherwise

	kick := &Packet{
		my: &MyMsg{
			Type:   int32(MyMsg_KICK),
			Key:    42,
			Rproto: -1,
			Id:     "some-conn-id",
		},
		echoId:  100,
		echoSeq: 1,
	}
	s.processPacket(kick) // same guard applies to every message type
}

// A legitimate client ping (Rproto=0, matching client.go's RECV_PROTO
// constant) must still reach the PING branch - this pins down that the
// new guard only rejects negative values, not the normal case.
func TestServerProcessPacketAllowsNonNegativeRproto(t *testing.T) {
	s := &Server{key: 42}
	ping := &Packet{
		my: &MyMsg{
			Type:   int32(MyMsg_PING),
			Key:    42,
			Rproto: 0,
			Data:   []byte{1, 2, 3},
		},
		echoId:  100,
		echoSeq: 1,
	}
	defer func() {
		if r := recover(); r == nil {
			t.Fatal("expected a panic from the nil p.conn reply attempt, proving the PING branch was reached")
		}
	}()
	s.processPacket(ping)
}
