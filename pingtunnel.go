package pingtunnel

import (
	"encoding/binary"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/esrrhs/gohome/common"
	"github.com/esrrhs/gohome/loggo"
	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
	"google.golang.org/protobuf/proto"
)

func sendICMP(id int, sequence int, conn icmp.PacketConn, server *net.IPAddr, target string,
	connId string, msgType uint32, data []byte, sproto int, rproto int, key int,
	tcpmode int, tcpmode_buffer_size int, tcpmode_maxwin int, tcpmode_resend_time int, tcpmode_compress int, tcpmode_stat int,
	timeout int, cryptoConfig *CryptoConfig, fecSender *FECSender, kcpTransport *KCPTransport, rateLimiter *RateLimiter) {

	m := &MyMsg{
		Id:                  connId,
		Type:                (int32)(msgType),
		Target:              target,
		Data:                data,
		Rproto:              (int32)(rproto),
		Key:                 (int32)(key),
		Tcpmode:             (int32)(tcpmode),
		TcpmodeBuffersize:   (int32)(tcpmode_buffer_size),
		TcpmodeMaxwin:       (int32)(tcpmode_maxwin),
		TcpmodeResendTimems: (int32)(tcpmode_resend_time),
		TcpmodeCompress:     (int32)(tcpmode_compress),
		TcpmodeStat:         (int32)(tcpmode_stat),
		Timeout:             (int32)(timeout),
		Magic:               (int32)(MyMsg_MAGIC),
	}

	mb, err := proto.Marshal(m)
	if err != nil {
		loggo.Error("sendICMP Marshal MyMsg error %s %s", server.String(), err)
		return
	}

	// Encrypt the marshaled data if encryption is enabled
	if cryptoConfig != nil {
		mb, err = cryptoConfig.Encrypt(mb)
		if err != nil {
			loggo.Error("sendICMP Encrypt error %s %s", server.String(), err)
			return
		}
	}

	// KCP supersedes FEC rather than composing with it (see cmd/main.go's
	// -kcp/-fec mutual exclusion check): once queued, mb is retransmitted
	// by the KCP engine itself, and the actual wire packet(s) go out later
	// from its output callback below, not synchronously from this call -
	// hence the early return instead of falling through to FEC/writeICMP.
	// The 0 sequence number is fine here: recvICMP never treats ICMP echo
	// seq as load-bearing (only echoId is), and a KCP session's own
	// flushes aren't tied 1:1 to external sendICMP calls anyway.
	if kcpTransport != nil {
		// flowID keeps independent flows (e.g. two unrelated DNS lookups)
		// off the same KCP session so one slow/lossy flow can't head-of-
		// line-block another - see kcpFlowID's doc comment.
		flowID := kcpFlowID(connId)
		destKey := fmt.Sprintf("%s|%d|%d", server.String(), id, flowID)
		session := kcpTransport.Session(destKey, server, id, func(segment []byte) {
			if err := writeICMP(conn, id, 0, sproto, server, kcpTransport.BuildPacket(flowID, segment), rateLimiter); err != nil {
				loggo.Error("sendICMP kcp write error %s %s", server.String(), err)
			}
		})
		if err := session.Send(mb); err != nil {
			loggo.Error("sendICMP kcp send error %s %s", server.String(), err)
		}
		return
	}

	var parityPackets [][]byte
	if fecSender != nil {
		framed, parity, ok := fecSender.WrapData(server.String(), mb)
		if ok {
			mb = framed
			parityPackets = parity
		} else {
			loggo.Debug("sendICMP fec: payload too large to protect (%d bytes), sending unprotected %s", len(mb), server.String())
		}
	}

	if err := writeICMP(conn, id, sequence, sproto, server, mb, rateLimiter); err != nil {
		loggo.Error("sendICMP Marshal error %s %s", server.String(), err)
		return
	}

	for _, p := range parityPackets {
		if err := writeICMP(conn, id, sequence, sproto, server, p, rateLimiter); err != nil {
			loggo.Error("sendICMP fec parity send error %s %s", server.String(), err)
		}
	}
}

// writeICMP is the one choke point every outgoing packet passes through
// regardless of mode (none/FEC/KCP, tcpmode or relay, PING/DATA/KICK) -
// see RateLimiter's doc comment for why that makes it the right place to
// enforce a shared, tunnel-wide send-rate cap rather than doing it
// per-connection.
func writeICMP(conn icmp.PacketConn, id int, sequence int, sproto int, server *net.IPAddr, data []byte, rateLimiter *RateLimiter) error {
	if !rateLimiter.Allow() {
		return fmt.Errorf("writeICMP: rate limit exceeded, dropping packet to %s", server.String())
	}

	body := &icmp.Echo{
		ID:   id,
		Seq:  sequence,
		Data: data,
	}

	msg := &icmp.Message{
		Type: (ipv4.ICMPType)(sproto),
		Code: 0,
		Body: body,
	}

	bytes, err := msg.Marshal(nil)
	if err != nil {
		return err
	}

	conn.WriteTo(bytes, icmpDstAddr(server))
	return nil
}

// kcpReplySproto is the ICMP type to use when a KCP session created here
// (i.e. the peer's first KCP packet arrived before we ever called
// sendICMP for them) needs to transmit an ACK-only segment. It can't be
// read off the peer's own MyMsg the way rproto normally would, because at
// this layer nothing has been decoded yet - the bytes are still inside
// KCP's reassembly buffer. In practice it's always the fixed sproto this
// Client/Server already uses for everything it sends (SEND_PROTO for a
// client, RECV_PROTO for a server), passed in by the caller.
func recvICMP(workResultLock *sync.WaitGroup, exit *bool, conn icmp.PacketConn, recv chan<- *Packet, cryptoConfig *CryptoConfig, fecReceiver *FECReceiver, kcpTransport *KCPTransport, kcpReplySproto int, peerModes *PeerModeTracker, rateLimiter *RateLimiter) {

	defer common.CrashLog()

	(*workResultLock).Add(1)
	defer (*workResultLock).Done()

	bytes := make([]byte, 10240)
	for !*exit {
		conn.SetReadDeadline(time.Now().Add(time.Millisecond * 100))
		n, srcaddr, err := conn.ReadFrom(bytes)

		if fecReceiver != nil {
			for _, d := range fecReceiver.FlushStale(FECGroupStaleTimeout) {
				deliverPayload(d.mb, cryptoConfig, recv, d.src, d.echoId, d.echoSeq)
			}
		}

		if err != nil {
			nerr, ok := err.(net.Error)
			if !ok || !nerr.Timeout() {
				loggo.Info("Error read icmp message %s", err)
				continue
			}
		}

		if n <= 0 {
			continue
		}

		echoId := int(binary.BigEndian.Uint16(bytes[4:6]))
		echoSeq := int(binary.BigEndian.Uint16(bytes[6:8]))

		// Extract the payload data
		payloadData := bytes[8:n]
		src := icmpSrcToIPAddr(srcaddr)

		if fecReceiver != nil && IsFECPacket(payloadData) {
			h, content, err := ParseFECHeader(payloadData)
			if err != nil {
				loggo.Debug("recvICMP fec header parse error: %s", err)
				continue
			}
			destKey := fmt.Sprintf("%s|%d", src.String(), echoId)
			if peerModes != nil {
				peerModes.Observe(destKey, PeerModeFEC, int(h.DataShards), int(h.ParityShards))
			}
			for _, d := range fecReceiver.Feed(destKey, h, content, src, echoId, echoSeq) {
				deliverPayload(d.mb, cryptoConfig, recv, d.src, d.echoId, d.echoSeq)
			}
			continue
		}

		if kcpTransport != nil && IsKCPPacket(payloadData) {
			flowID, segment, err := kcpTransport.ParsePacket(payloadData)
			if err != nil {
				loggo.Debug("recvICMP kcp header parse error: %s", err)
				continue
			}
			// peerKey is peer-level (no flowID): PeerModeTracker decides,
			// per peer, which reliability mode to reply in - that's a
			// coarser question than which KCP session a given flow's
			// bytes belong to, so it deliberately doesn't get flowID
			// folded in the way sessionKey below does.
			peerKey := fmt.Sprintf("%s|%d", src.String(), echoId)
			if peerModes != nil {
				peerModes.Observe(peerKey, PeerModeKCP, 0, 0)
			}
			// sessionKey must match sendICMP's destKey formula exactly
			// (peer address + the client's own echoId + flowID, from
			// either side's point of view) so both directions of one
			// flow's traffic land on the very same KCPSession - see
			// KCPTransport's and kcpFlowID's doc comments for why.
			sessionKey := fmt.Sprintf("%s|%d|%d", src.String(), echoId, flowID)
			session := kcpTransport.Session(sessionKey, src, echoId, func(seg []byte) {
				if err := writeICMP(conn, echoId, 0, kcpReplySproto, src, kcpTransport.BuildPacket(flowID, seg), rateLimiter); err != nil {
					loggo.Error("recvICMP kcp write error %s %s", src.String(), err)
				}
			})
			session.Input(segment)
			continue
		}

		if peerModes != nil {
			peerModes.Observe(fmt.Sprintf("%s|%d", src.String(), echoId), PeerModeNone, 0, 0)
		}
		deliverPayload(payloadData, cryptoConfig, recv, src, echoId, echoSeq)
	}
}

// deliverPayload decrypts (if enabled), unmarshals and enqueues one already
// FEC-resolved frame. Used both for plain (non-FEC) packets and for frames
// an FECReceiver produced, whether delivered immediately or reconstructed.
func deliverPayload(mb []byte, cryptoConfig *CryptoConfig, recv chan<- *Packet, src *net.IPAddr, echoId int, echoSeq int) {
	if cryptoConfig != nil {
		var err error
		mb, err = cryptoConfig.Decrypt(mb)
		if err != nil {
			loggo.Debug("recvICMP Decrypt error: %s", err)
			return
		}
	}

	my := &MyMsg{}
	err := proto.Unmarshal(mb, my)
	if err != nil {
		loggo.Debug("Unmarshal MyMsg error: %s", err)
		return
	}

	if my.Magic != (int32)(MyMsg_MAGIC) {
		loggo.Debug("processPacket data invalid %s", my.Id)
		return
	}

	recv <- &Packet{my: my, src: src, echoId: echoId, echoSeq: echoSeq}
}

type Packet struct {
	my      *MyMsg
	src     *net.IPAddr
	echoId  int
	echoSeq int
}

const (
	FRAME_MAX_SIZE int = 888
	FRAME_MAX_ID   int = 1000000
)
