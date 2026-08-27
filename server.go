package pingtunnel

import (
	"fmt"
	"github.com/esrrhs/gohome/common"
	"github.com/esrrhs/gohome/loggo"
	"github.com/esrrhs/gohome/network"
	"github.com/esrrhs/gohome/thread"
	"golang.org/x/net/icmp"
	"google.golang.org/protobuf/proto"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

func NewServer(icmpAddr string, key int, maxconn int, maxprocessthread int, maxprocessbuffer int, connecttmeout int, cryptoConfig *CryptoConfig, forwardConfig *ForwardConfig, fecConfig *FECConfig, kcpConfig *KCPConfig, connectHandshakeTimeoutSec int, maxPPS int, kcpSndWnd int, kcpRcvWnd int, kcpCongestion bool) (*Server, error) {
	if connectHandshakeTimeoutSec <= 0 {
		connectHandshakeTimeoutSec = 5
	}
	var fecSender *FECSender
	var fecReceiver *FECReceiver
	var peerModes *PeerModeTracker
	fecMacKey := deriveFECMacKey(cryptoConfig, key)

	switch {
	case fecConfig != nil:
		// Pinned to FEC (-fec was given): every peer must match these
		// exact shard counts, same as before adaptive mode existed.
		fecSender = NewFECSender(fecConfig, fecMacKey)
		fecReceiver = NewFECReceiver(fecConfig, fecMacKey)
	case kcpConfig != nil:
		// Pinned to KCP (-kcp was given): no FEC involvement, unchanged.
	default:
		// Neither -fec nor -kcp was given: adaptive mode. Accept and
		// reply in whichever mode (none/FEC/KCP) each connecting peer's
		// own traffic uses, tracked per destKey by peerModes - see
		// PeerModeTracker and (*Server).peerTransport. This is a strict
		// superset of the old flagless default (plain-only): a peer that
		// sends plain traffic still gets plain replies.
		peerModes = NewPeerModeTracker()
		fecReceiver = NewAdaptiveFECReceiver(fecMacKey)
		fecSender = NewAdaptiveFECSender(peerModes.FECParams, fecMacKey)
		kcpConfig = DefaultKCPConfig()
		// kcpSndWnd/kcpRcvWnd (-kcp-sndwnd/-kcp-rcvwnd) apply here too, not
		// just to a pinned -kcp server, since this adaptive path is what a
		// real deployment recommended to run without -fec/-kcp (see
		// infra-and-access memory) actually uses for KCP-using peers.
		if kcpSndWnd > 0 {
			kcpConfig.SndWnd = kcpSndWnd
		}
		if kcpRcvWnd > 0 {
			kcpConfig.RcvWnd = kcpRcvWnd
		}
		if kcpCongestion {
			kcpConfig.NoCongestion = 0
		}
		loggo.Info("neither -fec nor -kcp set: running adaptively, matching each client's own reliability mode automatically")
	}

	s := &Server{
		icmpAddr:         icmpAddr,
		exit:             false,
		key:              key,
		maxconn:          maxconn,
		maxprocessthread: maxprocessthread,
		maxprocessbuffer: maxprocessbuffer,
		connecttmeout:    connecttmeout,
		connectTimeout:   time.Duration(connectHandshakeTimeoutSec) * time.Second,
		cryptoConfig:     cryptoConfig,
		forwardConfig:    forwardConfig,
		fecConfig:        fecConfig,
		fecSender:        fecSender,
		fecReceiver:      fecReceiver,
		kcpConfig:        kcpConfig,
		peerModes:        peerModes,
		rateLimiter:      NewRateLimiter(maxPPS),
	}

	if maxprocessthread > 0 {
		s.processtp = thread.NewThreadPool(maxprocessthread, maxprocessbuffer, func(v interface{}) {
			packet := v.(*Packet)
			s.processDataPacket(packet)
		})
	}

	return s, nil
}

type Server struct {
	exit             bool
	key              int
	workResultLock   sync.WaitGroup
	maxconn          int
	maxprocessthread int
	maxprocessbuffer int
	connecttmeout    int
	// connectTimeout bounds how long RecvTCP waits for the tcpmode
	// handshake ack (conn.fm.IsConnected()) to come back from the client,
	// separate from connecttmeout (which bounds the actual outbound dial
	// to the target). Distinct from the client's own connectTimeout field
	// but conceptually the same knob, set from the same -connect-timeout
	// flag on both sides - see NewClient's connectTimeoutSec.
	connectTimeout time.Duration
	cryptoConfig   *CryptoConfig
	forwardConfig  *ForwardConfig
	fecConfig      *FECConfig
	fecSender      *FECSender
	fecReceiver    *FECReceiver
	kcpConfig      *KCPConfig
	kcpTransport   *KCPTransport
	// peerModes is non-nil only in adaptive mode (neither -fec nor -kcp
	// pinned this server to a single mode) - see NewServer/peerTransport.
	peerModes   *PeerModeTracker
	rateLimiter *RateLimiter

	icmpAddr string

	conn *icmp.PacketConn

	localConnMap sync.Map
	connErrorMap sync.Map

	sendPacket       uint64
	recvPacket       uint64
	sendPacketSize   uint64
	recvPacketSize   uint64
	localConnMapSize int

	processtp   *thread.ThreadPool
	recvcontrol chan int
}

type ServerConn struct {
	exit           bool
	timeout        int
	ipaddrTarget   *net.UDPAddr
	conn           *net.UDPConn
	udpTargetAddr  string
	udpRelayAddr   *net.UDPAddr
	udpViaProxy    bool
	tcpaddrTarget  *net.TCPAddr
	tcpconn        net.Conn // Changed from *net.TCPConn to support proxy connections
	id             string
	activeRecvTime time.Time
	activeSendTime time.Time
	close          bool
	rproto         int
	fm             *network.FrameMgr
	tcpmode        int
	echoId         int
	echoSeq        int
	activity       chan struct{}
}

func (p *Server) Run() error {

	conn, err := listenICMP(p.icmpAddr)
	if err != nil {
		loggo.Error("Error listening for ICMP packets: %s", err.Error())
		return err
	}
	p.conn = conn

	recv := make(chan *Packet, 10000)
	p.recvcontrol = make(chan int, 1)
	// Built here rather than in NewServer because its deliver callback
	// needs recv, which doesn't exist until now - same reason p.conn
	// itself is only set inside Run(), not the constructor.
	if p.kcpConfig != nil {
		macKey := deriveKCPMacKey(p.cryptoConfig, p.key)
		p.kcpTransport = NewKCPTransport(p.kcpConfig, macKey, func(msg []byte, peer *net.IPAddr, id int) {
			deliverPayload(msg, p.cryptoConfig, recv, peer, id, 0)
		})
	}
	go recvICMP(&p.workResultLock, &p.exit, *p.conn, recv, p.cryptoConfig, p.fecReceiver, p.kcpTransport, RECV_PROTO, p.peerModes, p.rateLimiter)

	go func() {
		defer common.CrashLog()

		p.workResultLock.Add(1)
		defer p.workResultLock.Done()

		for !p.exit {
			p.checkTimeoutConn()
			p.showNet()
			p.updateConnError()
			time.Sleep(time.Second)
		}
	}()

	go func() {
		defer common.CrashLog()

		p.workResultLock.Add(1)
		defer p.workResultLock.Done()

		for !p.exit {
			select {
			case <-p.recvcontrol:
				return
			case r := <-recv:
				p.processPacket(r)
			}
		}
	}()

	return nil
}

// peerTransport resolves which reliability layer (if any) to hand to
// sendICMP for a reply to (src, echoId). In pinned mode (peerModes nil)
// this is just p.fecSender/p.kcpTransport unconditionally, exactly as
// before adaptive mode existed. In adaptive mode it looks up what that
// specific peer's own traffic was last observed using, so a KCP-using
// client and an FEC-using client connected to the same server at the same
// time each get replies in their own mode - see PeerModeTracker.
func (p *Server) peerTransport(src *net.IPAddr, echoId int) (*FECSender, *KCPTransport) {
	if p.peerModes == nil {
		return p.fecSender, p.kcpTransport
	}
	destKey := fmt.Sprintf("%s|%d", src.String(), echoId)
	switch p.peerModes.Mode(destKey) {
	case PeerModeKCP:
		return nil, p.kcpTransport
	case PeerModeFEC:
		return p.fecSender, nil
	default:
		return nil, nil
	}
}

func (p *Server) Stop() {
	p.exit = true
	p.recvcontrol <- 1
	p.workResultLock.Wait()
	p.processtp.Stop()
	p.conn.Close()
}

func (p *Server) processPacket(packet *Packet) {

	if packet.my.Key != (int32)(p.key) {
		return
	}

	// A negative Rproto is a sentinel the server itself uses ("not
	// applicable, this is a reply") - see sendICMP calls throughout this
	// file, all of which pass -1 for it - and no legitimate client ever
	// sends one (RECV_PROTO, the only value client.go ever uses, is 0).
	// Its only legitimate purpose is being echoed back to the client
	// unread; the server itself must never act on a packet carrying one.
	// Skipping this check let a server's own reply that got delivered
	// back to its own raw ICMP socket - which happens routinely when
	// client and server are literally the same host (loopback testing:
	// the loopback interface delivers a sent packet to every matching
	// local socket, including the sender's own) - be reprocessed as a
	// fresh incoming request. That reply carries this same -1 sentinel,
	// which then got used (in the PING branch) as the *wire* ICMP type
	// of the next reply (an invalid type - byte 255 on the wire, since
	// -1 truncates to 0xFF), which itself loops back the same way: an
	// unbounded, unrate-limited self-sustaining flood, observed at
	// upward of 1500 packets/sec until this was found and fixed.
	if packet.my.Rproto < 0 {
		return
	}

	if packet.my.Type == (int32)(MyMsg_PING) {
		t := time.Time{}
		t.UnmarshalBinary(packet.my.Data)
		loggo.Info("ping from %s %s %d %d %d", packet.src.String(), t.String(), packet.my.Rproto, packet.echoId, packet.echoSeq)
		fecSender, kcpTransport := p.peerTransport(packet.src, packet.echoId)
		sendICMP(packet.echoId, packet.echoSeq, *p.conn, packet.src, "", "", (uint32)(MyMsg_PING), packet.my.Data,
			(int)(packet.my.Rproto), -1, p.key,
			0, 0, 0, 0, 0, 0,
			0, p.cryptoConfig, fecSender, kcpTransport, p.rateLimiter)
		return
	}

	if packet.my.Type == (int32)(MyMsg_KICK) {
		localConn := p.getServerConnById(packet.my.Id)
		if localConn != nil {
			p.close(localConn)
			loggo.Info("remote kick local %s", packet.my.Id)
		}
		return
	}

	if p.maxprocessthread > 0 {
		p.processtp.AddJob((int)(common.HashString(packet.my.Id)), packet)
	} else {
		p.processDataPacket(packet)
	}
}

func (p *Server) processDataPacketNewConn(id string, packet *Packet) *ServerConn {

	now := common.GetNowUpdateInSecond()

	loggo.Info("start add new connect  %s %s", id, packet.my.Target)

	if p.maxconn > 0 && p.localConnMapSize >= p.maxconn {
		loggo.Info("too many connections %d, server connected target fail %s", p.localConnMapSize, packet.my.Target)
		p.remoteError(packet.echoId, packet.echoSeq, id, (int)(packet.my.Rproto), packet.src)
		return nil
	}

	addr := packet.my.Target
	if p.isConnError(addr) {
		loggo.Info("addr connect Error before: %s %s", id, addr)
		p.remoteError(packet.echoId, packet.echoSeq, id, (int)(packet.my.Rproto), packet.src)
		return nil
	}

	if packet.my.Tcpmode > 0 {

		var c net.Conn
		var err error
		if p.forwardConfig != nil {
			c, err = DialThroughProxy(p.forwardConfig, addr, time.Millisecond*time.Duration(p.connecttmeout))
		} else {
			c, err = net.DialTimeout("tcp", addr, time.Millisecond*time.Duration(p.connecttmeout))
		}
		if err != nil {
			loggo.Error("Error listening for tcp packets: %s %s", id, err.Error())
			p.remoteError(packet.echoId, packet.echoSeq, id, (int)(packet.my.Rproto), packet.src)
			p.addConnError(addr)
			return nil
		}
		// For proxy connections, parse target address; for direct connections, get from remote addr
		var ipaddrTarget *net.TCPAddr
		if p.forwardConfig != nil {
			// When using proxy, resolve the original target address
			ipaddrTarget, _ = net.ResolveTCPAddr("tcp", addr)
		} else {
			ipaddrTarget = c.RemoteAddr().(*net.TCPAddr)
		}

		fm := network.NewFrameMgr(FRAME_MAX_SIZE, FRAME_MAX_ID, (int)(packet.my.TcpmodeBuffersize), (int)(packet.my.TcpmodeMaxwin), (int)(packet.my.TcpmodeResendTimems), (int)(packet.my.TcpmodeCompress),
			(int)(packet.my.TcpmodeStat))

		localConn := &ServerConn{exit: false, timeout: (int)(packet.my.Timeout), tcpconn: c, tcpaddrTarget: ipaddrTarget, id: id, activeRecvTime: now, activeSendTime: now, close: false,
			rproto: (int)(packet.my.Rproto), fm: fm, tcpmode: (int)(packet.my.Tcpmode), activity: make(chan struct{}, 1)}

		p.addServerConn(id, localConn)

		go p.RecvTCP(localConn, id, packet.src)
		return localConn

	} else {
		if p.forwardConfig != nil {
			if p.forwardConfig.Scheme != "socks5" {
				loggo.Error("UDP forwarding requires SOCKS5 proxy, got %s", p.forwardConfig.Scheme)
				p.remoteError(packet.echoId, packet.echoSeq, id, (int)(packet.my.Rproto), packet.src)
				p.addConnError(addr)
				return nil
			}

			association, err := DialUDPThroughProxy(p.forwardConfig, time.Millisecond*time.Duration(p.connecttmeout))
			if err != nil {
				loggo.Error("Error creating udp forward association: %s %s", id, err.Error())
				p.remoteError(packet.echoId, packet.echoSeq, id, (int)(packet.my.Rproto), packet.src)
				p.addConnError(addr)
				return nil
			}

			localConn := &ServerConn{
				exit:           false,
				timeout:        (int)(packet.my.Timeout),
				conn:           association.UDPConn,
				udpTargetAddr:  addr,
				udpRelayAddr:   association.RelayAddr,
				udpViaProxy:    true,
				tcpconn:        association.ControlConn,
				id:             id,
				activeRecvTime: now,
				activeSendTime: now,
				close:          false,
				rproto:         (int)(packet.my.Rproto),
				tcpmode:        (int)(packet.my.Tcpmode),
			}

			p.addServerConn(id, localConn)

			go p.Recv(localConn, id, packet.src)

			return localConn
		}

		c, err := net.DialTimeout("udp", addr, time.Millisecond*time.Duration(p.connecttmeout))
		if err != nil {
			loggo.Error("Error listening for udp packets: %s %s", id, err.Error())
			p.remoteError(packet.echoId, packet.echoSeq, id, (int)(packet.my.Rproto), packet.src)
			p.addConnError(addr)
			return nil
		}
		targetConn := c.(*net.UDPConn)
		ipaddrTarget := targetConn.RemoteAddr().(*net.UDPAddr)

		localConn := &ServerConn{exit: false, timeout: (int)(packet.my.Timeout), conn: targetConn, ipaddrTarget: ipaddrTarget, id: id, activeRecvTime: now, activeSendTime: now, close: false,
			rproto: (int)(packet.my.Rproto), tcpmode: (int)(packet.my.Tcpmode), udpTargetAddr: addr}

		p.addServerConn(id, localConn)

		go p.Recv(localConn, id, packet.src)

		return localConn
	}

	return nil
}

func (p *Server) processDataPacket(packet *Packet) {

	loggo.Debug("processPacket %s %s %d", packet.my.Id, packet.src.String(), len(packet.my.Data))

	now := common.GetNowUpdateInSecond()

	id := packet.my.Id
	localConn := p.getServerConnById(id)
	if localConn == nil {
		localConn = p.processDataPacketNewConn(id, packet)
		if localConn == nil {
			return
		}
	}

	localConn.activeRecvTime = now
	localConn.echoId = packet.echoId
	localConn.echoSeq = packet.echoSeq

	if packet.my.Type == (int32)(MyMsg_DATA) {

		// localConn.tcpmode (fixed at connection creation in
		// processDataPacketNewConn), not packet.my.Tcpmode: the two can
		// disagree for an individual packet (e.g. a stray/retransmitted
		// packet), and branching on the per-packet field here crashes -
		// a tcpmode connection never sets localConn.conn (it uses
		// localConn.fm instead), so a packet.my.Tcpmode of 0 for such a
		// connection would fall through to localConn.conn.Write on a nil
		// conn. The connection's own established mode is what actually
		// determines how its data must be interpreted for its whole
		// lifetime, regardless of what any single packet's field says.
		if localConn.tcpmode > 0 {
			f := &network.Frame{}
			err := proto.Unmarshal(packet.my.Data, f)
			if err != nil {
				loggo.Error("Unmarshal tcp Error %s", err)
				return
			}

			localConn.fm.OnRecvFrame(f)
			notifyActivity(localConn.activity)

		} else {
			if packet.my.Data == nil {
				return
			}

			var err error
			if localConn.udpViaProxy {
				targetAddr := localConn.udpTargetAddr
				if packet.my.Target != "" {
					targetAddr = packet.my.Target
				}
				if targetAddr == "" {
					loggo.Info("missing udp target for proxied udp conn %s", id)
					localConn.close = true
					return
				}
				udpPacket, packetErr := buildSocks5UDPDatagram(targetAddr, packet.my.Data)
				if packetErr != nil {
					loggo.Info("build socks5 udp datagram error %s", packetErr)
					localConn.close = true
					return
				}
				if localConn.udpRelayAddr == nil {
					loggo.Info("missing udp relay addr for proxied udp conn %s", id)
					localConn.close = true
					return
				}
				_, err = localConn.conn.WriteToUDP(udpPacket, localConn.udpRelayAddr)
			} else {
				_, err = localConn.conn.Write(packet.my.Data)
			}
			if err != nil {
				loggo.Info("WriteToUDP Error %s", err)
				localConn.close = true
				return
			}
		}

		p.recvPacket++
		p.recvPacketSize += (uint64)(len(packet.my.Data))
	}
}

func (p *Server) RecvTCP(conn *ServerConn, id string, src *net.IPAddr) {

	defer common.CrashLog()

	p.workResultLock.Add(1)
	defer p.workResultLock.Done()

	loggo.Info("server waiting target response %s -> %s %s", conn.tcpaddrTarget.String(), conn.id, conn.tcpconn.LocalAddr().String())

	loggo.Info("start wait remote connect tcp %s %s", conn.id, conn.tcpaddrTarget.String())
	startConnectTime := common.GetNowUpdateInSecond()
	connectWait := newAdaptiveLoopWait(2*time.Millisecond, 80*time.Millisecond)
	fecSender, kcpTransport := p.peerTransport(src, conn.echoId)
	// conn.fm (a network.FrameMgr) already provides this connection's own
	// reliable, ordered ARQ - its own window, ACKs, and resend timer
	// (tcpmode_resend_timems, default 400ms) - see the detailed comment
	// above client.go's AcceptTcpConn (this function's exact counterpart on
	// the other end of the same tcpmode connection). Wrapping its frames in
	// KCP as well stacks a second, independent ARQ on top of the first:
	// once KCP's own retransmission takes longer than FrameMgr's resend
	// timeout (routine under any real load - see KCPSession's backlog cap
	// in kcp_transport.go), FrameMgr sees the missing ACK as loss and sends
	// its own duplicate frame, which itself re-enters KCP as a brand new
	// message - a resend-amplification feedback loop that saturated the
	// KCP backlog within seconds under real VPN traffic (live-tested
	// 2026-08-24) and left the tunnel not working at all, not just slow.
	// FEC has no such problem (no retry timer of its own, just forward
	// redundancy) so fecSender is left untouched; only kcpTransport is
	// nilled here, for every sendICMP call in this function, falling
	// through to a plain unwrapped send exactly as tcpmode traffic used
	// before FEC/KCP existed.
	kcpTransport = nil
	for !p.exit && !conn.exit {
		if conn.fm.IsConnected() {
			break
		}
		conn.fm.Update()
		sendlist := conn.fm.GetSendList()
		hadWork := sendlist.Len() > 0
		for e := sendlist.Front(); e != nil; e = e.Next() {
			f := e.Value.(*network.Frame)
			mb, _ := conn.fm.MarshalFrame(f)
			sendICMP(conn.echoId, conn.echoSeq, *p.conn, src, "", id, (uint32)(MyMsg_DATA), mb,
				conn.rproto, -1, p.key, 0,
				0, 0, 0, 0, 0,
				0, p.cryptoConfig, fecSender, kcpTransport, p.rateLimiter)
			p.sendPacket++
			p.sendPacketSize += (uint64)(len(mb))
		}
		now := common.GetNowUpdateInSecond()
		diffclose := now.Sub(startConnectTime)
		if diffclose > p.connectTimeout {
			loggo.Info("can not connect remote tcp %s %s", conn.id, conn.tcpaddrTarget.String())
			p.close(conn)
			p.remoteError(conn.echoId, conn.echoSeq, id, conn.rproto, src)
			return
		}
		if hadWork {
			connectWait.hit()
			continue
		}
		wait := connectWait.miss()
		select {
		case <-conn.activity:
			connectWait.hit()
		case <-time.After(wait):
		}
	}

	if !conn.exit {
		loggo.Info("remote connected tcp %s %s", conn.id, conn.tcpaddrTarget.String())
	}

	bytes := make([]byte, 10240)

	tcpActiveRecvUnix := atomic.Int64{}
	tcpActiveRecvUnix.Store(common.GetNowUpdateInSecond().UnixNano())
	tcpActiveSendTime := common.GetNowUpdateInSecond()
	readErr := make(chan error, 1)
	stopRead := make(chan struct{})

	go func() {
		defer common.CrashLog()

		readWait := newAdaptiveLoopWait(2*time.Millisecond, 80*time.Millisecond)
		for !p.exit && !conn.exit {
			left := common.MinOfInt(conn.fm.GetSendBufferLeft(), len(bytes))
			if left <= 0 {
				wait := readWait.miss()
				select {
				case <-stopRead:
					return
				case <-conn.activity:
					readWait.hit()
					continue
				case <-time.After(wait):
					continue
				}
			}
			readWait.hit()

			conn.tcpconn.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
			n, err := conn.tcpconn.Read(bytes[0:left])
			if err != nil {
				nerr, ok := err.(net.Error)
				if ok && nerr.Timeout() {
					continue
				}
				select {
				case readErr <- err:
				default:
				}
				return
			}
			if n <= 0 {
				continue
			}

			conn.fm.WriteSendBuffer(bytes[:n])
			tcpActiveRecvUnix.Store(common.GetNowUpdateInSecond().UnixNano())
			notifyActivity(conn.activity)
		}
	}()

	loopWait := newAdaptiveLoopWait(2*time.Millisecond, 250*time.Millisecond)

mainLoop:
	for !p.exit && !conn.exit {
		now := common.GetNowUpdateInSecond()
		hadWork := false

		conn.fm.Update()

		sendlist := conn.fm.GetSendList()
		if sendlist.Len() > 0 {
			hadWork = true
			conn.activeSendTime = now
			for e := sendlist.Front(); e != nil; e = e.Next() {
				f := e.Value.(*network.Frame)
				mb, err := conn.fm.MarshalFrame(f)
				if err != nil {
					loggo.Error("Error tcp Marshal %s %s %s", conn.id, conn.tcpaddrTarget.String(), err)
					continue
				}
				sendICMP(conn.echoId, conn.echoSeq, *p.conn, src, "", id, (uint32)(MyMsg_DATA), mb,
					conn.rproto, -1, p.key, 0,
					0, 0, 0, 0, 0,
					0, p.cryptoConfig, fecSender, kcpTransport, p.rateLimiter)
				p.sendPacket++
				p.sendPacketSize += (uint64)(len(mb))
			}
		}

		if conn.fm.GetRecvBufferSize() > 0 {
			hadWork = true
			rr := conn.fm.GetRecvReadLineBuffer()
			conn.tcpconn.SetWriteDeadline(time.Now().Add(200 * time.Millisecond))
			n, err := conn.tcpconn.Write(rr)
			if err != nil {
				nerr, ok := err.(net.Error)
				if !ok || !nerr.Timeout() {
					loggo.Info("Error write tcp %s %s %s", conn.id, conn.tcpaddrTarget.String(), err)
					conn.fm.Close()
					break mainLoop
				}
			}
			if n > 0 {
				conn.fm.SkipRecvBuffer(n)
				tcpActiveSendTime = now
			}
		}

		select {
		case err := <-readErr:
			if err != nil {
				loggo.Info("Error read tcp %s %s %s", conn.id, conn.tcpaddrTarget.String(), err)
				conn.fm.Close()
				break mainLoop
			}
		default:
		}

		diffrecv := now.Sub(conn.activeRecvTime)
		diffsend := now.Sub(conn.activeSendTime)
		tcpdiffrecv := now.Sub(time.Unix(0, tcpActiveRecvUnix.Load()))
		tcpdiffsend := now.Sub(tcpActiveSendTime)
		if diffrecv > time.Second*(time.Duration(conn.timeout)) || diffsend > time.Second*(time.Duration(conn.timeout)) ||
			(tcpdiffrecv > time.Second*(time.Duration(conn.timeout)) && tcpdiffsend > time.Second*(time.Duration(conn.timeout))) {
			loggo.Info("close inactive conn %s %s", conn.id, conn.tcpaddrTarget.String())
			conn.fm.Close()
			break
		}

		if conn.fm.IsRemoteClosed() {
			loggo.Info("closed by remote conn %s %s", conn.id, conn.tcpaddrTarget.String())
			conn.fm.Close()
			break
		}

		if !hadWork {
			wait := loopWait.miss()
			select {
			case <-conn.activity:
				loopWait.hit()
			case err := <-readErr:
				if err != nil {
					loggo.Info("Error read tcp %s %s %s", conn.id, conn.tcpaddrTarget.String(), err)
					conn.fm.Close()
					break mainLoop
				}
			case <-time.After(wait):
			}
		} else {
			loopWait.hit()
		}
	}
	close(stopRead)

	conn.fm.Close()

	startCloseTime := common.GetNowUpdateInSecond()
	for !p.exit && !conn.exit {
		now := common.GetNowUpdateInSecond()

		conn.fm.Update()

		sendlist := conn.fm.GetSendList()
		for e := sendlist.Front(); e != nil; e = e.Next() {
			f := e.Value.(*network.Frame)
			mb, _ := conn.fm.MarshalFrame(f)
			sendICMP(conn.echoId, conn.echoSeq, *p.conn, src, "", id, (uint32)(MyMsg_DATA), mb,
				conn.rproto, -1, p.key, 0,
				0, 0, 0, 0, 0,
				0, p.cryptoConfig, fecSender, kcpTransport, p.rateLimiter)
			p.sendPacket++
			p.sendPacketSize += (uint64)(len(mb))
		}

		nodatarecv := true
		if conn.fm.GetRecvBufferSize() > 0 {
			rr := conn.fm.GetRecvReadLineBuffer()
			conn.tcpconn.SetWriteDeadline(time.Now().Add(time.Millisecond * 100))
			n, _ := conn.tcpconn.Write(rr)
			if n > 0 {
				conn.fm.SkipRecvBuffer(n)
				nodatarecv = false
			}
		}

		diffclose := now.Sub(startCloseTime)
		if diffclose > time.Second*60 {
			loggo.Info("close conn had timeout %s %s", conn.id, conn.tcpaddrTarget.String())
			break
		}

		remoteclosed := conn.fm.IsRemoteClosed()
		if remoteclosed && nodatarecv {
			loggo.Info("remote conn had closed %s %s", conn.id, conn.tcpaddrTarget.String())
			break
		}

		time.Sleep(time.Millisecond * 100)
	}

	time.Sleep(time.Second)

	loggo.Info("close tcp conn %s %s", conn.id, conn.tcpaddrTarget.String())
	p.close(conn)
}

func (p *Server) Recv(conn *ServerConn, id string, src *net.IPAddr) {

	defer common.CrashLog()

	p.workResultLock.Add(1)
	defer p.workResultLock.Done()

	loggo.Info("server waiting target response %s -> %s %s", conn.udpTargetString(), conn.id, conn.conn.LocalAddr().String())

	bytes := make([]byte, 2000)
	fecSender, kcpTransport := p.peerTransport(src, conn.echoId)
	loggo.Debug("DIAG PEERTRANSPORT src=%v echoId=%d fecSender=%v kcpTransport=%v", src, conn.echoId, fecSender != nil, kcpTransport != nil)

	for !p.exit {

		conn.conn.SetReadDeadline(time.Now().Add(time.Millisecond * 100))
		n, srcAddr, err := conn.conn.ReadFromUDP(bytes)
		if err != nil {
			nerr, ok := err.(net.Error)
			if !ok || !nerr.Timeout() {
				loggo.Info("ReadFromUDP Error read udp %s", err)
				conn.close = true
				return
			}
		}
		if n <= 0 {
			continue
		}

		now := common.GetNowUpdateInSecond()
		conn.activeSendTime = now

		targetAddr := conn.udpTargetString()
		payload := bytes[:n]

		if conn.udpViaProxy {
			if conn.udpRelayAddr != nil && !sameUDPAddr(srcAddr, conn.udpRelayAddr) {
				continue
			}
			parsedTarget, parsedPayload, parseErr := parseSocks5UDPDatagram(bytes[:n])
			if parseErr != nil {
				loggo.Debug("parse udp datagram from socks5 relay failed: %s", parseErr)
				continue
			}
			targetAddr = parsedTarget
			payload = parsedPayload
		}

		sendICMP(conn.echoId, conn.echoSeq, *p.conn, src, targetAddr, id, (uint32)(MyMsg_DATA), payload,
			conn.rproto, -1, p.key, 0,
			0, 0, 0, 0, 0,
			0, p.cryptoConfig, fecSender, kcpTransport, p.rateLimiter)

		p.sendPacket++
		p.sendPacketSize += (uint64)(len(payload))
	}
}

func (p *Server) close(conn *ServerConn) {
	if p.getServerConnById(conn.id) != nil {
		conn.exit = true
		if conn.conn != nil {
			conn.conn.Close()
		}
		if conn.tcpconn != nil {
			conn.tcpconn.Close()
		}
		p.deleteServerConn(conn.id)
	}
}

func (p *Server) checkTimeoutConn() {

	tmp := make(map[string]*ServerConn)
	p.localConnMap.Range(func(key, value interface{}) bool {
		id := key.(string)
		serverConn := value.(*ServerConn)
		tmp[id] = serverConn
		return true
	})

	now := common.GetNowUpdateInSecond()
	for _, conn := range tmp {
		if conn.tcpmode > 0 {
			continue
		}
		diffrecv := now.Sub(conn.activeRecvTime)
		diffsend := now.Sub(conn.activeSendTime)
		if diffrecv > time.Second*(time.Duration(conn.timeout)) || diffsend > time.Second*(time.Duration(conn.timeout)) {
			conn.close = true
		}
	}

	for id, conn := range tmp {
		if conn.tcpmode > 0 {
			continue
		}
		if conn.close {
			loggo.Info("close inactive conn %s %s", id, conn.udpTargetString())
			p.close(conn)
		}
	}
}

func (conn *ServerConn) udpTargetString() string {
	if conn.udpTargetAddr != "" {
		return conn.udpTargetAddr
	}
	if conn.ipaddrTarget != nil {
		return conn.ipaddrTarget.String()
	}
	return "unknown"
}

func sameUDPAddr(a *net.UDPAddr, b *net.UDPAddr) bool {
	if a == nil || b == nil {
		return false
	}
	if b.Port != 0 && a.Port != b.Port {
		return false
	}
	if b.IP == nil || b.IP.IsUnspecified() {
		return true
	}
	if a.IP == nil {
		return false
	}
	return a.IP.Equal(b.IP)
}

func (p *Server) showNet() {
	p.localConnMapSize = 0
	p.localConnMap.Range(func(key, value interface{}) bool {
		p.localConnMapSize++
		return true
	})
	loggo.Info("send %dPacket/s %dKB/s recv %dPacket/s %dKB/s %dConnections",
		p.sendPacket, p.sendPacketSize/1024, p.recvPacket, p.recvPacketSize/1024, p.localConnMapSize)
	p.sendPacket = 0
	p.recvPacket = 0
	p.sendPacketSize = 0
	p.recvPacketSize = 0
}

func (p *Server) addServerConn(uuid string, serverConn *ServerConn) {
	p.localConnMap.Store(uuid, serverConn)
}

func (p *Server) getServerConnById(uuid string) *ServerConn {
	ret, ok := p.localConnMap.Load(uuid)
	if !ok {
		return nil
	}
	return ret.(*ServerConn)
}

func (p *Server) deleteServerConn(uuid string) {
	p.localConnMap.Delete(uuid)
}

func (p *Server) remoteError(echoId int, echoSeq int, uuid string, rprpto int, src *net.IPAddr) {
	fecSender, kcpTransport := p.peerTransport(src, echoId)
	sendICMP(echoId, echoSeq, *p.conn, src, "", uuid, (uint32)(MyMsg_KICK), []byte{},
		rprpto, -1, p.key,
		0, 0, 0, 0, 0, 0, 0,
		p.cryptoConfig, fecSender, kcpTransport, p.rateLimiter)
}

func (p *Server) addConnError(addr string) {
	_, ok := p.connErrorMap.Load(addr)
	if !ok {
		now := common.GetNowUpdateInSecond()
		p.connErrorMap.Store(addr, now)
	}
}

func (p *Server) isConnError(addr string) bool {
	_, ok := p.connErrorMap.Load(addr)
	return ok
}

func (p *Server) updateConnError() {

	tmp := make(map[string]time.Time)
	p.connErrorMap.Range(func(key, value interface{}) bool {
		id := key.(string)
		t := value.(time.Time)
		tmp[id] = t
		return true
	})

	now := common.GetNowUpdateInSecond()
	for id, t := range tmp {
		diff := now.Sub(t)
		if diff > time.Second*5 {
			p.connErrorMap.Delete(id)
		}
	}
}
