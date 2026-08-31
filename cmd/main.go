package main

import (
	"flag"
	"fmt"
	"github.com/esrrhs/gohome/common"
	"github.com/esrrhs/gohome/loggo"
	"github.com/esrrhs/gohome/thirdparty"
	"github.com/esrrhs/pingtunnel"
	"net"
	"net/http"
	_ "net/http/pprof"
	"strconv"
	"time"
)

var usage = `
    通过伪造ping，把tcp/udp/sock5流量通过远程服务器转发到目的服务器上。用于突破某些运营商封锁TCP/UDP流量。
    By forging ping, the tcp/udp/sock5 traffic is forwarded to the destination server through the remote server. Used to break certain operators to block TCP/UDP traffic.

Usage:

    // server
    pingtunnel -type server

    // client, Forward udp
    pingtunnel -type client -l LOCAL_IP:4455 -s SERVER_IP -t SERVER_IP:4455

    // client, Forward tcp
    pingtunnel -type client -l LOCAL_IP:4455 -s SERVER_IP -t SERVER_IP:4455 -tcp 1

    // client, Forward sock5, implicitly open tcp, so no target server is needed
    pingtunnel -type client -l LOCAL_IP:4455 -s SERVER_IP -sock5 1

    -type     服务器或者客户端
              client or server

服务器参数server param:

    -icmp_l   本地地址，侦听此地址上的ICMP流量，默认为0.0.0.0
              Local address, listen for ICMP traffic on this address, defaults to 0.0.0.0

    -key      设置的纯数字密码，默认0, 参数为int类型，范围从0-2147483647，不可夹杂字母特殊符号
              Set password, default 0

    -nolog    不写日志文件，只打印标准输出，默认0
              Do not write log files, only print standard output, default 0 is off

    -noprint  不打印屏幕输出，默认0
              Do not print standard output, default 0 is off

    -loglevel 日志文件等级，默认info
              log level, default is info

    -maxconn  最大连接数，默认0，不受限制
              the max num of connections, default 0 is no limit

    -maxprt   server最大处理线程数，默认100
              max process thread in server, default 100

    -maxprb   server最大处理线程buffer数，默认1000
              max process thread's buffer in server, default 1000

    -conntt   server发起连接到目标地址的超时时间，默认1000ms
              The timeout period for the server to initiate a connection to the destination address. The default is 1000ms.

    -forward  通过指定的代理转发TCP流量，支持socks5和http代理，如 socks5://localhost:2080 或 http://localhost:8080
              Forward TCP traffic through the specified proxy. Supports socks5 and http proxies, e.g. socks5://localhost:2080 or http://localhost:8080

客户端参数client param:

    -l        本地的地址，发到这个端口的流量将转发到服务器
              Local address, traffic sent to this port will be forwarded to the server

    -s        服务器的地址，流量将通过隧道转发到这个服务器
              The address of the server, the traffic will be forwarded to this server through the tunnel

    -t        远端服务器转发的目的地址，流量将转发到这个地址
              Destination address forwarded by the remote server, traffic will be forwarded to this address

    -icmp_l   本地地址，侦听此地址上的ICMP流量，默认为0.0.0.0
              Local address, listen for ICMP traffic on this address, defaults to 0.0.0.0

    -timeout  本地记录连接超时的时间，单位是秒，默认60s
              The time when the local record connection timed out, in seconds, 60 seconds by default

    -key      设置的密码，默认0
              Set password, default 0

    -encrypt  加密模式，支持aes128, aes256, chacha20
              Encryption mode: aes128, aes256, chacha20

    -encrypt-key 加密密钥，支持base64编码或密码短语
              Encryption key, supports base64 encoded key or passphrase

    -fec      开启前向纠错(FEC)，用于在丢包链路（卫星、机场wifi等）上恢复丢失的数据包，默认关闭，客户端和服务器需要使用相同的fec参数
              Enable forward error correction (FEC) to recover lost packets on lossy links (satellite, airport wifi, etc). Default off. Client and server must use matching FEC parameters

    -fec-data FEC每个数据块的数据分片数，默认10，仅在-fec开启时生效
              FEC data shards per block, default 10, only used when -fec is enabled

    -fec-parity FEC每个数据块的冗余分片数，默认3，一个数据块最多可以容忍丢失这么多个分片，仅在-fec开启时生效
              FEC parity shards per block, default 3, tolerates losing up to this many shards per block, only used when -fec is enabled

    -kcp      使用KCP（可靠ARQ传输）代替默认的重传逻辑，默认关闭，不能和-fec同时使用，客户端和服务器需要同时开启
              Use KCP (reliable ARQ transport) instead of the default resend logic. Default off. Cannot be combined with -fec. Client and server must both enable it

              服务器提示：如果服务器既没有-fec也没有-kcp，它会自适应——每个客户端可以自由使用-fec、-kcp或都不用，服务器会自动匹配每个客户端各自的选择（包括同时连接使用不同模式的多个客户端）。仍然想让服务器只接受一种模式吗？照常显式设置-fec或-kcp，行为不变。
              Server note: if the server has neither -fec nor -kcp, it runs adaptively - each client is free to use -fec, -kcp, or neither, and the server automatically matches whatever that client uses (including multiple simultaneously-connected clients each using a different mode). To pin the server to exactly one mode as before, set -fec or -kcp explicitly as usual - behavior is unchanged in that case

    -tcp      设置是否转发tcp，默认0
              Set the switch to forward tcp, the default is 0

    -tcp_bs   tcp的发送接收缓冲区大小，默认1MB
              Tcp send and receive buffer size, default 1MB

    -tcp_mw   tcp的最大窗口，默认20000
              The maximum window of tcp, the default is 20000

    -tcp_rst  tcp的超时发送时间，默认400ms
              Tcp timeout resend time, default 400ms

    -tcp_gz   当数据包超过这个大小，tcp将压缩数据，0表示不压缩，默认0
              Tcp will compress data when the packet exceeds this size, 0 means no compression, default 0

    -tcp_stat 打印tcp的监控，默认0
              Print tcp connection statistic, default 0 is off

    -nolog    不写日志文件，只打印标准输出，默认0
              Do not write log files, only print standard output, default 0 is off

    -noprint  不打印屏幕输出，默认0
              Do not print standard output, default 0 is off

    -loglevel 日志文件等级，默认info
              log level, default is info

    -sock5    开启sock5转发，默认0
              Turn on sock5 forwarding, default 0 is off

    -s5user   sock5用户名，默认为空不需要认证
              sock5 username, default is empty and no authentication is required

    -s5pass   sock5密码，默认为空不需要认证
              sock5 password, default is empty and no authentication is required

    -profile  在指定端口开启性能检测，默认0不开启
              Enable performance detection on the specified port. The default 0 is not enabled.

    -s5filter sock5模式设置转发过滤，默认全转发，设置CN代表CN地区的直连不转发
              Set the forwarding filter in the sock5 mode. The default is full forwarding. For example, setting the CN indicates that the Chinese address is not forwarded.

    -s5ftfile sock5模式转发过滤的数据文件，默认读取当前目录的GeoLite2-Country.mmdb
              The data file in sock5 filter mode, the default reading of the current directory GeoLite2-Country.mmdb
`

func main() {

	defer common.CrashLog()

	t := flag.String("type", "", "client or server")
	listen := flag.String("l", "", "listen addr")
	target := flag.String("t", "", "target addr")
	server := flag.String("s", "", "server addr")
	icmpListen := flag.String("icmp_l", "0.0.0.0", "listen address for ICMP traffic")
	timeout := flag.Int("timeout", 60, "conn timeout")
	connectTimeout := flag.Int("connect-timeout", 15, "seconds to wait for a new tcpmode connection's handshake ack before giving up; raise this if many connections open at once over a slow/lossy link (e.g. a system-wide proxy client) and time out before the ack gets through")
	maxPPS := flag.Int("max-pps", pingtunnel.DefaultMaxPPS, "cap on total outbound ICMP packets/sec across every connection sharing this tunnel; a safety net against retransmission storms (e.g. many connections' FrameMgr resend timers firing at once under real loss) turning into a self-inflicted congestion collapse - lower it if your link is narrower than the default assumes")
	key := flag.Int("key", 0, "key")
	encryption := flag.String("encrypt", "", "encryption mode: aes128, aes256, chacha20")
	encryptionKey := flag.String("encrypt-key", "", "encryption key (base64 or passphrase)")
	fec := flag.Bool("fec", false, "enable forward error correction (FEC) to recover from packet loss on lossy links")
	fecData := flag.Int("fec-data", 10, "FEC data shards per block (used only when -fec is set)")
	fecParity := flag.Int("fec-parity", 3, "FEC parity shards per block, tolerates losing up to this many packets per block of fec-data+fec-parity (used only when -fec is set)")
	kcpFlag := flag.Bool("kcp", false, "use KCP (reliable ARQ) instead of the default resend logic for this tunnel; cannot be combined with -fec")
	kcpSndWnd := flag.Int("kcp-sndwnd", 0, "KCP send window, in segments (0 = built-in default, 256). Raise this for high-bandwidth-delay-product links (e.g. a fast but high-latency satellite link like Starlink) where the default window can't keep enough data in flight to fill the real link capacity. Applies both when -kcp is pinned and to the server's adaptive per-peer KCP sessions")
	kcpRcvWnd := flag.Int("kcp-rcvwnd", 0, "KCP receive window, in segments (0 = built-in default, 256) - see -kcp-sndwnd")
	kcpCongestion := flag.Bool("kcp-congestion", false, "enable KCP's built-in TCP-Reno-style congestion control (kcp-go's cwnd/ssthresh: slow start, additive increase, multiplicative decrease on loss) instead of blasting up to the static send window regardless of observed loss/RTT. Off by default (matches this project's original behavior, chosen when this project was tuned for a narrow-but-not-shared link); worth trying on a bandwidth-constrained or shared link (e.g. real satellite) where an uncontrolled static window can cause self-inflicted congestion")
	tcpmode := flag.Int("tcp", 0, "tcp mode")
	tcpmode_buffersize := flag.Int("tcp_bs", 1*1024*1024, "tcp mode buffer size")
	tcpmode_maxwin := flag.Int("tcp_mw", 20000, "tcp mode max win")
	tcpmode_resend_timems := flag.Int("tcp_rst", 400, "tcp mode resend time ms")
	tcpmode_compress := flag.Int("tcp_gz", 0, "tcp data compress")
	nolog := flag.Int("nolog", 0, "write log file")
	noprint := flag.Int("noprint", 0, "print stdout")
	tcpmode_stat := flag.Int("tcp_stat", 0, "print tcp stat")
	loglevel := flag.String("loglevel", "info", "log level")
	open_sock5 := flag.Int("sock5", 0, "sock5 mode")
	sock5_user := flag.String("s5user", "", "sock5 username")
	sock5_pass := flag.String("s5pass", "", "sock5 password")
	maxconn := flag.Int("maxconn", 0, "max num of connections")
	max_process_thread := flag.Int("maxprt", 100, "max process thread in server")
	max_process_buffer := flag.Int("maxprb", 1000, "max process thread's buffer in server")
	profile := flag.Int("profile", 0, "open profile")
	conntt := flag.Int("conntt", 1000, "the connect call's timeout")
	forward := flag.String("forward", "", "forward TCP traffic through proxy (socks5://host:port or http://host:port)")
	s5filter := flag.String("s5filter", "", "sock5 filter")
	s5ftfile := flag.String("s5ftfile", "GeoLite2-Country.mmdb", "sock5 filter file")
	flag.Usage = func() {
		fmt.Print(usage)
	}

	flag.Parse()

	if *t != "client" && *t != "server" {
		flag.Usage()
		return
	}
	if *t == "client" {
		if len(*listen) == 0 || len(*server) == 0 {
			flag.Usage()
			return
		}
		if *open_sock5 == 0 && len(*target) == 0 {
			flag.Usage()
			return
		}
		if *open_sock5 != 0 {
			*tcpmode = 1
		}
	}
	if *tcpmode_maxwin*10 > pingtunnel.FRAME_MAX_ID {
		fmt.Println("set tcp win to big, max = " + strconv.Itoa(pingtunnel.FRAME_MAX_ID/10))
		return
	}

	// Validate encryption parameters
	encryptionMode, err := pingtunnel.ParseEncryptionMode(*encryption)
	if err != nil {
		fmt.Printf("Invalid encryption mode: %v\n", err)
		return
	}

	if encryptionMode != pingtunnel.NoEncryption && *encryptionKey == "" {
		fmt.Println("Encryption key is required when encryption mode is specified")
		return
	}

	// Create crypto configuration
	var cryptoConfig *pingtunnel.CryptoConfig
	if encryptionMode != pingtunnel.NoEncryption {
		cryptoConfig, err = pingtunnel.NewCryptoConfig(encryptionMode, *encryptionKey)
		if err != nil {
			fmt.Printf("Failed to create crypto config: %v\n", err)
			return
		}
	}

	// Create FEC configuration. FEC is fully optional: when -fec is not set,
	// fecConfig stays nil and the wire format is byte-for-byte identical to
	// a build without FEC support. The client and server must agree on
	// -fec-data/-fec-parity themselves; a mismatch (or one side running
	// without FEC) is only logged and the offending packets are dropped,
	// never a crash.
	var fecConfig *pingtunnel.FECConfig
	if *fec {
		fecConfig, err = pingtunnel.NewFECConfig(*fecData, *fecParity)
		if err != nil {
			fmt.Printf("Failed to create fec config: %v\n", err)
			return
		}
	}

	// KCP is an alternative reliability layer to FEC (a full ARQ engine
	// instead of block erasure coding); the two are not composed together
	// in this first integration, so reject the combination up front rather
	// than silently picking one.
	var kcpConfig *pingtunnel.KCPConfig
	if *kcpFlag {
		if *fec {
			fmt.Println("-kcp and -fec cannot be used together")
			return
		}
		kcpConfig = pingtunnel.DefaultKCPConfig()
		if *kcpSndWnd > 0 {
			kcpConfig.SndWnd = *kcpSndWnd
		}
		if *kcpRcvWnd > 0 {
			kcpConfig.RcvWnd = *kcpRcvWnd
		}
		if *kcpCongestion {
			kcpConfig.NoCongestion = 0
		}
	}

	level := loggo.LEVEL_INFO
	if loggo.NameToLevel(*loglevel) >= 0 {
		level = loggo.NameToLevel(*loglevel)
	}
	loggo.Ini(loggo.Config{
		Level:     level,
		Prefix:    "pingtunnel",
		MaxDay:    3,
		NoLogFile: *nolog > 0,
		NoPrint:   *noprint > 0,
	})
	loggo.Info("start...")
	if cryptoConfig == nil {
		// Without -encrypt every MyMsg, including this numeric key, goes
		// out as cleartext inside the ICMP payload - anyone who can
		// observe the traffic (a transit hop, a shared L2 segment) can
		// read the key and then send crafted packets the server will
		// treat as authenticated. This is a config choice, not a bug, but
		// operators should know before relying on it.
		loggo.Warn("running without -encrypt: the key and all tunneled traffic are sent in cleartext; add -encrypt/-encrypt-key if this link is not already trusted/private")
	}
	if fecConfig != nil {
		loggo.Info("FEC enabled: data=%d parity=%d", fecConfig.DataShards, fecConfig.ParityShards)
	}
	if kcpConfig != nil {
		loggo.Info("KCP enabled: nodelay=%d interval=%dms resend=%d nc=%d sndwnd=%d rcvwnd=%d mtu=%d",
			kcpConfig.NoDelay, kcpConfig.Interval, kcpConfig.Resend, kcpConfig.NoCongestion,
			kcpConfig.SndWnd, kcpConfig.RcvWnd, kcpConfig.MTU)
	}

	if *t == "server" {
		// Parse forward proxy configuration
		var forwardConfig *pingtunnel.ForwardConfig
		if *forward != "" {
			var err error
			forwardConfig, err = pingtunnel.ParseForwardURL(*forward)
			if err != nil {
				fmt.Printf("Invalid forward URL: %v\n", err)
				return
			}
			loggo.Info("Forward proxy configured: %s", *forward)
		}

		s, err := pingtunnel.NewServer(*icmpListen, *key, *maxconn, *max_process_thread, *max_process_buffer, *conntt, cryptoConfig, forwardConfig, fecConfig, kcpConfig, *connectTimeout, *maxPPS, *kcpSndWnd, *kcpRcvWnd, *kcpCongestion)
		if err != nil {
			loggo.Error("ERROR: %s", err.Error())
			return
		}
		loggo.Info("Server start")
		err = s.Run()
		if err != nil {
			loggo.Error("Run ERROR: %s", err.Error())
			return
		}
	} else if *t == "client" {

		loggo.Info("type %s", *t)
		loggo.Info("listen %s", *listen)
		loggo.Info("server %s", *server)
		loggo.Info("target %s", *target)

		if *tcpmode == 0 {
			*tcpmode_buffersize = 0
			*tcpmode_maxwin = 0
			*tcpmode_resend_timems = 0
			*tcpmode_compress = 0
			*tcpmode_stat = 0
		}

		if len(*s5filter) > 0 {
			err := thirdparty.LoadGeoip2(*s5ftfile)
			if err != nil {
				loggo.Error("Load Sock5 ip file ERROR: %s", err.Error())
				return
			}
		}
		filter := func(addr string) bool {
			if len(*s5filter) <= 0 {
				return true
			}

			taddr, err := net.ResolveTCPAddr("tcp", addr)
			if err != nil {
				return false
			}

			ret, err := thirdparty.GetGeoipCountryIsoCode(taddr.IP.String())
			if err != nil {
				return false
			}
			if len(ret) <= 0 {
				return false
			}
			return ret != *s5filter
		}

		c, err := pingtunnel.NewClient(*listen, *server, *target, *timeout, *key, *icmpListen,
			*tcpmode, *tcpmode_buffersize, *tcpmode_maxwin, *tcpmode_resend_timems, *tcpmode_compress,
			*tcpmode_stat, *open_sock5, *maxconn, &filter, cryptoConfig, *sock5_user, *sock5_pass, fecConfig, kcpConfig, *connectTimeout, *maxPPS)
		if err != nil {
			loggo.Error("ERROR: %s", err.Error())
			return
		}
		loggo.Info("Client Listen %s (%s) Server %s (%s) TargetPort %s ICMP Listen %s", c.Addr(), c.IPAddr(),
			c.ServerAddr(), c.ServerIPAddr(), c.TargetAddr(), c.ICMPAddr())
		err = c.Run()
		if err != nil {
			loggo.Error("Run ERROR: %s", err.Error())
			return
		}
	} else {
		return
	}

	if *profile > 0 {
		go http.ListenAndServe("0.0.0.0:"+strconv.Itoa(*profile), nil)
	}

	for {
		time.Sleep(time.Hour)
	}
}
