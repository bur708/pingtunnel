# Pingtunnel

[<img src="https://img.shields.io/github/license/esrrhs/pingtunnel">](https://github.com/esrrhs/pingtunnel)
[<img src="https://img.shields.io/github/languages/top/esrrhs/pingtunnel">](https://github.com/esrrhs/pingtunnel)
[![Go Report Card](https://goreportcard.com/badge/github.com/esrrhs/pingtunnel)](https://goreportcard.com/report/github.com/esrrhs/pingtunnel)
[<img src="https://img.shields.io/github/v/release/esrrhs/pingtunnel">](https://github.com/esrrhs/pingtunnel/releases)
[<img src="https://img.shields.io/github/downloads/esrrhs/pingtunnel/total">](https://github.com/esrrhs/pingtunnel/releases)
[<img src="https://img.shields.io/docker/pulls/esrrhs/pingtunnel">](https://hub.docker.com/repository/docker/esrrhs/pingtunnel)
[<img src="https://img.shields.io/github/actions/workflow/status/esrrhs/pingtunnel/go.yml?branch=master">](https://github.com/esrrhs/pingtunnel/actions)

Pingtunnel is a tool that sends TCP/UDP traffic over ICMP.

## Note: This tool is only to be used for study and research, do not use it for illegal purposes

![image](network.jpg)

## This fork

This is a fork of [esrrhs/pingtunnel](https://github.com/esrrhs/pingtunnel) with a few additions on top of the original:

- **Encryption** (`-encrypt aes128|aes256|chacha20` + `-encrypt-key <passphrase>`) — authenticated encryption (AEAD) for the tunneled traffic, independent of the legacy numeric `-key`. Pick `chacha20` on devices without AES hardware acceleration (cheaper in software); `aes128`/`aes256` are fine on anything with AES-NI or an equivalent.
- **Reliability modes for lossy links** — `-fec`/`-fec-data`/`-fec-parity` (Reed-Solomon forward error correction: recovers from loss without retransmitting) and `-kcp` (a reliable ARQ layer instead of the default per-connection resend logic), mutually exclusive. Neither is required: the server auto-detects and matches whichever mode (or none) each connecting client is already using, per client, with no client-side configuration needed on the server's end.
- **`-kcp-congestion`** — opt into KCP's own TCP-Reno-style congestion control (slow start / additive-increase-multiplicative-decrease) instead of sending at a fixed window regardless of observed loss. Worth trying on a shared or bandwidth-constrained link.
- **`-kcp-sndwnd`/`-kcp-rcvwnd`** — tune KCP's send/receive window for high-bandwidth-delay-product links (e.g. a fast-but-high-latency satellite connection) where the default window can't keep enough data in flight.
- **`-max-pps`** — a shared token-bucket cap on total outbound ICMP packets/sec, guarding against retransmission storms turning into a self-inflicted congestion collapse under real loss.
- **`-connect-timeout`** — configurable handshake-ack timeout for new tcpmode connections (useful when many open at once over a slow/lossy link, e.g. behind a system-wide proxy client).

Everything above is opt-in and off by default; with no new flags set, the wire behavior is unchanged from upstream.

## Usage

### Install server

-   First prepare a server with a public IP, such as EC2 on AWS, assuming the domain name or public IP is www.yourserver.com
-   Download the corresponding installation package from [releases](https://github.com/esrrhs/pingtunnel/releases), such as pingtunnel_linux64.zip, then decompress and execute with **root** privileges
-   “-key” parameter is **int** type, only supports numbers between 0-2147483647

```
sudo wget (link of latest release)
sudo unzip pingtunnel_linux64.zip
sudo ./pingtunnel -type server
```

-   (Optional) Disable system default ping

```
echo 1 > /proc/sys/net/ipv4/icmp_echo_ignore_all
```

### Install the client

-   Download the corresponding installation package from [releases](https://github.com/esrrhs/pingtunnel/releases), such as pingtunnel_windows64.zip, and decompress it
-   Then run with **administrator** privileges. The commands corresponding to different forwarding functions are as follows.
-   If you see ping/pong logs, the connection is normal
-   “-key” parameter is **int** type, only supports numbers between 0-2147483647


#### Forward SOCKS5

```
pingtunnel.exe -type client -l :4455 -s www.yourserver.com -sock5 1
```

#### Forward tcp

```
pingtunnel.exe -type client -l :4455 -s www.yourserver.com -t www.yourserver.com:4455 -tcp 1
```

#### Forward udp

```
pingtunnel.exe -type client -l :4455 -s www.yourserver.com -t www.yourserver.com:4455
```

### Use Android Client

* [**pingtunnel-client**](https://github.com/bur708/pingtunnel-client) — a fork of the community Android client ([itismoej/pingtunnel-client](https://github.com/itismoej/pingtunnel-client)) updated to support this fork's encryption, FEC, and KCP reliability modes.

### Use Docker
It can also be started directly with docker, which is more convenient. It uses the same parameters as above.
-   server:
```
docker run --name pingtunnel-server -d --privileged --network host --restart=always esrrhs/pingtunnel ./pingtunnel -type server -key 123456
```
-   client:
```
docker run --name pingtunnel-client -d --restart=always -p 1080:1080 esrrhs/pingtunnel ./pingtunnel -type client -l :1080 -s www.yourserver.com -sock5 1 -key 123456
```

## Thanks for free JetBrains Open Source license

<img src="https://resources.jetbrains.com/storage/products/company/brand/logos/GoLand.png" height="200"/></a>


