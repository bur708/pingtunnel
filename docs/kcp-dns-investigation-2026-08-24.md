# KCP / real-world DNS reliability investigation — 2026-08-24

Status: **3 real bugs found, fixed, and verified. 1 issue remains open** (KCP
mode + real Android VPN traffic still intermittently fails DNS resolution
in the browser). This doc is a handoff for continuing that investigation,
written so a fresh session/tool with no prior context can pick it up.

## TL;DR for a fresh investigator

- The Pi-freezing crash, a KCP/tcpmode double-ARQ stall, and a FrameMgr
  congestion collapse are **fixed and confirmed working** (commits
  `f1d426a`, `176c3f9`, `844982d`). Don't re-diagnose these from scratch.
- **Still open**: with `-kcp` selected on the Android client, real browsing
  intermittently fails (`ERR_NAME_NOT_RESOLVED` in Chrome) even though the
  tunnel itself shows no crashes, no rate-limit drops, and fast/healthy TCP
  connects. Telegram and the app's own "test" button keep working through
  the same failures.
- A follow-up commit (`fa17e88`) fixed two real, measured problems (KCP
  head-of-line blocking across unrelated flows; unbounded per-flow session/
  goroutine overhead) and raised the rate-limit ceiling — but **did not
  resolve the user's actual symptom** in live retesting. Something else is
  still wrong, most likely in the SOCKS5-UDP-relay / DNS path or in how
  replies get wrapped for it, not in the crash/stall mechanisms already
  fixed.
- The most suspicious unexplored lead: **PING round-trips fail ~99.9% of
  the time, in every tested session today, regardless of reliability
  mode** (see "PING/PONG evidence" below) — but real TCP relay traffic
  (which never uses FEC/KCP wrapping, see below) works fine. This suggests
  the bug is specific to whatever code path FEC/KCP wrapping is still used
  for (PING, KICK, SOCKS5-UDP-relay), not a general network or transport
  problem.

## Repo / project context

- Go core: `bur708/pingtunnel` (fork of `esrrhs/pingtunnel`), this repo.
- Android app: `bur708/pingtunnel-client` (fork of
  `itismoej/pingtunnel-client`) — separate repo, not checked out here.
- The Android app bundles a `pingtunnel` binary built from *this* repo
  (cross-compiled for `android/arm64`, embedded as a "native library" —
  see "Build/deploy procedure" below).
- User's setup: Raspberry Pi runs the server (production, real internet
  access, low-stakes use case, no `-encrypt`). Phone is a Xiaomi running
  HyperOS, connects over real Wi-Fi (not same-host/loopback), using the
  Android app's full VPN mode (`PingtunnelVpnService` → `tun2socks` →
  local SOCKS5 → this project's `pingtunnel -type client -sock5 1`).

## What's already fixed (don't redo this work)

1. **`f1d426a`** — `kcp.KCP.Send` (vendored `github.com/xtaci/kcp-go`) had
   no backlog cap and `NoCongestion=1` meant nothing else throttled it
   either; a client pushing data faster than the real link drains grew the
   KCP send queue in memory without bound until the Pi OOM-killed into
   total unresponsiveness. This was the literal cause of a hard freeze/
   forced power-cycle the night before this investigation. Fixed with a
   real backlog cap + blocking-with-timeout in `KCPSession.Send`
   (`kcp_transport.go`).
2. **`176c3f9`** — tcpmode connections (`client.go`'s `AcceptTcpConn`,
   `server.go`'s `RecvTCP`) already have their own ARQ via
   `network.FrameMgr` (vendored `gohome/network`, its own window/ACK/
   resend-timer). They were *also* being wrapped in KCP when `-kcp` was
   selected, stacking two independent ARQ layers: whenever KCP's own
   retransmit took longer than FrameMgr's 400ms resend timeout (routine
   under load), FrameMgr sent a duplicate that re-entered KCP as a new
   message — a resend-amplification loop that saturated the (still
   unfixed at that point) KCP backlog almost instantly and left tcpmode
   traffic (i.e. **all real browsing/TCP traffic**) non-functional under
   `-kcp`. Fixed by passing `nil` for `kcpTransport` at every FrameMgr-
   protected send site, so tcpmode traffic is now **always plain**
   (unwrapped), regardless of the user's reliability-mode selection.
3. **`844982d`** — even with KCP out of the picture, `network.FrameMgr`
   itself (used by every tcpmode connection) has **no congestion control
   at all** — it retransmits per-connection on a fixed 400ms timer with no
   coordination across connections. Under real load, many connections'
   resend timers landed in the same instant, send rate spiked to 3000+pps
   while incoming ACKs dropped to ~0pps for seconds at a time, and the
   tunnel needed a manual restart to recover — a classic self-inflicted
   congestion collapse. Fixed with `RateLimiter` (new `ratelimit.go`): one
   shared token bucket per Client/Server instance, enforced in
   `writeICMP` (the single choke point every outgoing packet passes
   through regardless of mode), new `-max-pps` flag.

All three were live-verified: server ran over an hour under real use
(speedtest, YouTube, browsing) with zero crashes, zero rate-limit drops,
flat memory/CPU, and the user explicitly confirmed real browsing worked at
that point (**before** switching back to `-kcp` and finding the issue this
doc is about).

## What's NOT fixed / still open

**Symptom**: with `-kcp` selected, after some period of normal-looking use
(speedtest, some page loads), new page loads and YouTube start failing with
`ERR_NAME_NOT_RESOLVED` in Chrome. Telegram (already-established
connections) and the app's own connectivity "test" keep working. The
server process itself shows no crash, no rate-limit drops, no elevated
error rate, and reasonable resource use throughout.

### `fa17e88` — real fixes, but didn't close the issue

Committed as a single "exploratory" commit since neither part alone fully
explains or fixes the user's symptom, but both are independently real,
measured, verified improvements:

1. **KCP head-of-line blocking**: every non-tcpmode packet a peer sends —
   PING, KICK, and critically every independent SOCKS5-UDP-relay flow
   (i.e. every DNS lookup) — shared exactly **one** KCP session per peer
   (`sendICMP`/`recvICMP`'s destKey was only `(peer address, ICMP echo
   id)`, both constant for a given phone regardless of how many logical
   flows it has open). KCP guarantees in-order delivery *within* a
   session, so one lost/slow flow head-of-line-blocks every other flow
   multiplexed onto the same session behind it. Fixed with `kcpFlowID`
   (`kcp_transport.go`): hashes each packet's `connId` into one of a fixed
   pool of buckets, folded into a new 2-byte `flowID` field in the KCP
   wire header (MAC-covered, so it can't be tampered with to redirect
   traffic between sessions) and into the session lookup key.
2. **Per-flow session overhead**: the *first* version of the fix above
   gave every distinct `connId` its own session outright (no bucketing).
   Live-tested and found to trade one problem for another: a phone's
   background apps alone sustain on the order of **170–185 concurrent
   SOCKS5-UDP-relay flows** (mostly DNS, mostly unrelated to whatever the
   user is actively doing), and each `KCPSession` runs its own goroutine
   ticking every `Interval` ms (20ms default) until closed — unbounded
   per-flow sessions measured at ~8500 ticks/sec of pure idle-session
   bookkeeping, enough to show up as sustained CPU load (confirmed via
   `/proc/<pid>/stat` `utime`/`stime` deltas on the phone, see "Live
   diagnostics" below). Fixed by bounding the bucket pool to
   `kcpFlowBuckets = 32` and adding a 30s-idle-timeout reaper
   (`KCPTransport.reapIdle`, ticked every 10s).
3. **Rate limit ceiling**: raised `DefaultMaxPPS` 400 → 2000
   (`ratelimit.go`). 400 was sized purely as a safety net against the
   resend storm fixed in `844982d`, not as a throughput tune, and turned
   out to starve realistic concurrent DNS volume (~2pps/flow average at
   170+ concurrent flows) — plausible since KCP needs more round-trip
   packets per logical exchange (data segment + ACK) than FEC/none's
   single packet each way, so KCP flows would be first to miss the local
   SOCKS5 proxy's own reply timeout under that contention.

**Live retest result after all three sub-fixes deployed**: partial, brief
improvement (one previously-unreachable site, `ifconfig.co`, loaded once)
but subsequent new sites still failed the same way. **The core symptom
persists.**

### Investigation dead ends (ruled out, don't re-check these)

- **Android Doze / background process freeze.** Was the leading theory
  early on (a 48-second total silence window was observed in server logs
  once). Ruled out by: (a) pulling the phone's own process CPU-time deltas
  via `adb shell cat /proc/<pid>/stat` during a live "stuck" window — the
  `pingtunnel` process was actively burning CPU (`utime`/`stime` both
  climbing across repeated samples), not idle/frozen; (b) the client's own
  Go log file (see "Live diagnostics") kept writing a line every second
  with no gaps during "stuck" windows; (c) the same symptom occurs under
  conditions where Doze shouldn't apply differently by reliability mode,
  yet the user's own controlled A/B test (FEC ran clean for 30 minutes,
  KCP broke reproducibly soon after switching) pointed at something mode-
  dependent, not a general OS-level freeze.
- **General/current network quality being bad right now.** Re-checked with
  a raw `ping` flood from the Pi directly to the phone's LAN IP (bypassing
  pingtunnel entirely — see "Live diagnostics" for the exact command).
  Current baseline: ~3.5% loss at a 100pps burst, ~10ms average RTT — a
  healthy result, notably *better* than the very first (cold-radio-state)
  measurement earlier the same day (8.5% loss, RTT spiking to 477ms) that
  originally motivated building the rate limiter. The network is not
  currently degraded enough to explain near-total reply loss.
- **Android system-level Private DNS bypassing the VPN.** Checked via
  `adb shell settings get global private_dns_mode` → `off`. Not the cause.

### The strongest unexplained lead: PING/PONG loss

The client logs every PING it sends (`client.go:931`, format includes
`p.id`/`p.sequence`) and every successful PONG received (`client.go:802`,
`"pong from %s %s"`, only logged on success). Counting these across every
distinct client-process lifetime in one day's log file
(`pingtunnel_INFO_2026-08-24.log`, one file per calendar day, appended
across app restarts/reinstalls):

| Session (by client restart) | Pings sent | Pongs received |
|---|---|---|
| 1 (the user's originally-reported "FEC worked fine for 30 min" session) | 866 | **1** |
| 2 | 251 | **0** |
| 3 | 592 | **0** |
| 4 (post-`fa17e88`, `-kcp`, `-max-pps 2000`) | 123 | **1** |

**This ~99.9% reply-loss rate is present in every session today, including
the one the user considered fully working.** Meanwhile:

- The **server** reliably receives these PINGs (confirmed via
  `journalctl -u ptunnel-server | grep 'ping from'`, steady ~1/sec rate
  matching the client's own send interval) and — as far as the code shows
  — attempts a reply via the normal `sendICMP` path with no errors logged.
- **TCP relay traffic** (`AcceptTcpConn`/`RecvTCP`, always plain since
  `176c3f9`, never touches FEC/KCP wrapping) is reliably fast and healthy:
  observed real-domain connects (`update.googleapis.com:443`,
  `ipv4.ident.me:80`, Telegram's `185.60.218.54:443`/`149.154.167.41:5222`)
  completing in 12–150ms consistently, across every session tested today,
  regardless of reliability mode.

The pattern (plain/FrameMgr-protected traffic: healthy; FEC/KCP-*wrapped*
traffic: ~99.9% reply loss, in every mode tested) is the strongest signal
found so far that the bug is specific to the FEC/KCP wrapping path itself
— not a general transport, network, or OS problem. **This was not fully
chased down before time ran out on this session** — see "Next steps"
below. Whether PING's poor ratio is the *same* bug as the DNS
`ERR_NAME_NOT_RESOLVED` symptom, or a separate long-standing bug that just
happens to correlate, is unconfirmed.

One data point that doesn't fit cleanly: a synchronized test (ask the user
to open a fresh, never-visited hostname — `example.org` — at a noted
timestamp, then immediately pull the client's log) found **no trace of
that hostname anywhere in the log**, despite other concurrent DNS/TCP
traffic being clearly visible in the same window. Either the test didn't
actually route through the tunnel as expected (timing slip, or the app had
just been restarted seconds before — worth re ensuring the VPN is fully
up before testing), or something upstream of pingtunnel (Chrome's own DNS
cache/backoff for a previously-failed hostname?) suppressed the query.
Not resolved — re-run this test with tighter synchronization.

## Architecture notes a fresh investigator needs

- `pingtunnel.go`'s `sendICMP` / `recvICMP` / `writeICMP` are the shared
  choke points for *every* outgoing/incoming ICMP packet on both client
  and server, regardless of tcpmode vs relay, regardless of none/FEC/KCP.
- `client.go`'s `AcceptTcpConn` (tcpmode) and `server.go`'s `RecvTCP` pass
  `nil` for `kcpTransport` unconditionally (see `176c3f9`) — this path is
  **always plain**, FrameMgr is its only reliability layer, and it works.
- The **only** place FEC/KCP wrapping still applies is non-tcpmode
  traffic: `client.go`'s `Accept()` (raw UDP relay, believed lightly
  used in this VPN setup), `AcceptSock5UDPConn`/`recvSock5UDP` (SOCKS5
  UDP-associate relay — **this is the DNS path**, and also PING/KICK).
  `server.go`'s `Recv()` is the server-side counterpart.
- Adaptive mode (no `-fec`/`-kcp` pinned on the server) uses
  `PeerModeTracker` (`peer_mode.go`) / `Server.peerTransport` to decide,
  **per peer** (keyed only by `(source address, ICMP echo id)` — i.e. one
  entry per phone, not per flow), which wrapper to use for a reply, based
  on whichever mode was last *observed* from that peer's incoming traffic.
  Since `recvICMP` (which calls `Observe`) and `processPacket` (which
  calls `peerTransport` to decide a reply's wrapper) run in different
  goroutines connected by a buffered channel, and a single phone's traffic
  interleaves many concurrent flows all sharing the same peer key, **this
  was not audited for races or staleness in today's investigation** — a
  real candidate for where a reply could get sent in an unexpected wire
  format. Worth checking next.
- `kcpFlowID(connId string) uint16` (`kcp_transport.go`) hashes into
  `[1, kcpFlowBuckets-1]`, with `connId == ""` (PING, KICK before a real
  connection id exists) reserved to bucket `0`. Wire format for a
  KCP-framed packet: `[0]=version byte, [1:9]=HMAC-SHA256 truncated to 8
  bytes (covers flowID+segment), [9:11]=flowID big-endian uint16,
  [11:]=raw kcp.KCP segment bytes`.
- `RateLimiter` (`ratelimit.go`) is **one shared token bucket per
  Client/Server instance** — not per-flow, not per-mode. Applies uniformly
  to every `writeICMP` call. Default 2000pps as of `fa17e88`; tunable via
  `-max-pps`.
- **Android uses an unprivileged "ping socket"**, not a true raw socket
  (`icmp_listen_android.go`: tries `icmp.ListenPacket("udp4", addr)`
  first — apps can't get `CAP_NET_RAW` — falls back to `ip4:icmp` only if
  that fails). This sets a package-level flag (`setICMPDatagram`/
  `icmpDatagram`) that's checked in `client.go`'s `processPacket` to
  **bypass** a `packet.echoId != p.id` validation check. **This is a real,
  unexplored lead**: Linux's unprivileged ICMP ping-socket mechanism is
  documented to let the kernel rewrite/manage the ICMP ID field to
  demultiplex replies back to the right socket by local port, rather than
  trusting whatever ID value the application set — if that interacts with
  pingtunnel's assumption that its own chosen `p.id` round-trips
  unchanged end-to-end, replies could be getting silently mismatched or
  dropped at the kernel level on the Android side specifically. This was
  **not investigated today** beyond noticing the existence of the
  bypass-flag workaround (which itself suggests a previous developer hit
  a related issue and worked around part of it, not necessarily all of
  it).

## Live diagnostics used today (commands, for repeatability)

**Server-side log tail** (systemd-managed, see "Deploy procedure"):
```bash
sudo journalctl -u ptunnel-server -f --no-pager
sudo journalctl -u ptunnel-server --no-pager --since "5 min ago" | grep "ping from"
```

**Phone process liveness check** (proves the client process isn't frozen,
just possibly stuck/looping):
```bash
adb shell ps -A | grep -i "pingtunnel\|tun2socks"
adb shell cat /proc/<pid>/stat | awk '{print "utime="$14" stime="$15}'
# run twice a few seconds apart; both climbing = actively running, not frozen
adb shell cat /proc/<pid>/cgroup   # freezer/schedtune/cpuset group membership
```

**The client's own Go log file — by far the most useful diagnostic,
much more detailed than Android logcat (which showed essentially
nothing under the `Pingtunnel`/`PingtunnelVPN` tags once real traffic was
flowing)**. The app runs the bundled `pingtunnel` binary without
`-nolog`/`-loglevel` flags (see `PingtunnelArgs.kt` in the `pingtunnel-client`
repo), so it defaults to `-loglevel info` and **does** write real log files
to its own private app storage:
```bash
adb shell run-as com.pingtunnel.client.app ls -la files/
# pingtunnel_INFO_<date>.log, pingtunnel_WARN_<date>.log, pingtunnel.stderr

adb exec-out run-as com.pingtunnel.client.app cat files/pingtunnel_INFO_<date>.log > /tmp/pt_client.log
```
Note this file is **cumulative across every app restart within one
calendar day** — use `grep -n "main.main. start"` to find where each
distinct client process's log begins, and slice accordingly (see the
PING/PONG table above for how session boundaries were found).

**Raw network baseline** (bypasses pingtunnel entirely, isolates "is the
real network bad right now" from "is pingtunnel's own logic dropping
things"):
```bash
sudo ping -c 100 -i 0.1 -w 20 <phone-lan-ip>      # normal rate baseline
sudo ping -c 500 -i 0.01 -w 15 <phone-lan-ip>     # ~100pps burst
```

**Android system checks**:
```bash
adb shell settings get global private_dns_mode          # should be "off"
```

## Deploy / build procedure (for continuity)

**Server** (on the Pi, this repo):
```bash
go build -o ptunnel ./cmd
sudo systemctl restart ptunnel-server   # transient systemd unit, see below
```
First-time / after a reboot, the unit is created with:
```bash
sudo systemd-run --unit=ptunnel-server -p MemoryMax=400M -p OOMPolicy=kill \
  --working-directory=/home/bur/pingtunnel -- \
  /home/bur/pingtunnel/ptunnel -type server -icmp_l 0.0.0.0 -key 654321 -nolog 1 -loglevel debug
```
(`MemoryMax`/`OOMPolicy` are a safety net so a regression OOM-kills just
the process, not the whole Pi — added after the crash that started this
whole investigation. No `-kcp`/`-fec` flag: runs adaptively.)

**Android client** — this machine (the Pi) has no Flutter/Android SDK and
Aspire (the build machine, reachable via `ssh aspire`) has no Go
toolchain, so cross-compiling needs both:
```bash
# One-time on Aspire: fetch a throwaway Go toolchain (no sudo needed)
mkdir -p ~/go-toolchain && cd ~/go-toolchain
curl -fsSL -o go.tar.gz https://go.dev/dl/go1.25.0.linux-amd64.tar.gz
tar -xzf go.tar.gz && rm go.tar.gz

# Sync this repo's source to Aspire, then cross-compile with its NDK
rsync -az --delete --exclude='.git' --exclude='*.log' /home/bur/pingtunnel/ aspire:/tmp/pingtunnel-src/
ssh aspire '
  export PATH=~/go-toolchain/go/bin:$PATH
  NDK=~/android-sdk/ndk/27.0.12077973
  CC="$NDK/toolchains/llvm/prebuilt/linux-x86_64/bin/aarch64-linux-android21-clang"
  CXX="$NDK/toolchains/llvm/prebuilt/linux-x86_64/bin/aarch64-linux-android21-clang++"
  cd /tmp/pingtunnel-src/cmd
  CGO_ENABLED=1 GOOS=android GOARCH=arm64 CC="$CC" CXX="$CXX" go build -ldflags="-s -w" -o pingtunnel .
'

# Drop the binary into the Android app repo, rebuild, install
ssh aspire '
  cp /tmp/pingtunnel-src/cmd/pingtunnel ~/pingtunnel-client/templates/assets/binaries/pingtunnel/android-arm64/pingtunnel
  chmod 755 ~/pingtunnel-client/templates/assets/binaries/pingtunnel/android-arm64/pingtunnel
  export PATH=$HOME/flutter/bin:$HOME/android-sdk/cmdline-tools/latest/bin:$HOME/android-sdk/platform-tools:$HOME/.local/pyshim:$PATH
  cd ~/pingtunnel-client && bash scripts/bootstrap_flutter.sh
  cd app && flutter build apk --debug --target-platform android-arm64 --build-number=<N>
'
# <N> must be higher than whatever's already installed (111-115 used today)

# Install (phone connected via USB directly, or wireless adb via Aspire)
adb install -r <path-to-app-debug.apk>
adb shell am force-stop com.pingtunnel.client.app
```

**Pushing commits to GitHub** — the Pi has no GitHub credentials, push via
Aspire:
```bash
ssh aspire "rm -rf /tmp/pingtunnel-push && mkdir -p /tmp/pingtunnel-push"
rsync -az -e ssh /home/bur/pingtunnel/.git aspire:/tmp/pingtunnel-push/
ssh aspire "cd /tmp/pingtunnel-push && git remote set-url origin git@github.com:bur708/pingtunnel.git && git push origin master"
ssh aspire "rm -rf /tmp/pingtunnel-push"
```

## Suggested next steps, roughly in order of expected signal-to-effort

1. **Get a `-loglevel debug` capture from the Android client.** Currently
   `PingtunnelArgs.kt` (in the `pingtunnel-client` repo) doesn't pass
   `-loglevel`/`-nolog`, so the bundled binary defaults to `info` and the
   client-side per-packet `processDataPacket`-equivalent detail (visible
   server-side today) is invisible. Adding `-loglevel debug` (temporarily,
   for diagnosis) would directly show whether DNS response payloads ever
   arrive and get decoded on the client, independent of the PING/PONG
   proxy signal.
2. **Audit `PeerModeTracker`/`peerTransport` for cross-flow interference.**
   One tracker entry per `(peer address, echoId)` shared by every
   concurrent flow from one phone; confirm whether a reply for one flow
   can get sent in an unexpected wire format because another concurrent
   flow's traffic changed the tracked mode between `Observe()` (in
   `recvICMP`) and the reply's `peerTransport()` call (in `processPacket`,
   a different goroutine, connected by a buffered channel).
3. **Investigate the Android ping-socket ICMP-ID question directly.**
   Check whether the ID field pingtunnel sets survives unchanged through
   Android's kernel `udp4`/`IPPROTO_ICMP` ping-socket path, e.g. via
   `tcpdump` on the Pi's side observing actual echoId values on packets
   from the phone, compared to what the client's own log claims to have
   sent.
4. **Re-run the synchronized single-hostname test** with tighter timing —
   confirm the VPN is fully up and idle-settled before the test, use a
   hostname that's not already cached/failed in Chrome, and check whether
   it reaches pingtunnel's own code at all.
5. **Consider whether PING/PONG's poor ratio is a separate, longstanding,
   lower-priority bug** worth fixing on its own (it only gates the app's
   own RTT display, not real functionality) versus a red herring not
   worth chasing further if (1)-(3) point somewhere else entirely.
6. **Consider exempting SOCKS5-UDP-relay traffic from KCP wrapping
   entirely**, mirroring the `176c3f9` tcpmode exemption — i.e. route
   relay traffic through FEC-if-configured-else-plain, never KCP,
   regardless of the user's `-kcp` selection. FEC's redundancy tolerated
   whatever underlying reply loss exists noticeably better than KCP's
   single-shot-then-ACK-retry model in every test today. This would make
   `-kcp` functionally identical to `-fec`/none for the traffic that
   matters most in a real VPN workload — a real product tradeoff to weigh,
   not a pure code fix, but the fastest path to "it just works" if (1)-(4)
   don't turn up a cleaner root cause first.
