# KCP/DNS reliability, continued: Android ICMP-ident mismatch (2026-08-27)

## Context

Picks up where `docs/kcp-dns-investigation-2026-08-24.md` left off. That
doc's confirmed root cause (Linux kernel auto-replying to a client's own
Echo Request, corrupting a brand-new KCP session's `rcv_nxt`) was fixed on
this branch by commit `5eedf7c` (client-side reflection filter) and
`ef5c8a4` (SOCKS5 UDP relay teardown race). Both fixes are real and
correctly implemented.

User's report re-testing today, on the same real deployment (phone as
KCP client, Pi as server, same LAN for convenience of testing): **in FEC
mode everything works well (speed and responsiveness); switching to KCP,
the browser opens intermittently or not at all, while Telegram and other
messengers keep working.** This is the same class of symptom as the
2026-08-24 investigation, still present after both fixes above - meaning
there was at least one more bug layered on top.

## What this session found, in the order it was found

### 1. KCP sessions that never make progress retried forever (real bug, fixed)

`kcp-go`'s own dead-link detection (`segment.xmit >= dead_link`,
`kcp.go:831`) sets an unexported `state` field that nothing in the
vendored library or this project ever reads. A session whose peer never
replies (for whatever reason) retransmits its backlog forever. Because
`kcpFlowID` buckets many unrelated flows onto one shared session (see
`kcp-fix-2026-08-24-25` history), every new flow hashed into that same
bucket kept calling `Send`, which touches `lastActivityUnixNano` - so the
pre-existing idle reaper (`kcpSessionIdleTimeout`, keyed on exactly that
timestamp) never fired on a bucket stuck this way. One permanently-wedged
bucket silently ate roughly 1/32 of all traffic through it, forever.

**Fixed** in `kcp_transport.go`: `isDeadlocked()` tracks a separate
`lastRecvUnixNano` (touched only by `Input`, never by `Send`) and closes
a session that has an outstanding send backlog but has never once heard
back from the peer for `kcpDeadlockTimeout` (10s). Wired into
`KCPTransport.reapIdle`. Two new tests:
`TestKCPTransportReapsDeadlockedSessions`,
`TestKCPTransportDoesNotReapSessionThatHasReceivedSomething`.

Live-tested: confirmed firing (142-191 reaps per ~2-minute window before
the real root cause below was found), cut a self-reflection storm
roughly in half to a third - but real DNS success stayed at ~0-1%. This
was a real, worthwhile fix (bounds a genuine resource leak / permanent
lockup), but it wasn't *the* bug: it narrowed the problem rather than
closing it, because the *replacement* session for a reaped bucket was
itself also failing its own first exchange almost every time.

### 2. SOCKS5 relay grace period (real but minor contributor)

`sock5UDPOutstandingGrace` (how long a `ClientConn` survives its control
connection closing while a reply is still in flight) was 1.5s, sized for
the ~12ms RTT of an already-synced session. Raised to 8s to rule out the
relay simply closing before a slower first exchange could complete.
Live-tested: real but marginal improvement (0/356 -> 4/563 successful
client-side DNS decodes) - a genuine secondary factor, not the dominant
cause.

### 3. THE root cause: Android's ping-socket silently reassigns the ICMP ident

**This is the actual bug**, and it's a very old one - present since this
project first got a phone-side deployment, not something introduced this
session.

`icmp_listen_android.go` (Android-only, `//go:build android`) opens the
tunnel's ICMP socket like this:

```go
func listenICMP(addr string) (*icmp.PacketConn, error) {
	// Try unprivileged ICMP socket on Android.
	if conn, err := icmp.ListenPacket("udp4", addr); err == nil {
		setICMPDatagram(true)
		return conn, nil
	}
	setICMPDatagram(false)
	// Fallback to raw ICMP (will require CAP_NET_RAW).
	return icmp.ListenPacket("ip4:icmp", addr)
}
```

Unprivileged Android apps can't open real raw sockets (`SOCK_RAW` needs
`CAP_NET_RAW`), so this always falls into the `"udp4"` branch: Linux's
unprivileged "ping socket" facility (`SOCK_DGRAM` + `IPPROTO_ICMP`). The
kernel's ping-socket handler **overwrites the ICMP Echo Identifier of
every outgoing packet with that socket's own bound local port**,
completely ignoring whatever value the application puts in the packet it
constructs. This project's own `client.go` already half-knew this -
`processPacket`'s `!icmpDatagram && packet.echoId != p.id` check has
always skipped echoId validation specifically on Android - but that
awareness never propagated to the KCP layer, which kept using the
client's own randomized `p.id` (chosen once via `rand.Intn`) for both
directions of every `destKey`/`sessionKey` it computed.

Since the kernel silently substitutes a *different* id on the wire, every
reply the server ever sent came back to the client tagged with the
kernel's real ident - directly confirmed live, three separate test runs,
via a temporary `DIAG NEWSESSION`/`DIAG CLIENTID` diagnostic: the app's
own randomized id (`29022`, `16994`, `1748` across three runs) never once
appeared in a self-reflection drop or a first-received reply, while a
small, *consistent* id per run (`1640`, `1639`/`1638`, `1641`) reliably
carried every real, successful exchange. `DIAG PEERTRANSPORT` on the
server side confirmed the same thing from the other end: the server
never once created a reactive KCP session keyed on the client's
believed-real id, only on the kernel-assigned one.

Net effect: the client's own session-routing table was keyed on an id
that was *never actually on the wire*. Every reply matched a *different*
key than the one the request was filed under, so `recvICMP` treated
essentially every genuine reply as an unsolicited push and created a
brand-new "reactive" session for it - which is also why per-flow
sessions kept looking freshly wedged (see #1) instead of ever completing.
The rare (0-4 per few hundred) successes were luck: a session's very
first segment (`sn=0` both ways) can accidentally line up even across
two otherwise-unrelated session objects.

**Fixed** in `client.go`'s `Run()`: right after `listenICMP` succeeds, if
`icmpDatagram` is true, read the actual bound port back via
`conn.LocalAddr().(*net.UDPAddr).Port` and overwrite `p.id` with it,
*before* anything sends a packet or computes a session key. This makes
the app's own belief about its identity match what the kernel actually
puts on the wire, for every consumer (`kcpFlowID`'s destKey math,
`processPacket`'s now-redundant-but-harmless echoId check, PING/PONG,
everything).

### Live verification (build 125)

Same real deployment, immediately after the fix:

| | before (build 124, fixes #1+#2 only) | after (build 125, + ICMP-ident fix) |
|---|---|---|
| New sessions created | split across a "phantom" id (219, e.g. `29022`) and a "real" id (13, e.g. `1640`) | **one** consistent id (`1641`), 50/50 |
| Sessions that ever heard back (`DIAG FIRSTRECV`) | 0/219 for the phantom id | **50/50 (100%)** |
| `kcp session deadlocked` reaps | 167-191 per window | **0** |
| Client-side successful `dns_response` decodes | 0-4 out of 356-726 (~0-1%) | **100 out of 141 (~71%, server-confirmed 100/100 balanced)** |
| User's real-world browsing (KCP mode) | broken, matching the original complaint | **confirmed working by the user** |

User confirmed: "да, всё открывается нормально" (browsing now works
normally in KCP mode).

## What's still open / worth watching

- Even after this fix, `DIAG REFLECTION` (the 2026-08-25 anti-reflection
  filter, `5eedf7c`) still logged a large number of drops in the same
  test window. That's expected and correct now - genuine kernel
  reflections of the client's own requests still happen on this network
  and still need filtering - but it hasn't been re-quantified as a
  fraction of total traffic now that sessions actually complete. Worth a
  quick sanity check next time (drop rate should track roughly with
  request volume, not dwarf it the way it did before this fix).
- A handful of `sendICMP Marshal error ... sendto: no buffer space
  available` appeared server-side under load in the last test. Not
  investigated this session - likely just needs a larger socket send
  buffer or a lower burst rate; low priority since it didn't visibly
  affect the ~71% success measurement.
- The temporary diagnostics added this session (`DIAG CLIENTID`,
  `DIAG NEWSESSION`, `DIAG FIRSTRECV` in `kcp_transport.go`/`client.go`,
  `DIAG PEERTRANSPORT` in `server.go`, `DIAG REFLECTION` in
  `pingtunnel.go` from the prior session) are left in place, at
  `loggo.Info` level, matching this project's existing convention for
  the `diagnostic_trace.go`/`DIAG DNS` instrumentation from
  2026-08-24/25: cheap, low-volume once things work correctly, and
  valuable if this class of bug ever needs re-diagnosing. Remove them
  once nobody expects to need this specific trail again - not a strict
  requirement of "done."
- This bug was Android-specific and had nothing to do with FEC, KCP's
  own protocol logic, or the tunnel's wire format - it's worth
  double-checking whether the *desktop* (Linux/Windows/macOS) build of
  the client, which does get a real raw socket, was ever actually
  affected by any of this (it shouldn't have been, `icmpDatagram` should
  always be `false` there) - not verified live this session since only
  the phone was tested.
