# filter.c — XDP Anti-DDoS Firewall

An eBPF/XDP program that filters traffic at the NIC driver level, before it
reaches the kernel network stack. It protects game servers (RakNet titles,
Source-engine/Steam games, Minecraft, TCP MMORPGs like Ragnarok Online and
Ran Online, and more), voice servers (TeamSpeak 3), DNS, OpenVPN and
WireGuard with per-IP adaptive rate limiting, auto-blackholing, a
spoof-resistant UDP challenge/response check, and optional UDP reflection/
amplification defense (DNS/NTP/memcached/SSDP/chargen/etc.).

One binary = one server. You pick which games/services this specific box
runs at **compile time**, then attach the resulting program to its interface.
`monitor.py` (see [Monitoring](#monitoring)) gives you a live dashboard or a
Prometheus export of what it's doing.

## Requirements

- Linux kernel 4.18+ (Debian 12 "bookworm" and Debian 13 "trixie" both fine —
  nothing here needs BTF/CO-RE or a specific `vmlinux.h`)
- `clang`/LLVM with BPF target support
- `libbpf` headers (`bpf/bpf_helpers.h`, `bpf/bpf_endian.h`)
- `bpftool` (for loading, inspecting maps, detaching)
- A NIC/driver that supports native XDP for best performance (falls back to
  generic/SKB-mode XDP automatically if not — still works, just slower)

## 1. Choose what this server runs

Open `filter.c` and uncomment the `#define` lines for exactly what this box
hosts, or pass them on the command line instead (recommended — keeps the
source untouched and makes the build reproducible):

| Flag | Covers |
|---|---|
| `GAME_RUST` | Rust (RakNet, UDP 28015) |
| `GAME_FIVEM` | FiveM / RedM (UDP+TCP 30000-32000) |
| `GAME_MINECRAFT` | Bedrock (UDP 19132) + Java/GS4 query (UDP 25565-25575) |
| `GAME_TS3` | TeamSpeak 3 (UDP 9000-10500) |
| `GAME_ARK` | ARK: Survival Evolved (high/dynamic query ports) |
| `GAME_SAMP` | San Andreas Multiplayer (UDP 7777) |
| `GAME_SQUAD` | Squad (UDP 7787, 21114, 27165, 7000-8999) |
| `GAME_MORDHAU` | Mordhau (UDP 7000-8999, 15000, 27015) |
| `GAME_HLL` | Hell Let Loose (UDP 8778, 27015, 7000-8999) |
| `GAME_UNTURNED` | Unturned (RakNet, UDP 27015-27030) |
| `GAME_ALTV` | AltV (UDP 7788, 7000-8999) |
| `GAME_RAN` | Ran Online (TCP, proprietary protocol — no public per-packet signature exists) — enables a TCP exploit-payload blocklist instead of port/challenge gating. One informal source lists port 3001, unconfirmed, not wired in since it wouldn't change TCP behavior anyway (see `GAME_RAGNAROK` note) |
| `GAME_RAGNAROK` | Ragnarok Online (rAthena defaults: TCP 6900 login / 6121 char / 5121 map). Proprietary binary protocol, no public magic bytes to check. **Changes no runtime behavior** — TCP protection is already port-agnostic; this flag exists purely to document the deployment and satisfy the build guard |
| `GAME_SOURCE_ENGINE` | Steam A2S query (verified `0xFFFFFFFF` prefix), UDP 27000-27500 — covers **any** Source-engine/Steam game: CS:GO, CS2, TF2, GMod, L4D/L4D2, Insurgency, etc. Their game port, SourceTV, and matchmaking ports all fall in this range; their TCP ports (RCON, etc.) need no separate flag since TCP protection is already universal |
| `GAME_LEGACY_MISC_PORTS` | Ports 2896/2300/3659/4970-4980/22000-22126 carried over from an older config — exact games unconfirmed, enable only if you know this box needs them |
| `GAME_WARZ` | RakNet-based, same signature as `GAME_RUST`. **Port unverified** — defaults to `WARZ_PORT_MIN`/`WARZ_PORT_MAX` (33000-34000) from one unofficial support page for "The War Z"/*Infestation: Survivor Stories*; override with `-DWARZ_PORT_MIN=x -DWARZ_PORT_MAX=y` if you know the real port |
| `GAME_TALERUNNER` | Payload signature decoded from the original rule (`04 FF 3E ??`), but the game and its port were never confirmed anywhere public. **Requires** `-DTALERUNNER_PORT=<port>` — compile fails without it |
| `ENABLE_DNS` | This box answers DNS queries itself |
| `ENABLE_OPENVPN` | OpenVPN (UDP 1194) |
| `ENABLE_WIREGUARD` | WireGuard (UDP 51820) |
| `ENABLE_GRE` | This box terminates a GRE tunnel (e.g. PPTP) — exempts GRE from the other-protocol rate limiter below, scoped to the real tunnel peer via `GRE_ALLOWED_SRC`/`GRE_ALLOWED_DST` (see below). Leave undefined to have GRE rate-limited like any other non-UDP/TCP/ICMP protocol |
| `ENABLE_AMP_PROTECTION` | UDP reflection/amplification defense — DNS, NTP, memcached, SSDP, chargen, CLDAP, SNMP, portmap |

Anything not defined compiles out completely — no extra branches, no extra
verifier work, zero runtime cost.

You must define at least one flag; compiling with none of them fails with a
clear `#error` instead of silently producing a program that only does the
generic TCP/ICMP/fragment protection and passes all UDP straight through.

## 2. Build

```bash
clang -target bpf -O2 -DGAME_RUST -DGAME_TS3 -DENABLE_WIREGUARD \
  -c filter.c -o filter.o
```

Swap the `-D` flags for whatever this server actually runs. Example for a
Minecraft box that also runs a WireGuard admin tunnel:

```bash
clang -target bpf -O2 -DGAME_MINECRAFT -DENABLE_WIREGUARD -c filter.c -o filter.o
```

Example for a CS2 box with amplification defense turned on:

```bash
clang -target bpf -O2 -DGAME_SOURCE_ENGINE -DENABLE_AMP_PROTECTION -c filter.c -o filter.o
```

Example for a Ragnarok Online (rAthena) box — this flag doesn't add any
signature checks (see the table above), it just documents the deployment and
satisfies the build guard:

```bash
clang -target bpf -O2 -DGAME_RAGNAROK -c filter.c -o filter.o
```

## 3. Attach to the interface

```bash
sudo ip link set dev <iface> xdp obj filter.o sec xdp
```

Verify it attached:

```bash
ip link show dev <iface>
# look for "prog/xdp id <N>" in the output
```

If the NIC driver doesn't support native XDP, force generic mode to confirm
the program itself loads and works before troubleshooting driver support:

```bash
sudo ip link set dev <iface> xdpgeneric obj filter.o sec xdp
```

## 4. Detach / replace

```bash
sudo ip link set dev <iface> xdp off
```

Re-run the attach command after every rebuild — there's no hot-reload.

## Runtime behavior (always on, regardless of flags)

- Drops IP fragments and the reserved/"evil" bit — none of the supported
  protocols fragment legitimately.
- Drops any packet whose source address is bogon/special-use space (RFC1918
  private ranges, loopback, link-local, CGNAT, documentation/benchmarking
  ranges, multicast, reserved space) — no real internet host sends from
  these, so seeing one means the source is spoofed or leaked from a
  misconfigured network. Applies to every protocol. (`192.88.99.0/24`, the
  6to4 relay anycast block, is deliberately excluded — it's legitimately
  globally routed.)
- Drops UDP packets whose first 24 payload bytes are all printable ASCII —
  the signature shape of chargen reflection floods and generic junk-padded
  UDP floods; no supported protocol here opens with plain text.
- Drops invalid TCP flag combinations (null/Xmas/nmap-style scans).
- Per-IP adaptive rate limiting with auto-blackholing (30s) once an IP
  exceeds its packet budget for the current defense mode.
- SYN-flood protection across **all** TCP ports, weighted by a rough
  OS-shape heuristic (Windows-shaped SYNs get a generous budget since real
  players skew Windows; non-Windows or implausible SYNs cost more of the
  same budget).
- ICMP flood protection, sharing the same per-IP budget.
- Rate limiting (same shared per-IP budget) for **any other IP protocol** —
  ESP, AH, SUN-ND, IGMP, OSPF, GRE (unless `ENABLE_GRE`, see below), or an
  outright bogus protocol number. Previously these all fell through to an
  unconditional, unlimited `XDP_PASS` since only UDP/TCP/ICMP were handled
  at all.
- Reflected UDP privileged-source-port block: any UDP packet with a source
  port under 1024 (except `sport 53`, to allow real server-to-server DNS)
  gets dropped before any map lookup — a real client's ephemeral source
  port is never privileged.
- For enabled UDP games: a spoof-resistant challenge/response — the first
  packet that looks like a real protocol handshake gets a random cookie
  echoed back; only a source that actually receives and replies with it
  gets whitelisted for 180s. This defeats spoofed-source floods that static
  signature matching (e.g. iptables `-m string`) cannot.

## `ENABLE_GRE` — GRE tunnel bypass

Off by default, so GRE (protocol 47) gets the same rate-limited treatment as
any other unrecognized protocol. If this box actually terminates a GRE
tunnel (e.g. PPTP), enable it — but scope the trust to the real tunnel peer
rather than trusting all GRE, using the `IPV4()` helper macro:

```bash
clang -target bpf -O2 -DENABLE_GRE \
  -DGRE_ALLOWED_SRC='IPV4(203,0,113,5)' \
  -c filter.c -o filter.o
```

- `GRE_ALLOWED_SRC` — only GRE from this exact source IP is trusted.
- `GRE_ALLOWED_DST` — only GRE to this exact destination IP is trusted.
- Define either, or both (both must match), or neither.

A GRE packet that doesn't match the configured peer(s) is **not**
hard-blocked — it just falls through to the same rate-limited catch-all as
any other unrecognized protocol, so a spoofed-source GRE flood is still
capped even with `ENABLE_GRE` on. Defining neither `GRE_ALLOWED_SRC` nor
`GRE_ALLOWED_DST` trusts **all** GRE unconditionally — the least secure
option, only use it if you genuinely don't know the tunnel peer's IP.

## `ENABLE_AMP_PROTECTION` — reflection/amplification defense

Off by default; enable it to drop known UDP reflection/amplification
patterns, keyed by the packet's *source* port (the port a reflector replies
from), applied globally across all destination ports:

| Source port | Protocol | Rule |
|---|---|---|
| 53 | DNS | drop if payload > 750 bytes **and** the source isn't a known public resolver (real small-query replies are never this big; catches oversized-but-well-formed responses the DNS QR-bit check alone wouldn't) |
| 123 | NTP | drop if payload > 200 bytes **and** the source isn't a known public NTP server (normal client-mode reply is ~48-90 bytes; monlist/peer-list amp responses are far larger) |
| 19 | chargen | drop unconditionally |
| 111 | portmap/rpcbind | drop unconditionally |
| 161 | SNMP | drop unconditionally |
| 389 | CLDAP | drop unconditionally |
| 1900 | SSDP | drop unconditionally |
| 11211 | memcached | drop unconditionally |
| 37810 | known reflector port (carried over from original config) | drop unconditionally |

Caveat: the DNS 750-byte threshold will also drop a legitimate large EDNS0/
DNSSEC answer if this box is acting as a full recursive resolver rather than
just answering simple queries for its own game/voice services. Fine for the
intended use case here; worth knowing if you repurpose this flag elsewhere.

**Known public DNS resolvers** are exempted from the 750-byte threshold by
default — a real answer this box's own lookups get back from one of these
can legitimately be a large EDNS0/DNSSEC response:

| Provider | Addresses |
|---|---|
| Google | `8.8.8.8`, `8.8.4.4` |
| Cloudflare | `1.1.1.1`/`1.0.0.1` (standard), `1.1.1.2`/`1.0.0.2` (malware-blocking), `1.1.1.3`/`1.0.0.3` (malware + adult-content-blocking) |
| Quad9 | `9.9.9.9`/`149.112.112.112` (secured, default), `9.9.9.10`/`149.112.112.10` (unsecured/unfiltered), `9.9.9.11`/`149.112.112.11` (secured + EDNS Client Subnet) |
| AdGuard | `94.140.14.14`/`94.140.15.15` (default, ad-blocking), `94.140.14.15`/`94.140.15.16` (family protection), `94.140.14.140`/`94.140.14.141` (non-filtering) |

IPv4 only — this program doesn't process IPv6 at all, so IPv6 resolver
addresses (e.g. Cloudflare's `2606:4700:4700::1111`) don't apply here.

This only relaxes the size check for these specific, known-good source IPs;
every other source is still held to the 750-byte limit, so a spoofed
reflector can't just claim to be Google's IP to bypass it — spoofing past
this would need the attacker to actually control return routing from that
address, not just forge the header. Add more resolver IPs by editing
`is_known_public_dns()` in `filter.c` if this box also depends on another
known-good resolver (e.g. an ISP's own DNS).

**Known public NTP servers** get the same treatment for the 200-byte NTP
threshold:

| Provider | Addresses |
|---|---|
| Google Public NTP | `216.239.35.0`, `216.239.35.4`, `216.239.35.8`, `216.239.35.12` (time.google.com / time1-4.google.com) |
| Cloudflare Time Services | `162.159.200.1`, `162.159.200.123` (time.cloudflare.com) |

Add more via `is_known_public_ntp()` in `filter.c` the same way.

Note this program filters **ingress** traffic only — it never touches
outbound queries this box sends, so "allowing DNS out" to these resolvers
was never something this filter could block in the first place; only the
inbound-answer side needed the exemption above.

## Monitoring

Two ways to look at what the filter is doing: raw `bpftool` for one-off
checks, or `monitor.py` for a live dashboard / Prometheus export.

### The `stats` map directly

`BPF_MAP_TYPE_PERCPU_ARRAY`, 21 entries (constants named `ST_*` at the top
of `filter.c`) — it's per-CPU, so sum across CPUs for the total:

| Index | Name | Meaning |
|---|---|---|
| 0 | `ST_PASS` | aggregate pass (original counter, kept stable) |
| 1 | `ST_DROP` | aggregate drop |
| 2 | `ST_CHALLENGE` | UDP challenge sent (`XDP_TX`) |
| 3 | `ST_BLACKHOLE` | an IP newly *entered* blackhole (event count, not per-packet) |
| 4-5 | `ST_UDP_PASS`/`ST_UDP_DROP` | UDP totals |
| 6-7 | `ST_TCP_PASS`/`ST_TCP_DROP` | **new-connection (SYN) admissions only** — see caveat below |
| 8 | `ST_TCP_SYN` | new TCP connection attempts seen (pass + drop) |
| 9-10 | `ST_ICMP_PASS`/`ST_ICMP_DROP` | ICMP totals |
| 11-12 | `ST_OTHER_PASS`/`ST_OTHER_DROP` | GRE/ESP/AH/SUN-ND/IGMP/OSPF/etc. |
| 13-20 | `ST_FRAG_DROP`, `ST_BOGON_DROP`, `ST_GARBAGE_DROP`, `ST_AMP_DROP`, `ST_REFLECT_DROP`, `ST_BADFLAGS_DROP`, `ST_EXPLOIT_DROP`, `ST_RATELIMIT_DROP` | why a packet was dropped, breaking down the aggregate drop count by reason |

```bash
sudo bpftool map dump name stats
```

**Caveat on `ST_TCP_PASS`**: it only counts new connections (SYN packets)
allowed through. Established/data TCP packets bump nothing at all — that's
the zero-added-latency guarantee for the bulk of TCP traffic (repeatedly a
hard requirement while building this). So `ST_TCP_PASS` is "new connections
admitted," not "TCP packets passed." There's no way to count the latter
without adding a map write to every established-connection packet, which
would undo that guarantee — not done here on purpose.

**Scope of "incoming/outgoing" and "TCP state"**: this program is XDP
ingress-only — it never sees or touches outbound traffic, so there's no
"outgoing" counter to report; use `ip -s link show dev <iface>` or
vnstat/iftop for actual bandwidth in both directions. Similarly, "TCP state"
here is limited to what filter.c actually tracks (new-connection attempts
and their outcome) — the real TCP state machine (ESTABLISHED, TIME_WAIT,
etc.) lives in the kernel's connection tracking, not in this filter; use
`ss -s` / `ss -tan` for that.

### `monitor.py` — TUI and Prometheus export

A small script that reads the maps above via `bpftool` and shows them as a
live terminal dashboard or a Prometheus-scrapable HTTP endpoint. Run it ON
the box where `filter.c` is attached (needs `bpftool` and root/`CAP_BPF`).

```bash
python3 monitor.py --tui                    # live terminal dashboard
python3 monitor.py --once                   # single text snapshot
python3 monitor.py --once --json            # single JSON snapshot
python3 monitor.py --serve 0.0.0.0:9107     # Prometheus /metrics for Grafana
```

It shows: pass/drop totals and per-protocol breakdown with live rates,
the drop-reason breakdown table above, current defense mode, the list of
currently **blackholed ("bad") IPs** (from `rl_state`, sorted by packet
count, with time until unblock) and the count of currently **whitelisted
("good") IPs** (from `whitelist` — challenge-passed, still within the
180-second trust window).

Caveat: `monitor.py` was written and logic-tested against synthetic fixture
data (no Linux/eBPF environment was available to test it against real
`bpftool` output). The map-parsing assumptions — particularly the raw
struct layout of `rl_state`'s values — matched a set of constructed test
cases, but `bpftool`'s exact JSON shape has varied across versions. Run
`python3 monitor.py --debug-raw <map-name>` first on the real box and
compare against what `to_bytes()`/the struct formats in the script expect;
adjust if your `bpftool` emits something different.

## Defense mode

`defense_mode` (`BPF_MAP_TYPE_ARRAY`, 1 entry) scales the per-IP packet
budget: `0` = normal (200 pps), `1` = elevated (80 pps), `2` = critical
(30 pps). Nothing in this program writes to it — that's deliberately left
to an external controller (a small daemon reading `stats` and deciding when
attack intensity warrants tightening), since aggregating attack intensity
doesn't belong in the eBPF fast path. Set it with:

```bash
sudo bpftool map update name defense_mode key 0 0 0 0 value 1 0 0 0
```

## Known limitations

- **Not compiled or verifier-tested on this development machine** (no
  Linux/eBPF toolchain available here). Build and load it on the real
  Debian box with the commands above, and check `dmesg`/the verifier
  output before relying on it in production.
- `GAME_WARZ` and `GAME_TALERUNNER` are implemented (signatures decoded from
  the original iptables rules and cross-checked against public RakNet/Steam
  protocol docs for the other games — all matched byte-for-byte), but their
  **ports are not verified**. `GAME_TALERUNNER` won't compile without you
  supplying the real port; `GAME_WARZ` compiles with an unofficial
  best-guess default (33000-34000) that you should confirm or override.
- This is a single-profile-per-box design, not a multi-tenant one. If one
  box needs to front multiple customer IPs each running a different game,
  this compile-time approach doesn't fit — that needs a runtime dst-IP →
  profile map instead (deliberately not built, since the actual deployment
  here is one game server per box).
