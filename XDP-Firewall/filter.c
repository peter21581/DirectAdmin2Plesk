#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/udp.h>
#include <linux/tcp.h>
#include <linux/in.h>
#include <linux/icmp.h>
#include <linux/icmpv6.h>
#include <linux/in6.h>
#include <linux/pkt_cls.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

// XDP_PASS *is* the real kernel-defined verdict (from <linux/bpf.h>) — this
// is just a clearer name for the "explicitly let this through" cases below
// (runtime allowlist, trusted GRE peer, etc.), as opposed to "PASS" reading
// like a no-decision default. Compiles to the exact same value; XDP_DROP
// needs no such alias since "drop" is already unambiguous.
#define XDP_ACCEPT XDP_PASS

// Builds a dotted-quad IPv4 address into the same in-memory representation
// as ip->saddr/ip->daddr (raw network byte order), so it can be compared
// directly with == . Used by GRE_ALLOWED_SRC/GRE_ALLOWED_DST and the known-
// public-DNS-resolver allowlist below.
#define IPV4(a, b, c, d) ((__u32)(a) | ((__u32)(b) << 8) | ((__u32)(c) << 16) | ((__u32)(d) << 24))

// Builds an IPv6 address constant in the same raw-byte (wire-order)
// representation as ip6->saddr/ip6->daddr, from its 16 individual bytes
// (write it out the way the address's canonical form reads left-to-right).
// Used by the known-public-resolver allowlists below. `static const` inside
// a function does not consume BPF's tight per-function stack budget — it's
// compile-time data, not a local variable.
#define IPV6(a, b, c, d, e, f, g, h, i, j, k, l, m, n, o, p) \
  ((struct in6_addr) { \
    .s6_addr = { a, b, c, d, e, f, g, h, i, j, k, l, m, n, o, p } \
  })

// Compares two IPv6 addresses as two 64-bit words rather than a 16-byte
// loop — cheap, and correct regardless of host endianness since both sides
// are read the same way.
static inline int ipv6_eq(const struct in6_addr * a, const struct in6_addr * b) {
  const __u64 * a64 = (const __u64 * )(const void * ) a;
  const __u64 * b64 = (const __u64 * )(const void * ) b;
  return a64[0] == b64[0] && a64[1] == b64[1];
}

// ==== Compile-time service selection ====
// Define whatever this specific server actually runs, then compile and
// attach — e.g.:
//   clang -target bpf -DGAME_RUST -DGAME_TS3 -O2 -c filter.c -o filter.o
// Undefined services compile out completely: no extra branches, no extra
// verifier work, zero runtime cost for games this box doesn't host.
//
// #define GAME_RUST
// #define GAME_FIVEM
// #define GAME_MINECRAFT
// #define GAME_TS3
// #define GAME_ARK
// #define GAME_SAMP
// #define GAME_SQUAD
// #define GAME_MORDHAU
// #define GAME_HLL
// #define GAME_UNTURNED
// #define GAME_ALTV
// #define GAME_RAN               // TCP, proprietary protocol — no public per-packet
//                                 // signature exists, so protection is the exploit-payload
//                                 // blocklist below, not port/challenge gating.
// #define GAME_RAGNAROK          // TCP: 6900 (login), 6121 (char), 5121 (map) — rAthena
//                                 // defaults. Also proprietary/binary with no public
//                                 // per-packet magic bytes to check. This flag changes NO
//                                 // runtime behavior (TCP protection is already port-
//                                 // agnostic) — it exists only to document the deployment
//                                 // and satisfy the "define at least one flag" build guard.
// #define GAME_SOURCE_ENGINE     // Steam A2S query (0xFFFFFFFF prefix), UDP 27000-27500 —
//                                 // covers CS:GO/CS2, TF2, GMod, L4D/L4D2, Insurgency and
//                                 // any other Source-engine game (their game port, SourceTV,
//                                 // and matchmaking ports all fall in this range). TCP ports
//                                 // (RCON, etc.) need no separate flag — already covered by
//                                 // the always-on TCP protection below, regardless of port.
// #define GAME_LEGACY_MISC_PORTS // 2896/2300/3659/4970-4980/22000-22126 — carried over
//                                 // from the original iptables config, exact games unconfirmed
// #define GAME_WARZ    // RakNet-based, same magic as GAME_RUST. Port UNVERIFIED — one
//                       // fan support page for "The War Z"/Infestation: Survivor Stories
//                       // lists 33000-34000, used as the default below. Override with
//                       // -DWARZ_PORT_MIN=x -DWARZ_PORT_MAX=y if you know the real port.
// #define GAME_TALERUNNER // Signature decoded from the original rule (04 FF 3E ??), but
//                         // no public source confirms which game this is or what port it
//                         // uses. You MUST supply the real port: -DTALERUNNER_PORT=<port>
// #define ENABLE_DNS
// #define ENABLE_OPENVPN
// #define ENABLE_WIREGUARD
// #define ENABLE_GRE             // this box terminates a GRE tunnel (e.g. PPTP) —
//                                 // exempts GRE from the generic other-protocol rate
//                                 // limiter below. Leave undefined if you don't use GRE
//                                 // and want it rate-limited like any other DDoS vector.
//
// Scope the GRE exemption to your actual tunnel peer instead of trusting all
// GRE — use the IPV4() helper to build the value:
//   -DGRE_ALLOWED_SRC='IPV4(203,0,113,5)'   // only from this peer
//   -DGRE_ALLOWED_DST='IPV4(198,51,100,9)'  // only to this local IP
// Define either, both (both must match), or neither (trusts ALL GRE —
// least secure, only use this if you genuinely don't know the peer IP).
// #define ENABLE_IPIP             // this box terminates an IP-in-IP tunnel — same
//                                  // idea and same scoping knobs as ENABLE_GRE:
//                                  // -DIPIP_ALLOWED_SRC='IPV4(...)' / IPIP_ALLOWED_DST
// #define ENABLE_AMP_PROTECTION  // DNS/NTP/memcached/SSDP/chargen/etc. reflection defense
//
// #define ENABLE_HANDSHAKE_VERIFY // Full TCP handshake verification — rejects any
//                                  // non-SYN TCP packet whose flow never had a real
//                                  // SYN/SYN-ACK observed, catching pure ACK-floods
//                                  // that bogus_tcp_flags() alone can't see. This is a
//                                  // genuinely different kind of feature from the rest
//                                  // of this file — READ THE "ENABLE_HANDSHAKE_VERIFY"
//                                  // SECTION IN FILTER.md BEFORE ENABLING IT. In short:
//                                  // it requires a SECOND attach step (a TC egress hook,
//                                  // not just XDP — this program can't see its own
//                                  // replies otherwise), it adds a map lookup to every
//                                  // established-connection packet (no longer the
//                                  // zero-touch guarantee the rest of this file has),
//                                  // and it drops all pre-existing connections the
//                                  // moment it's attached (they have no tracked
//                                  // handshake state yet).

#if !defined(GAME_RUST) && !defined(GAME_FIVEM) && !defined(GAME_MINECRAFT) && \
  !defined(GAME_TS3) && !defined(GAME_ARK) && !defined(GAME_SAMP) && \
  !defined(GAME_SQUAD) && !defined(GAME_MORDHAU) && !defined(GAME_HLL) && \
  !defined(GAME_UNTURNED) && !defined(GAME_ALTV) && !defined(GAME_RAN) && \
  !defined(GAME_SOURCE_ENGINE) && !defined(GAME_LEGACY_MISC_PORTS) && \
  !defined(GAME_WARZ) && !defined(GAME_TALERUNNER) && !defined(GAME_RAGNAROK) && \
  !defined(ENABLE_DNS) && !defined(ENABLE_OPENVPN) && !defined(ENABLE_WIREGUARD) && \
  !defined(ENABLE_GRE) && !defined(ENABLE_IPIP) && !defined(ENABLE_AMP_PROTECTION) && \
  !defined(ENABLE_HANDSHAKE_VERIFY)
#error "Define at least one GAME_*/ENABLE_* macro before compiling (see top of file) — otherwise this program only does generic TCP/ICMP/fragment protection and passes all UDP straight through."
#endif

// Subnet-level (not just per-IP) new-connection rate limiting — catches a
// botnet spread across many IPs in one block, each individually under the
// per-IP cap in rl_state but adding up to a flood in aggregate. Always on
// (it's a direct extension of the SYN-flood protection below, not a
// separate opt-in feature area). Tune via -D if the defaults don't fit.
#ifndef SUBNET_MASK_BITS
#define SUBNET_MASK_BITS 20 // group source IPs into /20 subnets by default
#endif
#ifndef SUBNET_SYN_LIMIT
#define SUBNET_SYN_LIMIT 500 // new-connection SYNs/sec allowed from one whole subnet
#endif
#ifndef SUBNET_MASK_BITS_V6
#define SUBNET_MASK_BITS_V6 64 // /64 — the standard single-customer IPv6 delegation size;
                                // MUST be a multiple of 8 (mask_subnet_v6 is byte-aligned only)
#endif

#ifdef GAME_TALERUNNER
#ifndef TALERUNNER_PORT
#error "GAME_TALERUNNER has no public/confirmed port. Pass -DTALERUNNER_PORT=<port> at compile time."
#endif
#endif

#ifdef GAME_WARZ
#ifndef WARZ_PORT_MIN
#define WARZ_PORT_MIN 33000 // UNVERIFIED — see comment above, override if you know the real port
#endif
#ifndef WARZ_PORT_MAX
#define WARZ_PORT_MAX 34000
#endif
#endif

#define RL_WINDOW_NS 1000000000ULL // 1s per-IP rate window
#define BLACKHOLE_NS 30000000000ULL // 30s auto-blackhole once an IP exceeds its limit
#define WHITELIST_TTL_NS 180000000000ULL // 180s trust window after passing the UDP challenge
#define HANDSHAKE_TIMEOUT_NS 10000000000ULL // 10s to complete a TCP handshake once started

struct challenge {
  __u64 timestamp;
  __u32 cookie;
};

struct {
  __uint(type, BPF_MAP_TYPE_LRU_HASH);
  __type(key, __u32); // src IP (v4)
  __type(value, struct challenge);
  __uint(max_entries, 1000000);
}
challenge_sent SEC(".maps");

// IPv6 sibling of every v4 map below — can't share one map across address
// sizes, so each gets its own, same value type, same semantics, keyed by
// struct in6_addr instead of __u32.
struct {
  __uint(type, BPF_MAP_TYPE_LRU_HASH);
  __type(key, struct in6_addr);
  __type(value, struct challenge);
  __uint(max_entries, 1000000);
}
challenge_sent_v6 SEC(".maps");

// LRU_HASH (not per-CPU): a passed challenge must be visible to every core,
// otherwise a flow that lands on a different queue re-triggers the challenge.
struct {
  __uint(type, BPF_MAP_TYPE_LRU_HASH);
  __type(key, __u32);
  __type(value, __u64); // timestamp of when the challenge was passed
  __uint(max_entries, 2000000);
}
whitelist SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_LRU_HASH);
  __type(key, struct in6_addr);
  __type(value, __u64);
  __uint(max_entries, 2000000);
}
whitelist_v6 SEC(".maps");

// Per-IP adaptive rate limiting / blackhole state
struct ip_state {
  __u64 window_start;
  __u32 pkt_count;
  __u64 blackhole_until; // 0 = not blackholed
};

struct {
  __uint(type, BPF_MAP_TYPE_LRU_HASH);
  __type(key, __u32);
  __type(value, struct ip_state);
  __uint(max_entries, 2000000);
}
rl_state SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_LRU_HASH);
  __type(key, struct in6_addr);
  __type(value, struct ip_state);
  __uint(max_entries, 2000000);
}
rl_state_v6 SEC(".maps");

// Subnet-level new-connection rate state (see SUBNET_MASK_BITS above). Just
// a rolling window/count, deliberately no blackhole_until like ip_state —
// a whole /20 (v4) or /64 (v6) can be shared by thousands of real users
// behind CGNAT/a single ISP delegation, so this only throttles the current
// window rather than escalating to a lasting block the way a single
// misbehaving IP does.
struct subnet_state {
  __u64 window_start;
  __u32 pkt_count;
};

struct {
  __uint(type, BPF_MAP_TYPE_LRU_HASH);
  __type(key, __u32);
  __type(value, struct subnet_state);
  __uint(max_entries, 200000);
}
subnet_syn_state SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_LRU_HASH);
  __type(key, struct in6_addr); // pre-masked to the /64 (see mask_subnet_v6)
  __type(value, struct subnet_state);
  __uint(max_entries, 200000);
}
subnet_syn_state_v6 SEC(".maps");

// LPM (longest-prefix-match) key for the runtime allow/block lists below.
// prefixlen MUST be the first field (BPF_MAP_TYPE_LPM_TRIE requirement).
// addr is a plain IPv4 address in the same raw network-byte-order layout as
// ip->saddr — a /32 entry is just prefixlen=32 with the exact address; a
// CIDR block (including one of the many individual prefixes an ASN or
// country resolves to) is prefixlen=<mask> with the network address.
struct ip_key {
  __u32 prefixlen;
  __u32 addr;
};

// Same idea, IPv6 — prefixlen still first (LPM requirement), then the raw
// 16-byte address in its normal wire-order representation. A CIDR block
// here (again including ASN/country-resolved prefixes) is prefixlen=<mask>
// with the network address; a single IP is prefixlen=128.
struct ip6_key {
  __u32 prefixlen;
  struct in6_addr addr;
};

// Runtime allowlist — checked first, before every other check in this
// program (fragment/bogon/rate-limit/everything). Populated/depopulated at
// runtime via xdpctl.py (bpftool map update/delete), independent IP/32,
// CIDR, ASN (resolved to its announced prefixes), or country (resolved to
// its aggregate CIDR blocks) — the kernel side only ever does one LPM
// lookup; ASN/country are a userspace-side prefix expansion, not something
// XDP can look up on its own.
struct {
  __uint(type, BPF_MAP_TYPE_LPM_TRIE);
  __uint(map_flags, BPF_F_NO_PREALLOC);
  __type(key, struct ip_key);
  __type(value, __u8); // tag: 1=manual 2=asn 3=country, for `xdpctl.py list`
  __uint(max_entries, 200000);
}
runtime_allow SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_LPM_TRIE);
  __uint(map_flags, BPF_F_NO_PREALLOC);
  __type(key, struct ip6_key);
  __type(value, __u8);
  __uint(max_entries, 200000);
}
runtime_allow_v6 SEC(".maps");

// Runtime blocklist — checked second (after the allowlist, so an allow
// entry always wins over a block entry for the same address), before
// everything else. Same key/tag scheme as runtime_allow.
struct {
  __uint(type, BPF_MAP_TYPE_LPM_TRIE);
  __uint(map_flags, BPF_F_NO_PREALLOC);
  __type(key, struct ip_key);
  __type(value, __u8);
  __uint(max_entries, 1000000);
}
runtime_block SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_LPM_TRIE);
  __uint(map_flags, BPF_F_NO_PREALLOC);
  __type(key, struct ip6_key);
  __type(value, __u8);
  __uint(max_entries, 1000000);
}
runtime_block_v6 SEC(".maps");

#ifdef ENABLE_HANDSHAKE_VERIFY
// Shared between the ingress (xdp_anti_ddos) and egress (tcp_egress_track)
// programs below — this is the whole reason ENABLE_HANDSHAKE_VERIFY needs a
// second (TC egress) attach point: this program never sends a TCP SYN-ACK
// itself (the kernel's own TCP stack does, for real listening sockets), so
// there is no way to observe "did we really reply to this SYN" from an
// ingress-only hook.
//
// Framed from the external peer's point of view regardless of who
// initiated: peer_ip/peer_port always belong to the other side, local_port
// always belongs to this box — so the exact same key is computed the same
// way by both the ingress and egress programs for a given flow (ingress
// reads it from saddr/source/dest, egress reads the same fields from
// daddr/dest/source).
struct tcp_flow_key {
  __u32 peer_ip;
  __u16 peer_port;
  __u16 local_port;
};

// established=0 means "a handshake packet was sent, waiting for the peer's
// next expected packet" (server side: waiting for the client's final ACK;
// client side: waiting for the server's SYN-ACK) — not yet trusted.
// established=1 means a real handshake actually completed.
struct tcp_flow_state {
  __u8 established;
  __u64 ts; // last transition, used to time out a stuck pending handshake
};

struct {
  __uint(type, BPF_MAP_TYPE_LRU_HASH);
  __type(key, struct tcp_flow_key);
  __type(value, struct tcp_flow_state);
  __uint(max_entries, 2000000);
}
tcp_handshake SEC(".maps");
#endif

// Defense mode: 0=normal 1=elevated 2=critical.
// Written by an external controller (userspace daemon reading `stats`,
// e.g. a Prometheus exporter) based on aggregate attack intensity.
struct {
  __uint(type, BPF_MAP_TYPE_ARRAY);
  __type(key, __u32);
  __type(value, __u32);
  __uint(max_entries, 1);
}
defense_mode SEC(".maps");

// Stats indices, for monitoring/dashboards (see monitor.py). 0-3 are the
// original aggregate counters, kept stable; 4+ add protocol- and reason-level
// breakdown. NOTE: established TCP traffic (non-SYN packets that aren't
// otherwise dropped) deliberately bumps NOTHING here — that's the zero-
// added-latency guarantee for the bulk of TCP traffic, so ST_TCP_PASS only
// reflects new-connection (SYN) admissions, not total TCP volume.
#define ST_PASS 0 // aggregate pass
#define ST_DROP 1 // aggregate drop
#define ST_CHALLENGE 2 // UDP challenge sent (XDP_TX)
#define ST_BLACKHOLE 3 // IP newly entered blackhole (event, not per-packet)
#define ST_UDP_PASS 4
#define ST_UDP_DROP 5
#define ST_TCP_PASS 6 // SYN admissions only — see note above
#define ST_TCP_DROP 7
#define ST_TCP_SYN 8 // new-connection attempts seen (pass + drop)
#define ST_ICMP_PASS 9
#define ST_ICMP_DROP 10
#define ST_OTHER_PASS 11 // GRE/ESP/AH/SUN-ND/IGMP/OSPF/etc.
#define ST_OTHER_DROP 12
#define ST_FRAG_DROP 13 // IP fragment / evil-bit
#define ST_BOGON_DROP 14 // bogon source address
#define ST_GARBAGE_DROP 15 // chargen-style ASCII garbage flood
#define ST_AMP_DROP 16 // ENABLE_AMP_PROTECTION reflection/amplification
#define ST_REFLECT_DROP 17 // reflected privileged UDP source port
#define ST_BADFLAGS_DROP 18 // invalid TCP flag combination
#define ST_EXPLOIT_DROP 19 // GAME_RAN known-bad TCP payload
#define ST_RATELIMIT_DROP 20 // adaptive per-IP pps limit exceeded
#define ST_RUNTIME_ALLOW 21 // matched runtime_allow (IP/CIDR/ASN/country)
#define ST_RUNTIME_BLOCK 22 // matched runtime_block (IP/CIDR/ASN/country)
#define ST_BADSYN_LEN_DROP 23 // SYN packet size doesn't match any real OS's handshake shape
#define ST_SUBNET_DROP 24 // subnet-level (not just per-IP) new-connection rate exceeded
#define ST_BADPAYLOAD_DROP 25 // known-bad UDP payload signature (flood-tool fingerprints)
#define ST_MALFORMED_DROP 26 // protocol header claims an impossible size (e.g. UDP len < 8)
#define ST_LEAK_DROP 27 // blocked a data-leak-prone request (e.g. FiveM /players.json)
#define ST_UNVERIFIED_DROP 28 // rejected: source hasn't passed a required prior verification step
#define ST_IPV6_PASS 29 // aggregate IPv6 pass (family-level visibility; protocol/reason
#define ST_IPV6_DROP 30 // breakdown above is shared across v4 and v6, not split further)
#define ST_COUNT 31

struct {
  __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
  __type(key, __u32);
  __type(value, __u64);
  __uint(max_entries, ST_COUNT);
}
stats SEC(".maps");

static __u32 pps_limits[3] = {
  200,
  80,
  30
}; // per-IP packets/sec: normal, elevated, critical

// TeamSpeak 3 voice servers (Voxility rule: UDP 9000-10500)
#define TS3_PORT_MIN 9000
#define TS3_PORT_MAX 10500

// dport is expected in host byte order (already converted by the caller)
static inline int is_legit_port(__u16 dport) {
#ifdef ENABLE_DNS
  if (dport == 53) return 1;
#endif
#ifdef ENABLE_OPENVPN
  if (dport == 1194) return 1;
#endif
#ifdef ENABLE_WIREGUARD
  if (dport == 51820) return 1;
#endif
#ifdef GAME_LEGACY_MISC_PORTS
  if (dport == 2896 || dport == 2300 || dport == 3659) return 1;
  if (dport >= 4970 && dport <= 4980) return 1;
  if (dport >= 22000 && dport <= 22126) return 1;
#endif
#ifdef GAME_RUST
  if (dport == 28015) return 1;
#endif
#if defined(GAME_SAMP) || defined(GAME_MORDHAU) || defined(GAME_SQUAD) || \
  defined(GAME_HLL) || defined(GAME_ALTV)
  if (dport >= 7000 && dport <= 8999) return 1; // covers 7777/7787/7788/8778 too
#endif
#ifdef GAME_MORDHAU
  if (dport == 15000 || dport == 27015) return 1; // checked in payload_looks_legit but never gated here
#endif
#ifdef GAME_SQUAD
  if (dport == 21114 || dport == 27165) return 1; // ditto
#endif
#ifdef GAME_HLL
  if (dport == 27015) return 1; // ditto
#endif
#ifdef GAME_TS3
  if (dport >= TS3_PORT_MIN && dport <= TS3_PORT_MAX) return 1;
#endif
#ifdef GAME_SOURCE_ENGINE
  if (dport >= 27000 && dport <= 27500) return 1;
#endif
#ifdef GAME_FIVEM
  if (dport >= 30000 && dport <= 32000) return 1;
#endif
#ifdef GAME_MINECRAFT
  if (dport == 19132) return 1; // Bedrock
  if (dport >= 25565 && dport <= 25575) return 1; // Java (+ GS4 query)
  if (dport >= 19000 && dport <= 20000) return 1; // extra backend range (e.g. BungeeCord/Velocity)
#endif
#ifdef GAME_ARK
  if (dport >= 19132 && dport <= 65535) return 1; // ARK query ports are high/dynamic
#endif
#ifdef GAME_UNTURNED
  if (dport >= 27015 && dport <= 27030) return 1;
#endif
#ifdef GAME_WARZ
  if (dport >= WARZ_PORT_MIN && dport <= WARZ_PORT_MAX) return 1;
#endif
#ifdef GAME_TALERUNNER
  if (dport == TALERUNNER_PORT) return 1;
#endif
  return 0;
}

// Generates a random cookie (uses src port + time)
static inline __u32 gen_cookie(__u16 src_port, __u64 ts) {
  return bpf_get_prandom_u32() ^ src_port ^ (ts & 0xffffffff);
}

static inline void bump_stat(__u32 idx) {
  __u64 * v = bpf_map_lookup_elem( & stats, & idx);
  if (v)( * v)++;
}

// Bogon/special-use source addresses: ranges that should never appear as a
// SOURCE address arriving from the public internet (RFC1918 private space,
// loopback, link-local, CGNAT, documentation/benchmarking ranges, multicast,
// and reserved space). A real internet host never sends from these — seeing
// one here means the source is spoofed or the packet leaked from a
// misconfigured network. Always on, no flag, no map access.
//
// Deliberately NOT included: 192.88.99.0/24 (6to4 relay anycast, RFC 3068)
// — that block is legitimately globally routed, unlike the others here.
static inline int is_bogon_source(__u32 saddr) {
  __u8 b0 = saddr & 0xff;
  __u8 b1 = (saddr >> 8) & 0xff;
  __u8 b2 = (saddr >> 16) & 0xff;

  if (b0 == 0) return 1; // 0.0.0.0/8
  if (b0 == 10) return 1; // 10.0.0.0/8
  if (b0 == 100 && b1 >= 64 && b1 <= 127) return 1; // 100.64.0.0/10 (CGNAT)
  if (b0 == 127) return 1; // 127.0.0.0/8 (loopback)
  if (b0 == 169 && b1 == 254) return 1; // 169.254.0.0/16 (link-local)
  if (b0 == 172 && b1 >= 16 && b1 <= 31) return 1; // 172.16.0.0/12
  if (b0 == 192 && b1 == 0 && b2 == 0) return 1; // 192.0.0.0/24 (IETF protocol assignments)
  if (b0 == 192 && b1 == 0 && b2 == 2) return 1; // 192.0.2.0/24 (TEST-NET-1)
  if (b0 == 192 && b1 == 168) return 1; // 192.168.0.0/16
  if (b0 == 198 && b1 >= 18 && b1 <= 19) return 1; // 198.18.0.0/15 (benchmarking)
  if (b0 == 198 && b1 == 51 && b2 == 100) return 1; // 198.51.100.0/24 (TEST-NET-2)
  if (b0 == 203 && b1 == 0 && b2 == 113) return 1; // 203.0.113.0/24 (TEST-NET-3)
  if (b0 >= 224) return 1; // 224.0.0.0/4 multicast, 240.0.0.0/4 reserved, 255.255.255.255 broadcast
  return 0;
}

// IPv6 bogon/special-use source addresses — the same idea as
// is_bogon_source() above, for the ranges that actually matter for a
// public-facing game/voice server: unspecified/loopback, link-local,
// Unique Local Addresses (the v6 analogue of RFC1918 private space),
// documentation, and multicast. Deliberately not chasing every entry in
// IANA's IPv6 special-purpose registry (Teredo, 6to4, NAT64, discard-only,
// etc.) — those are rare transitional-tunneling edge cases, not a
// meaningful DDoS source, and chasing all of them isn't worth the extra
// branches for what this file protects.
static inline int is_bogon_source_v6(struct in6_addr * addr) {
  __u8 * b = addr -> s6_addr;

  // :: (unspecified) and ::1 (loopback) — first 15 bytes zero, last byte 0 or 1
  int first15_zero = 1;
  #pragma unroll
  for (int i = 0; i < 15; i++)
    if (b[i] != 0) first15_zero = 0;
  if (first15_zero && (b[15] == 0 || b[15] == 1)) return 1;

  // ::ffff:0:0/96 — IPv4-mapped addresses, never a legitimate wire source
  if (first15_zero == 0) {
    int first10_zero = 1;
    #pragma unroll
    for (int i = 0; i < 10; i++)
      if (b[i] != 0) first10_zero = 0;
    if (first10_zero && b[10] == 0xff && b[11] == 0xff) return 1;
  }

  if (b[0] == 0xfe && (b[1] & 0xc0) == 0x80) return 1; // fe80::/10 link-local
  if ((b[0] & 0xfe) == 0xfc) return 1; // fc00::/7 Unique Local Address
  if (b[0] == 0x20 && b[1] == 0x01 && b[2] == 0x0d && b[3] == 0xb8) return 1; // 2001:db8::/32 documentation
  if (b[0] == 0xff) return 1; // ff00::/8 multicast
  return 0;
}

// Invalid TCP flag combinations (null/xmas/nmap-style scans, stack fingerprint
// probes). No legitimate stack ever sends these — cheap bitmask, zero map access.
static inline int bogus_tcp_flags(struct tcphdr * tcp) {
  __u8 f = (tcp -> fin) | (tcp -> syn << 1) | (tcp -> rst << 2) |
    (tcp -> psh << 3) | (tcp -> ack << 4) | (tcp -> urg << 5);

  if (f == 0x00) return 1; // NULL scan
  if ((f & 0x03) == 0x03) return 1; // SYN+FIN
  if ((f & 0x05) == 0x05) return 1; // SYN+RST
  if (f == 0x01) return 1; // FIN only, no ACK
  if (f == 0x29) return 1; // FIN+PSH+URG, no ACK/SYN/RST (Xmas scan)
  if (f == 0x3f) return 1; // all flags set
  return 0;
}

// Chargen-style amplification/garbage-flood detector: 24 straight
// printable-ASCII bytes (0x21-0x7E) at the start of the UDP payload. No
// binary game/voice/VPN protocol here opens with plain text — they all lead
// with magic bytes/opcodes — so this shape reliably flags chargen reflection
// or generic junk-padded floods. Applies globally, not gated by any GAME_*
// flag, matching the original (port-agnostic) rule.
static inline int is_ascii_garbage_flood(void * data, void * data_end) {
  if (data + 24 > data_end) return 0;
  __u8 * p = (__u8 * ) data;
  #pragma unroll
  for (int i = 0; i < 24; i++) {
    if (p[i] < 0x21 || p[i] > 0x7e) return 0;
  }
  return 1;
}

// A handful of known-bad UDP payload signatures, decoded from validated
// production u32 rules — origin of some of these is unclear (opaque
// flood-tool fingerprints), but they're specific enough that a false
// positive on unrelated legit traffic isn't realistic. Applied globally,
// same as the chargen check above. One additional signature from the same
// source ("getstatus"-shaped, checked against UDP-header-region bytes
// rather than payload bytes) was NOT ported — its offset math didn't match
// the pattern of every other rule in that config closely enough to be
// confident the decode is right, and a wrong signature here is worse than
// no signature.
static inline int is_known_bad_udp_payload(void * data, void * data_end) {
  if (data + 5 <= data_end && bpf_strncmp(data, 5, "flood") == 0)
    return 1; // literal ASCII filler text from a crude flood tool
  if (data + 4 <= data_end && * (__u32 * ) data == 0x34663866) // "f8f4", little-endian read
    return 1; // opaque booter-tool signature
  if (data + 8 <= data_end && * (__u32 * ) data == 0x646e61d6 &&
    * (__u32 * )(data + 4) == 0x78252928)
    return 1; // opaque botnet payload fragment
  return 0;
}

#ifdef ENABLE_AMP_PROTECTION
// Well-known public DNS resolvers — Google, Cloudflare (incl. the 1.1.1.1
// for Families malware/adult-content-filtering variants), Quad9 (incl. the
// unsecured and ECS variants), and AdGuard (incl. Family Protection and
// non-filtering variants). A real lookup this box sends out to one of these
// can legitimately come back with a large EDNS0/DNSSEC answer over the
// 750-byte amp threshold below; exempting these specific, well-known
// operators (rather than raising the threshold for everyone) keeps the
// amplification check meaningful for actual spoofed reflectors. IPv4
// addresses — see is_known_public_dns_v6() below for the IPv6 ones. Add
// more addresses here if this box also depends on another known-good
// resolver (e.g. an ISP's own DNS).
static inline int is_known_public_dns(__u32 src_ip) {
  // Google
  if (src_ip == IPV4(8, 8, 8, 8) || src_ip == IPV4(8, 8, 4, 4)) return 1;
  // Cloudflare: standard, malware-blocking, malware+adult-content-blocking
  if (src_ip == IPV4(1, 1, 1, 1) || src_ip == IPV4(1, 0, 0, 1) ||
    src_ip == IPV4(1, 1, 1, 2) || src_ip == IPV4(1, 0, 0, 2) ||
    src_ip == IPV4(1, 1, 1, 3) || src_ip == IPV4(1, 0, 0, 3)) return 1;
  // Quad9: secured (default), unsecured/unfiltered, secured+ECS
  if (src_ip == IPV4(9, 9, 9, 9) || src_ip == IPV4(149, 112, 112, 112) ||
    src_ip == IPV4(9, 9, 9, 10) || src_ip == IPV4(149, 112, 112, 10) ||
    src_ip == IPV4(9, 9, 9, 11) || src_ip == IPV4(149, 112, 112, 11)) return 1;
  // AdGuard: default (ad-blocking), family protection, non-filtering
  if (src_ip == IPV4(94, 140, 14, 14) || src_ip == IPV4(94, 140, 15, 15) ||
    src_ip == IPV4(94, 140, 14, 15) || src_ip == IPV4(94, 140, 15, 16) ||
    src_ip == IPV4(94, 140, 14, 140) || src_ip == IPV4(94, 140, 14, 141)) return 1;
  return 0;
}

// Same providers as is_known_public_dns() above, their IPv6 addresses.
static inline int is_known_public_dns_v6(struct in6_addr * src_ip) {
  static const struct in6_addr google_dns_1 = IPV6(0x20, 0x01, 0x48, 0x60, 0x48, 0x60, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x88, 0x88);
  static const struct in6_addr google_dns_2 = IPV6(0x20, 0x01, 0x48, 0x60, 0x48, 0x60, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x88, 0x44);
  static const struct in6_addr cf_std_1 = IPV6(0x26, 0x06, 0x47, 0x00, 0x47, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x11, 0x11);
  static const struct in6_addr cf_std_2 = IPV6(0x26, 0x06, 0x47, 0x00, 0x47, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10, 0x01);
  static const struct in6_addr cf_malware_1 = IPV6(0x26, 0x06, 0x47, 0x00, 0x47, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x11, 0x12);
  static const struct in6_addr cf_malware_2 = IPV6(0x26, 0x06, 0x47, 0x00, 0x47, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10, 0x02);
  static const struct in6_addr cf_family_1 = IPV6(0x26, 0x06, 0x47, 0x00, 0x47, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x11, 0x13);
  static const struct in6_addr cf_family_2 = IPV6(0x26, 0x06, 0x47, 0x00, 0x47, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10, 0x03);
  static const struct in6_addr quad9_secured_1 = IPV6(0x26, 0x20, 0x00, 0xfe, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xfe);
  static const struct in6_addr quad9_secured_2 = IPV6(0x26, 0x20, 0x00, 0xfe, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x09);
  static const struct in6_addr quad9_unsecured_1 = IPV6(0x26, 0x20, 0x00, 0xfe, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10);
  static const struct in6_addr quad9_unsecured_2 = IPV6(0x26, 0x20, 0x00, 0xfe, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xfe, 0x00, 0x10);
  static const struct in6_addr quad9_ecs_1 = IPV6(0x26, 0x20, 0x00, 0xfe, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x11);
  static const struct in6_addr quad9_ecs_2 = IPV6(0x26, 0x20, 0x00, 0xfe, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xfe, 0x00, 0x11);
  static const struct in6_addr adguard_default_1 = IPV6(0x2a, 0x10, 0x50, 0xc0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0a, 0xd1, 0x00, 0xff);
  static const struct in6_addr adguard_default_2 = IPV6(0x2a, 0x10, 0x50, 0xc0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0a, 0xd2, 0x00, 0xff);
  static const struct in6_addr adguard_family_1 = IPV6(0x2a, 0x10, 0x50, 0xc0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xba, 0xd1, 0x00, 0xff);
  static const struct in6_addr adguard_family_2 = IPV6(0x2a, 0x10, 0x50, 0xc0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xba, 0xd2, 0x00, 0xff);
  static const struct in6_addr adguard_nofilter_1 = IPV6(0x2a, 0x10, 0x50, 0xc0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0xff);
  static const struct in6_addr adguard_nofilter_2 = IPV6(0x2a, 0x10, 0x50, 0xc0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0xff);

  return ipv6_eq(src_ip, & google_dns_1) || ipv6_eq(src_ip, & google_dns_2) ||
    ipv6_eq(src_ip, & cf_std_1) || ipv6_eq(src_ip, & cf_std_2) ||
    ipv6_eq(src_ip, & cf_malware_1) || ipv6_eq(src_ip, & cf_malware_2) ||
    ipv6_eq(src_ip, & cf_family_1) || ipv6_eq(src_ip, & cf_family_2) ||
    ipv6_eq(src_ip, & quad9_secured_1) || ipv6_eq(src_ip, & quad9_secured_2) ||
    ipv6_eq(src_ip, & quad9_unsecured_1) || ipv6_eq(src_ip, & quad9_unsecured_2) ||
    ipv6_eq(src_ip, & quad9_ecs_1) || ipv6_eq(src_ip, & quad9_ecs_2) ||
    ipv6_eq(src_ip, & adguard_default_1) || ipv6_eq(src_ip, & adguard_default_2) ||
    ipv6_eq(src_ip, & adguard_family_1) || ipv6_eq(src_ip, & adguard_family_2) ||
    ipv6_eq(src_ip, & adguard_nofilter_1) || ipv6_eq(src_ip, & adguard_nofilter_2);
}

// Well-known public NTP servers — Google Public NTP (time.google.com and
// time1-4.google.com all resolve within this /24) and Cloudflare Time
// Services (time.cloudflare.com). Exempted from the 200-byte NTP amp
// threshold below the same way is_known_public_dns() exempts real resolvers
// from the DNS threshold.
static inline int is_known_public_ntp(__u32 src_ip) {
  if (src_ip == IPV4(216, 239, 35, 0) || src_ip == IPV4(216, 239, 35, 4) ||
    src_ip == IPV4(216, 239, 35, 8) || src_ip == IPV4(216, 239, 35, 12)) return 1; // Google
  if (src_ip == IPV4(162, 159, 200, 1) || src_ip == IPV4(162, 159, 200, 123)) return 1; // Cloudflare
  return 0;
}

// Cloudflare Time Services' IPv6 addresses only — Google Public NTP's IPv6
// addresses are not documented as stable (anycast, resolved live, no
// published static list the way the IPv4 /24 is), so they're deliberately
// not hardcoded here rather than guessed at. A real Google NTP reply over
// IPv6 still gets checked by the plain 200-byte threshold, just without
// this specific exemption.
static inline int is_known_public_ntp_v6(struct in6_addr * src_ip) {
  static const struct in6_addr cf_ntp_1 = IPV6(0x26, 0x06, 0x47, 0x00, 0x00, 0xf1, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01);
  static const struct in6_addr cf_ntp_2 = IPV6(0x26, 0x06, 0x47, 0x00, 0x00, 0xf1, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x23);
  return ipv6_eq(src_ip, & cf_ntp_1) || ipv6_eq(src_ip, & cf_ntp_2);
}

// Known UDP reflection/amplification patterns, keyed by the packet's claimed
// source port (the port a reflector "replies" from). Toggle this whole class
// of protection with ENABLE_AMP_PROTECTION. Applies globally, same as the
// chargen check above — an attacker picks the destination port, not us.
static inline int is_amp_flood(struct udphdr * udp, void * data_end, __u32 src_ip) {
  __u16 sport = bpf_ntohs(udp -> source);
  __u32 len = (__u32)(data_end - (void * )(udp + 1)); // payload bytes actually present

  // DNS amplification: a real reply to a normal small query is nowhere near
  // this big; DNSSEC/ANY-query amp responses routinely are. Complements the
  // QR-bit check in payload_looks_legit() by also catching oversized-but-
  // well-formed responses, and by applying even when the target isn't our
  // own DNS port. Known public resolvers are exempted from the size check
  // (see is_known_public_dns above); everyone else is held to it.
  if (sport == 53) return len > 750 && !is_known_public_dns(src_ip);
  // NTP amplification (monlist/peer-list): normal client-mode NTP replies
  // are ~48-90 bytes; monlist-style amp responses are far larger. Known
  // public NTP servers are exempted the same way DNS resolvers are above.
  if (sport == 123) return len > 200 && !is_known_public_ntp(src_ip);
  // Ports whose traffic this box never legitimately expects unsolicited,
  // regardless of size — established reflection/amplification vectors.
  return sport == 19 || // chargen
    sport == 111 || // portmap/rpcbind
    sport == 161 || // SNMP
    sport == 389 || // CLDAP
    sport == 1900 || // SSDP
    sport == 11211 || // memcached
    sport == 37810; // known reflector port, carried over from original config
}

// Same as is_amp_flood() above, checking the IPv6 known-resolver lists.
static inline int is_amp_flood_v6(struct udphdr * udp, void * data_end, struct in6_addr * src_ip) {
  __u16 sport = bpf_ntohs(udp -> source);
  __u32 len = (__u32)(data_end - (void * )(udp + 1));

  if (sport == 53) return len > 750 && !is_known_public_dns_v6(src_ip);
  if (sport == 123) return len > 200 && !is_known_public_ntp_v6(src_ip);
  return sport == 19 || sport == 111 || sport == 161 || sport == 389 ||
    sport == 1900 || sport == 11211 || sport == 37810;
}
#endif

#ifdef GAME_RAN
// Known-bad TCP payload prefixes (Ran Online protocol exploit signatures,
// validated production blocklist — 6 concrete 9-byte sequences sharing a
// common "09 00 00 00 ... 00 00 01" shape). Port-agnostic on purpose: we
// don't know which port this game listens on, and the pattern is specific
// enough that a collision with unrelated legit traffic isn't realistic.
static inline int is_known_bad_tcp_payload(void * data, void * data_end) {
  if (data + 9 > data_end) return 0;
  __u8 * p = (__u8 * ) data;
  if (p[0] != 0x09 || p[1] != 0x00 || p[2] != 0x00 || p[3] != 0x00) return 0;
  if (p[6] != 0x00 || p[7] != 0x00 || p[8] != 0x01) return 0;
  __u16 mid = (p[4] << 8) | p[5];
  return mid == 0x2009 || mid == 0x330e || mid == 0x1809 ||
    mid == 0x4906 || mid == 0x1f09 || mid == 0x2006;
}
#endif

#ifdef GAME_FIVEM
// FiveM exposes a /players.json HTTP endpoint by default that leaks every
// connected player's real IP address — a known privacy/IP-grabbing vector
// in that community, not a DDoS concern. Scoped strictly to FiveM's TCP
// port range and to established connections carrying a payload (an HTTP
// request never arrives on the SYN itself, so this never touches the hot
// SYN path). Single-packet substring scan only — like iptables' own
// non-conntrack -m string, this can miss a request whose path happens to
// straddle a TCP segment boundary.
static inline int is_players_json_request(void * data, void * data_end) {
  #pragma unroll
  for (int i = 0; i < 128; i++) {
    if (data + i + 13 > data_end) break;
    if (bpf_strncmp((char * ) data + i, 13, "/players.json") == 0)
      return 1;
  }
  return 0;
}
#endif

// IPv4 header checksum (fixed 20-byte header, no options — consistent with
// the rest of this program which never parses IP options).
static inline __u16 ip_checksum(struct iphdr * ip) {
  __u32 csum = 0;
  __u16 * p = (__u16 * ) ip;
  ip -> check = 0;
  #pragma unroll
  for (int i = 0; i < 10; i++)
    csum += p[i];
  csum = (csum & 0xffff) + (csum >> 16);
  csum = (csum & 0xffff) + (csum >> 16);
  return ~csum;
}

// UDP checksum over IPv6's pseudo-header + UDP header + payload. IPv6 has
// no header-level checksum at all (unlike IPv4), so the UDP checksum is
// mandatory (RFC 8200) — there's no "set it to 0" option the way the IPv4
// challenge reply uses. len_bytes is the UDP header+payload length in
// bytes (a small, fixed value here — just the 8-byte UDP header + 4-byte
// cookie — so the whole thing safely fits the same fixed 16-bit-word-pair
// summing approach ip_checksum() uses, just over a different, larger
// pseudo-header).
static inline __u16 udp6_checksum(struct in6_addr * saddr, struct in6_addr * daddr, struct udphdr * udp, __u16 len_bytes) {
  __u32 csum = 0;
  __u16 * sp = (__u16 * ) saddr;
  __u16 * dp = (__u16 * ) daddr;

  #pragma unroll
  for (int i = 0; i < 8; i++) csum += sp[i];
  #pragma unroll
  for (int i = 0; i < 8; i++) csum += dp[i];

  csum += bpf_htons(len_bytes); // upper-layer packet length (pseudo-header)
  csum += bpf_htons(IPPROTO_UDP); // next header (pseudo-header)

  udp -> check = 0;
  __u16 * up = (__u16 * ) udp;
  #pragma unroll
  for (int i = 0; i < 6; i++) csum += up[i]; // 8-byte UDP header + 4-byte cookie = 12 bytes = 6 words

  csum = (csum & 0xffff) + (csum >> 16);
  csum = (csum & 0xffff) + (csum >> 16);
  __u16 result = ~csum;
  return result == 0 ? 0xffff : result; // RFC 8200: a computed 0 must be sent as all-ones
}

// A sentinel struct returned by ipv6_find_upper() below to report both the
// real upper-layer protocol (if found) and where its header starts.
struct ip6_upper {
  __u8 proto; // IPPROTO_TCP/UDP/ICMPV6 if resolved, or a sentinel:
              //   0xFF = hit ESP/AH/an unknown extension header, or a
              //          truncated/malformed chain — give up and PASS.
              //          Can't inspect further (ESP/AH payload is opaque
              //          or unfamiliar), and would rather risk missing a
              //          rare attack shape than break real IPsec traffic.
              //   0xFE = a Fragment extension header was seen — DROP,
              //          mirrors the IPv4 fragment policy exactly.
              //   0xFD = more than IPV6_MAX_EXT_HEADERS extension headers
              //          chained — DROP. Real traffic essentially never
              //          needs this many; it's a known evasion shape.
  void * hdr;
};

#define IPV6_MAX_EXT_HEADERS 4

// Bounded walk of IPv6 extension headers (Hop-by-Hop Options, Destination
// Options, Routing) to find the real upper-layer protocol. IPv6 moves
// fragmentation into its own extension header instead of base-header
// fields the way IPv4 does, so "is this fragmented" has to be answered
// here rather than with a single field check.
static inline struct ip6_upper ipv6_find_upper(struct ipv6hdr * ip6, void * data_end) {
  struct ip6_upper result = {
    .proto = 0xfd,
    .hdr = NULL
  };
  __u8 next = ip6 -> nexthdr;
  void * cur = (void * )(ip6 + 1);

  #pragma unroll
  for (int i = 0; i < IPV6_MAX_EXT_HEADERS; i++) {
    if (next == IPPROTO_TCP || next == IPPROTO_UDP || next == IPPROTO_ICMPV6) {
      result.proto = next;
      result.hdr = cur;
      return result;
    }
    if (next == 44) { // Fragment header
      result.proto = 0xfe;
      return result;
    }
    if (next == 0 || next == 60 || next == 43) { // Hop-by-Hop, Destination Options, Routing
      if (cur + 2 > data_end) {
        result.proto = 0xff;
        return result;
      }
      __u8 * hdr = (__u8 * ) cur;
      __u8 hdr_next = hdr[0];
      __u8 hdr_len = hdr[1];
      void * next_hdr = cur + ((int)hdr_len + 1) * 8;
      if (next_hdr > data_end) {
        result.proto = 0xff;
        return result;
      }
      next = hdr_next;
      cur = next_hdr;
      continue;
    }
    // ESP, AH, or anything else unrecognized — can't safely parse further.
    result.proto = 0xff;
    return result;
  }
  return result; // loop exhausted without resolving — proto stays 0xfd
}

// Adaptive per-IP rate limit. Returns 1 if the packet should be dropped
// (blackholed, or the IP exceeded the limit for the current defense mode).
// `weight` lets a caller spend more of the shared budget per packet (e.g. a
// SYN whose TCP/IP shape doesn't look like a real client stack).
static inline int rate_limited(__u32 src_ip, __u64 now, __u32 weight) {
  __u32 mkey = 0;
  __u32 * mode = bpf_map_lookup_elem( & defense_mode, & mkey);
  __u32 idx = 0;
  if (mode && * mode < 3) idx = * mode;
  __u32 limit = pps_limits[idx];

  struct ip_state * st = bpf_map_lookup_elem( & rl_state, & src_ip);
  if (st) {
    if (st -> blackhole_until && now < st -> blackhole_until)
      return 1;
    if (now - st -> window_start > RL_WINDOW_NS) {
      st -> window_start = now;
      st -> pkt_count = weight;
      st -> blackhole_until = 0;
      return 0;
    }
    st -> pkt_count += weight;
    if (st -> pkt_count > limit) {
      st -> blackhole_until = now + BLACKHOLE_NS;
      bump_stat(ST_BLACKHOLE);
      return 1;
    }
    return 0;
  }

  struct ip_state new_st = {
    .window_start = now,
    .pkt_count = weight,
    .blackhole_until = 0
  };
  bpf_map_update_elem( & rl_state, & src_ip, & new_st, BPF_ANY);
  return 0;
}

// Same as rate_limited() above, against rl_state_v6 instead — duplicated
// rather than parameterized by map, since passing a BPF map reference
// through a function argument isn't portable across verifier versions.
// Shares the same defense_mode/pps_limits budget as the v4 path.
static inline int rate_limited_v6(struct in6_addr * src_ip, __u64 now, __u32 weight) {
  __u32 mkey = 0;
  __u32 * mode = bpf_map_lookup_elem( & defense_mode, & mkey);
  __u32 idx = 0;
  if (mode && * mode < 3) idx = * mode;
  __u32 limit = pps_limits[idx];

  struct ip_state * st = bpf_map_lookup_elem( & rl_state_v6, src_ip);
  if (st) {
    if (st -> blackhole_until && now < st -> blackhole_until)
      return 1;
    if (now - st -> window_start > RL_WINDOW_NS) {
      st -> window_start = now;
      st -> pkt_count = weight;
      st -> blackhole_until = 0;
      return 0;
    }
    st -> pkt_count += weight;
    if (st -> pkt_count > limit) {
      st -> blackhole_until = now + BLACKHOLE_NS;
      bump_stat(ST_BLACKHOLE);
      return 1;
    }
    return 0;
  }

  struct ip_state new_st = {
    .window_start = now,
    .pkt_count = weight,
    .blackhole_until = 0
  };
  bpf_map_update_elem( & rl_state_v6, src_ip, & new_st, BPF_ANY);
  return 0;
}

// Rough p0f-style OS bucketing from the SYN's own IP/TCP header — not full
// signature matching (see pf.os), just "does this look like a real client
// stack, and is it Windows-shaped (the common case) or not". Real player
// traffic skews Windows; non-Windows-shaped or implausible SYNs get a
// stricter share of the same per-IP budget.
static inline __u32 syn_weight(struct iphdr * ip, struct tcphdr * tcp) {
  if (ip -> ttl > 250 || bpf_ntohs(tcp -> window) == 0)
    return 50; // implausible for any real stack — burn the budget in one hit
  if (ip -> ttl <= 64) return 4; // Linux/BSD/macOS-shaped — less common for players
  if (ip -> ttl <= 128) return 1; // Windows-shaped — generous, matches typical player base
  return 4; // rare bucket (router/embedded/Solaris-shaped) — stricter
}

// Same idea as syn_weight() above, using hop_limit (IPv6's name for the
// same field TTL is in IPv4).
static inline __u32 syn_weight_v6(struct ipv6hdr * ip6, struct tcphdr * tcp) {
  if (ip6 -> hop_limit > 250 || bpf_ntohs(tcp -> window) == 0)
    return 50;
  if (ip6 -> hop_limit <= 64) return 4;
  if (ip6 -> hop_limit <= 128) return 1;
  return 4;
}

// A real OS's SYN is never exactly 40 bytes of IP-total-length (that's a
// bare 20-byte IP + 20-byte TCP header with zero options — every real stack
// sends at least MSS) and never much over ~64 bytes either (that's already
// a generous allowance for MSS+SACK+timestamp+window-scale+NOP padding).
// Anything outside that shape is a flood tool's crafted packet, not a real
// handshake attempt. Checked before touching any map.
static inline int bad_syn_length(struct iphdr * ip) {
  __u16 total_len = bpf_ntohs(ip -> tot_len);
  return total_len == 40 || total_len > 64;
}

// Same idea, IPv6 — but ipv6hdr's payload_len is the length of everything
// AFTER the fixed 40-byte base header (unlike IPv4's tot_len, which
// includes the IP header itself), so the equivalent bare-TCP-header size is
// 20, not 40, and the generous upper bound is 44, not 64.
static inline int bad_syn_length_v6(struct ipv6hdr * ip6) {
  __u16 payload_len = bpf_ntohs(ip6 -> payload_len);
  return payload_len == 20 || payload_len > 44;
}

// Masks a wire-order IPv4 address (see IPV4() above) down to its top
// SUBNET_MASK_BITS bits, for grouping source IPs into subnets. Done
// byte-by-byte on purpose: the raw integer's byte order is reversed from
// address order (see IPV4()'s comment), so a plain host-order CIDR mask
// would silently mask the wrong bits.
static inline __u32 mask_subnet(__u32 addr) {
  __u8 b[4] = {
    (__u8)(addr & 0xff),
    (__u8)((addr >> 8) & 0xff),
    (__u8)((addr >> 16) & 0xff),
    (__u8)((addr >> 24) & 0xff)
  };
  #pragma unroll
  for (int i = 0; i < 4; i++) {
    int byte_bits = SUBNET_MASK_BITS - i * 8;
    if (byte_bits <= 0) b[i] = 0;
    else if (byte_bits < 8) b[i] &= (__u8)(0xff << (8 - byte_bits));
  }
  return (__u32) b[0] | ((__u32) b[1] << 8) | ((__u32) b[2] << 16) | ((__u32) b[3] << 24);
}

// Same idea for IPv6, zeroing out everything past SUBNET_MASK_BITS_V6.
// Byte-aligned only (SUBNET_MASK_BITS_V6 must be a multiple of 8) — every
// realistic IPv6 delegation size (/48, /56, /64) already is, so this
// doesn't need mask_subnet()'s bit-level generality.
static inline void mask_subnet_v6(struct in6_addr * addr, struct in6_addr * out) {
  int keep_bytes = SUBNET_MASK_BITS_V6 / 8;
  #pragma unroll
  for (int i = 0; i < 16; i++)
    out -> s6_addr[i] = (i < keep_bytes) ? addr -> s6_addr[i] : 0;
}

// Subnet-level (not just per-IP) new-connection rate check — catches a
// botnet spread across many IPs in the same block, each individually under
// rl_state's per-IP cap but adding up to a flood in aggregate. Rolling
// window only, no escalating blackhole (see subnet_syn_state's comment).
static inline int subnet_syn_flood(__u32 src_ip, __u64 now) {
  __u32 subnet = mask_subnet(src_ip);
  struct subnet_state * st = bpf_map_lookup_elem( & subnet_syn_state, & subnet);
  if (st) {
    if (now - st -> window_start > RL_WINDOW_NS) {
      st -> window_start = now;
      st -> pkt_count = 1;
      return 0;
    }
    st -> pkt_count++;
    return st -> pkt_count > SUBNET_SYN_LIMIT;
  }
  struct subnet_state new_st = {
    .window_start = now,
    .pkt_count = 1
  };
  bpf_map_update_elem( & subnet_syn_state, & subnet, & new_st, BPF_ANY);
  return 0;
}

// Same as subnet_syn_flood() above, against subnet_syn_state_v6.
static inline int subnet_syn_flood_v6(struct in6_addr * src_ip, __u64 now) {
  struct in6_addr subnet;
  mask_subnet_v6(src_ip, & subnet);
  struct subnet_state * st = bpf_map_lookup_elem( & subnet_syn_state_v6, & subnet);
  if (st) {
    if (now - st -> window_start > RL_WINDOW_NS) {
      st -> window_start = now;
      st -> pkt_count = 1;
      return 0;
    }
    st -> pkt_count++;
    return st -> pkt_count > SUBNET_SYN_LIMIT;
  }
  struct subnet_state new_st = {
    .window_start = now,
    .pkt_count = 1
  };
  bpf_map_update_elem( & subnet_syn_state_v6, & subnet, & new_st, BPF_ANY);
  return 0;
}

// ICMP echo-request (ping) is common, expected traffic (monitoring, path
// checks); other ICMP types arriving unsolicited are rarer and more often
// signal abuse (e.g. spoofed error floods) — same weighted-budget idea as
// syn_weight(), just for ICMP.
static inline __u32 icmp_weight(struct icmphdr * icmp) {
  return icmp -> type == ICMP_ECHO ? 1 : 4;
}

// Same idea for ICMPv6 — note the echo-request type value is different
// from ICMPv4's (128, not 8).
static inline __u32 icmpv6_weight(struct icmp6hdr * icmp6) {
  return icmp6 -> icmp6_type == ICMPV6_ECHO_REQUEST ? 1 : 4;
}

// Checks whether the payload "looks legit" for a given protocol (first few bytes)
static inline int payload_looks_legit(void * data, void * data_end, __u16 dport) {
#ifdef ENABLE_DNS
  if (dport == 53) {
    if (data + 12 > data_end) return 0;
    __u16 flags = * (__u16 * )(data + 2);
    return (bpf_ntohs(flags) & 0x8000) == 0; // QR=0 (query)
  }
#endif
#ifdef ENABLE_OPENVPN
  if (dport == 1194) return data + 1 <= data_end && (( * (char * ) data & 0x38) >> 3) == 7; // P_CONTROL_HARD_RESET_CLIENT_V2/3
#endif
#ifdef ENABLE_WIREGUARD
  if (dport == 51820) return data + 4 <= data_end && * (char * ) data == 1; // type 1 handshake initiation
#endif
#ifdef GAME_SOURCE_ENGINE
  if (dport >= 27000 && dport <= 27500) return data + 4 <= data_end && * (__u32 * ) data == 0xffffffff;
#endif
#ifdef GAME_RUST
  // Rust accepts two query mechanisms: RakNet's ID_OPEN_CONNECTION_REQUEST_1
  // + start of offline-message magic (exact 4-byte signature validated in
  // production), and a bare Source-engine-style query prefix (also
  // explicitly allowed in production, alongside the RakNet path).
  if (dport == 28015)
    return data + 4 <= data_end &&
    ( * (__u32 * ) data == 0xffff0005 || // 05 00 FF FF, little-endian read
      * (__u32 * ) data == 0xffffffff);
#endif
#ifdef GAME_MINECRAFT
  // Bedrock (RakNet unconnected ping, dedicated port — strict gate)
  if (dport == 19132) {
    if (data + 1 > data_end) return 0;
    __u8 first = * (__u8 * ) data;
    return first == 0x01 || first == 0x02; // ID_UNCONNECTED_PING(_OPEN_CONNECTIONS)
  }
  // Java GS4 query protocol (dedicated range — strict gate)
  if (dport >= 25565 && dport <= 25575)
    return data + 2 <= data_end && * (__u16 * ) data == 0xfdfe; // 0xFE 0xFD magic, little-endian read
#endif
#ifdef GAME_TS3
  // Client-to-server handshake starts with magic "TS3INIT1"
  if (dport >= TS3_PORT_MIN && dport <= TS3_PORT_MAX)
    return data + 8 <= data_end && bpf_strncmp(data, 8, "TS3INIT1") == 0;
#endif

#if defined(GAME_SAMP) || defined(GAME_MORDHAU) || defined(GAME_SQUAD) || \
  defined(GAME_HLL) || defined(GAME_ALTV)
  if (dport == 7777 || (dport >= 7000 && dport <= 8999)) {
    if (data + 1 > data_end) return 0;
    __u8 first = * (__u8 * ) data;
    if (first == 0x01 || first == 0x02) return 1;
  }
#endif

#ifdef GAME_SAMP
  // San Andreas Multiplayer query, shares default port 7777 with the block
  // above — magic "SAMP" prefix, or an alternate 2-byte magic also seen in
  // production. A TS3INIT-shaped payload arriving on a SAMP port is a
  // cross-protocol-confusion tell (a real SAMP client never sends that) —
  // reject outright rather than falling through to the permissive default
  // at the end of this function.
  if (dport == 7777) {
    if (data + 4 <= data_end && * (__u32 * ) data == 0x49335354) return 0; // "TS3I"
    if (data + 4 <= data_end && bpf_strncmp(data, 4, "SAMP") == 0) return 1;
    if (data + 2 <= data_end && * (__u16 * ) data == 0x1e08) return 1;
  }
#endif

#ifdef GAME_ALTV
  // usually 7788 UDP, but also within the 7000-8999 range
  if (dport == 7788 || (dport >= 7000 && dport <= 8999)) {
    if (data + 4 <= data_end) {
      if ( * (__u32 * ) data == 0x544C41) // "ALT\0" little-endian
        return 1;
    }
  }
#endif

#ifdef GAME_FIVEM
  // FiveM / RedM (30000-32000 UDP + TCP init)
  if (dport >= 30000 && dport <= 32000) {
    if (data + 15 <= data_end && * (__u32 * ) data == 0xffffffff) {
      char * str = (char * )(data + 4);
      // Exact query strings validated in production ("getinfo xyz"/"getinfo xxx",
      // 11 bytes) — the previous bare "info" (4 bytes) matched too loosely and
      // wasn't part of the real FiveM query protocol.
      if (bpf_strncmp(str, 11, "getinfo xyz") == 0 || bpf_strncmp(str, 11, "getinfo xxx") == 0)
        return 1;
    }
    // FiveM connect packet
    if (data + 16 <= data_end) {
      if ( * (__u64 * ) data == 0x0000000000000000 && * (__u64 * )(data + 8) == 0x636F6E6E656374) // "connect\0"
        return 1;
    }
  }
#endif

#ifdef GAME_MORDHAU
  // frequently in 7000-8999 + 15000
  if ((dport >= 7000 && dport <= 8999) || dport == 15000 || dport == 7777 || dport == 27015) {
    // Mordhau beacon: starts with 0x00 0x00 0x00 0x00 or 0x01 0x00 0x00 0x00
    if (data + 4 <= data_end && * (__u32 * ) data <= 0x00000001)
      return 1;
  }
#endif

#ifdef GAME_SQUAD
  // often 7787, 21114, 27165, etc.
  if (dport == 7787 || dport == 21114 || dport == 27165 || (dport >= 7000 && dport <= 8999)) {
    if (data + 2 <= data_end && * (__u16 * ) data == 0x0000)
      return 1;
  }
#endif

#ifdef GAME_HLL
  if (dport == 8778 || dport == 27015 || (dport >= 7000 && dport <= 8999)) {
    if (data + 4 <= data_end && * (__u32 * ) data == 0x00000000)
      return 1;
  }
#endif

#ifdef GAME_ARK
  // query port = gameport + 15000, e.g. 7777 + 15000 = 22777
  if (dport >= 19132 && dport <= 65535) { // ARK query ports are high/dynamic
    if (data + 4 <= data_end && * (__u32 * ) data == 0xffffffff)
      return 1; // Source engine query (TSource Engine Query, A2S, etc.)
    if (data + 4 <= data_end && * (__u32 * ) data == 0x31305356)
      return 1; // "VS01" — alternate ARK query magic, little-endian read
  }
#endif

#ifdef GAME_UNTURNED
  // RakNet-based, often 27015-27030
  if (dport >= 27015 && dport <= 27030) {
    if (data + 1 <= data_end) {
      __u8 id = * (__u8 * ) data;
      // Unturned offline message ID: 0x05-0x0E are legit
      if (id >= 0x05 && id <= 0x0E)
        return 1;
    }
  }
#endif

#ifdef GAME_WARZ
  // Same RakNet ID_OPEN_CONNECTION_REQUEST_1 + offline-message-magic
  // signature as Rust — validated in production against the "GXP_RUST"
  // rule, which used the identical byte pattern.
  if (dport >= WARZ_PORT_MIN && dport <= WARZ_PORT_MAX)
    return data + 4 <= data_end && * (__u32 * ) data == 0xffff0005; // 05 00 FF FF, little-endian read
#endif

#ifdef GAME_TALERUNNER
  // Decoded from the original u32 rule: payload bytes 04 FF 3E ?? (4th byte
  // wildcarded — the rule masked it out too).
  if (dport == TALERUNNER_PORT)
    return data + 4 <= data_end && ( * (__u32 * ) data & 0x00ffffff) == 0x003eff04;
#endif
  return 1; // other protocols – we accept the first packet
}

SEC("xdp")
int xdp_anti_ddos(struct xdp_md * ctx) {
  void * data = (void * )(long) ctx -> data;
  void * data_end = (void * )(long) ctx -> data_end;

  struct ethhdr * eth = data;
  if (data + sizeof( * eth) > data_end) return XDP_ACCEPT;

  if (eth -> h_proto == bpf_htons(ETH_P_IP)) {
    struct iphdr * ip = data + sizeof( * eth);
    if ((void * ) & ip[1] > data_end) return XDP_ACCEPT;

    // Runtime allow/block lists (xdpctl.py) — checked first, ahead of every
    // other check in this program, including the bogon filter below. An
    // allow entry always wins over a block entry for the same address
    // (checked first); a match here skips fragment/bogon/rate-limit/
    // everything else entirely, in both directions.
    {
      struct ip_key key = {
        .prefixlen = 32,
        .addr = ip -> saddr
      };
      if (bpf_map_lookup_elem( & runtime_allow, & key)) {
        bump_stat(ST_PASS);
        bump_stat(ST_RUNTIME_ALLOW);
        return XDP_ACCEPT;
      }
      if (bpf_map_lookup_elem( & runtime_block, & key)) {
        bump_stat(ST_DROP);
        bump_stat(ST_RUNTIME_BLOCK);
        return XDP_DROP;
      }
    }

    // Drop fragments and the reserved/"evil" bit: none of the protocols this
    // program inspects fragment legitimately, and fragmented floods are a
    // common evasion/DoS vector. Single field check, no map access.
    __u16 frag = bpf_ntohs(ip -> frag_off);
    if ((frag & 0x2000) || (frag & 0x1fff) || (frag & 0x8000)) {
      bump_stat(ST_DROP);
      bump_stat(ST_FRAG_DROP);
      return XDP_DROP;
    }

    // Bogon source: no real internet host sends from RFC1918/loopback/
    // link-local/CGNAT/documentation/multicast/reserved space. Applies to
    // every protocol, before any protocol-specific dispatch.
    if (is_bogon_source(ip -> saddr)) {
      bump_stat(ST_DROP);
      bump_stat(ST_BOGON_DROP);
      return XDP_DROP;
    }

    if (ip -> protocol == IPPROTO_UDP) {
      struct udphdr * udp = (void * )(ip + 1);
      if ((void * )(udp + 1) > data_end) return XDP_ACCEPT;

      // A UDP packet whose own length field claims less than the 8-byte
      // header it's part of is never valid — a malformed/crafted packet,
      // not real traffic. Checked before anything else, no map access.
      if (bpf_ntohs(udp -> len) < sizeof( * udp)) {
        bump_stat(ST_DROP);
        bump_stat(ST_UDP_DROP);
        bump_stat(ST_MALFORMED_DROP);
        return XDP_DROP;
      }

      if (is_ascii_garbage_flood((void * )(udp + 1), data_end)) {
        bump_stat(ST_DROP);
        bump_stat(ST_UDP_DROP);
        bump_stat(ST_GARBAGE_DROP);
        return XDP_DROP;
      }

      if (is_known_bad_udp_payload((void * )(udp + 1), data_end)) {
        bump_stat(ST_DROP);
        bump_stat(ST_UDP_DROP);
        bump_stat(ST_BADPAYLOAD_DROP);
        return XDP_DROP;
      }

#ifdef ENABLE_AMP_PROTECTION
      if (is_amp_flood(udp, data_end, ip -> saddr)) {
        bump_stat(ST_DROP);
        bump_stat(ST_UDP_DROP);
        bump_stat(ST_AMP_DROP);
        return XDP_DROP;
      }
#endif

      __u16 dport = bpf_ntohs(udp -> dest);

      if (!is_legit_port(dport)) {
        // Not one of this box's declared services — still worth a baseline
        // per-IP rate limit rather than an unconditional pass, so a flood
        // aimed at a port this box doesn't use doesn't get a completely
        // free ride. Shares the same per-IP budget as everything else (one
        // abusive source, one shared cap) — no new map, and no cost at all
        // for a source that stays under it.
        __u32 src_ip = ip -> saddr;
        __u64 ts = bpf_ktime_get_ns();
        if (rate_limited(src_ip, ts, 1)) {
          bump_stat(ST_DROP);
          bump_stat(ST_UDP_DROP);
          bump_stat(ST_RATELIMIT_DROP);
          return XDP_DROP;
        }
        bump_stat(ST_PASS);
        bump_stat(ST_UDP_PASS);
        return XDP_ACCEPT; // not our port → kernel
      }

      // Reflected/amplified UDP (memcached, NTP monlist, chargen, SSDP, ...)
      // always arrives from a privileged source port. Real game/voice/VPN
      // clients never use one, so this is a safe, cheap hard drop before any
      // map lookup — also means it doesn't cost latency for real traffic.
      // DNS is excluded: legitimate server-to-server DNS often uses sport 53.
      __u16 sport = bpf_ntohs(udp -> source);
      if (dport != 53 && sport != 0 && sport < 1024) {
        bump_stat(ST_DROP);
        bump_stat(ST_UDP_DROP);
        bump_stat(ST_REFLECT_DROP);
        return XDP_DROP;
      }

#ifdef GAME_FIVEM
      // A packet claiming both source and destination port 30120 (FiveM's
      // default port) is a validated production reflection/loop signature,
      // not real client traffic — a real client's ephemeral source port
      // never matches the server's own game port.
      if (sport == 30120 && dport == 30120) {
        bump_stat(ST_DROP);
        bump_stat(ST_UDP_DROP);
        bump_stat(ST_REFLECT_DROP);
        return XDP_DROP;
      }
#endif

      __u32 src_ip = ip -> saddr;
      __u64 ts = bpf_ktime_get_ns();

      // Adaptive rate limit / auto-blackhole, before everything else
      if (rate_limited(src_ip, ts, 1)) {
        bump_stat(ST_DROP);
        bump_stat(ST_UDP_DROP);
        bump_stat(ST_RATELIMIT_DROP);
        return XDP_DROP;
      }

      // Check the whitelist
      __u64 * wl_ts = bpf_map_lookup_elem( & whitelist, & src_ip);
      if (wl_ts && ts - * wl_ts < WHITELIST_TTL_NS) {
        bump_stat(ST_PASS);
        bump_stat(ST_UDP_PASS);
        return XDP_ACCEPT;
      }

      void * payload = (void * )(udp + 1);
      int legit = payload_looks_legit(payload, data_end, dport);

      // If this is a response to the challenge (second packet with the same cookie)
      if (data_end - payload >= 4) {
        __u32 * maybe_cookie = payload;
        struct challenge * ch = bpf_map_lookup_elem( & challenge_sent, & src_ip);
        if (ch && ch -> cookie == * maybe_cookie && ts - ch -> timestamp < 5000000000ULL) { // 5s
          bpf_map_update_elem( & whitelist, & src_ip, & ts, BPF_ANY);
          bpf_map_delete_elem( & challenge_sent, & src_ip);
          bump_stat(ST_PASS);
          bump_stat(ST_UDP_PASS);
          return XDP_ACCEPT;
        }
      }

      // If the payload looks legit → send a challenge
      if (legit) {
        __u32 cookie = gen_cookie(udp -> source, ts);
        struct challenge ch = {
          .timestamp = ts,
          .cookie = cookie
        };
        bpf_map_update_elem( & challenge_sent, & src_ip, & ch, BPF_ANY);

        // Build the challenge reply in-place: shrink the packet down to
        // eth+ip+udp+4-byte cookie and send it back to the sender (XDP_TX
        // on the same interface).
        __u8 src_mac[6], dst_mac[6];
        __builtin_memcpy(src_mac, eth -> h_source, 6);
        __builtin_memcpy(dst_mac, eth -> h_dest, 6);
        __u32 daddr = ip -> daddr, saddr = ip -> saddr;
        __be16 sport = udp -> source, rdport = udp -> dest;

        int new_len = (int) sizeof( * eth) + (int) sizeof( * ip) + (int) sizeof( * udp) + 4;
        int diff = new_len - (int)(data_end - data);
        if (bpf_xdp_adjust_tail(ctx, diff))
          return XDP_DROP;

        data = (void * )(long) ctx -> data;
        data_end = (void * )(long) ctx -> data_end;
        if (data + new_len > data_end)
          return XDP_DROP;

        eth = data;
        __builtin_memcpy(eth -> h_dest, src_mac, 6);
        __builtin_memcpy(eth -> h_source, dst_mac, 6);

        ip = data + sizeof( * eth);
        ip -> ttl = 64;
        ip -> saddr = daddr;
        ip -> daddr = saddr;
        ip -> tot_len = bpf_htons(sizeof( * ip) + sizeof( * udp) + 4);
        ip -> check = ip_checksum(ip);

        udp = (void * )(ip + 1);
        udp -> source = rdport;
        udp -> dest = sport;
        udp -> len = bpf_htons(sizeof( * udp) + 4);
        udp -> check = 0; // allowed for IPv4 UDP

        __u32 * cookie_out = (void * )(udp + 1);
        if ((void * )(cookie_out + 1) > data_end)
          return XDP_DROP;
        * cookie_out = cookie;

        bump_stat(ST_CHALLENGE);
        return XDP_TX;
      }

      bump_stat(ST_DROP);
      bump_stat(ST_UDP_DROP);
      return XDP_DROP;
    }

    if (ip -> protocol == IPPROTO_TCP) {
      if (ip -> ihl < 5) return XDP_ACCEPT; // malformed header
      struct tcphdr * tcp = (void * ) ip + (ip -> ihl * 4); // account for IP options
      if ((void * )(tcp + 1) > data_end) return XDP_ACCEPT;

      if (bogus_tcp_flags(tcp)) {
        bump_stat(ST_DROP);
        bump_stat(ST_TCP_DROP);
        bump_stat(ST_BADFLAGS_DROP);
        return XDP_DROP;
      }

#ifdef ENABLE_HANDSHAKE_VERIFY
      // Full handshake verification — see the ENABLE_HANDSHAKE_VERIFY
      // comment at the top of this file and the matching section in
      // FILTER.md before enabling this. Framed from the peer's point of
      // view (see struct tcp_flow_key's comment): on ingress, the peer is
      // always whoever sent us this packet.
      {
        struct tcp_flow_key hs_key = {
          .peer_ip = ip -> saddr,
          .peer_port = bpf_ntohs(tcp -> source),
          .local_port = bpf_ntohs(tcp -> dest)
        };

        if (tcp -> fin || tcp -> rst) {
          // Connection closing — stop tracking it either way, whether it
          // was ever established or not.
          bpf_map_delete_elem( & tcp_handshake, & hs_key);
        } else if (tcp -> syn && !tcp -> ack) {
          // New inbound connection attempt (we'd be the server). No state
          // to check yet — state gets created on OUR egress SYN-ACK reply
          // (tcp_egress_track below), once the kernel actually decides to
          // answer it. Falls through to the existing SYN-flood protection.
        } else {
          // Either a SYN-ACK arriving inbound (we'd be the client — this
          // is a reply to our own outbound SYN) or a non-SYN packet
          // (established data, or the client's final handshake ACK
          // completing a connection we're the server for).
          struct tcp_flow_state * hs = bpf_map_lookup_elem( & tcp_handshake, & hs_key);
          __u64 hs_now = bpf_ktime_get_ns();
          if (hs && (hs -> established || hs_now - hs -> ts < HANDSHAKE_TIMEOUT_NS)) {
            if (!hs -> established) {
              hs -> established = 1;
              hs -> ts = hs_now;
            }
          } else {
            // No matching handshake ever observed for this flow (or it
            // timed out) — this is exactly the pure-ACK-flood / unsolicited
            // SYN-ACK shape GXP_TCP_STATELESS was built to catch. Reject
            // outright rather than silently letting it through the way an
            // ingress-only filter otherwise would have to.
            bump_stat(ST_DROP);
            bump_stat(ST_TCP_DROP);
            bump_stat(ST_UNVERIFIED_DROP);
            return XDP_DROP;
          }
        }
      }
#endif

#ifdef GAME_RAN
      void * tcp_payload = (void * ) tcp + (tcp -> doff * 4); // account for TCP options
      if (is_known_bad_tcp_payload(tcp_payload, data_end)) {
        bump_stat(ST_DROP);
        bump_stat(ST_TCP_DROP);
        bump_stat(ST_EXPLOIT_DROP);
        return XDP_DROP;
      }
#endif

#ifdef GAME_FIVEM
      __u16 fivem_dport = bpf_ntohs(tcp -> dest);
      if (fivem_dport >= 30000 && fivem_dport <= 32000) {
        if (tcp -> syn && !tcp -> ack) {
          // FiveM's real client flow is UDP first (getinfo/connect, gated
          // by the challenge/response system above) — the TCP connection
          // (HTTP/NUI/asset streaming) only ever follows after that
          // succeeds. Reject the TCP handshake outright from a source
          // that hasn't recently passed the UDP challenge — matches the
          // original production config's _fxconn gate for this exact port
          // range, just backed by our own (spoof-resistant) whitelist.
          __u32 fivem_src = ip -> saddr;
          __u64 * fivem_wl = bpf_map_lookup_elem( & whitelist, & fivem_src);
          __u64 fivem_now = bpf_ktime_get_ns();
          if (!fivem_wl || fivem_now - * fivem_wl >= WHITELIST_TTL_NS) {
            bump_stat(ST_DROP);
            bump_stat(ST_TCP_DROP);
            bump_stat(ST_UNVERIFIED_DROP);
            return XDP_DROP;
          }
        } else if (!tcp -> syn) {
          // Only established connections can carry an HTTP request at all.
          void * http_payload = (void * ) tcp + (tcp -> doff * 4); // account for TCP options
          if (is_players_json_request(http_payload, data_end)) {
            bump_stat(ST_DROP);
            bump_stat(ST_TCP_DROP);
            bump_stat(ST_LEAK_DROP);
            return XDP_DROP;
          }
        }
      }
#endif

#ifdef GAME_TS3
      // TeamSpeak 3's file-transfer port (avatars/icons/channel files) — a
      // real client only ever opens this after already completing the UDP
      // voice handshake (see whitelist/is_known_public_dns's sibling map
      // above). Reject the TCP handshake outright from a source that
      // hasn't recently passed that UDP challenge; there's no legitimate
      // reason to hit this port first.
      if (tcp -> syn && !tcp -> ack && bpf_ntohs(tcp -> dest) == 30033) {
        __u32 ts3_src = ip -> saddr;
        __u64 * ts3_wl = bpf_map_lookup_elem( & whitelist, & ts3_src);
        __u64 ts3_now = bpf_ktime_get_ns();
        if (!ts3_wl || ts3_now - * ts3_wl >= WHITELIST_TTL_NS) {
          bump_stat(ST_DROP);
          bump_stat(ST_TCP_DROP);
          bump_stat(ST_UNVERIFIED_DROP);
          return XDP_DROP;
        }
      }
#endif

      // Per-IP SYN-flood protection, across all TCP ports (SSH, panel,
      // FiveM/RedM init, etc). Only new handshake attempts (SYN without
      // ACK) touch the map — established connections pass through
      // immediately, with no extra lookup or latency. Established/data
      // packets bump NOTHING here — that's the zero-added-latency
      // guarantee, so ST_TCP_PASS only ever reflects SYN admissions, never
      // the bulk established-connection volume.
      if (tcp -> syn && !tcp -> ack) {
        bump_stat(ST_TCP_SYN);

        // Cheapest check first, no map access: does this even look like a
        // real OS's SYN packet by size?
        if (bad_syn_length(ip)) {
          bump_stat(ST_DROP);
          bump_stat(ST_TCP_DROP);
          bump_stat(ST_BADSYN_LEN_DROP);
          return XDP_DROP;
        }

        __u32 src_ip = ip -> saddr;
        __u64 ts = bpf_ktime_get_ns();

        // Subnet-level check before the per-IP one — catches a botnet
        // spread across one block before spending a per-IP map write on it.
        if (subnet_syn_flood(src_ip, ts)) {
          bump_stat(ST_DROP);
          bump_stat(ST_TCP_DROP);
          bump_stat(ST_SUBNET_DROP);
          return XDP_DROP;
        }

        if (rate_limited(src_ip, ts, syn_weight(ip, tcp))) {
          bump_stat(ST_DROP);
          bump_stat(ST_TCP_DROP);
          bump_stat(ST_RATELIMIT_DROP);
          return XDP_DROP;
        }
        bump_stat(ST_PASS);
        bump_stat(ST_TCP_PASS);
      }
    }

    // ICMP flood protection (echo floods, smurf-style abuse). Shares the
    // same per-IP budget as TCP/UDP — one abusive source, one shared cap.
    // Echo requests (common, expected) cost less of that budget than other
    // ICMP types (rarer, more often abuse) — see icmp_weight().
    if (ip -> protocol == IPPROTO_ICMP) {
      struct icmphdr * icmp = (void * )(ip + 1);
      __u32 weight = 1;
      if ((void * )(icmp + 1) <= data_end) weight = icmp_weight(icmp);

      __u32 src_ip = ip -> saddr;
      __u64 ts = bpf_ktime_get_ns();
      if (rate_limited(src_ip, ts, weight)) {
        bump_stat(ST_DROP);
        bump_stat(ST_ICMP_DROP);
        bump_stat(ST_RATELIMIT_DROP);
        return XDP_DROP;
      }
      bump_stat(ST_PASS);
      bump_stat(ST_ICMP_PASS);
    }

#ifdef ENABLE_GRE
    // GRE is essential infra on this box (e.g. a PPTP tunnel). Scoped to the
    // actual tunnel peer via GRE_ALLOWED_SRC/GRE_ALLOWED_DST when defined —
    // only a packet matching the configured peer(s) is trusted outright.
    // A GRE packet that doesn't match still isn't hard-blocked: it falls
    // through to the rate-limited catch-all below like any unrecognized
    // protocol, so a spoofed/random-source GRE flood is still capped even
    // with ENABLE_GRE on.
    if (ip -> protocol == IPPROTO_GRE) {
      int gre_trusted = 1;
#ifdef GRE_ALLOWED_SRC
      gre_trusted = gre_trusted && (ip -> saddr == GRE_ALLOWED_SRC);
#endif
#ifdef GRE_ALLOWED_DST
      gre_trusted = gre_trusted && (ip -> daddr == GRE_ALLOWED_DST);
#endif
      if (gre_trusted) {
        bump_stat(ST_PASS);
        bump_stat(ST_OTHER_PASS);
        return XDP_ACCEPT;
      }
    }
#endif

#ifdef ENABLE_IPIP
    // Same idea as ENABLE_GRE, for IP-in-IP tunnels (protocol 4).
    if (ip -> protocol == IPPROTO_IPIP) {
      int ipip_trusted = 1;
#ifdef IPIP_ALLOWED_SRC
      ipip_trusted = ipip_trusted && (ip -> saddr == IPIP_ALLOWED_SRC);
#endif
#ifdef IPIP_ALLOWED_DST
      ipip_trusted = ipip_trusted && (ip -> daddr == IPIP_ALLOWED_DST);
#endif
      if (ipip_trusted) {
        bump_stat(ST_PASS);
        bump_stat(ST_OTHER_PASS);
        return XDP_ACCEPT;
      }
    }
#endif

    // Any other IP protocol — GRE (47) if ENABLE_GRE isn't set (or set but
    // not matching GRE_ALLOWED_SRC/DST), IPIP (4) similarly, ESP (50),
    // AH (51), SUN-ND (77), IGMP, OSPF, or an outright bogus protocol
    // number. None of this is expected in any real volume on a game/voice
    // server. Rate-limited (same shared per-IP budget) rather than
    // hard-blocked, so it doesn't break other legitimate low-volume
    // protocol use while still capping a raw-protocol flood — this was
    // previously a silent, unlimited pass.
    if (ip -> protocol != IPPROTO_UDP && ip -> protocol != IPPROTO_TCP && ip -> protocol != IPPROTO_ICMP) {
      __u32 src_ip = ip -> saddr;
      __u64 ts = bpf_ktime_get_ns();
      if (rate_limited(src_ip, ts, 1)) {
        bump_stat(ST_DROP);
        bump_stat(ST_OTHER_DROP);
        bump_stat(ST_RATELIMIT_DROP);
        return XDP_DROP;
      }
      bump_stat(ST_PASS);
      bump_stat(ST_OTHER_PASS);
    }
  } else if (eth -> h_proto == bpf_htons(ETH_P_IPV6)) {
    struct ipv6hdr * ip6 = data + sizeof( * eth);
    if ((void * )(ip6 + 1) > data_end) return XDP_ACCEPT;

    // Runtime allow/block lists (IPv6) — same semantics as the v4 ones:
    // checked first, ahead of everything else, allow always wins over
    // block for the same address.
    {
      struct ip6_key key = {
        .prefixlen = 128,
        .addr = ip6 -> saddr
      };
      if (bpf_map_lookup_elem( & runtime_allow_v6, & key)) {
        bump_stat(ST_IPV6_PASS);
        bump_stat(ST_RUNTIME_ALLOW);
        return XDP_ACCEPT;
      }
      if (bpf_map_lookup_elem( & runtime_block_v6, & key)) {
        bump_stat(ST_IPV6_DROP);
        bump_stat(ST_RUNTIME_BLOCK);
        return XDP_DROP;
      }
    }

    if (is_bogon_source_v6( & ip6 -> saddr)) {
      bump_stat(ST_IPV6_DROP);
      bump_stat(ST_BOGON_DROP);
      return XDP_DROP;
    }

    struct ip6_upper upper = ipv6_find_upper(ip6, data_end);
    if (upper.proto == 0xfe) { // Fragment extension header — mirrors the IPv4 fragment policy
      bump_stat(ST_IPV6_DROP);
      bump_stat(ST_FRAG_DROP);
      return XDP_DROP;
    }
    if (upper.proto == 0xfd) { // more extension headers than any real traffic needs
      bump_stat(ST_IPV6_DROP);
      bump_stat(ST_FRAG_DROP); // same bucket: header-shape evasion, not a distinct new reason
      return XDP_DROP;
    }
    if (upper.proto == 0xff) { // ESP/AH/unknown/truncated — can't inspect, don't break it
      bump_stat(ST_IPV6_PASS);
      return XDP_ACCEPT;
    }

    if (upper.proto == IPPROTO_UDP) {
      struct udphdr * udp = upper.hdr;
      if ((void * )(udp + 1) > data_end) return XDP_ACCEPT;

      if (bpf_ntohs(udp -> len) < sizeof( * udp)) {
        bump_stat(ST_IPV6_DROP);
        bump_stat(ST_UDP_DROP);
        bump_stat(ST_MALFORMED_DROP);
        return XDP_DROP;
      }

      if (is_ascii_garbage_flood((void * )(udp + 1), data_end)) {
        bump_stat(ST_IPV6_DROP);
        bump_stat(ST_UDP_DROP);
        bump_stat(ST_GARBAGE_DROP);
        return XDP_DROP;
      }

      if (is_known_bad_udp_payload((void * )(udp + 1), data_end)) {
        bump_stat(ST_IPV6_DROP);
        bump_stat(ST_UDP_DROP);
        bump_stat(ST_BADPAYLOAD_DROP);
        return XDP_DROP;
      }

#ifdef ENABLE_AMP_PROTECTION
      if (is_amp_flood_v6(udp, data_end, & ip6 -> saddr)) {
        bump_stat(ST_IPV6_DROP);
        bump_stat(ST_UDP_DROP);
        bump_stat(ST_AMP_DROP);
        return XDP_DROP;
      }
#endif

      __u16 dport = bpf_ntohs(udp -> dest);

      if (!is_legit_port(dport)) {
        struct in6_addr src_ip = ip6 -> saddr;
        __u64 ts = bpf_ktime_get_ns();
        if (rate_limited_v6( & src_ip, ts, 1)) {
          bump_stat(ST_IPV6_DROP);
          bump_stat(ST_UDP_DROP);
          bump_stat(ST_RATELIMIT_DROP);
          return XDP_DROP;
        }
        bump_stat(ST_IPV6_PASS);
        bump_stat(ST_UDP_PASS);
        return XDP_ACCEPT; // not our port → kernel
      }

      __u16 sport = bpf_ntohs(udp -> source);
      if (dport != 53 && sport != 0 && sport < 1024) {
        bump_stat(ST_IPV6_DROP);
        bump_stat(ST_UDP_DROP);
        bump_stat(ST_REFLECT_DROP);
        return XDP_DROP;
      }

#ifdef GAME_FIVEM
      if (sport == 30120 && dport == 30120) {
        bump_stat(ST_IPV6_DROP);
        bump_stat(ST_UDP_DROP);
        bump_stat(ST_REFLECT_DROP);
        return XDP_DROP;
      }
#endif

      struct in6_addr src_ip = ip6 -> saddr;
      __u64 ts = bpf_ktime_get_ns();

      if (rate_limited_v6( & src_ip, ts, 1)) {
        bump_stat(ST_IPV6_DROP);
        bump_stat(ST_UDP_DROP);
        bump_stat(ST_RATELIMIT_DROP);
        return XDP_DROP;
      }

      __u64 * wl_ts = bpf_map_lookup_elem( & whitelist_v6, & src_ip);
      if (wl_ts && ts - * wl_ts < WHITELIST_TTL_NS) {
        bump_stat(ST_IPV6_PASS);
        bump_stat(ST_UDP_PASS);
        return XDP_ACCEPT;
      }

      void * payload = (void * )(udp + 1);
      int legit = payload_looks_legit(payload, data_end, dport);

      if (data_end - payload >= 4) {
        __u32 * maybe_cookie = payload;
        struct challenge * ch = bpf_map_lookup_elem( & challenge_sent_v6, & src_ip);
        if (ch && ch -> cookie == * maybe_cookie && ts - ch -> timestamp < 5000000000ULL) { // 5s
          bpf_map_update_elem( & whitelist_v6, & src_ip, & ts, BPF_ANY);
          bpf_map_delete_elem( & challenge_sent_v6, & src_ip);
          bump_stat(ST_IPV6_PASS);
          bump_stat(ST_UDP_PASS);
          return XDP_ACCEPT;
        }
      }

      if (legit) {
        __u32 cookie = gen_cookie(udp -> source, ts);
        struct challenge ch = {
          .timestamp = ts,
          .cookie = cookie
        };
        bpf_map_update_elem( & challenge_sent_v6, & src_ip, & ch, BPF_ANY);

        // Same idea as the IPv4 challenge reply, with three real
        // differences: a fixed 40-byte header instead of 20, address swap
        // via a 16-byte struct copy instead of a 32-bit scalar swap, and
        // no IP-level checksum to compute (IPv6 doesn't have one) — but the
        // UDP checksum, optional and left at 0 for the v4 reply, is
        // mandatory here (see udp6_checksum()).
        __u8 src_mac[6], dst_mac[6];
        __builtin_memcpy(src_mac, eth -> h_source, 6);
        __builtin_memcpy(dst_mac, eth -> h_dest, 6);
        struct in6_addr daddr6 = ip6 -> daddr, saddr6 = ip6 -> saddr;
        __be16 sport_be = udp -> source, rdport_be = udp -> dest;

        int new_len = (int) sizeof( * eth) + (int) sizeof( * ip6) + (int) sizeof( * udp) + 4;
        int diff = new_len - (int)(data_end - data);
        if (bpf_xdp_adjust_tail(ctx, diff))
          return XDP_DROP;

        data = (void * )(long) ctx -> data;
        data_end = (void * )(long) ctx -> data_end;
        if (data + new_len > data_end)
          return XDP_DROP;

        eth = data;
        __builtin_memcpy(eth -> h_dest, src_mac, 6);
        __builtin_memcpy(eth -> h_source, dst_mac, 6);

        ip6 = data + sizeof( * eth);
        ip6 -> hop_limit = 64;
        ip6 -> saddr = daddr6;
        ip6 -> daddr = saddr6;
        ip6 -> payload_len = bpf_htons(sizeof( * udp) + 4);
        ip6 -> nexthdr = IPPROTO_UDP;

        udp = (void * )(ip6 + 1);
        udp -> source = rdport_be;
        udp -> dest = sport_be;
        udp -> len = bpf_htons(sizeof( * udp) + 4);

        __u32 * cookie_out = (void * )(udp + 1);
        if ((void * )(cookie_out + 1) > data_end)
          return XDP_DROP;
        * cookie_out = cookie;

        udp -> check = udp6_checksum( & ip6 -> saddr, & ip6 -> daddr, udp, sizeof( * udp) + 4);

        bump_stat(ST_CHALLENGE);
        return XDP_TX;
      }

      bump_stat(ST_IPV6_DROP);
      bump_stat(ST_UDP_DROP);
      return XDP_DROP;
    }

    if (upper.proto == IPPROTO_TCP) {
      struct tcphdr * tcp = upper.hdr;
      if ((void * )(tcp + 1) > data_end) return XDP_ACCEPT;

      if (bogus_tcp_flags(tcp)) {
        bump_stat(ST_IPV6_DROP);
        bump_stat(ST_TCP_DROP);
        bump_stat(ST_BADFLAGS_DROP);
        return XDP_DROP;
      }

      // ENABLE_HANDSHAKE_VERIFY is IPv4-only for now (see FILTER.md) —
      // no tcp_handshake_v6 map, nothing to check here yet.

#ifdef GAME_RAN
      void * tcp_payload6 = (void * ) tcp + (tcp -> doff * 4); // account for TCP options
      if (is_known_bad_tcp_payload(tcp_payload6, data_end)) {
        bump_stat(ST_IPV6_DROP);
        bump_stat(ST_TCP_DROP);
        bump_stat(ST_EXPLOIT_DROP);
        return XDP_DROP;
      }
#endif

#ifdef GAME_FIVEM
      __u16 fivem_dport6 = bpf_ntohs(tcp -> dest);
      if (fivem_dport6 >= 30000 && fivem_dport6 <= 32000) {
        if (tcp -> syn && !tcp -> ack) {
          struct in6_addr fivem_src6 = ip6 -> saddr;
          __u64 * fivem_wl6 = bpf_map_lookup_elem( & whitelist_v6, & fivem_src6);
          __u64 fivem_now6 = bpf_ktime_get_ns();
          if (!fivem_wl6 || fivem_now6 - * fivem_wl6 >= WHITELIST_TTL_NS) {
            bump_stat(ST_IPV6_DROP);
            bump_stat(ST_TCP_DROP);
            bump_stat(ST_UNVERIFIED_DROP);
            return XDP_DROP;
          }
        } else if (!tcp -> syn) {
          void * http_payload6 = (void * ) tcp + (tcp -> doff * 4);
          if (is_players_json_request(http_payload6, data_end)) {
            bump_stat(ST_IPV6_DROP);
            bump_stat(ST_TCP_DROP);
            bump_stat(ST_LEAK_DROP);
            return XDP_DROP;
          }
        }
      }
#endif

#ifdef GAME_TS3
      if (tcp -> syn && !tcp -> ack && bpf_ntohs(tcp -> dest) == 30033) {
        struct in6_addr ts3_src6 = ip6 -> saddr;
        __u64 * ts3_wl6 = bpf_map_lookup_elem( & whitelist_v6, & ts3_src6);
        __u64 ts3_now6 = bpf_ktime_get_ns();
        if (!ts3_wl6 || ts3_now6 - * ts3_wl6 >= WHITELIST_TTL_NS) {
          bump_stat(ST_IPV6_DROP);
          bump_stat(ST_TCP_DROP);
          bump_stat(ST_UNVERIFIED_DROP);
          return XDP_DROP;
        }
      }
#endif

      if (tcp -> syn && !tcp -> ack) {
        bump_stat(ST_TCP_SYN);

        if (bad_syn_length_v6(ip6)) {
          bump_stat(ST_IPV6_DROP);
          bump_stat(ST_TCP_DROP);
          bump_stat(ST_BADSYN_LEN_DROP);
          return XDP_DROP;
        }

        struct in6_addr src_ip6 = ip6 -> saddr;
        __u64 ts6 = bpf_ktime_get_ns();

        if (subnet_syn_flood_v6( & src_ip6, ts6)) {
          bump_stat(ST_IPV6_DROP);
          bump_stat(ST_TCP_DROP);
          bump_stat(ST_SUBNET_DROP);
          return XDP_DROP;
        }

        if (rate_limited_v6( & src_ip6, ts6, syn_weight_v6(ip6, tcp))) {
          bump_stat(ST_IPV6_DROP);
          bump_stat(ST_TCP_DROP);
          bump_stat(ST_RATELIMIT_DROP);
          return XDP_DROP;
        }
        bump_stat(ST_IPV6_PASS);
        bump_stat(ST_TCP_PASS);
      }
    }

    // ICMPv6 flood protection — same shared per-IP budget idea as ICMPv4,
    // note the different echo-request type value (see icmpv6_weight()).
    if (upper.proto == IPPROTO_ICMPV6) {
      struct icmp6hdr * icmp6 = upper.hdr;
      __u32 weight = 1;
      if ((void * )(icmp6 + 1) <= data_end) weight = icmpv6_weight(icmp6);

      struct in6_addr src_ip6 = ip6 -> saddr;
      __u64 ts6 = bpf_ktime_get_ns();
      if (rate_limited_v6( & src_ip6, ts6, weight)) {
        bump_stat(ST_IPV6_DROP);
        bump_stat(ST_ICMP_DROP);
        bump_stat(ST_RATELIMIT_DROP);
        return XDP_DROP;
      }
      bump_stat(ST_IPV6_PASS);
      bump_stat(ST_ICMP_PASS);
    }

    // GRE/IPIP trusted-peer scoping (ENABLE_GRE/ENABLE_IPIP's
    // *_ALLOWED_SRC/DST) is IPv4-only for now (see FILTER.md) —
    // IPv6-encapsulated GRE/IPIP, or anything else unrecognized, just
    // falls into the same rate-limited catch-all as any other protocol.
    if (upper.proto != IPPROTO_UDP && upper.proto != IPPROTO_TCP && upper.proto != IPPROTO_ICMPV6) {
      struct in6_addr src_ip6 = ip6 -> saddr;
      __u64 ts6 = bpf_ktime_get_ns();
      if (rate_limited_v6( & src_ip6, ts6, 1)) {
        bump_stat(ST_IPV6_DROP);
        bump_stat(ST_OTHER_DROP);
        bump_stat(ST_RATELIMIT_DROP);
        return XDP_DROP;
      }
      bump_stat(ST_IPV6_PASS);
      bump_stat(ST_OTHER_PASS);
    }
  }

  return XDP_ACCEPT;
}

#ifdef ENABLE_HANDSHAKE_VERIFY
// Egress half of full handshake verification (see the top-of-file
// ENABLE_HANDSHAKE_VERIFY comment and FILTER.md). Attached as a separate TC
// egress hook — NOT loaded/attached the same way as xdp_anti_ddos above; see
// FILTER.md for the second attach command this requires. Only records
// state; never itself blocks anything (an operator's own outbound traffic
// should never be dropped by this program).
SEC("tc")
int tcp_egress_track(struct __sk_buff * skb) {
  void * data = (void * )(long) skb -> data;
  void * data_end = (void * )(long) skb -> data_end;

  struct ethhdr * eth = data;
  if (data + sizeof( * eth) > data_end) return TC_ACT_OK;
  if (eth -> h_proto != bpf_htons(ETH_P_IP)) return TC_ACT_OK;

  struct iphdr * ip = data + sizeof( * eth);
  if ((void * ) & ip[1] > data_end) return TC_ACT_OK;
  if (ip -> protocol != IPPROTO_TCP) return TC_ACT_OK;
  if (ip -> ihl < 5) return TC_ACT_OK;

  struct tcphdr * tcp = (void * ) ip + (ip -> ihl * 4);
  if ((void * )(tcp + 1) > data_end) return TC_ACT_OK;

  // Same key shape as the ingress side, but read from the egress fields:
  // the peer is whoever we're sending this packet to.
  struct tcp_flow_key key = {
    .peer_ip = ip -> daddr,
    .peer_port = bpf_ntohs(tcp -> dest),
    .local_port = bpf_ntohs(tcp -> source)
  };

  if (tcp -> fin || tcp -> rst) {
    bpf_map_delete_elem( & tcp_handshake, & key);
    return TC_ACT_OK;
  }

  // Only a SYN (we're initiating, as a client) or a SYN-ACK (the kernel's
  // own reply, as a server, to a SYN we let through on ingress) starts a
  // new pending handshake. Anything else egressing is either data on an
  // already-tracked flow (nothing to do) or irrelevant.
  if (tcp -> syn) {
    struct tcp_flow_state st = {
      .established = 0,
      .ts = bpf_ktime_get_ns()
    };
    bpf_map_update_elem( & tcp_handshake, & key, & st, BPF_ANY);
  }

  return TC_ACT_OK;
}
#endif

char _license[] SEC("license") = "GPL";
