#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/udp.h>
#include <linux/tcp.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

// Builds a dotted-quad IPv4 address into the same in-memory representation
// as ip->saddr/ip->daddr (raw network byte order), so it can be compared
// directly with == . Used by GRE_ALLOWED_SRC/GRE_ALLOWED_DST and the known-
// public-DNS-resolver allowlist below.
#define IPV4(a, b, c, d) ((__u32)(a) | ((__u32)(b) << 8) | ((__u32)(c) << 16) | ((__u32)(d) << 24))

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
// #define ENABLE_AMP_PROTECTION  // DNS/NTP/memcached/SSDP/chargen/etc. reflection defense

#if !defined(GAME_RUST) && !defined(GAME_FIVEM) && !defined(GAME_MINECRAFT) && \
  !defined(GAME_TS3) && !defined(GAME_ARK) && !defined(GAME_SAMP) && \
  !defined(GAME_SQUAD) && !defined(GAME_MORDHAU) && !defined(GAME_HLL) && \
  !defined(GAME_UNTURNED) && !defined(GAME_ALTV) && !defined(GAME_RAN) && \
  !defined(GAME_SOURCE_ENGINE) && !defined(GAME_LEGACY_MISC_PORTS) && \
  !defined(GAME_WARZ) && !defined(GAME_TALERUNNER) && !defined(GAME_RAGNAROK) && \
  !defined(ENABLE_DNS) && !defined(ENABLE_OPENVPN) && !defined(ENABLE_WIREGUARD) && \
  !defined(ENABLE_GRE) && !defined(ENABLE_AMP_PROTECTION)
#error "Define at least one GAME_*/ENABLE_* macro before compiling (see top of file) — otherwise this program only does generic TCP/ICMP/fragment protection and passes all UDP straight through."
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

struct challenge {
  __u64 timestamp;
  __u32 cookie;
};

struct {
  __uint(type, BPF_MAP_TYPE_LRU_HASH);
  __type(key, __u32); // src IP (v4) ili hash za v6
  __type(value, struct challenge);
  __uint(max_entries, 1000000);
}
challenge_sent SEC(".maps");

// LRU_HASH (not per-CPU): a passed challenge must be visible to every core,
// otherwise a flow that lands on a different queue re-triggers the challenge.
struct {
  __uint(type, BPF_MAP_TYPE_LRU_HASH);
  __type(key, __u32);
  __type(value, __u64); // timestamp kad je prošao challenge
  __uint(max_entries, 2000000);
}
whitelist SEC(".maps");

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
#define ST_COUNT 21

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

// dport se očekuje u host redosledu (već konvertovan pozivaocem)
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

// Generiše random cookie (koristi src port + time)
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

#ifdef ENABLE_AMP_PROTECTION
// Well-known public DNS resolvers — Google, Cloudflare (incl. the 1.1.1.1
// for Families malware/adult-content-filtering variants), Quad9 (incl. the
// unsecured and ECS variants), and AdGuard (incl. Family Protection and
// non-filtering variants). A real lookup this box sends out to one of these
// can legitimately come back with a large EDNS0/DNSSEC answer over the
// 750-byte amp threshold below; exempting these specific, well-known
// operators (rather than raising the threshold for everyone) keeps the
// amplification check meaningful for actual spoofed reflectors. IPv4 only —
// this program doesn't process IPv6 at all. Add more addresses here if this
// box also depends on another known-good resolver (e.g. an ISP's own DNS).
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

// Adaptivni per-IP rate limit. Vraća 1 ako paket treba dropovati
// (blackholed ili je IP prešao limit za trenutni defense mode). `weight`
// lets a caller spend more of the shared budget per packet (e.g. a SYN whose
// TCP/IP shape doesn't look like a real client stack).
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

// Provera da li je payload "legit" za određeni protokol (prvih par bajtova)
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
  // RakNet ID_OPEN_CONNECTION_REQUEST_1 + start of offline-message magic —
  // exact 4-byte signature validated in production, not just the first byte.
  if (dport == 28015) return data + 4 <= data_end && * (__u32 * ) data == 0xffff0005; // 05 00 FF FF, little-endian read
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
  // above — magic "SAMP" prefix.
  if (dport == 7777) {
    if (data + 4 <= data_end && bpf_strncmp(data, 4, "SAMP") == 0)
      return 1;
  }
#endif

#ifdef GAME_ALTV
  // obično 7788 UDP, ali i u 7000-8999 range
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
    // Mordhau beacon: počinje sa 0x00 0x00 0x00 0x00 ili 0x01 0x00 0x00 0x00
    if (data + 4 <= data_end && * (__u32 * ) data <= 0x00000001)
      return 1;
  }
#endif

#ifdef GAME_SQUAD
  // često 7787, 21114, 27165 itd.
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
  // query port = gameport + 15000, npr. 7777 + 15000 = 22777
  if (dport >= 19132 && dport <= 65535) { // ARK query portovi su visoki
    if (data + 4 <= data_end && * (__u32 * ) data == 0xffffffff)
      return 1; // Source engine query (TSource Engine Query, A2S, etc.)
    if (data + 4 <= data_end && * (__u32 * ) data == 0x31305356)
      return 1; // "VS01" — alternate ARK query magic, little-endian read
  }
#endif

#ifdef GAME_UNTURNED
  // RakNet-based, često 27015-27030
  if (dport >= 27015 && dport <= 27030) {
    if (data + 1 <= data_end) {
      __u8 id = * (__u8 * ) data;
      // Unturned offline message ID: 0x05 - 0x0E su legit
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
  return 1; // ostali protokoli – prihvatamo prvi paket
}

SEC("xdp")
int xdp_anti_ddos(struct xdp_md * ctx) {
  void * data = (void * )(long) ctx -> data;
  void * data_end = (void * )(long) ctx -> data_end;

  struct ethhdr * eth = data;
  if (data + sizeof( * eth) > data_end) return XDP_PASS;

  if (eth -> h_proto == bpf_htons(ETH_P_IP)) {
    struct iphdr * ip = data + sizeof( * eth);
    if ((void * ) & ip[1] > data_end) return XDP_PASS;

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
      if ((void * )(udp + 1) > data_end) return XDP_PASS;

      if (is_ascii_garbage_flood((void * )(udp + 1), data_end)) {
        bump_stat(ST_DROP);
        bump_stat(ST_UDP_DROP);
        bump_stat(ST_GARBAGE_DROP);
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

      if (!is_legit_port(dport)) return XDP_PASS; // nije naš port → kernel

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

      __u32 src_ip = ip -> saddr;
      __u64 ts = bpf_ktime_get_ns();

      // Adaptivni rate limit / auto-blackhole, pre svega ostalog
      if (rate_limited(src_ip, ts, 1)) {
        bump_stat(ST_DROP);
        bump_stat(ST_UDP_DROP);
        bump_stat(ST_RATELIMIT_DROP);
        return XDP_DROP;
      }

      // Proveri whitelist
      __u64 * wl_ts = bpf_map_lookup_elem( & whitelist, & src_ip);
      if (wl_ts && ts - * wl_ts < 180000000000ULL) { // 180 sekundi whitelist
        bump_stat(ST_PASS);
        bump_stat(ST_UDP_PASS);
        return XDP_PASS;
      }

      void * payload = (void * )(udp + 1);
      int legit = payload_looks_legit(payload, data_end, dport);

      // Ako je ovo odgovor na challenge (drugi paket sa istim cookie-om)
      if (data_end - payload >= 4) {
        __u32 * maybe_cookie = payload;
        struct challenge * ch = bpf_map_lookup_elem( & challenge_sent, & src_ip);
        if (ch && ch -> cookie == * maybe_cookie && ts - ch -> timestamp < 5000000000ULL) { // 5s
          bpf_map_update_elem( & whitelist, & src_ip, & ts, BPF_ANY);
          bpf_map_delete_elem( & challenge_sent, & src_ip);
          bump_stat(ST_PASS);
          bump_stat(ST_UDP_PASS);
          return XDP_PASS;
        }
      }

      // Ako payload izgleda legit → pošalji challenge
      if (legit) {
        __u32 cookie = gen_cookie(udp -> source, ts);
        struct challenge ch = {
          .timestamp = ts,
          .cookie = cookie
        };
        bpf_map_update_elem( & challenge_sent, & src_ip, & ch, BPF_ANY);

        // Napravi challenge reply in-place: skupi paket na eth+ip+udp+4-byte
        // cookie i pošalji ga nazad pošiljaocu (XDP_TX na isti interfejs).
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
        udp -> check = 0; // dozvoljeno za IPv4 UDP

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
      if (ip -> ihl < 5) return XDP_PASS; // malformed header
      struct tcphdr * tcp = (void * ) ip + (ip -> ihl * 4); // account for IP options
      if ((void * )(tcp + 1) > data_end) return XDP_PASS;

      if (bogus_tcp_flags(tcp)) {
        bump_stat(ST_DROP);
        bump_stat(ST_TCP_DROP);
        bump_stat(ST_BADFLAGS_DROP);
        return XDP_DROP;
      }

#ifdef GAME_RAN
      void * tcp_payload = (void * ) tcp + (tcp -> doff * 4); // account for TCP options
      if (is_known_bad_tcp_payload(tcp_payload, data_end)) {
        bump_stat(ST_DROP);
        bump_stat(ST_TCP_DROP);
        bump_stat(ST_EXPLOIT_DROP);
        return XDP_DROP;
      }
#endif

      // Per-IP SYN-flood protection, sve TCP portove (SSH, panel, FiveM/RedM
      // init, itd). Samo novi handshake pokušaji (SYN bez ACK) diraju mapu —
      // uspostavljene konekcije prolaze odmah, bez ikakvog dodatnog lookup-a
      // ili kašnjenja. Established/data packets bump NOTHING here — that's
      // the zero-added-latency guarantee, so ST_TCP_PASS only ever reflects
      // SYN admissions, never the bulk established-connection volume.
      if (tcp -> syn && !tcp -> ack) {
        bump_stat(ST_TCP_SYN);
        __u32 src_ip = ip -> saddr;
        __u64 ts = bpf_ktime_get_ns();
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

    // ICMP flood protection (echo floods, smurf-style abuse). Shares the same
    // per-IP budget as TCP/UDP — one abusive source, one shared cap.
    if (ip -> protocol == IPPROTO_ICMP) {
      __u32 src_ip = ip -> saddr;
      __u64 ts = bpf_ktime_get_ns();
      if (rate_limited(src_ip, ts, 1)) {
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
        return XDP_PASS;
      }
    }
#endif

    // Any other IP protocol — GRE (47) if ENABLE_GRE isn't set (or set but
    // not matching GRE_ALLOWED_SRC/DST), ESP (50), AH (51), SUN-ND (77),
    // IGMP, OSPF, or an outright bogus protocol number. None of this is
    // expected in any real volume on a game/voice server. Rate-limited
    // (same shared per-IP budget) rather than hard-blocked, so it doesn't
    // break other legitimate low-volume,
    // non-GRE protocol use while still capping a raw-protocol flood — this
    // was previously a silent, unlimited pass.
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
  }

  return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
