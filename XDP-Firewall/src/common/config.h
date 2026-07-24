#pragma once

// Enables dynamic filters.
// Disable this for better performance if you only plan on adding entries to the block and drop maps.
#define ENABLE_FILTERS

// Enables IPv4 range drop map.
// Disable this if you don't plan on adding IPv4 ranges to the drop map as it will increase performance.
//#define ENABLE_IP_RANGE_DROP

// The maximum IP ranges supported in the IP range drop map.
#define MAX_IP_RANGES 4096

// The maximum amount of filters allowed.
// Decrease this value if you receive errors related to the BPF program being too large.
#define MAX_FILTERS 1000

// Feel free to comment this out if you don't want the `blocked` entry on the stats map to be incremented every single time a packet is dropped from the source IP being on the blocked map.
// Commenting this line out should increase performance when blocking malicious traffic.
#define DO_STATS_ON_BLOCK_MAP

// Similar to DO_STATS_ON_BLOCK_MAP, but for IPv4 range drop map.
#define DO_STATS_ON_IP_RANGE_DROP_MAP

// When this is defined, a check will occur inside the IPv4 and IPv6 filters.
// For IPv6 packets, if no IPv6 source/destination IP addresses are set, but there is an IPv4 address, it will ignore the filter.
// The same goes for IPv4, if there is no IPv4 source/destination IP addresses set, if an IPv6 address is set, it will ignore the filter.
#define ALLOW_SINGLE_IP_V4_V6

// Enables filter logging through XDP.
// If performance is a concern, it is best to disable this feature by commenting out the below line with //.
#define ENABLE_FILTER_LOGGING

// Maximum interfaces the firewall can attach to.
#define MAX_INTERFACES 6

// NOTE - If you're receiving a high volume of spoofed packets, it is recommended you disable rate limiting below.
// This is because the PPS/BPS counters are updated for every packet and with a spoofed attack, the LRU map will recycle a lot of entries resulting in additional load on the CPU.
// Enable source IP rate limiting.
//#define ENABLE_RL_IP

// Enable source flow rate limiting.
#define ENABLE_RL_FLOW

// Maximum entries in source IP rate limit map.
#define MAX_RL_IP 100000

// Maximum entries in source flow rate limit map.
#define MAX_RL_FLOW 100000

// Maximum entries in block map.
#define MAX_BLOCK 100000

// Enables IPv6.
// If you're not using IPv6, this will speed up performance of the XDP program.
#define ENABLE_IPV6

// If enabled, uses a newer bpf_loop() function when choosing a source port for a new connection.
// This allows for a much higher source port range. However, it requires a more recent kernel.
#define USE_NEW_LOOP

// Whether to enable chaining multiple XDP programs with this tool (1 = enable. 0 = disable).
#define XDP_MULTIPROG_ENABLED 1

// The XDP program's run priority (used for running multiple XDP programs together).
#define XDP_MULTIPROG_PRIORITY 10

// The action that indicates it should go onto the next program (default XDP_PASS).
#define XDP_MULTIPROG_ACTION XDP_PASS

// ==== Merged in from a second XDP firewall (game-server-focused; compile-time
// GAME_*/ENABLE_* flags, no runtime config). These protections are always-on
// core checks (toggle each below), separate from and running before the
// per-rule `filters` list — a bogon/garbage/amplification packet never
// needs to reach the (much more expensive) rule loop at all. The `game`
// field on an individual filter rule (see types.h's filter_t.game_id and
// common/games.h) is the runtime-configurable equivalent of that project's
// compile-time GAME_* flags: a rule can require the payload to actually
// match a real game protocol's signature, not just its port.

// Drops packets from bogon/special-use source addresses (RFC1918 private
// ranges, loopback, link-local, CGNAT, documentation/benchmarking ranges,
// multicast, reserved space) — no real internet host sends from these, so
// seeing one means the source is spoofed or leaked from a misconfigured
// network. Applies to IPv4 and IPv6 (if ENABLE_IPV6 is also defined).
#define ENABLE_BOGON_FILTER

// Drops a handful of known-bad UDP payload signatures (flood-tool
// fingerprints) and UDP packets whose first bytes are all printable ASCII
// (the chargen-reflection / generic junk-padded-UDP-flood shape) — no
// supported game protocol opens with plain text.
#define ENABLE_BAD_PAYLOAD_FILTER

// UDP reflection/amplification defense: drops oversized "replies" on
// classic amplification source ports (DNS, NTP, memcached, SSDP, chargen,
// CLDAP, SNMP, portmap) that this box never solicited. Known public DNS/NTP
// resolvers (Google, Cloudflare, Quad9, AdGuard) are exempted from the
// size-based DNS/NTP checks since their legitimate replies can be large.
#define ENABLE_AMP_PROTECTION

// Generic anti-spoofing checks, always on regardless of the `filters` list:
// drops UDP packets with a privileged (<1024) source port other than 53
// (a real client's ephemeral source port is never privileged -- this shape
// only occurs in reflected/spoofed floods), and drops invalid TCP flag
// combinations (null/Xmas/nmap-style scans -- no real stack sends these).
#define ENABLE_ANTI_SPOOF

// Per-source-IP ICMP flood protection, always on regardless of the
// `filters` list: a 1-second rolling packet budget (weighted -- echo
// requests, common/expected, cost less of the budget than other, rarer,
// more-often-abusive ICMP types). Independent of ENABLE_RL_IP/
// ENABLE_RL_FLOW, which only apply to rules that explicitly set
// ip_pps/flow_pps.
#define ENABLE_ICMP_PROTECTION
#ifndef ICMP_PPS_LIMIT
#define ICMP_PPS_LIMIT 200 // packets/sec budget before a source's ICMP gets dropped
#endif

// Always-on per-source-IP TCP/UDP packet budget with auto-blackholing --
// closes the gap the rest of this file's protections don't: a flood that
// doesn't match any bogon/anti-spoof/amplification signature and hits a
// port no `filters` rule covers (or a pure TCP ACK flood -- no SYN, no
// game payload, nothing else here inspects it) previously sailed straight
// through. This is a 1-second rolling packet budget per source IP across
// ALL TCP/UDP traffic; exceeding it blackholes the source into the same
// map_block/map_block6 maps a filter rule's block_time already uses --
// reuses the exact mechanism this engine already has, no new drop path.
// Known public DNS/NTP resolvers are exempted (see
// xdp/utils/amp.h's is_known_public_dns()/is_known_public_ntp()) so
// legitimate high-volume resolver traffic this box solicited never gets
// blackholed. ICMP has its own separate budget (ENABLE_ICMP_PROTECTION
// above); this only covers TCP/UDP.
#define ENABLE_ADAPTIVE_RATE_LIMIT
#ifndef ADAPTIVE_PPS_LIMIT
#define ADAPTIVE_PPS_LIMIT 2000 // packets/sec budget before a source gets blackholed
#endif
#ifndef ADAPTIVE_BLOCK_TIME
#define ADAPTIVE_BLOCK_TIME 30 // seconds to blackhole a source that exceeds the budget
#endif

// The spoof-resistant UDP challenge/response system: for a filter rule
// whose game profile has needs_challenge (see common/games.h), a source
// isn't trusted on its first handshake-shaped packet alone -- that packet
// is dropped and the source remembered; a second one arriving within a
// plausible real-client retry window (see xdp/utils/challenge.h) proves
// the source can complete a round trip and gets it whitelisted (see
// UDP_CHALLENGE_TTL below). No crafted reply packet is sent -- see
// README.md's "Spoof-resistant challenge/response" section for why this
// design was chosen over an active cookie-echo challenge. No separate
// opt-in needed beyond setting `game` on a rule to one of the games this
// applies to -- undefine this to disable it globally (e.g. if you'd rather
// trust the payload signature alone).
#define ENABLE_UDP_CHALLENGE
#ifndef UDP_CHALLENGE_TTL
#define UDP_CHALLENGE_TTL 180 // seconds a source stays trusted after passing the challenge
#endif

// ==== Advanced, opt-in protections (all off by default) ====
// Each of these is a bigger architectural or behavioral commitment than the
// always-on protections above -- read its comment before enabling.

// Replaces the passive "seen-twice" challenge validator above with the
// original design's active cookie-echo challenge: on a source's first
// handshake-shaped packet, this box drops it, generates a random cookie,
// and sends a crafted UDP reply (XDP_TX) containing only that 4-byte
// cookie back to the source; a subsequent packet whose first 4 bytes match
// the cookie whitelists the source immediately (faster than waiting for a
// second natural retry). Requires ENABLE_UDP_CHALLENGE to also be defined.
//
// This does NOT emulate the real game protocol's actual handshake reply --
// it's a generic 4-byte probe, not a valid RakNet/A2S/TS3/SAMP response.
// Whether a given game client's network stack does anything useful with an
// unexpected reply shaped like this (retries in a way that echoes it,
// ignores it and falls back to its own retry loop, etc.) depends on that
// client's own implementation and isn't something this firewall can
// guarantee across every supported game. Where it doesn't help, this
// degrades gracefully to the same outcome as the passive validator alone
// (the source still gets whitelisted once it naturally retries within the
// window) -- it just adds a second, faster path when it does work.
//#define ENABLE_UDP_ACTIVE_CHALLENGE

// Adds three refinements to new TCP connection (SYN) handling, all sharing
// one toggle since they're one cohesive unit: (1) weights each SYN's cost
// against the adaptive rate-limit budget (ENABLE_ADAPTIVE_RATE_LIMIT) by a
// rough OS plausibility check from TTL/window (a real client's stack is
// almost always Linux/BSD/macOS- or Windows-shaped; an implausible TTL or
// a zero window size costs much more of the budget in one hit); (2) a
// subnet-level (not just per-IP) new-SYN-rate check, catching a botnet
// spread across many IPs in one block that's each individually under the
// per-IP budget but adds up in aggregate; (3) rejects a SYN whose total
// packet size doesn't match any real OS's handshake shape (exactly a bare
// header with zero TCP options, or much larger than a full realistic
// option set) before spending any map lookup on it at all. On by default --
// every part of this is either header-only (no map access) or a single
// low-frequency map touch (SYNs are a small fraction of total traffic
// compared to established data), and all three were unconditional/always-on
// in the original design this was ported from. Turn it off if you want the
// adaptive rate limiter's flat per-packet budget to be the only thing
// governing new connections.
#define ENABLE_SYN_PROTECTION
#ifndef SUBNET_MASK_BITS
#define SUBNET_MASK_BITS 20 // group source IPs into /20 subnets by default
#endif
#ifndef SUBNET_SYN_LIMIT
#define SUBNET_SYN_LIMIT 500 // new-connection SYNs/sec allowed from one whole subnet
#endif
#ifndef SUBNET_MASK_BITS_V6
#define SUBNET_MASK_BITS_V6 64 // /64 -- standard single-customer IPv6 delegation size;
                                // MUST be a multiple of 8 (byte-aligned masking only)
#endif

// Tor relay ORPort connection-flood mitigation, ported from a separate
// XDP firewall design built specifically for the layer-7 (low-packet-rate,
// high-connection-count) attacks that have targeted Tor relays. This box
// running a Tor relay is a deployment choice orthogonal to everything else
// in this file -- leave undefined unless that's actually what this box is
// for. See README.md's "Tor relay (ORPort) mitigation" section before
// enabling: it needs the companion tor-relay-sync.py script kept running
// to populate the known-relay list from Tor's own consensus.
//#define ENABLE_TOR_RELAY
#ifndef TOR_ORPORT
#define TOR_ORPORT 9001
#endif
#ifndef TOR_CONN_LIMIT
#define TOR_CONN_LIMIT 4 // max simultaneous connections from one non-relay source
#endif
#ifndef TOR_RELAY_CONN_LIMIT
#define TOR_RELAY_CONN_LIMIT 16 // higher cap for known relays -- legitimately share an IP
#endif
// A non-relay source is blacklisted for TOR_BLACKLIST_TIME once it opens
// more than TOR_FAST_LIMIT new connections within TOR_FAST_WINDOW_NS OR
// more than TOR_SLOW_LIMIT within TOR_SLOW_WINDOW_NS -- the dual window
// catches both a fast burst and a slower drip that'd otherwise stay under
// the fast threshold. Known relays are exempt from this blacklist
// entirely (still capped at TOR_RELAY_CONN_LIMIT concurrent connections).
#define TOR_FAST_WINDOW_NS 120000000000ULL // 2 minutes
#ifndef TOR_FAST_LIMIT
#define TOR_FAST_LIMIT 8
#endif
#define TOR_SLOW_WINDOW_NS 3600000000000ULL // 1 hour
#ifndef TOR_SLOW_LIMIT
#define TOR_SLOW_LIMIT 16
#endif
#ifndef TOR_BLACKLIST_TIME
#define TOR_BLACKLIST_TIME 86400 // seconds (24h)
#endif

// Full TCP connection state tracking: a small state machine (see
// common/types.h's TCP_TRACK_* / tcp_flow_state_t and xdp/prog.c's
// comments for the exact transition rules) that rejects any packet that
// doesn't belong to a real, currently-tracked connection at the right
// point in its lifecycle -- not just "was there ever a SYN" (that alone
// only catches pure ACK-floods): a spoofed FIN/RST flood aimed at killing
// real connections, or an ACK arriving before the handshake it claims to
// belong to ever completed, get rejected too. This is deliberately NOT a
// full RFC 793 implementation (11 states, sequence-number tracking,
// retransmission handling) -- that's the kernel conntrack's job for
// traffic that reaches it; this only needs enough state to tell "does
// this packet belong to a real tracked connection," which is what
// actually matters for DDoS mitigation here.
//
// Requires a SECOND attach point beyond the XDP hook -- a TC egress hook
// (see xdp/prog.c's tcp_egress_track) -- since this box never sends its
// own SYN-ACKs from the ingress-only XDP program and has no way to
// observe "did we really reply to this SYN" otherwise. The loader
// attaches this automatically when built with this flag on (see
// README.md's "Full TCP connection state tracking" section for the exact
// mechanics and costs): every established-connection packet now costs a
// map lookup (no longer zero-touch), and any connection already open
// before this loads has no tracked state and gets rejected as unverified
// until it opens a new one.
//#define ENABLE_HANDSHAKE_VERIFY
#ifndef HANDSHAKE_TIMEOUT_NS
#define HANDSHAKE_TIMEOUT_NS 10000000000ULL // 10s to complete a TCP handshake once started
#endif
#ifndef TCP_CLOSE_GRACE_NS
#define TCP_CLOSE_GRACE_NS 10000000000ULL // 10s to finish a close sequence (FIN/FIN-ACK/ACK) once started
#endif