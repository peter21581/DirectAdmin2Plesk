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