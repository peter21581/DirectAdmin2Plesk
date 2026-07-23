#pragma once

#include <common/int_types.h>
#include <common/types.h>

#include <xdp/utils/helpers.h>

struct 
{
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, u32);
    __type(value, stats_t);
} map_stats SEC(".maps");

struct 
{
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, MAX_BLOCK);
    __type(key, u32);
    __type(value, u64);
} map_block SEC(".maps");

#ifdef ENABLE_IPV6
struct 
{
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, MAX_BLOCK);
    __type(key, u128);
    __type(value, u64);
} map_block6 SEC(".maps");
#endif

#ifdef ENABLE_IP_RANGE_DROP
struct
{
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __uint(max_entries, MAX_IP_RANGES);
    __uint(map_flags, BPF_F_NO_PREALLOC);
    __type(key, lpm_trie_key_t);
    __type(value, u64);
} map_range_drop SEC(".maps");
#endif

#ifdef ENABLE_FILTERS
#ifdef ENABLE_RL_IP
struct 
{
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, MAX_RL_IP);
    __type(key, u32);
    __type(value, cl_stats_t);
} map_ip_stats SEC(".maps");

#ifdef ENABLE_IPV6
struct 
{
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, MAX_RL_IP);
    __type(key, u128);
    __type(value, cl_stats_t);
} map_ip6_stats SEC(".maps");
#endif
#endif

#ifdef ENABLE_RL_FLOW
struct 
{
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, MAX_RL_FLOW);
    __type(key, flow_t);
    __type(value, cl_stats_t);
} map_flow_stats SEC(".maps");

#ifdef ENABLE_IPV6
struct 
{
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, MAX_RL_FLOW);
    __type(key, flow6_t);
    __type(value, cl_stats_t);
} map_flow6_stats SEC(".maps");
#endif
#endif

struct 
{
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, MAX_FILTERS);
    __type(key, u32);
    __type(value, filter_t);
} map_filters SEC(".maps");

#ifdef ENABLE_FILTER_LOGGING
struct
{
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 16);
} map_filter_log SEC(".maps");
#endif

#ifdef ENABLE_UDP_CHALLENGE
// map_challenge/map_challenge6: one pending-challenge record per
// not-yet-whitelisted source, reusing pps_state_t's two u64/u32 fields as
// {window_start=ts of first sighting, pkt_count=active-challenge cookie}
// rather than adding a near-identical struct just for this (pkt_count is
// unused/0 when ENABLE_UDP_ACTIVE_CHALLENGE is off). A second sighting
// within a plausible retry window, OR (when active challenges are on) a
// packet whose first 4 bytes echo the cookie, promotes the source into
// map_whitelist -- see xdp/utils/challenge.h.
struct
{
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 1000000);
    __type(key, u32);
    __type(value, pps_state_t);
} map_challenge SEC(".maps");

struct
{
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 2000000);
    __type(key, u32);
    __type(value, u64); // timestamp (ns since boot) of when whitelisted
} map_whitelist SEC(".maps");

#ifdef ENABLE_IPV6
struct
{
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 1000000);
    __type(key, u128);
    __type(value, pps_state_t);
} map_challenge6 SEC(".maps");

struct
{
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 2000000);
    __type(key, u128);
    __type(value, u64);
} map_whitelist6 SEC(".maps");
#endif
#endif
#endif

#ifdef ENABLE_ICMP_PROTECTION
struct
{
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 2000000);
    __type(key, u32);
    __type(value, pps_state_t);
} map_icmp_state SEC(".maps");

#ifdef ENABLE_IPV6
struct
{
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 2000000);
    __type(key, u128);
    __type(value, pps_state_t);
} map_icmp_state6 SEC(".maps");
#endif
#endif

#ifdef ENABLE_ADAPTIVE_RATE_LIMIT
struct
{
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 2000000);
    __type(key, u32);
    __type(value, pps_state_t);
} map_rl_state SEC(".maps");

#ifdef ENABLE_IPV6
struct
{
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 2000000);
    __type(key, u128);
    __type(value, pps_state_t);
} map_rl_state6 SEC(".maps");
#endif
#endif

#ifdef ENABLE_SYN_PROTECTION
struct
{
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 200000);
    __type(key, u32); // pre-masked to /SUBNET_MASK_BITS
    __type(value, pps_state_t);
} map_subnet_syn SEC(".maps");

#ifdef ENABLE_IPV6
struct
{
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 200000);
    __type(key, u128); // pre-masked to /SUBNET_MASK_BITS_V6
    __type(value, pps_state_t);
} map_subnet_syn6 SEC(".maps");
#endif
#endif

#ifdef ENABLE_TOR_RELAY
// Known Tor relay IPs -- populated by the companion tor-relay-sync.py
// script from Tor's own consensus (see README.md), NOT by xdpfw-add. A
// hit here doesn't bypass filtering -- relays still go through
// tor_conn_check_v4/v6 (see xdp/utils/tor.h), just with a higher
// concurrency cap and immunity from the connection-rate blacklist.
struct
{
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __uint(map_flags, BPF_F_NO_PREALLOC);
    __uint(max_entries, 20000);
    __type(key, lpm_trie_key_t);
    __type(value, u8);
} map_tor_known_relays SEC(".maps");

struct
{
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 2000000);
    __type(key, u32);
    __type(value, tor_conn_state_t);
} map_tor_conn SEC(".maps");

#ifdef ENABLE_IPV6
struct
{
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __uint(map_flags, BPF_F_NO_PREALLOC);
    __uint(max_entries, 20000);
    __type(key, lpm_trie_key6_t);
    __type(value, u8);
} map_tor_known_relays6 SEC(".maps");

struct
{
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 500000);
    __type(key, u128);
    __type(value, tor_conn_state_t);
} map_tor_conn6 SEC(".maps");
#endif
#endif

#ifdef ENABLE_HANDSHAKE_VERIFY
// Shared between the ingress (xdp_prog_main) and egress (tcp_egress_track)
// programs -- IPv4 only for now (see README.md). This is the whole reason
// ENABLE_HANDSHAKE_VERIFY needs a second (TC egress) attach point: this
// program never sends a TCP SYN-ACK itself (the kernel's own TCP stack
// does, for real listening sockets), so there's no way to observe "did we
// really reply to this SYN" from an ingress-only XDP hook.
struct
{
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 2000000);
    __type(key, tcp_flow_key_t);
    __type(value, tcp_flow_state_t);
} map_tcp_handshake SEC(".maps");
#endif