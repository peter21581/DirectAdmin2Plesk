#pragma once

#include <common/int_types.h>

struct filter_ip
{
    u32 src_ip;
    u8 src_cidr;

    u32 dst_ip;
    u8 dst_cidr;

#ifdef ENABLE_IPV6
    u32 src_ip6[4];
    u32 dst_ip6[4];
#endif

    unsigned int do_min_ttl : 1;
    u8 min_ttl;

    unsigned int do_max_ttl : 1;
    u8 max_ttl;

    unsigned int do_min_len : 1;
    u16 min_len;

    unsigned int do_max_len : 1;
    u16 max_len;

    unsigned int do_tos : 1;
    u8 tos;
} typedef filter_ip_t;

struct filter_tcp
{
    unsigned int enabled : 1;

    unsigned int do_sport_min : 1;
    u16 sport_min;

    unsigned int do_sport_max : 1;
    u16 sport_max;

    unsigned int do_dport_min : 1;
    u16 dport_min;

    unsigned int do_dport_max : 1;
    u16 dport_max;

    // TCP flags.
    unsigned int do_urg : 1;
    unsigned int urg : 1;

    unsigned int do_ack : 1;
    unsigned int ack : 1;

    unsigned int do_rst : 1;
    unsigned int rst : 1;

    unsigned int do_psh : 1;
    unsigned int psh : 1;

    unsigned int do_syn : 1;
    unsigned int syn : 1;

    unsigned int do_fin : 1;
    unsigned int fin : 1;

    unsigned int do_ece : 1;
    unsigned int ece : 1;

    unsigned int do_cwr : 1;
    unsigned int cwr : 1;
} typedef filter_tcp_t;

struct filter_udp
{
    unsigned int enabled : 1;

    unsigned int do_sport_min : 1;
    u16 sport_min;

    unsigned int do_sport_max : 1;
    u16 sport_max;

    unsigned int do_dport_min : 1;
    u16 dport_min;

    unsigned int do_dport_max : 1;
    u16 dport_max;
} typedef filter_udp_t;

struct filter_icmp
{
    unsigned int enabled : 1;

    unsigned int do_code : 1;
    u8 code;

    unsigned int do_type : 1;
    u8 type;
} typedef filter_icmp_t;

struct filter
{
    unsigned int set : 1;
    unsigned int log : 1;
    unsigned int enabled : 1;

    u8 action;
    u16 block_time;

    // If set, the packet's UDP/TCP payload must also match this game's real
    // protocol signature (see xdp/utils/games.h) for the rule to match --
    // the runtime-configurable equivalent of the other project's compile-time
    // GAME_* flags. Requires udp.enabled or tcp.enabled to also be set.
    unsigned int do_game : 1;
    u8 game_id;

    // Set automatically (see loader/utils/xdp.c's update_filter()) for
    // games whose GAME_PROFILES entry has needs_challenge -- gates this
    // rule's UDP traffic behind the spoof-resistant challenge/response
    // system (xdp/utils/challenge.h) instead of trusting the source
    // address outright. Never applied to TCP traffic -- a real 3-way
    // handshake already provides that resistance.
    unsigned int do_challenge : 1;

#ifdef ENABLE_RL_IP
    unsigned int do_ip_pps : 1;
    u64 ip_pps;

    unsigned int do_ip_bps : 1;
    u64 ip_bps;
#endif

#ifdef ENABLE_RL_FLOW
    unsigned int do_flow_pps : 1;
    u64 flow_pps;

    unsigned int do_flow_bps : 1;
    u64 flow_bps;
#endif
    
    filter_ip_t ip;

    filter_tcp_t tcp;
    filter_udp_t udp;
    filter_icmp_t icmp;
} __attribute__((__aligned__(8))) typedef filter_t;

struct stats
{
    u64 allowed;
    u64 dropped;
    u64 passed;
} typedef stats_t;

struct cl_stats
{
    u64 pps;
    u64 bps;
    u64 next_update;
} typedef cl_stats_t;

// Generic per-source-IP rolling-window packet counter -- shared by
// xdp/utils/icmp_protect.h (ICMP flood budget) and xdp/utils/adaptive_rl.h
// (the always-on TCP/UDP packet budget). Separate from cl_stats_t since
// both of those are always-on regardless of whether ENABLE_RL_IP/
// ENABLE_RL_FLOW filter-rule rate limiting is compiled in.
struct pps_state
{
    u64 window_start;
    u32 pkt_count;
} typedef pps_state_t;

struct flow
{
    u32 ip;
    u16 port;
    u8 protocol;
} typedef flow_t;

struct flow6
{
    u128 ip;
    u16 port;
    u8 protocol;
} typedef flow6_t;

struct filter_log_event
{
    u64 ts;
    int filter_id;

    int length;

    u32 src_ip;
    u32 src_ip6[4];

    u16 src_port;

    u32 dst_ip;
    u32 dst_ip6[4];

    u16 dst_port;

    u8 protocol;

    u64 ip_pps;
    u64 ip_bps;

    u64 flow_pps;
    u64 flow_bps;
} typedef filter_log_event_t;

struct lpm_trie_key
{
    u32 prefix_len;
    u32 data;
} typedef lpm_trie_key_t;

// Same idea, IPv6 -- used by ENABLE_TOR_RELAY's known-relay map (see
// xdp/utils/tor.h). prefix_len must stay first (LPM_TRIE requirement).
struct lpm_trie_key6
{
    u32 prefix_len;
    u32 data[4];
} typedef lpm_trie_key6_t;

// Dual time-window new-connection counter plus a live concurrent-
// connection count, for ENABLE_TOR_RELAY's ORPort connection-flood
// mitigation (see xdp/utils/tor.h).
struct tor_conn_state
{
    u64 fast_window_start;
    u32 fast_count;
    u64 slow_window_start;
    u32 slow_count;
    u32 concurrent;
    u64 blackhole_until;
} typedef tor_conn_state_t;

// ENABLE_HANDSHAKE_VERIFY's shared flow-tracking state (see xdp/prog.c's
// xdp_prog_main ingress checks and tcp_egress_track TC program). Framed
// from the external peer's point of view regardless of who initiated:
// peer_ip/peer_port always belong to the other side, local_port always
// belongs to this box -- so the exact same key is computed the same way
// by both programs for a given flow (ingress reads it from saddr/source/
// dest, egress reads the same fields from daddr/dest/source).
struct tcp_flow_key
{
    u32 peer_ip;
    u16 peer_port;
    u16 local_port;
} typedef tcp_flow_key_t;

// ENABLE_HANDSHAKE_VERIFY's per-flow state -- enough to validate a
// connection's lifecycle without reimplementing RFC 793 in full (that's
// the kernel conntrack's job for packets that reach it; this only needs
// to answer "does this packet belong to a real, currently-tracked
// connection"). See xdp/prog.c's tcp_track_state enum and comments for
// the transition rules.
#define TCP_TRACK_PENDING 0     // handshake started (SYN sent our way, or by us) -- not yet trusted
#define TCP_TRACK_ESTABLISHED 1 // handshake completed
#define TCP_TRACK_CLOSING 2     // a FIN was seen from either side -- still tracked for the rest
                                 // of the close sequence, not yet trusted to re-open

struct tcp_flow_state
{
    u8 state;
    u64 ts; // last transition, used to time out a stuck pending handshake or finish a stale close
} typedef tcp_flow_state_t;