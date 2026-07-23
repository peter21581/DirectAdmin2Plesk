#pragma once

#include <common/all.h>

#include <xdp/utils/helpers.h>
#include <xdp/utils/maps.h>

#ifdef ENABLE_UDP_CHALLENGE

// A source is trusted once a SECOND handshake-shaped packet arrives from it
// within this window after the first -- real UDP game clients universally
// retry an unanswered handshake attempt on a short timeout (a property of
// the protocols themselves, not something this firewall has to emulate).
// An indiscriminate spoofed-source flood essentially never re-sends from
// the exact same forged source at a plausible retry cadence, so this is
// enough to separate real clients from noise without this firewall having
// to construct and send a crafted reply packet (and without betting on
// correctly reverse-engineering exactly what byte sequence a given game's
// client-side stack would treat as a valid continuation of its own
// handshake -- get that wrong and every real client silently breaks).
#define CHALLENGE_MIN_GAP_NS 100000000ULL   // 100ms -- reject a repeat this fast (same burst, not a retry)
#define CHALLENGE_MAX_GAP_NS 5000000000ULL  // 5s -- reject a repeat this slow (stale, start over)

static __always_inline int challenge_is_whitelisted_v4(u32 ip, u64 now)
{
    u64 *ts = bpf_map_lookup_elem(&map_whitelist, &ip);

    return ts && (now - *ts) < ((u64)UDP_CHALLENGE_TTL * NANO_TO_SEC);
}

/**
 * Tracks a handshake-shaped packet from a not-yet-whitelisted source.
 *
 * @return 1 if this is the source's second sighting within a plausible
 *         retry window (source is now whitelisted -- let this packet
 *         through too), 0 if not (first sighting, too soon, or stale --
 *         the caller should drop this packet).
 */
static __always_inline int challenge_track_v4(u32 ip, u64 now)
{
    u64 *first_seen = bpf_map_lookup_elem(&map_challenge, &ip);

    if (first_seen)
    {
        u64 gap = now - *first_seen;

        if (gap >= CHALLENGE_MIN_GAP_NS && gap <= CHALLENGE_MAX_GAP_NS)
        {
            bpf_map_update_elem(&map_whitelist, &ip, &now, BPF_ANY);
            bpf_map_delete_elem(&map_challenge, &ip);

            return 1;
        }
    }

    bpf_map_update_elem(&map_challenge, &ip, &now, BPF_ANY);

    return 0;
}

#ifdef ENABLE_IPV6
static __always_inline int challenge_is_whitelisted_v6(u128 ip, u64 now)
{
    u64 *ts = bpf_map_lookup_elem(&map_whitelist6, &ip);

    return ts && (now - *ts) < ((u64)UDP_CHALLENGE_TTL * NANO_TO_SEC);
}

static __always_inline int challenge_track_v6(u128 ip, u64 now)
{
    u64 *first_seen = bpf_map_lookup_elem(&map_challenge6, &ip);

    if (first_seen)
    {
        u64 gap = now - *first_seen;

        if (gap >= CHALLENGE_MIN_GAP_NS && gap <= CHALLENGE_MAX_GAP_NS)
        {
            bpf_map_update_elem(&map_whitelist6, &ip, &now, BPF_ANY);
            bpf_map_delete_elem(&map_challenge6, &ip);

            return 1;
        }
    }

    bpf_map_update_elem(&map_challenge6, &ip, &now, BPF_ANY);

    return 0;
}
#endif

#endif
