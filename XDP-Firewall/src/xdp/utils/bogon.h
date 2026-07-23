#pragma once

#include <common/all.h>

#include <xdp/utils/helpers.h>

#ifdef ENABLE_BOGON_FILTER

/**
 * Checks whether an IPv4 source address is bogon/special-use space -- no
 * real internet host sends from these, so seeing one means the source is
 * spoofed or leaked from a misconfigured network.
 *
 * 192.88.99.0/24 (the 6to4 relay anycast block) is deliberately excluded --
 * it's legitimately globally routed.
 *
 * @param saddr Source address, raw network byte order (iphdr->saddr).
 *
 * @return 1 if bogon, 0 if not.
 */
static __always_inline int is_bogon_source_v4(u32 saddr)
{
    return is_ip_in_range(saddr, IPV4(0, 0, 0, 0), 8) ||        // "this" network
        is_ip_in_range(saddr, IPV4(10, 0, 0, 0), 8) ||          // RFC1918
        is_ip_in_range(saddr, IPV4(100, 64, 0, 0), 10) ||       // CGNAT
        is_ip_in_range(saddr, IPV4(127, 0, 0, 0), 8) ||         // loopback
        is_ip_in_range(saddr, IPV4(169, 254, 0, 0), 16) ||      // link-local
        is_ip_in_range(saddr, IPV4(172, 16, 0, 0), 12) ||       // RFC1918
        is_ip_in_range(saddr, IPV4(192, 0, 0, 0), 24) ||        // IETF protocol assignments
        is_ip_in_range(saddr, IPV4(192, 0, 2, 0), 24) ||        // TEST-NET-1
        is_ip_in_range(saddr, IPV4(192, 168, 0, 0), 16) ||      // RFC1918
        is_ip_in_range(saddr, IPV4(198, 18, 0, 0), 15) ||       // benchmarking
        is_ip_in_range(saddr, IPV4(198, 51, 100, 0), 24) ||     // TEST-NET-2
        is_ip_in_range(saddr, IPV4(203, 0, 113, 0), 24) ||      // TEST-NET-3
        is_ip_in_range(saddr, IPV4(224, 0, 0, 0), 4) ||         // multicast
        is_ip_in_range(saddr, IPV4(240, 0, 0, 0), 4) ||         // reserved
        saddr == IPV4(255, 255, 255, 255);                     // broadcast
}

#ifdef ENABLE_IPV6
/**
 * Same idea for IPv6. Deliberately narrower than a full bogon list --
 * covers the ranges that actually show up as spoofed/misconfigured
 * traffic in practice, not Teredo/6to4/NAT64/discard-only ranges.
 *
 * @param saddr Source address, u32[4] raw byte order (as used throughout
 *              this codebase for v6 -- see filter_ip_t.src_ip6).
 *
 * @return 1 if bogon, 0 if not.
 */
static __always_inline int is_bogon_source_v6(const u32 *saddr)
{
    const u8 *b = (const u8 *)saddr;

    // :: and ::1
    if (b[0] == 0 && b[1] == 0 && b[2] == 0 && b[3] == 0 && b[4] == 0 && b[5] == 0 &&
        b[6] == 0 && b[7] == 0 && b[8] == 0 && b[9] == 0 && b[10] == 0 && b[11] == 0 &&
        b[12] == 0 && b[13] == 0 && b[14] == 0 && (b[15] == 0 || b[15] == 1))
    {
        return 1;
    }

    // ::ffff:0:0/96 (IPv4-mapped)
    if (b[0] == 0 && b[1] == 0 && b[2] == 0 && b[3] == 0 && b[4] == 0 && b[5] == 0 &&
        b[6] == 0 && b[7] == 0 && b[8] == 0 && b[9] == 0 && b[10] == 0xff && b[11] == 0xff)
    {
        return 1;
    }

    // fe80::/10 link-local
    if (b[0] == 0xfe && (b[1] & 0xc0) == 0x80)
    {
        return 1;
    }

    // fc00::/7 ULA
    if ((b[0] & 0xfe) == 0xfc)
    {
        return 1;
    }

    // 2001:db8::/32 documentation
    if (b[0] == 0x20 && b[1] == 0x01 && b[2] == 0x0d && b[3] == 0xb8)
    {
        return 1;
    }

    // ff00::/8 multicast
    if (b[0] == 0xff)
    {
        return 1;
    }

    return 0;
}
#endif

#endif
