#pragma once

#include <common/all.h>

#include <xdp/utils/helpers.h>

// Known public DNS/NTP resolvers -- exempted from the amplification size
// check below (ENABLE_AMP_PROTECTION) and from the always-on packet budget
// (ENABLE_ADAPTIVE_RATE_LIMIT, see adaptive_rl.h) since their legitimate
// replies (DNSSEC, large record sets, high volume under load) can
// genuinely look like a flood otherwise. Deliberately a small,
// high-confidence list (Google and Cloudflare's well-known, stable
// anycast addresses) rather than a longer one -- see README's merge notes
// for why this is smaller than what a from-scratch build might include.
// Not gated behind ENABLE_AMP_PROTECTION since ENABLE_ADAPTIVE_RATE_LIMIT
// needs these too and the two toggle independently.

/**
 * @param src_ip Source address, raw network byte order.
 *
 * @return 1 if known, 0 if not.
 */
static __always_inline int is_known_public_dns(u32 src_ip)
{
    return src_ip == IPV4(8, 8, 8, 8) ||
        src_ip == IPV4(8, 8, 4, 4) ||
        src_ip == IPV4(1, 1, 1, 1) ||
        src_ip == IPV4(1, 0, 0, 1);
}

/**
 * Only Cloudflare's well-documented time.cloudflare.com address is
 * included; Google Public NTP's addresses aren't hardcoded since they
 * aren't documented as stable the same way (live-resolved anycast).
 *
 * @param src_ip Source address, raw network byte order.
 *
 * @return 1 if known, 0 if not.
 */
static __always_inline int is_known_public_ntp(u32 src_ip)
{
    return src_ip == IPV4(162, 159, 200, 1);
}

#ifdef ENABLE_IPV6
/**
 * IPv6 counterparts of is_known_public_dns()/is_known_public_ntp() above
 * -- same small, high-confidence list (Google + Cloudflare's well-known
 * IPv6 anycast addresses).
 *
 * @param src_ip Source address, u32[4] raw byte order.
 */
static __always_inline int is_known_public_dns_v6(const u32 *src_ip)
{
    static const u32 google_1[4] = IPV6(0x20, 0x01, 0x48, 0x60, 0x48, 0x60, 0, 0, 0, 0, 0, 0, 0, 0, 0x88, 0x88);
    static const u32 google_2[4] = IPV6(0x20, 0x01, 0x48, 0x60, 0x48, 0x60, 0, 0, 0, 0, 0, 0, 0, 0, 0x88, 0x44);
    static const u32 cf_1[4] = IPV6(0x26, 0x06, 0x47, 0x00, 0x47, 0x00, 0, 0, 0, 0, 0, 0, 0, 0, 0x11, 0x11);
    static const u32 cf_2[4] = IPV6(0x26, 0x06, 0x47, 0x00, 0x47, 0x00, 0, 0, 0, 0, 0, 0, 0, 0, 0x10, 0x01);

    return ipv6_eq(src_ip, google_1) || ipv6_eq(src_ip, google_2) ||
        ipv6_eq(src_ip, cf_1) || ipv6_eq(src_ip, cf_2);
}

static __always_inline int is_known_public_ntp_v6(const u32 *src_ip)
{
    static const u32 cf_ntp[4] = IPV6(0x26, 0x06, 0x47, 0x00, 0, 0xf1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1);

    return ipv6_eq(src_ip, cf_ntp);
}
#endif

#ifdef ENABLE_AMP_PROTECTION

/**
 * Checks a UDP packet against known reflection/amplification patterns,
 * keyed by the packet's claimed source port (the port a reflector
 * "replies" from). An attacker picks the destination port, not us, so
 * this applies regardless of which local port received the packet.
 *
 * @param src_ip Source address, raw network byte order.
 * @param sport UDP source port, host byte order.
 * @param payload_len Bytes of UDP payload actually present.
 *
 * @return 1 if it looks like a reflection/amplification flood, 0 if not.
 */
static __always_inline int is_amp_flood(u32 src_ip, u16 sport, u32 payload_len)
{
    // DNS amplification: a real reply to a normal small query is nowhere
    // near this big; DNSSEC/ANY-query amp responses routinely are. Known
    // public resolvers are exempted since their legitimate replies can be
    // large.
    if (sport == 53)
    {
        return payload_len > 750 && !is_known_public_dns(src_ip);
    }

    // NTP amplification (monlist/peer-list): normal client-mode NTP
    // replies are ~48-90 bytes; monlist-style amp responses are far
    // larger. Known public NTP servers are exempted the same way DNS
    // resolvers are above.
    if (sport == 123)
    {
        return payload_len > 200 && !is_known_public_ntp(src_ip);
    }

    // Ports whose traffic this box never legitimately expects unsolicited,
    // regardless of size -- established reflection/amplification vectors.
    return sport == 19 ||    // chargen
        sport == 111 ||      // portmap/rpcbind
        sport == 161 ||      // SNMP
        sport == 389 ||      // CLDAP
        sport == 1900 ||     // SSDP
        sport == 11211;      // memcached
}

#ifdef ENABLE_IPV6
/**
 * Same idea as is_amp_flood() above for IPv6.
 *
 * @param src_ip Source address, u32[4] raw byte order.
 * @param sport UDP source port, host byte order.
 * @param payload_len Bytes of UDP payload actually present.
 *
 * @return 1 if it looks like a reflection/amplification flood, 0 if not.
 */
static __always_inline int is_amp_flood_v6(const u32 *src_ip, u16 sport, u32 payload_len)
{
    if (sport == 53)
    {
        return payload_len > 750 && !is_known_public_dns_v6(src_ip);
    }

    if (sport == 123)
    {
        return payload_len > 200 && !is_known_public_ntp_v6(src_ip);
    }

    return sport == 19 || sport == 111 || sport == 161 || sport == 389 ||
        sport == 1900 || sport == 11211;
}
#endif

#endif
