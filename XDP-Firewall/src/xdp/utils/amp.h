#pragma once

#include <common/all.h>

#include <xdp/utils/helpers.h>

#ifdef ENABLE_AMP_PROTECTION

/**
 * Known public DNS resolvers -- exempted from the DNS amplification size
 * check below since their legitimate replies (DNSSEC, large record sets)
 * can genuinely be large. Deliberately a small, high-confidence list
 * (Google and Cloudflare's well-known, stable anycast addresses) rather
 * than a longer one -- see README's merge notes for why this is smaller
 * than what a from-scratch build might include.
 *
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
    // near this big; DNSSEC/ANY-query amp responses routinely are.
    if (sport == 53)
    {
        return payload_len > 750 && !is_known_public_dns(src_ip);
    }

    // NTP amplification (monlist/peer-list): normal client-mode NTP
    // replies are ~48-90 bytes; monlist-style amp responses are far
    // larger. No resolver exemption here (unlike DNS) -- kept deliberately
    // conservative rather than guessing at which NTP servers are safe to
    // exempt.
    if (sport == 123)
    {
        return payload_len > 200;
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
 * Same idea as is_amp_flood() above for IPv6 -- no known-resolver
 * exemption here (kept deliberately conservative rather than guessing at
 * which IPv6 DNS/NTP servers are safe to exempt without re-verifying).
 *
 * @param sport UDP source port, host byte order.
 * @param payload_len Bytes of UDP payload actually present.
 *
 * @return 1 if it looks like a reflection/amplification flood, 0 if not.
 */
static __always_inline int is_amp_flood_v6(u16 sport, u32 payload_len)
{
    if (sport == 53)
    {
        return payload_len > 750;
    }

    if (sport == 123)
    {
        return payload_len > 200;
    }

    return sport == 19 || sport == 111 || sport == 161 || sport == 389 ||
        sport == 1900 || sport == 11211;
}
#endif

#endif
