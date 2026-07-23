#pragma once

#include <common/all.h>

#include <xdp/utils/helpers.h>

#include <linux/tcp.h>

#ifdef ENABLE_ANTI_SPOOF

/**
 * Invalid TCP flag combinations -- null/Xmas/nmap-style scans, or a
 * SYN combined with FIN/RST. No real TCP stack produces these; a normal
 * packet always has at least one sane flag set and never combines SYN
 * with FIN or RST.
 */
static __always_inline int bogus_tcp_flags(struct tcphdr *tcp)
{
    if (!tcp->syn && !tcp->ack && !tcp->fin && !tcp->rst && !tcp->psh && !tcp->urg)
    {
        return 1; // null scan
    }

    if (tcp->fin && tcp->psh && tcp->urg && !tcp->syn && !tcp->ack)
    {
        return 1; // Xmas scan
    }

    if (tcp->syn && (tcp->fin || tcp->rst))
    {
        return 1;
    }

    return 0;
}

/**
 * A real client's ephemeral UDP source port is never privileged (<1024) --
 * this shape only occurs in reflected/spoofed floods abusing a privileged
 * service's port as the apparent source. Port 53 (DNS) is exempted since
 * real server-to-server DNS legitimately uses it as a source port.
 */
static __always_inline int is_reflected_udp_source(u16 sport)
{
    return sport != 0 && sport != 53 && sport < 1024;
}

#endif
