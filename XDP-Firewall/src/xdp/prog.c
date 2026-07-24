#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/udp.h>
#include <linux/tcp.h>
#include <linux/icmp.h>
#include <linux/icmpv6.h>
#include <linux/in.h>
#include <linux/pkt_cls.h>
#include <stdatomic.h>

#include <common/all.h>

#include <xdp/utils/rl.h>
#include <xdp/utils/rule.h>
#include <xdp/utils/stats.h>
#include <xdp/utils/helpers.h>
#include <xdp/utils/bogon.h>
#include <xdp/utils/payload.h>
#include <xdp/utils/amp.h>
#include <xdp/utils/antispoof.h>
#include <xdp/utils/icmp_protect.h>
#include <xdp/utils/adaptive_rl.h>
#include <xdp/utils/syn_protect.h>
#include <xdp/utils/tor.h>

#include <xdp/utils/maps.h>

struct 
{
    __uint(priority, 10);
    __uint(XDP_PASS, 1);
} XDP_RUN_CONFIG(xdp_prog_main);

SEC("xdp_prog")
int xdp_prog_main(struct xdp_md *ctx)
{
    // Initialize data.
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    // Retrieve stats map value.
    u32 key = 0;
    stats_t* stats = bpf_map_lookup_elem(&map_stats, &key);

    // Scan ethernet header.
    struct ethhdr *eth = data;

    // Check if the ethernet header is valid.
    if (unlikely(eth + 1 > (struct ethhdr *)data_end))
    {
        inc_pkt_stats(stats, STATS_TYPE_DROPPED);

        return XDP_DROP;
    }

    // Check Ethernet protocol.
#ifdef ENABLE_IPV6
    if (unlikely(eth->h_proto != htons(ETH_P_IP) && eth->h_proto != htons(ETH_P_IPV6)))
#else
    if (unlikely(eth->h_proto != htons(ETH_P_IP)))
#endif
    {
        inc_pkt_stats(stats, STATS_TYPE_PASSED);
        
        return XDP_PASS;
    }

    // Initialize IP headers.
    struct iphdr *iph = NULL;
    struct ipv6hdr *iph6 = NULL;
    u128 src_ip6 = 0;

    // Set IPv4 and IPv6 common variables.
    if (eth->h_proto == htons(ETH_P_IP))
    {
        iph = data + sizeof(struct ethhdr);

        if (unlikely(iph + 1 > (struct iphdr *)data_end))
        {
            inc_pkt_stats(stats, STATS_TYPE_DROPPED);

            return XDP_DROP;
        }
    }
#ifdef ENABLE_IPV6
    else
    {
        iph6 = data + sizeof(struct ethhdr);

        if (unlikely(iph6 + 1 > (struct ipv6hdr *)data_end))
        {
            inc_pkt_stats(stats, STATS_TYPE_DROPPED);

            return XDP_DROP;
        }

        memcpy(&src_ip6, iph6->saddr.in6_u.u6_addr32, sizeof(src_ip6));
    }
#endif
    
    // We only want to process TCP, UDP, and ICMP protocols.
    if ((iph && iph->protocol != IPPROTO_UDP && iph->protocol != IPPROTO_TCP && iph->protocol != IPPROTO_ICMP) || (iph6 && iph6->nexthdr != IPPROTO_UDP && iph6->nexthdr != IPPROTO_TCP && iph6->nexthdr != IPPROTO_ICMP))
    {
        inc_pkt_stats(stats, STATS_TYPE_PASSED);

        return XDP_PASS;
    }

    // Retrieve nanoseconds since system boot as timestamp.
    u64 now = bpf_ktime_get_ns();

    // Check block map.
    u64 *blocked = NULL;

    if (iph)
    {
        blocked = bpf_map_lookup_elem(&map_block, &iph->saddr);
    }
#ifdef ENABLE_IPV6
    else
    {
        blocked = bpf_map_lookup_elem(&map_block6, &src_ip6);
    }
#endif
    
    if (blocked != NULL)
    {
        if (*blocked > 0 && now > *blocked)
        {
            // Remove element from map.
            if (iph)
            {
                bpf_map_delete_elem(&map_block, &iph->saddr);
            }
#ifdef ENABLE_IPV6
            else
            {
                bpf_map_delete_elem(&map_block6, &src_ip6);
            }
#endif
        }
        else
        {
#ifdef DO_STATS_ON_BLOCK_MAP
            // Increase blocked stats entry.
            inc_pkt_stats(stats, STATS_TYPE_DROPPED);
#endif

            // They're still blocked. Drop the packet.
            return XDP_DROP;
        }
    }

#ifdef ENABLE_IP_RANGE_DROP
    if (iph && check_ip_range_drop(iph->saddr))
    {
#ifdef DO_STATS_ON_IP_RANGE_DROP_MAP
        inc_pkt_stats(stats, STATS_TYPE_DROPPED);
#endif

        return XDP_DROP;
    }
#endif

#ifdef ENABLE_BOGON_FILTER
    if (iph && is_bogon_source_v4(iph->saddr))
    {
        inc_pkt_stats(stats, STATS_TYPE_DROPPED);

        return XDP_DROP;
    }
#ifdef ENABLE_IPV6
    if (iph6 && is_bogon_source_v6(iph6->saddr.in6_u.u6_addr32))
    {
        inc_pkt_stats(stats, STATS_TYPE_DROPPED);

        return XDP_DROP;
    }
#endif
#endif

    // Parse layer-4 headers and determine source port and protocol. This
    // always runs regardless of ENABLE_FILTERS -- anti-spoof/bad-payload/
    // amplification/ICMP protection are always-on core checks (see below),
    // not something that should disappear just because dynamic filter
    // rules are compiled out for a minimal block-map-only build.
    struct tcphdr *tcph = NULL;
    struct udphdr *udph = NULL;
    struct icmphdr *icmph = NULL;

    struct icmp6hdr *icmp6h = NULL;

    // First byte after the transport header -- used by the `game` filter
    // option's payload signature check (see xdp/utils/games.h) and by the
    // bad-payload/amplification checks below.
    void *payload = NULL;

    u16 src_port = 0;

#ifdef ENABLE_FILTER_LOGGING
    u16 dst_port = 0;
#endif

    u8 protocol = 0;
    
    if (iph)
    {
        protocol = iph->protocol;

        switch (iph->protocol)
        {
            case IPPROTO_TCP:
                // Scan TCP header.
                tcph = data + sizeof(struct ethhdr) + (iph->ihl * 4);

                // Check TCP header.
                if (unlikely(tcph + 1 > (struct tcphdr *)data_end))
                {
                    inc_pkt_stats(stats, STATS_TYPE_DROPPED);

                    return XDP_DROP;
                }

                src_port = tcph->source;

#ifdef ENABLE_FILTER_LOGGING
                dst_port = tcph->dest;
#endif

                payload = (void *)tcph + (tcph->doff * 4);

#ifdef ENABLE_ANTI_SPOOF
                if (bogus_tcp_flags(tcph))
                {
                    inc_pkt_stats(stats, STATS_TYPE_DROPPED);

                    return XDP_DROP;
                }
#endif

#ifdef ENABLE_HANDSHAKE_VERIFY
                // Full TCP connection state tracking -- see config.h's
                // ENABLE_HANDSHAKE_VERIFY comment and README.md's matching
                // section before enabling this. Framed from the peer's
                // point of view (see tcp_flow_key_t's comment): on
                // ingress, the peer is always whoever sent us this packet.
                {
                    tcp_flow_key_t hs_key = {
                        .peer_ip = iph->saddr,
                        .peer_port = ntohs(tcph->source),
                        .local_port = ntohs(tcph->dest)
                    };

                    tcp_flow_state_t *hs = bpf_map_lookup_elem(&map_tcp_handshake, &hs_key);

                    if (tcph->rst)
                    {
                        // A real RST only ever belongs to a flow we're
                        // already tracking in some state -- one arriving
                        // for a completely untracked flow is either stray
                        // noise (nothing was relying on it anyway) or a
                        // spoofed RST-flood aimed at killing real
                        // connections. Drop it either way.
                        if (!hs)
                        {
                            inc_pkt_stats(stats, STATS_TYPE_DROPPED);

                            return XDP_DROP;
                        }

                        bpf_map_delete_elem(&map_tcp_handshake, &hs_key);
                    }
                    else if (tcph->fin)
                    {
                        // Same reasoning as RST above for an untracked
                        // flow. A tracked flow (any state) moves to
                        // CLOSING and gets a grace window for the rest of
                        // the close sequence (FIN-ACK, final ACK) rather
                        // than being evicted immediately -- evicting on
                        // the first FIN would reject that tail end as
                        // unverified.
                        if (!hs)
                        {
                            inc_pkt_stats(stats, STATS_TYPE_DROPPED);

                            return XDP_DROP;
                        }

                        hs->state = TCP_TRACK_CLOSING;
                        hs->ts = now;
                    }
                    else if (tcph->syn && !tcph->ack)
                    {
                        // New inbound connection attempt (we'd be the
                        // server). No state to check yet -- state gets
                        // created on OUR egress SYN-ACK reply
                        // (tcp_egress_track below), once the kernel
                        // actually decides to answer it. Falls through to
                        // the SYN-flood protection further down.
                    }
                    else
                    {
                        // Either a SYN-ACK arriving inbound (we'd be the
                        // client), the client's final handshake ACK, or a
                        // plain established-connection data/ACK packet --
                        // valid only if it belongs to a flow we're
                        // already tracking, at the right point in its
                        // lifecycle.
                        int valid = hs && (
                            hs->state == TCP_TRACK_ESTABLISHED ||
                            (hs->state == TCP_TRACK_PENDING && now - hs->ts < HANDSHAKE_TIMEOUT_NS) ||
                            (hs->state == TCP_TRACK_CLOSING && now - hs->ts < TCP_CLOSE_GRACE_NS)
                        );

                        if (!valid)
                        {
                            // No matching connection ever observed for
                            // this flow (or it timed out) -- exactly the
                            // pure-ACK-flood / unsolicited SYN-ACK shape
                            // this feature exists to catch.
                            inc_pkt_stats(stats, STATS_TYPE_DROPPED);

                            return XDP_DROP;
                        }

                        if (hs->state == TCP_TRACK_PENDING)
                        {
                            hs->state = TCP_TRACK_ESTABLISHED;
                            hs->ts = now;
                        }
                    }
                }
#endif

#ifdef ENABLE_TOR_RELAY
                // ORPort connection-flood mitigation (see config.h's
                // ENABLE_TOR_RELAY comment and xdp/utils/tor.h). Runs
                // independently of ENABLE_ADAPTIVE_RATE_LIMIT above (that
                // one budgets by packet rate; this attack is low-PPS,
                // high-connection-count, so it needs its own mechanism).
                if (ntohs(tcph->dest) == TOR_ORPORT && !is_tor_trusted_v4(iph->saddr))
                {
                    if (tcph->syn && !tcph->ack)
                    {
                        int tor_is_relay = tor_is_known_relay_v4(iph->saddr);
                        int tor_verdict = tor_conn_check_v4(iph->saddr, now, tor_is_relay);

                        if (tor_verdict != TOR_CONN_ALLOW)
                        {
                            inc_pkt_stats(stats, STATS_TYPE_DROPPED);

                            return XDP_DROP;
                        }
                    }
                    else if (tcph->fin || tcph->rst)
                    {
                        tor_conn_release_v4(iph->saddr);
                    }
                }
#endif

                break;

            case IPPROTO_UDP:
                // Scan UDP header.
                udph = data + sizeof(struct ethhdr) + (iph->ihl * 4);

                // Check UDP header.
                if (unlikely(udph + 1 > (struct udphdr *)data_end))
                {
                    inc_pkt_stats(stats, STATS_TYPE_DROPPED);

                    return XDP_DROP;
                }

                src_port = udph->source;

#ifdef ENABLE_FILTER_LOGGING
                dst_port = udph->dest;
#endif

                payload = (void *)(udph + 1);

#ifdef ENABLE_ANTI_SPOOF
                if (is_reflected_udp_source(ntohs(udph->source)))
                {
                    inc_pkt_stats(stats, STATS_TYPE_DROPPED);

                    return XDP_DROP;
                }
#endif

#ifdef ENABLE_BAD_PAYLOAD_FILTER
                if (is_ascii_garbage_flood(payload, data_end) || is_known_bad_udp_payload(payload, data_end))
                {
                    inc_pkt_stats(stats, STATS_TYPE_DROPPED);

                    return XDP_DROP;
                }
#endif

#ifdef ENABLE_AMP_PROTECTION
                if (is_amp_flood(iph->saddr, ntohs(udph->source), (u32)(data_end - payload)))
                {
                    inc_pkt_stats(stats, STATS_TYPE_DROPPED);

                    return XDP_DROP;
                }
#endif

                break;

            case IPPROTO_ICMP:
                // Scan ICMP header.
                icmph = data + sizeof(struct ethhdr) + (iph->ihl * 4);

                // Check ICMP header.
                if (unlikely(icmph + 1 > (struct icmphdr *)data_end))
                {
                    inc_pkt_stats(stats, STATS_TYPE_DROPPED);

                    return XDP_DROP;
                }

#ifdef ENABLE_ICMP_PROTECTION
                if (icmp_rate_limited_v4(iph->saddr, icmp_weight_v4(icmph), now))
                {
                    inc_pkt_stats(stats, STATS_TYPE_DROPPED);

                    return XDP_DROP;
                }
#endif

                break;
        }
    }
#ifdef ENABLE_IPV6
    else if (iph6)
    {
        protocol = iph6->nexthdr;

        switch (iph6->nexthdr)
        {
            case IPPROTO_TCP:
                // Scan TCP header.
                tcph = data + sizeof(struct ethhdr) + sizeof(struct ipv6hdr);

                // Check TCP header.
                if (unlikely(tcph + 1 > (struct tcphdr *)data_end))
                {
                    inc_pkt_stats(stats, STATS_TYPE_DROPPED);

                    return XDP_DROP;
                }

                src_port = tcph->source;

#ifdef ENABLE_FILTER_LOGGING
                dst_port = tcph->dest;
#endif

                payload = (void *)tcph + (tcph->doff * 4);

#ifdef ENABLE_ANTI_SPOOF
                if (bogus_tcp_flags(tcph))
                {
                    inc_pkt_stats(stats, STATS_TYPE_DROPPED);

                    return XDP_DROP;
                }
#endif

#ifdef ENABLE_TOR_RELAY
                if (ntohs(tcph->dest) == TOR_ORPORT && !is_tor_trusted_v6(iph6->saddr.in6_u.u6_addr32))
                {
                    if (tcph->syn && !tcph->ack)
                    {
                        int tor_is_relay = tor_is_known_relay_v6(iph6->saddr.in6_u.u6_addr32);
                        int tor_verdict = tor_conn_check_v6(src_ip6, now, tor_is_relay);

                        if (tor_verdict != TOR_CONN_ALLOW)
                        {
                            inc_pkt_stats(stats, STATS_TYPE_DROPPED);

                            return XDP_DROP;
                        }
                    }
                    else if (tcph->fin || tcph->rst)
                    {
                        tor_conn_release_v6(src_ip6);
                    }
                }
#endif

                break;

            case IPPROTO_UDP:
                // Scan UDP header.
                udph = data + sizeof(struct ethhdr) + sizeof(struct ipv6hdr);

                // Check TCP header.
                if (unlikely(udph + 1 > (struct udphdr *)data_end))
                {
                    inc_pkt_stats(stats, STATS_TYPE_DROPPED);

                    return XDP_DROP;
                }

                src_port = udph->source;

#ifdef ENABLE_FILTER_LOGGING
                dst_port = udph->dest;
#endif

                payload = (void *)(udph + 1);

#ifdef ENABLE_ANTI_SPOOF
                if (is_reflected_udp_source(ntohs(udph->source)))
                {
                    inc_pkt_stats(stats, STATS_TYPE_DROPPED);

                    return XDP_DROP;
                }
#endif

#ifdef ENABLE_BAD_PAYLOAD_FILTER
                if (is_ascii_garbage_flood(payload, data_end) || is_known_bad_udp_payload(payload, data_end))
                {
                    inc_pkt_stats(stats, STATS_TYPE_DROPPED);

                    return XDP_DROP;
                }
#endif

#ifdef ENABLE_AMP_PROTECTION
                if (is_amp_flood_v6(iph6->saddr.in6_u.u6_addr32, ntohs(udph->source), (u32)(data_end - payload)))
                {
                    inc_pkt_stats(stats, STATS_TYPE_DROPPED);

                    return XDP_DROP;
                }
#endif

                break;

            case IPPROTO_ICMPV6:
                // Scan ICMPv6 header.
                icmp6h = data + sizeof(struct ethhdr) + sizeof(struct ipv6hdr);

                // Check ICMPv6 header.
                if (unlikely(icmp6h + 1 > (struct icmp6hdr *)data_end))
                {
                    inc_pkt_stats(stats, STATS_TYPE_DROPPED);

                    return XDP_DROP;
                }

#ifdef ENABLE_ICMP_PROTECTION
                {
                    u128 icmp_src_ip6;
                    memcpy(&icmp_src_ip6, iph6->saddr.in6_u.u6_addr32, sizeof(icmp_src_ip6));

                    if (icmp_rate_limited_v6(icmp_src_ip6, icmp_weight_v6(icmp6h), now))
                    {
                        inc_pkt_stats(stats, STATS_TYPE_DROPPED);

                        return XDP_DROP;
                    }
                }
#endif

                break;
        }
    }
#endif

#ifdef ENABLE_ADAPTIVE_RATE_LIMIT
    // Always-on TCP/UDP packet budget -- catches floods that don't match
    // any of the more specific signatures above, regardless of port (see
    // config.h's ENABLE_ADAPTIVE_RATE_LIMIT comment). Known DNS/NTP
    // resolvers are exempted so legitimate resolver traffic never trips it.
    if (protocol == IPPROTO_TCP || protocol == IPPROTO_UDP)
    {
        int trusted = 0;
        u32 weight = 1;

        if (protocol == IPPROTO_UDP)
        {
            u16 sport_host = ntohs(src_port);

            if (sport_host == 53 || sport_host == 123)
            {
                if (iph)
                {
                    trusted = sport_host == 53 ? is_known_public_dns(iph->saddr) : is_known_public_ntp(iph->saddr);
                }
#ifdef ENABLE_IPV6
                else if (iph6)
                {
                    trusted = sport_host == 53
                        ? is_known_public_dns_v6(iph6->saddr.in6_u.u6_addr32)
                        : is_known_public_ntp_v6(iph6->saddr.in6_u.u6_addr32);
                }
#endif
            }
        }

#ifdef ENABLE_SYN_PROTECTION
        if (protocol == IPPROTO_TCP && tcph->syn && !tcph->ack)
        {
            // Cheapest check first, no map access: does this even look
            // like a real OS's SYN packet by size?
            if (iph && bad_syn_length_v4(iph))
            {
                inc_pkt_stats(stats, STATS_TYPE_DROPPED);

                return XDP_DROP;
            }
#ifdef ENABLE_IPV6
            else if (iph6 && bad_syn_length_v6(iph6))
            {
                inc_pkt_stats(stats, STATS_TYPE_DROPPED);

                return XDP_DROP;
            }
#endif

            // Subnet-level check before spending a per-IP map write --
            // catches a botnet spread across one block before the
            // adaptive budget below would (each IP might individually
            // stay under it).
            if (iph && subnet_syn_flood_v4(iph->saddr, now))
            {
                inc_pkt_stats(stats, STATS_TYPE_DROPPED);

                return XDP_DROP;
            }
#ifdef ENABLE_IPV6
            else if (iph6 && subnet_syn_flood_v6(src_ip6, now))
            {
                inc_pkt_stats(stats, STATS_TYPE_DROPPED);

                return XDP_DROP;
            }
#endif

            if (iph)
            {
                weight = syn_weight_v4(iph, tcph);
            }
#ifdef ENABLE_IPV6
            else if (iph6)
            {
                weight = syn_weight_v6(iph6, tcph);
            }
#endif
        }
#endif

        if (!trusted)
        {
            if (iph && adaptive_rate_limited_v4(iph->saddr, now, weight))
            {
                inc_pkt_stats(stats, STATS_TYPE_DROPPED);

                return XDP_DROP;
            }
#ifdef ENABLE_IPV6
            else if (iph6 && adaptive_rate_limited_v6(src_ip6, now, weight))
            {
                inc_pkt_stats(stats, STATS_TYPE_DROPPED);

                return XDP_DROP;
            }
#endif
        }
    }
#endif

#ifdef ENABLE_FILTERS
    // Retrieve total packet length.
    u16 pkt_len = data_end - data;

    // Update client stats (PPS/BPS).
    u64 ip_pps = 0;
    u64 ip_bps = 0;

    u64 flow_pps = 0;
    u64 flow_bps = 0;

#if defined(ENABLE_RL_IP) || defined(ENABLE_RL_FLOW)
    if (iph)
    {
#ifdef ENABLE_RL_IP
        update_ip_stats(&ip_pps, &ip_bps, iph->saddr, pkt_len, now);
#endif

#ifdef ENABLE_RL_FLOW
        update_flow_stats(&flow_pps, &flow_bps, iph->saddr, src_port, protocol, pkt_len, now);
#endif
    }
#ifdef ENABLE_IPV6
    else if (iph6)
    {
#ifdef ENABLE_RL_IP
        update_ip6_stats(&ip_pps, &ip_bps, &src_ip6, pkt_len, now);
#endif

#ifdef ENABLE_RL_FLOW
        update_flow6_stats(&flow_pps, &flow_bps, &src_ip6, src_port, protocol, pkt_len, now);
#endif
    }
#endif
#endif

    // Create rule context.
    rule_ctx_t rule = {0};
    rule.flow_pps = flow_pps;
    rule.flow_bps = flow_bps;
    rule.ip_pps = ip_pps;
    rule.ip_bps = ip_bps;
    rule.pkt_len = pkt_len;

#ifdef ENABLE_FILTER_LOGGING
    rule.now = now;
    rule.protocol = protocol;
    rule.src_port = src_port;
    rule.dst_port = dst_port;
#endif
    
    rule.iph = iph;
    
    rule.tcph = tcph;
    rule.udph = udph;
    rule.icmph = icmph;

    rule.iph6 = iph6;
    rule.icmph6 = icmp6h;

    rule.payload = payload;
    rule.data_end = data_end;

#ifdef USE_NEW_LOOP
    bpf_loop(MAX_FILTERS, process_rule, &rule, 0);
#else
#pragma unroll 30
    for (int i = 0; i < MAX_FILTERS; i++)
    {
        if (process_rule(i, &rule))
        {
            break;
        }
    }
#endif

    if (rule.matched)
    {
        goto matched;
    }
#endif

    inc_pkt_stats(stats, STATS_TYPE_PASSED);
            
    return XDP_PASS;

#ifdef ENABLE_FILTERS
matched:
#ifdef ENABLE_UDP_ACTIVE_CHALLENGE
    // Active cookie-echo challenge reply (see config.h's ENABLE_UDP_
    // ACTIVE_CHALLENGE comment and xdp/utils/challenge.h) -- rule.c
    // already decided this is needed (rule.action/block_time are also set
    // to a plain drop as a fallback in case adjust_tail below fails).
    if (rule.send_challenge && udph)
    {
        u8 src_mac[6], dst_mac[6];
        memcpy(src_mac, eth->h_source, 6);
        memcpy(dst_mac, eth->h_dest, 6);
        __be16 sport_be = udph->source, dport_be = udph->dest;
        u32 cookie = rule.challenge_cookie;

        if (iph)
        {
            u32 daddr = iph->daddr, saddr = iph->saddr;

            int new_len = (int)sizeof(*eth) + (int)sizeof(*iph) + (int)sizeof(*udph) + 4;
            int diff = new_len - (int)(data_end - data);

            if (bpf_xdp_adjust_tail(ctx, diff))
            {
                inc_pkt_stats(stats, STATS_TYPE_DROPPED);

                return XDP_DROP;
            }

            data = (void *)(long)ctx->data;
            data_end = (void *)(long)ctx->data_end;

            if (data + new_len > data_end)
            {
                return XDP_DROP;
            }

            eth = data;
            memcpy(eth->h_dest, src_mac, 6);
            memcpy(eth->h_source, dst_mac, 6);

            iph = data + sizeof(*eth);
            iph->ttl = 64;
            iph->saddr = daddr;
            iph->daddr = saddr;
            iph->tot_len = htons(sizeof(*iph) + sizeof(*udph) + 4);
            iph->check = ip_checksum(iph);

            udph = (void *)(iph + 1);
            udph->source = dport_be;
            udph->dest = sport_be;
            udph->len = htons(sizeof(*udph) + 4);
            udph->check = 0; // optional for IPv4 UDP

            u32 *cookie_out = (void *)(udph + 1);

            if ((void *)(cookie_out + 1) > data_end)
            {
                return XDP_DROP;
            }

            *cookie_out = cookie;

            inc_pkt_stats(stats, STATS_TYPE_DROPPED); // original request didn't reach the backend, replaced with a probe

            return XDP_TX;
        }
#ifdef ENABLE_IPV6
        else if (iph6)
        {
            u32 daddr6[4], saddr6[4];
            memcpy(daddr6, iph6->daddr.in6_u.u6_addr32, 16);
            memcpy(saddr6, iph6->saddr.in6_u.u6_addr32, 16);

            int new_len = (int)sizeof(*eth) + (int)sizeof(*iph6) + (int)sizeof(*udph) + 4;
            int diff = new_len - (int)(data_end - data);

            if (bpf_xdp_adjust_tail(ctx, diff))
            {
                inc_pkt_stats(stats, STATS_TYPE_DROPPED);

                return XDP_DROP;
            }

            data = (void *)(long)ctx->data;
            data_end = (void *)(long)ctx->data_end;

            if (data + new_len > data_end)
            {
                return XDP_DROP;
            }

            eth = data;
            memcpy(eth->h_dest, src_mac, 6);
            memcpy(eth->h_source, dst_mac, 6);

            iph6 = data + sizeof(*eth);
            iph6->hop_limit = 64;
            memcpy(iph6->saddr.in6_u.u6_addr32, daddr6, 16);
            memcpy(iph6->daddr.in6_u.u6_addr32, saddr6, 16);
            iph6->payload_len = htons(sizeof(*udph) + 4);
            iph6->nexthdr = IPPROTO_UDP;

            udph = (void *)(iph6 + 1);
            udph->source = dport_be;
            udph->dest = sport_be;
            udph->len = htons(sizeof(*udph) + 4);

            u32 *cookie_out = (void *)(udph + 1);

            if ((void *)(cookie_out + 1) > data_end)
            {
                return XDP_DROP;
            }

            *cookie_out = cookie;

            udph->check = udp6_checksum(iph6->saddr.in6_u.u6_addr32, iph6->daddr.in6_u.u6_addr32, udph, sizeof(*udph) + 4);

            inc_pkt_stats(stats, STATS_TYPE_DROPPED);

            return XDP_TX;
        }
#endif
    }
#endif

    if (rule.action == 0)
    {
        // Before dropping, update the block map.
        if (rule.block_time > 0)
        {
            u64 new_time = now + (rule.block_time * NANO_TO_SEC);
            
            if (iph)
            {
                bpf_map_update_elem(&map_block, &iph->saddr, &new_time, BPF_ANY);
            }
#ifdef ENABLE_IPV6
            else
            {
                bpf_map_update_elem(&map_block6, &src_ip6, &new_time, BPF_ANY);
            }
#endif      
        }

        inc_pkt_stats(stats, STATS_TYPE_DROPPED);

        return XDP_DROP;
    }
    else
    {
        inc_pkt_stats(stats, STATS_TYPE_ALLOWED);
    }

    return XDP_PASS;
#endif
}

#ifdef ENABLE_HANDSHAKE_VERIFY
// Egress half of full handshake verification (see config.h's
// ENABLE_HANDSHAKE_VERIFY comment and README.md's matching section).
// Attached as a separate TC egress hook -- NOT loaded/attached the same
// way as xdp_prog_main above; the loader does this automatically for
// builds with this flag on (see loader/utils/xdp.c's attach_tc_egress()).
// Only records state; never itself blocks anything (an operator's own
// outbound traffic should never be dropped by this program).
SEC("tc")
int tcp_egress_track(struct __sk_buff *skb)
{
    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;

    struct ethhdr *eth = data;

    if (data + sizeof(*eth) > data_end || eth->h_proto != htons(ETH_P_IP))
    {
        return TC_ACT_OK;
    }

    struct iphdr *ip = data + sizeof(*eth);

    if ((void *)(ip + 1) > data_end || ip->protocol != IPPROTO_TCP || ip->ihl < 5)
    {
        return TC_ACT_OK;
    }

    struct tcphdr *tcp = (void *)ip + (ip->ihl * 4);

    if ((void *)(tcp + 1) > data_end)
    {
        return TC_ACT_OK;
    }

    // Same key shape as the ingress side, but read from the egress
    // fields: the peer is whoever we're sending this packet to.
    tcp_flow_key_t key = {
        .peer_ip = ip->daddr,
        .peer_port = ntohs(tcp->dest),
        .local_port = ntohs(tcp->source)
    };

    if (tcp->rst)
    {
        bpf_map_delete_elem(&map_tcp_handshake, &key);

        return TC_ACT_OK;
    }

    if (tcp->fin)
    {
        // Mirrors the ingress side: move to CLOSING (grace window for
        // the rest of the close sequence) rather than deleting outright.
        // Our own outbound FIN always belongs to a flow we're already
        // tracking in some state -- if not (e.g. a connection open
        // before this program attached), there's nothing to update.
        tcp_flow_state_t *hs = bpf_map_lookup_elem(&map_tcp_handshake, &key);

        if (hs)
        {
            hs->state = TCP_TRACK_CLOSING;
            hs->ts = bpf_ktime_get_ns();
        }

        return TC_ACT_OK;
    }

    // Only a SYN (we're initiating, as a client) or a SYN-ACK (the
    // kernel's own reply, as a server, to a SYN we let through on
    // ingress) starts a new pending handshake.
    if (tcp->syn)
    {
        tcp_flow_state_t st = { .state = TCP_TRACK_PENDING, .ts = bpf_ktime_get_ns() };
        bpf_map_update_elem(&map_tcp_handshake, &key, &st, BPF_ANY);
    }

    return TC_ACT_OK;
}
#endif

char _license[] SEC("license") = "GPL";

__uint(xsk_prog_version, XDP_DISPATCHER_VERSION) SEC(XDP_METADATA_SECTION);