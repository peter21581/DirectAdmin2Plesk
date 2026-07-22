#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/udp.h>
#include <linux/tcp.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#define RL_WINDOW_NS 1000000000ULL // 1s per-IP rate window
#define BLACKHOLE_NS 30000000000ULL // 30s auto-blackhole once an IP exceeds its limit

struct challenge {
  __u64 timestamp;
  __u32 cookie;
};

struct {
  __uint(type, BPF_MAP_TYPE_LRU_HASH);
  __type(key, __u32); // src IP (v4) ili hash za v6
  __type(value, struct challenge);
  __uint(max_entries, 1000000);
}
challenge_sent SEC(".maps");

// LRU_HASH (not per-CPU): a passed challenge must be visible to every core,
// otherwise a flow that lands on a different queue re-triggers the challenge.
struct {
  __uint(type, BPF_MAP_TYPE_LRU_HASH);
  __type(key, __u32);
  __type(value, __u64); // timestamp kad je prošao challenge
  __uint(max_entries, 2000000);
}
whitelist SEC(".maps");

// Per-IP adaptive rate limiting / blackhole state
struct ip_state {
  __u64 window_start;
  __u32 pkt_count;
  __u64 blackhole_until; // 0 = not blackholed
};

struct {
  __uint(type, BPF_MAP_TYPE_LRU_HASH);
  __type(key, __u32);
  __type(value, struct ip_state);
  __uint(max_entries, 2000000);
}
rl_state SEC(".maps");

// Defense mode: 0=normal 1=elevated 2=critical.
// Written by an external controller (userspace daemon reading `stats`,
// e.g. a Prometheus exporter) based on aggregate attack intensity.
struct {
  __uint(type, BPF_MAP_TYPE_ARRAY);
  __type(key, __u32);
  __type(value, __u32);
  __uint(max_entries, 1);
}
defense_mode SEC(".maps");

// stats[0]=pass 1=drop 2=challenge_sent 3=blackholed, for monitoring/dashboards
struct {
  __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
  __type(key, __u32);
  __type(value, __u64);
  __uint(max_entries, 4);
}
stats SEC(".maps");

static __u32 pps_limits[3] = {
  200,
  80,
  30
}; // per-IP packets/sec: normal, elevated, critical

// TeamSpeak 3 voice servers (Voxility rule: UDP 9000-10500)
#define TS3_PORT_MIN 9000
#define TS3_PORT_MAX 10500

// dport se očekuje u host redosledu (već konvertovan pozivaocem)
static inline int is_legit_port(__u16 dport) {
  if (dport == 53 || dport == 1194 || dport == 2896 || dport == 2300 || dport == 3659 || dport == 28015 || dport == 51820)
    return 1;
  if (dport >= 4970 && dport <= 4980) return 1;
  if (dport >= 7000 && dport <= 8999) return 1;
  if (dport >= TS3_PORT_MIN && dport <= TS3_PORT_MAX) return 1;
  if (dport >= 22000 && dport <= 22126) return 1;
  if (dport >= 27000 && dport <= 27500) return 1;
  if (dport >= 30000 && dport <= 32000) return 1;
  return 0;
}

// Generiše random cookie (koristi src port + time)
static inline __u32 gen_cookie(__u16 src_port, __u64 ts) {
  return bpf_get_prandom_u32() ^ src_port ^ (ts & 0xffffffff);
}

static inline void bump_stat(__u32 idx) {
  __u64 * v = bpf_map_lookup_elem( & stats, & idx);
  if (v)( * v)++;
}

// Invalid TCP flag combinations (null/xmas/nmap-style scans, stack fingerprint
// probes). No legitimate stack ever sends these — cheap bitmask, zero map access.
static inline int bogus_tcp_flags(struct tcphdr * tcp) {
  __u8 f = (tcp -> fin) | (tcp -> syn << 1) | (tcp -> rst << 2) |
    (tcp -> psh << 3) | (tcp -> ack << 4) | (tcp -> urg << 5);

  if (f == 0x00) return 1; // NULL scan
  if ((f & 0x03) == 0x03) return 1; // SYN+FIN
  if ((f & 0x05) == 0x05) return 1; // SYN+RST
  if (f == 0x01) return 1; // FIN only, no ACK
  if (f == 0x29) return 1; // FIN+PSH+URG, no ACK/SYN/RST (Xmas scan)
  if (f == 0x3f) return 1; // all flags set
  return 0;
}

// IPv4 header checksum (fixed 20-byte header, no options — consistent with
// the rest of this program which never parses IP options).
static inline __u16 ip_checksum(struct iphdr * ip) {
  __u32 csum = 0;
  __u16 * p = (__u16 * ) ip;
  ip -> check = 0;
  #pragma unroll
  for (int i = 0; i < 10; i++)
    csum += p[i];
  csum = (csum & 0xffff) + (csum >> 16);
  csum = (csum & 0xffff) + (csum >> 16);
  return ~csum;
}

// Adaptivni per-IP rate limit. Vraća 1 ako paket treba dropovati
// (blackholed ili je IP prešao limit za trenutni defense mode).
static inline int rate_limited(__u32 src_ip, __u64 now) {
  __u32 mkey = 0;
  __u32 * mode = bpf_map_lookup_elem( & defense_mode, & mkey);
  __u32 idx = 0;
  if (mode && * mode < 3) idx = * mode;
  __u32 limit = pps_limits[idx];

  struct ip_state * st = bpf_map_lookup_elem( & rl_state, & src_ip);
  if (st) {
    if (st -> blackhole_until && now < st -> blackhole_until)
      return 1;
    if (now - st -> window_start > RL_WINDOW_NS) {
      st -> window_start = now;
      st -> pkt_count = 1;
      st -> blackhole_until = 0;
      return 0;
    }
    st -> pkt_count++;
    if (st -> pkt_count > limit) {
      st -> blackhole_until = now + BLACKHOLE_NS;
      bump_stat(3);
      return 1;
    }
    return 0;
  }

  struct ip_state new_st = {
    .window_start = now,
    .pkt_count = 1,
    .blackhole_until = 0
  };
  bpf_map_update_elem( & rl_state, & src_ip, & new_st, BPF_ANY);
  return 0;
}

// Provera da li je payload "legit" za određeni protokol (prvih par bajtova)
static inline int payload_looks_legit(void * data, void * data_end, __u16 dport) {
  // DNS
  if (dport == 53) {
    if (data + 12 > data_end) return 0;
    __u16 flags = * (__u16 * )(data + 2);
    return (bpf_ntohs(flags) & 0x8000) == 0; // QR=0 (query)
  }
  // OpenVPN
  if (dport == 1194) return data + 1 <= data_end && (( * (char * ) data & 0x38) >> 3) == 7; // P_CONTROL_HARD_RESET_CLIENT_V2/3
  // Wireguard
  if (dport == 51820) return data + 4 <= data_end && * (char * ) data == 1; // type 1 handshake initiation
  // Steam A2S
  if (dport >= 27000 && dport <= 27500) return data + 4 <= data_end && * (__u32 * ) data == 0xffffffff;
  // RakNet (Rust, Unturned)
  if (dport == 28015) return data + 1 <= data_end && * (char * ) data == '\x05'; // offline message
  // TeamSpeak 3 (client-to-server handshake starts with magic "TS3INIT1")
  if (dport >= TS3_PORT_MIN && dport <= TS3_PORT_MAX)
    return data + 8 <= data_end && bpf_strncmp(data, 8, "TS3INIT1") == 0;

  if (dport == 7777 || (dport >= 7000 && dport <= 8999)) {
    if (data + 1 > data_end) return 0;
    __u8 first = * (__u8 * ) data;
    if (first == 0x01 || first == 0x02) return 1;
  }

  // AltV (obično 7788 UDP, ali i u 7000-8999 range)
  if (dport == 7788 || (dport >= 7000 && dport <= 8999)) {
    if (data + 4 <= data_end) {
      if ( * (__u32 * ) data == 0x544C41) // "ALT\0" little-endian
        return 1;
    }
  }

  // FiveM / RedM (30000-32000 UDP + TCP init)
  if (dport >= 30000 && dport <= 32000) {
    if (data + 8 <= data_end && * (__u32 * ) data == 0xffffffff) {
      char * str = (char * )(data + 4);
      if (bpf_strncmp(str, 7, "getinfo") == 0 || bpf_strncmp(str, 4, "info") == 0)
        return 1;
    }
    // FiveM connect packet
    if (data + 16 <= data_end) {
      if ( * (__u64 * ) data == 0x0000000000000000 && * (__u64 * )(data + 8) == 0x636F6E6E656374) // "connect\0"
        return 1;
    }
  }

  // Mordhau (frequently in 7000-8999 + 15000)
  if ((dport >= 7000 && dport <= 8999) || dport == 15000 || dport == 7777 || dport == 27015) {
    // Mordhau beacon: počinje sa 0x00 0x00 0x00 0x00 ili 0x01 0x00 0x00 0x00
    if (data + 4 <= data_end && * (__u32 * ) data <= 0x00000001)
      return 1;
  }

  // Squad (često 7787, 21114, 27165 itd.)
  if (dport == 7787 || dport == 21114 || dport == 27165 || (dport >= 7000 && dport <= 8999)) {
    if (data + 2 <= data_end && * (__u16 * ) data == 0x0000)
      return 1;
  }

  // Hell Let Loose
  if (dport == 8778 || dport == 27015 || (dport >= 7000 && dport <= 8999)) {
    if (data + 4 <= data_end && * (__u32 * ) data == 0x00000000)
      return 1;
  }

  // ARK: Survival Evolved (query port = gameport + 15000, npr. 7777 + 15000 = 22777)
  if (dport >= 19132 && dport <= 65535) { // ARK query portovi su visoki
    if (data + 5 <= data_end && * (__u32 * ) data == 0xffffffff && * (__u8 * )(data + 4) == 'T')
      return 1; // \xFF\xFF\xFF\xFF TSource Engine Query
  }

  // Unturned (RakNet-based, često 27015-27030)
  if (dport >= 27015 && dport <= 27030) {
    if (data + 1 <= data_end) {
      __u8 id = * (__u8 * ) data;
      // Unturned offline message ID: 0x05 - 0x0E su legit
      if (id >= 0x05 && id <= 0x0E)
        return 1;
    }
  }
  return 1; // ostali protokoli – prihvatamo prvi paket
}

SEC("xdp")
int xdp_anti_ddos(struct xdp_md * ctx) {
  void * data = (void * )(long) ctx -> data;
  void * data_end = (void * )(long) ctx -> data_end;

  struct ethhdr * eth = data;
  if (data + sizeof( * eth) > data_end) return XDP_PASS;

  if (eth -> h_proto == bpf_htons(ETH_P_IP)) {
    struct iphdr * ip = data + sizeof( * eth);
    if ((void * ) & ip[1] > data_end) return XDP_PASS;

    // Drop fragments and the reserved/"evil" bit: none of the protocols this
    // program inspects fragment legitimately, and fragmented floods are a
    // common evasion/DoS vector. Single field check, no map access.
    __u16 frag = bpf_ntohs(ip -> frag_off);
    if ((frag & 0x2000) || (frag & 0x1fff) || (frag & 0x8000)) {
      bump_stat(1);
      return XDP_DROP;
    }

    if (ip -> protocol == IPPROTO_UDP) {
      struct udphdr * udp = (void * )(ip + 1);
      if ((void * )(udp + 1) > data_end) return XDP_PASS;

      __u16 dport = bpf_ntohs(udp -> dest);

      if (!is_legit_port(dport)) return XDP_PASS; // nije naš port → kernel

      // Reflected/amplified UDP (memcached, NTP monlist, chargen, SSDP, ...)
      // always arrives from a privileged source port. Real game/voice/VPN
      // clients never use one, so this is a safe, cheap hard drop before any
      // map lookup — also means it doesn't cost latency for real traffic.
      // DNS is excluded: legitimate server-to-server DNS often uses sport 53.
      __u16 sport = bpf_ntohs(udp -> source);
      if (dport != 53 && sport != 0 && sport < 1024) {
        bump_stat(1);
        return XDP_DROP;
      }

      __u32 src_ip = ip -> saddr;
      __u64 ts = bpf_ktime_get_ns();

      // Adaptivni rate limit / auto-blackhole, pre svega ostalog
      if (rate_limited(src_ip, ts)) {
        bump_stat(1);
        return XDP_DROP;
      }

      // Proveri whitelist
      __u64 * wl_ts = bpf_map_lookup_elem( & whitelist, & src_ip);
      if (wl_ts && ts - * wl_ts < 180000000000ULL) { // 180 sekundi whitelist
        bump_stat(0);
        return XDP_PASS;
      }

      void * payload = (void * )(udp + 1);
      int legit = payload_looks_legit(payload, data_end, dport);

      // Ako je ovo odgovor na challenge (drugi paket sa istim cookie-om)
      if (data_end - payload >= 4) {
        __u32 * maybe_cookie = payload;
        struct challenge * ch = bpf_map_lookup_elem( & challenge_sent, & src_ip);
        if (ch && ch -> cookie == * maybe_cookie && ts - ch -> timestamp < 5000000000ULL) { // 5s
          bpf_map_update_elem( & whitelist, & src_ip, & ts, BPF_ANY);
          bpf_map_delete_elem( & challenge_sent, & src_ip);
          bump_stat(0);
          return XDP_PASS;
        }
      }

      // Ako payload izgleda legit → pošalji challenge
      if (legit) {
        __u32 cookie = gen_cookie(udp -> source, ts);
        struct challenge ch = {
          .timestamp = ts,
          .cookie = cookie
        };
        bpf_map_update_elem( & challenge_sent, & src_ip, & ch, BPF_ANY);

        // Napravi challenge reply in-place: skupi paket na eth+ip+udp+4-byte
        // cookie i pošalji ga nazad pošiljaocu (XDP_TX na isti interfejs).
        __u8 src_mac[6], dst_mac[6];
        __builtin_memcpy(src_mac, eth -> h_source, 6);
        __builtin_memcpy(dst_mac, eth -> h_dest, 6);
        __u32 daddr = ip -> daddr, saddr = ip -> saddr;
        __be16 sport = udp -> source, rdport = udp -> dest;

        int new_len = (int) sizeof( * eth) + (int) sizeof( * ip) + (int) sizeof( * udp) + 4;
        int diff = new_len - (int)(data_end - data);
        if (bpf_xdp_adjust_tail(ctx, diff))
          return XDP_DROP;

        data = (void * )(long) ctx -> data;
        data_end = (void * )(long) ctx -> data_end;
        if (data + new_len > data_end)
          return XDP_DROP;

        eth = data;
        __builtin_memcpy(eth -> h_dest, src_mac, 6);
        __builtin_memcpy(eth -> h_source, dst_mac, 6);

        ip = data + sizeof( * eth);
        ip -> ttl = 64;
        ip -> saddr = daddr;
        ip -> daddr = saddr;
        ip -> tot_len = bpf_htons(sizeof( * ip) + sizeof( * udp) + 4);
        ip -> check = ip_checksum(ip);

        udp = (void * )(ip + 1);
        udp -> source = rdport;
        udp -> dest = sport;
        udp -> len = bpf_htons(sizeof( * udp) + 4);
        udp -> check = 0; // dozvoljeno za IPv4 UDP

        __u32 * cookie_out = (void * )(udp + 1);
        if ((void * )(cookie_out + 1) > data_end)
          return XDP_DROP;
        * cookie_out = cookie;

        bump_stat(2);
        return XDP_TX;
      }

      bump_stat(1);
      return XDP_DROP;
    }

    if (ip -> protocol == IPPROTO_TCP) {
      if (ip -> ihl < 5) return XDP_PASS; // malformed header
      struct tcphdr * tcp = (void * ) ip + (ip -> ihl * 4); // account for IP options
      if ((void * )(tcp + 1) > data_end) return XDP_PASS;

      if (bogus_tcp_flags(tcp)) {
        bump_stat(1);
        return XDP_DROP;
      }

      // Per-IP SYN-flood protection, sve TCP portove (SSH, panel, FiveM/RedM
      // init, itd). Samo novi handshake pokušaji (SYN bez ACK) diraju mapu —
      // uspostavljene konekcije prolaze odmah, bez ikakvog dodatnog lookup-a
      // ili kašnjenja.
      if (tcp -> syn && !tcp -> ack) {
        __u32 src_ip = ip -> saddr;
        __u64 ts = bpf_ktime_get_ns();
        if (rate_limited(src_ip, ts)) {
          bump_stat(1);
          return XDP_DROP;
        }
        bump_stat(0);
      }
    }

    // ICMP flood protection (echo floods, smurf-style abuse). Shares the same
    // per-IP budget as TCP/UDP — one abusive source, one shared cap.
    if (ip -> protocol == IPPROTO_ICMP) {
      __u32 src_ip = ip -> saddr;
      __u64 ts = bpf_ktime_get_ns();
      if (rate_limited(src_ip, ts)) {
        bump_stat(1);
        return XDP_DROP;
      }
      bump_stat(0);
    }
  }

  return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
