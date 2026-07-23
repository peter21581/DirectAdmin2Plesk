#!/usr/bin/env python3
"""
XDP anti-DDoS filter monitor — reads the BPF maps defined in filter.c via
`bpftool` and shows either a live terminal dashboard or a Prometheus
/metrics HTTP endpoint.

Requires: bpftool, root (or CAP_BPF + CAP_PERFMON) to read the maps, and
filter.c already attached (`ip link set dev <iface> xdp obj filter.o sec xdp`).
Run ON the box where the XDP program is loaded — this reads live kernel
state, not a log file.

CAVEAT — not tested against live bpftool output. This was written without
access to a Linux/eBPF environment (dev machine here is a Mac with no BPF
toolchain at all). bpftool's JSON shape for map dumps has varied a bit
across versions and depends on whether BTF debug info survived your build.
Run with --debug-raw first on the real box to see exactly what your
bpftool emits, and adjust to_bytes()/the struct formats below if it
doesn't match what's assumed here.

Usage:
  monitor.py --tui                      # live terminal dashboard (curses)
  monitor.py --once                     # single text snapshot, for scripts
  monitor.py --once --json              # single JSON snapshot
  monitor.py --serve 0.0.0.0:9107       # Prometheus /metrics HTTP endpoint
  monitor.py --debug-raw <map-name>     # dump bpftool's raw JSON for one map

Scope, on purpose:
  - This only sees what filter.c sees: INGRESS traffic. There is no
    "outgoing traffic" metric here because XDP never touches egress — use
    `ip -s link show dev <iface>` or vnstat/iftop for actual bandwidth in
    both directions.
  - "TCP state" here means only what filter.c tracks: new-connection (SYN)
    attempts and their pass/drop outcome. Real TCP state machine (ESTABLISHED,
    TIME_WAIT, etc.) is the kernel's job — use `ss -s` / `ss -tan` for that.
    filter.c deliberately does not touch established connections at all
    (that's the zero-added-latency guarantee), so there is no per-packet
    signal to show for them.
"""
import argparse
import json
import struct
import subprocess
import sys
import time

STAT_NAMES = [
    "pass", "drop", "challenge", "blackhole",  # 0-3: original aggregate counters
    "udp_pass", "udp_drop",
    "tcp_pass", "tcp_drop", "tcp_syn",
    "icmp_pass", "icmp_drop",
    "other_pass", "other_drop",
    "frag_drop", "bogon_drop", "garbage_drop", "amp_drop",
    "reflect_drop", "badflags_drop", "exploit_drop", "ratelimit_drop",
    "runtime_allow", "runtime_block",  # xdpctl.py-managed IP/CIDR/ASN/country lists
    "badsyn_len_drop", "subnet_drop", "badpayload_drop", "malformed_drop",
    "leak_drop", "unverified_drop",
]

WHITELIST_TTL_S = 180  # must match filter.c's whitelist TTL


def run_bpftool(*args):
    try:
        proc = subprocess.run(
            ["bpftool", "-j", *args], capture_output=True, text=True, check=True
        )
    except FileNotFoundError:
        sys.exit(
            "bpftool not found. Install it (usually part of linux-tools-<kernel>) "
            "and run this on the box where filter.c is attached."
        )
    except subprocess.CalledProcessError as e:
        raise RuntimeError(f"bpftool {' '.join(args)} failed: {e.stderr.strip()}")
    return json.loads(proc.stdout)


def find_map_id(name):
    maps = run_bpftool("map", "show", "name", name)
    if not maps:
        raise RuntimeError(
            f"no map named '{name}' found — is filter.c attached? "
            f"(check `ip link show dev <iface>` for an xdp prog)"
        )
    return maps[0]["id"]


def to_bytes(field):
    """bpftool's JSON represents map key/value bytes a few different ways
    depending on version and whether BTF survived the build. Normalize
    whatever we get into a plain bytes object."""
    if isinstance(field, bytes):
        return field
    if isinstance(field, int):
        return field.to_bytes(8, "little")
    if isinstance(field, str):
        return bytes.fromhex(field.replace("0x", ""))
    if isinstance(field, list):
        out = []
        for b in field:
            if isinstance(b, str):
                out.append(int(b, 16) if b.lower().startswith("0x") else int(b))
            else:
                out.append(int(b))
        return bytes(out)
    raise TypeError(f"unrecognized bpftool field shape: {field!r}")


def dump_map(name):
    return run_bpftool("map", "dump", "id", str(find_map_id(name)))


def fmt_ip(raw4):
    return ".".join(str(b) for b in raw4)


def boot_epoch():
    """bpf_ktime_get_ns() is nanoseconds since boot, not wall-clock time.
    Estimate the wall-clock moment of boot so we can show timestamps as
    'N seconds ago' / an approximate local time. A second or two of drift
    against this estimate is normal and not worth chasing."""
    with open("/proc/uptime") as f:
        uptime_s = float(f.read().split()[0])
    return time.time() - uptime_s


def read_stats():
    """stats is BPF_MAP_TYPE_PERCPU_ARRAY — sum each index across CPUs."""
    totals = [0] * len(STAT_NAMES)
    for entry in dump_map("stats"):
        idx = int.from_bytes(to_bytes(entry["key"]), "little")
        if idx >= len(totals):
            continue
        values = entry.get("values")
        if values is not None:
            total = sum(
                v["value"] if isinstance(v, dict) else int.from_bytes(to_bytes(v), "little")
                for v in values
            )
        else:
            total = int.from_bytes(to_bytes(entry["value"]), "little")
        totals[idx] = total
    return dict(zip(STAT_NAMES, totals))


def read_defense_mode():
    entries = dump_map("defense_mode")
    if not entries:
        return 0
    return int.from_bytes(to_bytes(entries[0]["value"]), "little")


def read_rl_state(now_ns):
    """rl_state: key=u32 src IP, value=struct ip_state {
      u64 window_start; u32 pkt_count; u64 blackhole_until; } — 24 bytes,
    with 4 bytes of compiler padding after pkt_count so blackhole_until
    lands on an 8-byte boundary. Format string: <QIxxxxQ (8+4+4pad+8=24)."""
    out = []
    for entry in dump_map("rl_state"):
        key = to_bytes(entry["key"])
        val = to_bytes(entry["value"])
        if len(key) < 4 or len(val) < 24:
            continue
        _window_start, pkt_count, blackhole_until = struct.unpack_from("<QIxxxxQ", val)
        out.append({
            "ip": fmt_ip(key[:4]),
            "pkt_count": pkt_count,
            "blackholed": bool(blackhole_until) and blackhole_until > now_ns,
            "blackhole_remaining_s": max(0.0, (blackhole_until - now_ns) / 1e9) if blackhole_until else 0.0,
        })
    return out


def read_whitelist(epoch):
    """whitelist: key=u32 src IP, value=u64 timestamp (ns since boot) of the
    last passed UDP challenge. filter.c only trusts entries under 180s old;
    older ones are stale leftovers still sitting in the LRU map."""
    out = []
    for entry in dump_map("whitelist"):
        key = to_bytes(entry["key"])
        val = to_bytes(entry["value"])
        if len(key) < 4 or len(val) < 8:
            continue
        ts_ns = struct.unpack_from("<Q", val)[0]
        age_s = time.time() - (epoch + ts_ns / 1e9)
        out.append({"ip": fmt_ip(key[:4]), "age_s": age_s, "trusted": 0 <= age_s < WHITELIST_TTL_S})
    return out


def snapshot():
    now_ns = 0
    try:
        with open("/proc/uptime") as f:
            now_ns = int(float(f.read().split()[0]) * 1e9)
    except OSError:
        pass
    epoch = boot_epoch()
    rl = read_rl_state(now_ns)
    wl = read_whitelist(epoch)
    return {
        "time": time.time(),
        "stats": read_stats(),
        "defense_mode": read_defense_mode(),
        "blackholed": [e for e in rl if e["blackholed"]],
        "tracked_ips": len(rl),
        "whitelisted": [e for e in wl if e["trusted"]],
    }


# ---------------------------------------------------------------- one-shot

def print_text(snap):
    s = snap["stats"]
    print(f"defense_mode: {snap['defense_mode']} (0=normal 1=elevated 2=critical)")
    print(f"pass={s['pass']} drop={s['drop']} challenge={s['challenge']} blackhole_events={s['blackhole']}")
    print(f"  udp   pass={s['udp_pass']:>10} drop={s['udp_drop']:>10}")
    print(f"  tcp   pass={s['tcp_pass']:>10} drop={s['tcp_drop']:>10}  syn_seen={s['tcp_syn']}")
    print(f"  icmp  pass={s['icmp_pass']:>10} drop={s['icmp_drop']:>10}")
    print(f"  other pass={s['other_pass']:>10} drop={s['other_drop']:>10}")
    print("  drop reasons:")
    for name in ("frag_drop", "bogon_drop", "garbage_drop", "amp_drop",
                 "reflect_drop", "badflags_drop", "exploit_drop", "ratelimit_drop",
                 "runtime_block", "badsyn_len_drop", "subnet_drop", "badpayload_drop",
                 "malformed_drop", "leak_drop", "unverified_drop"):
        print(f"    {name:<15} {s[name]}")
    print(f"runtime allowlist hits (xdpctl.py allow/allow-asn/allow-country): {s['runtime_allow']}")
    print(f"currently blackholed IPs: {len(snap['blackholed'])} (of {snap['tracked_ips']} tracked)")
    for e in sorted(snap["blackholed"], key=lambda x: -x["pkt_count"])[:20]:
        print(f"    {e['ip']:<16} pkt_count={e['pkt_count']:<8} unblocks in {e['blackhole_remaining_s']:.0f}s")
    print(f"currently whitelisted (trusted) IPs: {len(snap['whitelisted'])}")


# --------------------------------------------------------------------- TUI

def run_tui(interval):
    import curses

    def loop(stdscr):
        curses.curs_set(0)
        stdscr.nodelay(True)
        prev = None
        prev_t = None
        while True:
            snap = snapshot()
            now = snap["time"]
            stdscr.erase()
            h, w = stdscr.getmaxyx()
            row = 0

            def line(text=""):
                nonlocal row
                if row < h - 1:
                    stdscr.addnstr(row, 0, text, max(0, w - 1))
                row += 1

            s = snap["stats"]
            rate = {}
            if prev and prev_t and now > prev_t:
                dt = now - prev_t
                for k in s:
                    rate[k] = (s[k] - prev.get(k, s[k])) / dt

            def r(name):
                return f"{rate[name]:.1f}/s" if name in rate else "…"

            line(f"XDP anti-DDoS monitor — defense_mode={snap['defense_mode']} "
                 f"(0=normal 1=elevated 2=critical)   [q] quit")
            line("=" * (w - 1))
            line(f"{'':10}{'pass':>12}{'drop':>12}{'drop rate':>14}")
            line(f"{'total':10}{s['pass']:>12}{s['drop']:>12}{r('drop'):>14}")
            line(f"{'udp':10}{s['udp_pass']:>12}{s['udp_drop']:>12}{r('udp_drop'):>14}")
            line(f"{'tcp':10}{s['tcp_pass']:>12}{s['tcp_drop']:>12}{r('tcp_drop'):>14}"
                 f"   (syn_seen={s['tcp_syn']}, established traffic not counted — see --help)")
            line(f"{'icmp':10}{s['icmp_pass']:>12}{s['icmp_drop']:>12}{r('icmp_drop'):>14}")
            line(f"{'other':10}{s['other_pass']:>12}{s['other_drop']:>12}{r('other_drop'):>14}")
            line(f"challenges sent: {s['challenge']}   new blackhole events: {s['blackhole']}")
            line("")
            line("drop reasons:")
            for name in ("frag_drop", "bogon_drop", "garbage_drop", "amp_drop",
                         "reflect_drop", "badflags_drop", "exploit_drop", "ratelimit_drop",
                         "runtime_block", "badsyn_len_drop", "subnet_drop", "badpayload_drop",
                 "malformed_drop", "leak_drop", "unverified_drop"):
                line(f"  {name:<15} {s[name]:>10}  {r(name):>10}")
            line(f"runtime allowlist hits: {s['runtime_allow']:>10}  {r('runtime_allow'):>10}"
                 f"   (xdpctl.py allow/allow-asn/allow-country)")
            line("")
            bad = sorted(snap["blackholed"], key=lambda x: -x["pkt_count"])
            line(f"blackholed (bad) IPs: {len(bad)} of {snap['tracked_ips']} tracked")
            for e in bad[:max(0, h - row - 4)]:
                line(f"  {e['ip']:<16} pkt_count={e['pkt_count']:<8} unblocks in {e['blackhole_remaining_s']:.0f}s")
            line("")
            line(f"whitelisted (good, challenge-passed) IPs: {len(snap['whitelisted'])}")

            stdscr.refresh()
            prev, prev_t = s, now

            deadline = time.time() + interval
            while time.time() < deadline:
                try:
                    ch = stdscr.getch()
                except curses.error:
                    ch = -1
                if ch in (ord("q"), ord("Q")):
                    return
                time.sleep(0.05)

    curses.wrapper(loop)


# ------------------------------------------------------------- Prometheus

def render_prometheus(snap):
    s = snap["stats"]
    lines = [
        "# HELP xdp_filter_packets_total Packets seen by filter.c, by protocol/category and outcome.",
        "# TYPE xdp_filter_packets_total counter",
    ]
    for name, value in s.items():
        lines.append(f'xdp_filter_packets_total{{category="{name}"}} {value}')
    lines += [
        "# HELP xdp_filter_defense_mode Current defense mode (0=normal 1=elevated 2=critical).",
        "# TYPE xdp_filter_defense_mode gauge",
        f"xdp_filter_defense_mode {snap['defense_mode']}",
        "# HELP xdp_filter_blackholed_ips Number of source IPs currently blackholed.",
        "# TYPE xdp_filter_blackholed_ips gauge",
        f"xdp_filter_blackholed_ips {len(snap['blackholed'])}",
        "# HELP xdp_filter_tracked_ips Number of source IPs currently tracked for rate limiting.",
        "# TYPE xdp_filter_tracked_ips gauge",
        f"xdp_filter_tracked_ips {snap['tracked_ips']}",
        "# HELP xdp_filter_whitelisted_ips Number of source IPs currently trusted (passed UDP challenge).",
        "# TYPE xdp_filter_whitelisted_ips gauge",
        f"xdp_filter_whitelisted_ips {len(snap['whitelisted'])}",
    ]
    return "\n".join(lines) + "\n"


def run_server(host, port):
    from http.server import BaseHTTPRequestHandler, HTTPServer

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            if self.path != "/metrics":
                self.send_response(404)
                self.end_headers()
                return
            try:
                body = render_prometheus(snapshot()).encode()
            except Exception as e:  # noqa: BLE001 — surface any bpftool/parse error to the scrape
                self.send_response(500)
                self.end_headers()
                self.wfile.write(str(e).encode())
                return
            self.send_response(200)
            self.send_header("Content-Type", "text/plain; version=0.0.4")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, fmt, *args):
            pass  # quiet — Prometheus scrapes every few seconds

    print(f"Serving /metrics on http://{host}:{port}/metrics")
    HTTPServer((host, port), Handler).serve_forever()


# --------------------------------------------------------------------- CLI

def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--tui", action="store_true", help="live curses dashboard")
    ap.add_argument("--once", action="store_true", help="single snapshot then exit")
    ap.add_argument("--json", action="store_true", help="with --once, print JSON instead of text")
    ap.add_argument("--serve", metavar="HOST:PORT", help="serve Prometheus /metrics, e.g. 0.0.0.0:9107")
    ap.add_argument("--interval", type=float, default=2.0, help="TUI refresh interval in seconds (default 2)")
    ap.add_argument("--debug-raw", metavar="MAP_NAME", help="print bpftool's raw JSON for one map and exit")
    args = ap.parse_args()

    if args.debug_raw:
        print(json.dumps(dump_map(args.debug_raw), indent=2))
        return

    if args.serve:
        host, _, port = args.serve.partition(":")
        run_server(host or "0.0.0.0", int(port))
        return

    if args.tui:
        run_tui(args.interval)
        return

    # default: --once behavior even if the flag was omitted
    snap = snapshot()
    if args.json:
        print(json.dumps(snap, indent=2))
    else:
        print_text(snap)


if __name__ == "__main__":
    main()
