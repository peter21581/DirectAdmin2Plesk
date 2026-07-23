#!/usr/bin/env python3
"""
tor-relay-sync.py -- populates ENABLE_TOR_RELAY's map_tor_known_relays /
map_tor_known_relays6 pinned BPF maps from Tor's own cached-consensus file.

Run daily via cron/a systemd timer, and once right after this program's
XDP program attaches so the set isn't empty in the meantime (see
README.md's "Tor relay (ORPort) mitigation" section for the exact
ExecStartPost hook).

Requires: bpftool, root (or CAP_BPF), and pin_maps=true in xdpfw.conf
(the default) so /sys/fs/bpf/xdpfw/map_tor_known_relays[6] exist.

Security note: the consensus file's content is attacker-influenceable (any
relay can publish itself into it), so the actual line-parsing runs as the
unprivileged user Tor itself runs as (via `runuser`), not as root -- only
the result, already re-validated as well-formed IP addresses by Python's
ipaddress module, ever reaches the privileged bpftool calls in this
process.

Usage:
  tor-relay-sync.py
  tor-relay-sync.py --tor-user debian-tor
  tor-relay-sync.py --consensus /var/lib/tor/cached-consensus
"""
import argparse
import ipaddress
import json
import struct
import subprocess
import sys

MAP_PIN_DIR = "/sys/fs/bpf/xdpfw"
TAG = 1

PARSE_AWK = r'''
/^r / { print "4", $7 }
/^a / { if (match($2, /\[[^]]+\]/)) print "6", substr($2, RSTART+1, RLENGTH-2) }
'''

DEFAULT_CONSENSUS = "/var/lib/tor/cached-consensus"
DEFAULT_TOR_USER = "debian-tor"


def run_bpftool(*args, check=True):
    try:
        return subprocess.run(["bpftool", *args], capture_output=True, text=True, check=check)
    except FileNotFoundError:
        sys.exit("bpftool not found. Install it and run this on the box where xdpfw is attached.")


def to_bytes(field):
    """bpftool's JSON key/value shape varies by version/BTF availability."""
    if isinstance(field, bytes):
        return field
    if isinstance(field, int):
        return field.to_bytes(8, "little")
    if isinstance(field, str):
        return bytes.fromhex(field.replace("0x", ""))
    if isinstance(field, list):
        return bytes(int(b, 16) if isinstance(b, str) else int(b) for b in field)
    raise TypeError(f"unrecognized bpftool field shape: {field!r}")


def hex_arg(b):
    return " ".join(f"{byte:02x}" for byte in b)


def key_bytes(ip):
    """Packs a struct lpm_trie_key { u32 prefix_len; u32 data; } (v4) or
    lpm_trie_key6 { u32 prefix_len; u32 data[4]; } (v6) -- prefix_len first
    (native/little-endian), then the address in its raw wire-order bytes
    (matching how the XDP program itself reads saddr/saddr.in6_u.u6_addr32)."""
    addr = ipaddress.ip_address(ip)
    prefix_len = 32 if addr.version == 4 else 128

    return struct.pack("<I", prefix_len) + addr.packed


def map_path(base_name, ip):
    v6 = ipaddress.ip_address(ip).version == 6
    return f"{MAP_PIN_DIR}/{base_name}6" if v6 else f"{MAP_PIN_DIR}/{base_name}"


def flush_map(pinned_path):
    result = run_bpftool("-j", "map", "dump", "pinned", pinned_path, check=False)
    if result.returncode != 0:
        return  # map not pinned (not built with ENABLE_TOR_RELAY, or pin_maps=false)
    for entry in json.loads(result.stdout):
        key = to_bytes(entry["key"])
        run_bpftool("map", "delete", "pinned", pinned_path, "key", "hex", *hex_arg(key).split(), check=False)


def add_relay(ip):
    path = map_path("map_tor_known_relays", ip)
    kb = key_bytes(ip)
    run_bpftool("map", "update", "pinned", path, "key", "hex", *hex_arg(kb).split(),
                "value", "hex", f"{TAG:02x}")


def parse_consensus(consensus_path, tor_user):
    try:
        proc = subprocess.run(
            ["runuser", "-u", tor_user, "--", "awk", PARSE_AWK, consensus_path],
            capture_output=True, text=True, check=True,
        )
    except FileNotFoundError:
        sys.exit("runuser/awk not found -- this needs to run on a real Linux box with Tor installed.")
    except subprocess.CalledProcessError as e:
        sys.exit(f"failed to read/parse {consensus_path} as {tor_user}: {e.stderr.strip()}")

    v4, v6 = [], []
    for line in proc.stdout.splitlines():
        _fam, _, addr = line.partition(" ")
        try:
            ip = ipaddress.ip_address(addr)
        except ValueError:
            continue  # malformed line from the consensus -- skip, don't trust it
        (v4 if ip.version == 4 else v6).append(str(ip))
    return v4, v6


def sync(consensus_path, tor_user):
    v4, v6 = parse_consensus(consensus_path, tor_user)
    if not v4 and not v6:
        print("no relays parsed from the consensus -- leaving existing known-relay sets untouched", file=sys.stderr)
        return 1

    flush_map(f"{MAP_PIN_DIR}/map_tor_known_relays")
    flush_map(f"{MAP_PIN_DIR}/map_tor_known_relays6")

    for ip in v4 + v6:
        add_relay(ip)

    print(f"synced {len(v4)} IPv4 + {len(v6)} IPv6 known relays")
    return 0


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--consensus", default=DEFAULT_CONSENSUS, help=f"path to Tor's cached-consensus (default: {DEFAULT_CONSENSUS})")
    ap.add_argument("--tor-user", default=DEFAULT_TOR_USER, help=f"unprivileged user Tor runs as (default: {DEFAULT_TOR_USER})")
    args = ap.parse_args()
    sys.exit(sync(args.consensus, args.tor_user))


if __name__ == "__main__":
    main()
