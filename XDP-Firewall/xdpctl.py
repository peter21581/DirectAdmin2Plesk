#!/usr/bin/env python3
"""
xdpctl.py — runtime allow/block-list manager for filter.c's XDP firewall.

Adds/removes entries in the `runtime_allow` / `runtime_block` LPM-trie maps
while the XDP program keeps running — no rebuild, no reattach. Accepts a
single IP (implicit /32), a CIDR block, an ASN (resolved to its currently
announced prefixes via the RIPEstat public API), or a country code
(resolved to its aggregate CIDR blocks via ipdeny.com's public zone files).

Run ON the box where filter.c is attached. Requires bpftool and root (or
CAP_BPF). Resolving an ASN or country additionally requires outbound HTTPS
access from this box to stat.ripe.net / ipdeny.com.

CAVEAT — same as monitor.py: written and logic-tested (key byte-packing,
list parsing) against synthetic fixtures, not against a live bpftool/kernel,
since no Linux/eBPF environment was available while writing this. Run with
`list-allow`/`list-block` after adding an entry to confirm it actually
landed before trusting it in production.

Usage:
  xdpctl.py allow   <ip|cidr>       # e.g. 203.0.113.5  or  203.0.113.0/24
  xdpctl.py block   <ip|cidr>
  xdpctl.py unallow <ip|cidr>
  xdpctl.py unblock <ip|cidr>

  xdpctl.py allow-asn   <ASN>        # e.g. 15169  (or AS15169)
  xdpctl.py block-asn   <ASN>
  xdpctl.py allow-country <CC>       # e.g. US, DE, TH (ISO 3166-1 alpha-2)
  xdpctl.py block-country <CC>

  xdpctl.py list-allow
  xdpctl.py list-block
"""
import argparse
import ipaddress
import json
import re
import struct
import subprocess
import sys
import urllib.request

TAG_MANUAL = 1
TAG_ASN = 2
TAG_COUNTRY = 3
TAG_NAMES = {TAG_MANUAL: "manual", TAG_ASN: "asn", TAG_COUNTRY: "country"}

USER_AGENT = "xdpctl.py (filter.c runtime allow/block list manager)"


def run_bpftool(*args, check=True):
    try:
        return subprocess.run(
            ["bpftool", *args], capture_output=True, text=True, check=check
        )
    except FileNotFoundError:
        sys.exit(
            "bpftool not found. Install it (usually part of linux-tools-<kernel> "
            "on Debian, or bpftool on AlmaLinux) and run this on the box where "
            "filter.c is attached."
        )


def key_bytes(network):
    """Pack a struct ip_key { u32 prefixlen; u32 addr; } exactly the way
    filter.c's compiler laid it out: prefixlen first (native/little-endian
    on any real target here), then the 4 address octets in their literal
    wire order (matching the IPV4() macro convention in filter.c — NOT
    byte-swapped)."""
    net = ipaddress.ip_network(network, strict=False)
    if net.version != 4:
        raise ValueError("filter.c is IPv4-only — no IPv6 support")
    addr_bytes = net.network_address.packed  # 4 bytes, in dotted-quad order
    return struct.pack("<I", net.prefixlen) + addr_bytes


def hex_arg(b):
    """bpftool wants each byte as a separate space-separated hex token."""
    return " ".join(f"{byte:02x}" for byte in b)


def map_update(map_name, network, tag):
    kb = key_bytes(network)
    args = [
        "map", "update", "name", map_name,
        "key", "hex", *hex_arg(kb).split(),
        "value", "hex", f"{tag:02x}",
    ]
    run_bpftool(*args)
    print(f"{map_name}: added {network} (tag={TAG_NAMES[tag]})")


def map_delete(map_name, network):
    kb = key_bytes(network)
    args = ["map", "delete", "name", map_name, "key", "hex", *hex_arg(kb).split()]
    result = run_bpftool(*args, check=False)
    if result.returncode != 0:
        print(f"{map_name}: {network} was not present (or bpftool error): "
              f"{result.stderr.strip()}", file=sys.stderr)
    else:
        print(f"{map_name}: removed {network}")


def to_bytes(field):
    """Same defensive decoder as monitor.py — bpftool's JSON key/value shape
    varies by version and BTF availability."""
    if isinstance(field, bytes):
        return field
    if isinstance(field, int):
        return field.to_bytes(8, "little")
    if isinstance(field, str):
        return bytes.fromhex(field.replace("0x", ""))
    if isinstance(field, list):
        out = []
        for b in field:
            out.append(int(b, 16) if isinstance(b, str) else int(b))
        return bytes(out)
    raise TypeError(f"unrecognized bpftool field shape: {field!r}")


def list_map(map_name):
    result = run_bpftool("-j", "map", "dump", "name", map_name)
    entries = json.loads(result.stdout)
    rows = []
    for e in entries:
        key = to_bytes(e["key"])
        val = to_bytes(e["value"])
        if len(key) < 8:
            continue
        prefixlen = struct.unpack_from("<I", key, 0)[0]
        addr = key[4:8]
        tag = val[0] if val else 0
        cidr = f"{'.'.join(str(b) for b in addr)}/{prefixlen}"
        rows.append((cidr, TAG_NAMES.get(tag, f"tag{tag}")))
    if not rows:
        print(f"{map_name}: empty")
        return
    for cidr, tag in sorted(rows):
        print(f"  {cidr:<20} {tag}")


def fetch_json(url):
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    with urllib.request.urlopen(req, timeout=20) as resp:
        return json.loads(resp.read())


def fetch_text(url):
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    with urllib.request.urlopen(req, timeout=20) as resp:
        return resp.read().decode()


def resolve_asn_prefixes(asn):
    """RIPEstat's announced-prefixes API — free, public, no API key. Returns
    IPv4 CIDR strings currently announced by this ASN."""
    asn_num = re.sub(r"(?i)^as", "", str(asn))
    url = f"https://stat.ripe.net/data/announced-prefixes/data.json?resource=AS{asn_num}"
    data = fetch_json(url)
    prefixes = []
    for entry in data.get("data", {}).get("prefixes", []):
        prefix = entry.get("prefix", "")
        if ":" not in prefix:  # IPv4 only
            prefixes.append(prefix)
    return prefixes


def resolve_country_prefixes(country_code):
    """ipdeny.com's free aggregated per-country IPv4 zone files."""
    cc = country_code.lower()
    url = f"https://www.ipdeny.com/ipblocks/data/countries/{cc}.zone"
    text = fetch_text(url)
    return [line.strip() for line in text.splitlines() if line.strip()]


def cmd_single(args, map_name, tag_or_none, remove):
    if remove:
        map_delete(map_name, args.target)
    else:
        map_update(map_name, args.target, tag_or_none or TAG_MANUAL)


def cmd_bulk(args, map_name, prefixes, tag):
    if not prefixes:
        print("nothing resolved — check the ASN/country code and try again", file=sys.stderr)
        sys.exit(1)
    print(f"resolved {len(prefixes)} prefixes, adding to {map_name}...")
    for p in prefixes:
        try:
            map_update(map_name, p, tag)
        except Exception as e:  # noqa: BLE001 — keep going, report at the end
            print(f"  failed on {p}: {e}", file=sys.stderr)


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)

    for name in ("allow", "block", "unallow", "unblock"):
        p = sub.add_parser(name)
        p.add_argument("target", help="IP address or CIDR, e.g. 203.0.113.5 or 203.0.113.0/24")

    for name in ("allow-asn", "block-asn"):
        p = sub.add_parser(name)
        p.add_argument("asn", help="ASN number, e.g. 15169 or AS15169")

    for name in ("allow-country", "block-country"):
        p = sub.add_parser(name)
        p.add_argument("country", help="ISO 3166-1 alpha-2 country code, e.g. US")

    sub.add_parser("list-allow")
    sub.add_parser("list-block")

    args = ap.parse_args()

    if args.cmd == "allow":
        cmd_single(args, "runtime_allow", TAG_MANUAL, remove=False)
    elif args.cmd == "block":
        cmd_single(args, "runtime_block", TAG_MANUAL, remove=False)
    elif args.cmd == "unallow":
        cmd_single(args, "runtime_allow", None, remove=True)
    elif args.cmd == "unblock":
        cmd_single(args, "runtime_block", None, remove=True)
    elif args.cmd == "allow-asn":
        cmd_bulk(args, "runtime_allow", resolve_asn_prefixes(args.asn), TAG_ASN)
    elif args.cmd == "block-asn":
        cmd_bulk(args, "runtime_block", resolve_asn_prefixes(args.asn), TAG_ASN)
    elif args.cmd == "allow-country":
        cmd_bulk(args, "runtime_allow", resolve_country_prefixes(args.country), TAG_COUNTRY)
    elif args.cmd == "block-country":
        cmd_bulk(args, "runtime_block", resolve_country_prefixes(args.country), TAG_COUNTRY)
    elif args.cmd == "list-allow":
        list_map("runtime_allow")
    elif args.cmd == "list-block":
        list_map("runtime_block")


if __name__ == "__main__":
    main()
