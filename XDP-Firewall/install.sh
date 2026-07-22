#!/usr/bin/env bash
# install.sh — dependency installer for filter.c (XDP anti-DDoS firewall)
# on Debian/Ubuntu and AlmaLinux/RHEL/Rocky.
#
# Installs: clang/LLVM (BPF target codegen), libbpf headers, bpftool,
# matching kernel headers, iproute2 (for `ip link ... xdp`), python3
# (monitor.py / xdpctl.py), and curl (xdpctl.py's ASN/country lookups).
#
# This only installs build/runtime dependencies. It does not build or
# attach filter.c itself — see FILTER.md for that.
#
# CAVEAT: written and reviewed for correctness, but not run end-to-end on a
# real Debian or AlmaLinux box (no such environment was available while
# writing this). Read through it before running with root privileges on a
# production box, same as you should for any installer script.

set -euo pipefail

if [ "$(id -u)" -ne 0 ]; then
  echo "Run as root (sudo $0)." >&2
  exit 1
fi

if [ ! -r /etc/os-release ]; then
  echo "Cannot detect distro: /etc/os-release not found." >&2
  exit 1
fi
. /etc/os-release

KREL="$(uname -r)"

case "${ID}:${ID_LIKE:-}" in
  debian:* | ubuntu:* | *:*debian* )
    echo "Detected Debian-family distro (${PRETTY_NAME:-$ID})."
    export DEBIAN_FRONTEND=noninteractive
    apt-get update
    apt-get install -y \
      clang llvm \
      libbpf-dev \
      bpftool \
      "linux-headers-${KREL}" \
      iproute2 \
      python3 \
      curl
    # bpftool sometimes ships as linux-tools-<kernel> instead of a standalone
    # package, depending on the Debian/Ubuntu release — fall back if the
    # plain 'bpftool' package doesn't exist.
    if ! command -v bpftool >/dev/null 2>&1; then
      echo "bpftool not on PATH after install — trying linux-tools packages..."
      apt-get install -y "linux-tools-${KREL}" linux-tools-common || \
        apt-get install -y linux-tools-generic || true
    fi
    ;;

  almalinux:* | rocky:* | rhel:* | centos:* | *:*rhel* | *:*fedora* )
    echo "Detected RHEL-family distro (${PRETTY_NAME:-$ID})."
    PKG_MGR="dnf"
    command -v dnf >/dev/null 2>&1 || PKG_MGR="yum"
    "$PKG_MGR" install -y epel-release || true
    "$PKG_MGR" install -y \
      clang llvm \
      libbpf-devel \
      bpftool \
      "kernel-devel-${KREL}" \
      iproute \
      python3 \
      curl
    if ! command -v bpftool >/dev/null 2>&1; then
      echo "bpftool not on PATH after install — trying kernel-tools..."
      "$PKG_MGR" install -y kernel-tools || true
    fi
    ;;

  * )
    echo "Unrecognized distro (ID=${ID}, ID_LIKE=${ID_LIKE:-}). This script" >&2
    echo "only knows Debian/Ubuntu and AlmaLinux/RHEL/Rocky/CentOS. Install" >&2
    echo "clang, llvm, libbpf headers, bpftool, matching kernel headers," >&2
    echo "iproute2, python3, and curl manually." >&2
    exit 1
    ;;
esac

echo
echo "Checking what actually landed:"
for bin in clang bpftool ip python3 curl; do
  if command -v "$bin" >/dev/null 2>&1; then
    printf '  %-10s OK  (%s)\n' "$bin" "$(command -v "$bin")"
  else
    printf '  %-10s MISSING — install it manually before building/running filter.c\n' "$bin"
  fi
done

echo
echo "Done. Next: see FILTER.md to build and attach filter.c."
