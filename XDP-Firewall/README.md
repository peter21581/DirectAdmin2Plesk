A *stateless* firewall that attaches to the [XDP](https://www.iovisor.org/technology/xdp) hook in the Linux kernel using [(e)BPF](https://ebpf.io/) for fast packet processing.

This firewall is designed for performance and flexibility, offering features such as dynamic filtering, source IP blocking, IP range dropping, and real-time packet counters. This makes it a powerful tool for network engineers, security professionals, and anyone interested in XDP or high-performance firewalling.

I ultimately hope this tool helps existing network engineers and programmers interested in utilizing XDP or anybody interested in getting into those fields! (D)DoS protection and mitigation is an important part of Cyber Security and understanding networking concepts and packet flow at a low-to-medium level would certainly help those who are pursuing a career in the field 🙂

## 🔀 About this fork

This is a merge of [gamemann/XDP-Firewall](https://github.com/gamemann/XDP-Firewall) (MIT-licensed, see `LICENSE.md`) — its loader, `libconfig`-driven `xdpfw.conf` runtime configuration (no rebuild needed to change rules), pinned-BPF-map `xdpfw-add`/`xdpfw-del` CLI tools, systemd service, and `install.sh`/`Makefile` build system are kept essentially as-is — with game-server-focused protections ported in from a second, compile-time-flag-based XDP firewall this repository used to contain.

**Always on, no config needed** (IPv4 + IPv6, toggle each independently in `src/common/config.h` if you want to turn one off — all four are on by default):
- **Bogon source filtering** — `ENABLE_BOGON_FILTER`.
- **Anti-spoofing** — `ENABLE_ANTI_SPOOF`: invalid TCP flag combinations (null/Xmas/nmap-style scans) and reflected privileged-UDP-source-port floods.
- **UDP reflection/amplification protection** — `ENABLE_AMP_PROTECTION`, with a known-public-DNS-resolver exemption. Bundled with known-bad UDP payload / ASCII-garbage-flood detection (`ENABLE_BAD_PAYLOAD_FILTER`).
- **ICMP flood protection** — `ENABLE_ICMP_PROTECTION`, a weighted per-source-IP budget.

**Opt-in per rule** — add `game = "..."` to a `filters` entry (see [The `game` filter option](#-the-game-filter-option)):
- A payload signature check for games with a well-understood handshake (RakNet-based titles, Source-engine/Steam A2S, TeamSpeak 3, SAMP) — catches a flood that hits the right port with a garbage/empty payload, which a port-only rule can't tell apart from a real client.
- Setting `game` alone, with no `udp_enabled`/`tcp_enabled`/ports specified, auto-fills that game's conventional protocol and port — an explicit value in the rule always overrides the profile default.
- For games whose handshake is well-understood enough to validate (see the profile table below), a spoof-resistant **UDP challenge/response** system (`ENABLE_UDP_CHALLENGE`) automatically applies too — no separate toggle needed beyond picking one of those games.

**Not carried over in this merge** (documented, not silently dropped — see [Merge notes](#-merge-notes-whats-not-carried-over) at the bottom): SYN-flood OS-fingerprint weighting, Tor relay (ORPort) connection-flood mitigation, full TCP handshake verification, and the old project's Python `monitor.py` TUI/Prometheus exporter. Each is either a substantial standalone subsystem or (for the challenge/response system) was deliberately redesigned rather than ported verbatim — see below.

## 🚀 Features Overview
All features can be enabled or disabled through the build-time configuration ([`config.h`](./src/common/config.h) before compilation) or runtime configuration on disk. If you're planning to only use certain features such as the source IP block and drop functionality, it is recommended you disable other features like dynamic filtering to achieve best performance.

### 🔥 High-Performance Packet Filtering
* **XDP-Powered** - Runs at the earliest point in the network stack for **minimal latency**.
* **eBPF-Based** - Uses BPF maps for efficient rule lookups and packet processing.

### 🛑 Source IP Blocking & Dropping
* Instantly **drop packets** from known bad IP addresses.
* Uses a **BPF map** for **efficient** lookups and blocking.
* Can be managed dynamically via CLI tools (`xdpfw-add`, `xdpfw-del`).

### ⚡ Dynamic Filtering (Rule-Based)
* Define **custom rules** to allow or drop packets based on protocols, ports, IP addresses, and more!
* Supports **temporary bans** by adding IPs to the block list for a configurable duration.
* Supports **TCP, UDP, and ICMP** layer-4 protocols and **IPv6**!
* Includes both source **flow-based** and **IP-based** rate limiting!
* Ideal for mitigating **non-spoofed (D)DoS attacks**.

### 🌍 IP Range Dropping (CIDR)
* Block entire **IP subnets** efficiently at the XDP level.
* Supports **CIDR-based filtering** (e.g., `192.168.1.0/24`).
* Disabled by default but can be enabled in [`config.h`](./src/common/config.h).

### 📊 Real-Time Packet Counters
* Track **allowed, dropped, and passed** packets in real time.
* Supports **per-second statistics** for better traffic analysis.

### 📜 Logging System
* Built-in **logging** to terminal and/or a file.
* Configurable **verbosity levels** to control log output.

### 📌 Pinned Maps & CLI Utilities
* **Pinned BPF maps** allow external programs to interact with firewall rules.
* CLI utilities (`xdpfw-add`, `xdpfw-del`) enable **dynamic rule** management without restarting the firewall.
* Supports integration with **user-space security systems** for enhanced protection.

### 🎮 Game Protocol Awareness
* The `game` filter option validates the packet's actual payload against a known game protocol signature — not just its port — for 16 games/engines: Rust, FiveM/RedM, Minecraft (Bedrock + Java), any Source-engine/Steam title, SAMP, TeamSpeak 3, ARK, Squad, Mordhau, Hell Let Loose, Unturned, AltV, Ragnarok Online, and The War Z.
* Catches port-targeted floods with garbage/empty payloads that a port-only rule can't distinguish from a real client.
* Setting `game` alone auto-fills that game's conventional protocol and default port — no need to also spell out `udp_enabled`/`udp_dport` unless you want to override them.
* Enabled per-rule at runtime, no rebuild needed — see [The `game` filter option](#-the-game-filter-option).

### 🕵️ Spoof-Resistant UDP Challenge/Response
* For games with a well-understood handshake shape (see the profile table below), a source isn't trusted on its first packet alone — it has to naturally retry its own handshake (a near-universal property of connection-oriented UDP game protocols) within a plausible window before being whitelisted.
* No custom reply packet is crafted or sent — a spoofed flood essentially never re-sends from the same forged source at a real client's retry cadence, so this is enough to separate real players from noise.
* Applies automatically once `game` is set to an eligible game — see [The `game` filter option](#-the-game-filter-option).

### 🛡️ Always-On Core Protections
* **Bogon filtering** — drops packets from bogon/special-use source addresses (RFC1918, loopback, link-local, CGNAT, documentation ranges, multicast, reserved space).
* **Anti-spoofing** — drops invalid TCP flag combinations (null/Xmas/nmap-style scans) and reflected privileged-UDP-source-port floods.
* **Amplification protection** — drops oversized DNS/NTP/memcached/SSDP/chargen/CLDAP/SNMP/portmap "replies" this box never solicited, with a known-public-DNS-resolver exemption. Bundled with known-bad UDP payload / ASCII-garbage-flood detection.
* **ICMP flood protection** — a weighted per-source-IP packet budget (echo requests cost less than rarer, more-often-abusive ICMP types).
* All toggle independently in [`config.h`](./src/common/config.h) (`ENABLE_BOGON_FILTER`, `ENABLE_ANTI_SPOOF`, `ENABLE_AMP_PROTECTION`, `ENABLE_BAD_PAYLOAD_FILTER`, `ENABLE_ICMP_PROTECTION`) — **all on by default**, no `filters` rule required, and **independent of `ENABLE_FILTERS`** too: even if you compile out dynamic filter rules entirely for a minimal block-map-only build, these core protections still run. Only game/app-specific matching needs an explicit rule (and needs `ENABLE_FILTERS`, since it's implemented as a filter rule option).

## 🛠️ Building & Installing
Before building, ensure the following packages are installed. These packages can be installed with `apt` on Debian-based systems (e.g. Ubuntu, etc.), but there should be similar names in other package managers.

```bash
# Install dependencies.
sudo apt install -y libconfig-dev llvm clang libelf-dev build-essential

# Install dependencies for building LibXDP and LibBPF.
sudo apt install -y libpcap-dev m4 gcc-multilib

# You may need tools for your Linux kernel since BPFTool is required.
# If this doesn't work and you still run into issues, I'd suggest building BPFTool from source (https://github.com/libbpf/bpftool).
sudo apt install -y linux-tools-$(uname -r)
```

You can use `git` to clone this project. Make sure to include the `--recursive` flag so it downloads the XDP Tools sub-module! Otherwise, you will need to execute `git submodule update --init` while in the cloned repository's directory.

```bash
# Clone repository via Git. Use recursive flag to download XDP Tools sub-module.
git clone --recursive https://github.com/gamemann/XDP-Firewall.git

# Change directory to cloned repository.
cd XDP-Firewall
```

From here, you have two options to build and install the firewall.

### With Bash Script
The easiest way to build and install the firewall is to use the provided [`install.sh`](./install.sh) Bash script. This script relies on `sudo` being installed on your system. If you do not have sudo, please refer to the below steps on building and installing this tool without the Bash script.

If you don't have LibXDP installed on your system yet, I'd recommend using the following command.

```bash
./install.sh --libxdp
```

Otherwise, you can exclude the `--libxdp` flag if you'd like.

Additionally, here is a list of flags you may pass to this script.

| Name | Description |
| ---- | ----------- |
| --libxdp | Build and install LibXDP before building the tool. |
| --no-install | Build the tool and/or LibXDP without installing them. |
| --clean | Remove build files for the tool and LibXDP. |
| --no-static | Do *not* statically link LibXDP and LibBPF object files when building the tool. This makes the build process faster, but you may need to alter your `LD_LIBRARY_PATH` env variable before running the tool and requires LibXDP to be installed on your system already. |
| --objdump | Dumps the XDP/BPF object file using [`llvm-objdump`](https://llvm.org/docs/CommandGuide/llvm-objdump.html) to Assemby into `objdump.asm`. This is used for debugging. |
| --help | Displays help message. |


### Without Bash Script
If you do not want to use the Bash script above, you may use `make` to build and install this tool instead.

```
# Build XDP-Tools (LibXDP and LibBPF).
make libxdp

# Install LibXDP & LibBPF onto your system.
# Warning: This command must be executed as root! `sudo` should do this for you if you have it installed and have privileges.
sudo libxdp_install

# Build the firewall tool.
make

# Install the tool onto your system.
# Warning: This command must be executed as root! `sudo` should do this for you if you have it installed and have privileges.
sudo make install
```

## 💻 CLI Usage
The following command line arguments are supported when running the firewall.

| Name | Default | Description |
| ---- | ------- | ----------- |
| -c, --config | `/etc/xdpfw/xdpfw.conf` | The path to the config file. |
| -o, --offload | N/A | If set, attempts to load the XDP program in hardware/offload mode. |
| -s, --skb | N/A | If set, forces the XDP program to be loaded using SKB mode instead of DRV mode. |
| -t, --time | N/A | If set, will run the tool for this long in seconds. E.g. `--time 30` runs the tool for 30 seconds before exiting. |
| -l, --list | N/A | If set, will print the current config values and exit. |
| -h, --help | N/A | Prints a help message. |

Additionally, there are command line overrides for base config options you may include.

| Name | Example | Description |
| ---- | ------- | ----------- |
| -v, --verbose | `-v 3` | Overrides the config's verbose value. |
| --log-file | `--log-file ./test.log` | Overrides the config's log file value. |
| -i, --interface | `-i enp1s0` | Overrides the config's first interface value. |
| -p, --pin-maps | `-p 0` | Overrides the config's pin maps value. |
| -u, --update-time | `-u 30` | Overrides the config's update time value. |
| -n, --no-stats | `-n 1` | Overrides the config's no stats value. |
| --stats-ps | `--stats-ps 1` | Overrides the config's stats per second value. |
| --stdout-ut | `--stdout-ut 500` | Overrides the config's stdout update time value. |

## ⚙️ Configuration
There are two configuration methods for this firewall:

1️⃣ **Build-Time Configuration** - Modify hard-coded constants in [`config.h`](./src/common/config.h) by commenting (`//`) or uncommenting options along with setting values. Since these settings are required at build time, the firewall must be rebuilt for changes to take effect.

2️⃣ **Runtime Configuration** - Settings can also be adjusted via a configuration file stored on disk. By default, this file is located at `/etc/xdpfw/xdpfw.conf`, but you can specify a different path using the `-c` or `--config` CLI options.

The [`libconfig`](https://hyperrealm.github.io/libconfig/libconfig_manual.html) library and syntax is used when parsing the config file.

Here are more details on the layout of the runtime configuration.

### Main
| Name | Type | Default | Description |
| ---- | ---- | ------- | ----------- |
| verbose | int | `2` | The verbose level for logging (0 - 5 supported so far). |
| log_file | string | `/var/log/xdpfw.log` | The log file location. If the string is empty (`""`), the log file is disabled. |
| interface | string \| list of strings | `NULL` | The network interface(s) to attach the XDP program to (usually retrieved with `ip a` or `ifconfig`). |
| pin_maps | bool | `true` | Pins main BPF maps to `/sys/fs/bpf/xdpfw/[map_name]` on the file system. |
| update_time | int | `0` | How often to update the config and filtering rules from the file system in seconds (0 disables). |
| no_stats | bool | `false` | Whether to enable or disable packet counters. Disabling packet counters will improve performance, but result in less visibility on what the XDP Firewall is doing. |
| stats_per_second | bool | `false` | If true, packet counters and stats are calculated per second. `stdout_update_time` must be 1000 or less for this to work properly. |
| stdout_update_time | int | `1000` | How often to update `stdout` when displaying packet counters in milliseconds. |
| filters | list of filter objects | `()` | A list of filters to use with the XDP Firewall. |
| ip_drop_ranges | list of strings | `()` | A list of IP ranges (strings) to drop if the IP range drop feature is enabled. | 

### Filter Object
| Name | Type | Default | Description |
| ---- | ---- | ------- | ----------- |
| enabled | bool | `true` | Whether the rule is enabled or not. |
| log | bool | `false` | Whether to log packets that are matched. |
| action | int | `1` | The value of `0` drops or blocks the packet while `1` allows/passes the packet through. |
| block_time | int | `1` | The amount of seconds to block the source IP for if matched. |
| game | string | `NULL` | Requires the payload to match this game's real protocol signature. See [The `game` filter option](#-the-game-filter-option). |
| ip_pps | int64 | `NULL` | Matches if this threshold of packets per second is exceeded for a source IP. |
| ip_bps | int64 | `NULL` | Matches if this threshold of bytes per second is exceeded for a source IP. |
| flow_pps | int64 | `NULL` | Matches if this threshold of packets per second is exceeded for a source flow (IP and port). |
| flow_bps | int64 | `NULL` | Matches if this threshold of bytes per second is exceeded for a source flow (IP and port). |

#### IP Options
| Name | Type | Default | Description |
| ---- | ---- | ------- | ----------- |
| src_ip | string | `NULL` | The source IPv4 address to match (e.g. `10.50.0.3`). CIDRs are also supported (e.g. `10.50.0.0/24`)! |
| dst_ip | string | `NULL` | The destination IPv4 address to match (e.g. `10.50.0.4`). CIDRs are also supported (e.g. `10.50.0.0/24`)! |
| src_ip6 | string | `NULL` | The source IPv6 address to match (e.g. `fe80::18c4:dfff:fe70:d8a6`). |
| dst_ip6 | string | `NULL` | The destination IPv6 address to match (e.g. `fe80::ac21:14ff:fe4b:3a6d`). |
| min_ttl | int | `NULL` | The minimum TTL (time-to-live) to match. |
| max_ttl | int | `NULL` | The maximum TTL (time-to-live) to match. |
| min_len | int | `NULL` | The minimum packet length to match (includes the entire packet including the ethernet header and payload). |
| max_len | int | `NULL` | The maximum packet length to match (includes the entire packet including the ethernet header and payload). |
| tos | int | `NULL` | The ToS (type-of-service) to match. |

#### TCP Options
You may additionally specified TCP header options for a filter rule which start with `tcp_`.

| Name | Type | Default | Description |
| ---- | ---- | ------- | ----------- |
| tcp_enabled | bool | `false` | Whether to enable TCP on this filter rule. |
| tcp_sport | int \| string | `NULL` | The TCP source port to match with single range support (e.g., `"20-22"`). |
| tcp_dport | int \| string | `NULL` | The TCP destination port to match with single range support (e.g., `"20-22"`). |
| tcp_syn | bool | `false` | Matches if the TCP SYN flag is set. |
| tcp_ack | bool | `false` | Matches if the TCP ACK flag is set. |
| tcp_rst | bool | `false` | Matches if the TCP RST flag is set. |
| tcp_psh | bool | `false` | Matches if the TCP PSH flag is set. |
| tcp_urg | bool | `false` | Matches if the TCP URG flag is set. |
| tcp_fin | bool | `false` | Matches if the TCP FIN flag is set. |
| tcp_ece | bool | `false` | Matches if the TCP ECE flag is set. |
| tcp_cwr | bool | `false` | Matches if the TCP CWR flag is set. |

#### UDP Options
You may additionally specified UDP header options for a filter rule which start with `udp_`.

| Name | Type | Default | Description |
| ---- | ---- | ------- | ----------- |
| udp_enabled | bool | `false` | Whether to enable UDP on this filter rule. |
| udp_sport | int \| string | `NULL` | The UDP source port to match with single range support (e.g., `"27000-27015"`). |
| udp_dport | int \| string | `NULL` | The UDP destination port to match with single range support (e.g., `"27000-27015"`). |

#### ICMP Options
You may additionally specified UDP header options for a filter rule which start with `icmp_`.

| Name | Type | Default | Description |
| ---- | ---- | ------- | ----------- |
| icmp_enabled | bool | `false` | Whether to enable ICMP on this filter rule. |
| icmp_code | int | `NULL` | The ICMP code to match. |
| icmp_type | int | `NULL` | The ICMP type to match. |

#### Notes
* When a setting field inside of a filter rule is not set or if it's set to `-1` (or `NULL`), the default setting value will be used (see [`set_filter_defaults()`](https://github.com/gamemann/XDP-Firewall/blob/master/src/loader/utils/config.c#L1047)).
* When a filter rule's setting is set, but doesn't match the packet, the program moves onto the next filter rule. Therefore, all of the filter rule's settings that are set must match the packet in order to perform the action specified. Think of it as something like `if src_ip == "10.50.0.3" and udp_dport == 27015: action`. 
* As of right now, you can specify up to **1000 total** dynamic filter rules. You may increase this limit by raising the `MAX_FILTERS` constant in the `src/common/config.h` [file](https://github.com/gamemann/XDP-Firewall/blob/master/src/common/config.h#L5) and then recompile the firewall.
* At this time, each port value supports a single port range per filter rule. This is because adding support for multiple ports/port ranges would require an additional `for` loop which would make the BPF program larger and result in slower performance, etc.

### 🎮 The `game` filter option
A filter rule can require the packet's UDP/TCP payload to match a known game protocol's real signature, not just its port — catches a flood aimed at the right port with garbage or empty payload, which a port-only rule can't distinguish from a real client. This is the runtime-configurable replacement for what used to be a compile-time `GAME_*` flag in the project this feature was merged from.

The minimal form is just the game name — protocol and port are auto-filled from the game's conventional default (see the table below):

```squidconf
{
    enabled = true,
    action = 1,

    game = "rust"
}
```

...which is exactly equivalent to writing:

```squidconf
{
    enabled = true,
    action = 1,

    udp_enabled = true,
    udp_dport = 28015,

    game = "rust"
}
```

Any field you *do* specify explicitly always wins over the profile default — e.g. set your own `udp_dport` if your Rust server doesn't run on the conventional `28015`, or `udp_enabled = false` to disable protocol matching for that rule entirely while still checking the payload signature against whatever TCP/UDP traffic the rest of the rule matches. Auto-fill only ever fills in a field you left unset (`-1`/absent) — it never overrides something you wrote.

Supported values (case-insensitive), with each game's default profile:

| Value | Game(s) | Protocol | Default port | Payload signature | Challenge/response |
| ---- | ---- | ---- | ---- | ---- | ---- |
| `rust` | Rust | UDP | 28015 | RakNet `OFFLINE_MESSAGE_DATA_ID` magic (16 bytes) | Yes |
| `fivem` | FiveM / RedM | UDP | 30120 | Same RakNet magic | Yes |
| `minecraft_be` | Minecraft: Bedrock Edition | UDP | 19132 | Same RakNet magic | Yes |
| `minecraft_java` | Minecraft: Java Edition | TCP | 25565 | none (proprietary varint handshake) | No |
| `source_engine` | Any Source-engine/Steam game (CS:GO, CS2, TF2, GMod, L4D/L4D2, Insurgency, etc.) | UDP | 27015 | Steam A2S query prefix (`0xFFFFFFFF`) | Yes |
| `samp` | San Andreas Multiplayer | UDP | 7777 | `"SAMP"` 4-byte magic | Yes |
| `ts3` | TeamSpeak 3 | UDP | 9987 | `"TS3INIT1"` UDP handshake preamble | Yes |
| `ark` | ARK: Survival Evolved | UDP | 7777 | none (port-scope only) | No |
| `squad` | Squad | UDP | 7787 | none | No |
| `mordhau` | Mordhau | UDP | 7777 | none | No |
| `hll` | Hell Let Loose | UDP | 7777 | none | No |
| `unturned` | Unturned | UDP | 27015 | RakNet magic | Yes |
| `altv` | AltV | UDP | 7788 | none | No |
| `ragnarok` | Ragnarok Online (rAthena defaults) | TCP | 6900 (login; add separate rules for the 6121/5121 char/map ports) | none | No |
| `warz` | The War Z / Infestation: Survivor Stories | UDP | 33000 (**unverified** — a best-guess default, override if you know the real port) | RakNet magic | Yes |

The full list of ports/protocols/defaults lives in [`src/common/games.h`](./src/common/games.h)'s `GAME_PROFILES` table.

**Games marked "none" for payload signature are port-scope only** — `game` still auto-fills protocol/port for convenience, and still labels the rule for your own reference, but no payload validation happens (there's no publicly confirmed magic-byte signature for that game's protocol, and a wrong signature is worse than no signature — a couple of secondary/alternate signatures from the project this was merged from were reviewed and deliberately not carried over for the same reason). These games get ordinary header-based filtering plus this engine's rate-limiting/block-map protection, same as any other rule.

**FiveM's TCP side** (HTTP/NUI/asset streaming, typically ports 30000-32000) needs its own separate manual rule — don't set `game = "fivem"` on it. FiveM's profile is UDP-only (the RakNet signature check would never match real HTTP traffic and the rule would silently block everything). Just use plain `tcp_enabled`/`tcp_dport` without `game` for that rule; it still gets full header-based/rate-limit protection.

#### Spoof-resistant challenge/response
Games marked "Yes" above get an additional protection automatically: a source isn't trusted on its very first packet. The first handshake-shaped packet from a not-yet-trusted source is dropped and the source is remembered; if a **second** handshake-shaped packet arrives from that same source within a plausible retry window (100ms-5s), the source is whitelisted for `UDP_CHALLENGE_TTL` seconds (180 by default, see `config.h`) and let through from then on.

This works because real UDP game clients almost universally retry an unanswered handshake attempt on a short timeout — it's an inherent property of building a reliable-enough connection on top of unreliable UDP, not something this firewall has to know per-game. An indiscriminate spoofed-source flood essentially never re-sends from the exact same forged source at that cadence, so two sightings is enough signal.

This is a deliberately different (and safer) design than the original project's active cookie-echo challenge, which crafted and sent back a custom reply packet the real client was expected to echo. Reconstructing that exactly — correctly emulating what a real game client's network stack would treat as a valid continuation of its own handshake, for each protocol, with no compiler or test environment available to verify it — risked silently breaking every real client's connection in production if any byte-level detail was wrong. The passive "seen-twice" approach needs no crafted reply packet at all, so it can't make that mistake; the tradeoff is it's a weaker guarantee than a true cryptographic challenge (an attacker who controls a real, non-spoofed source can trivially pass it by just sending two packets) — but the actual threat model here (indiscriminate spoofed-source floods) is exactly what it's built to stop. Toggle it off entirely with `ENABLE_UDP_CHALLENGE` in `config.h` if you'd rather trust the payload signature alone.

### Runtime Example
Here's a runtime config example.

```squidconf
verbose = 5;
log_file = "";
interface = "ens18";
pin_maps = true;
update_time = 15;
no_stats = false;
stats_per_second = true;

filters = (
    {
        enabled = true,
        action = 0,

        udp_enabled = true,
        udp_dport = 27015
    },
    {
        enabled = true,
        action = 1,

        tcp_enabled = true,
        tcp_syn = true,
        tcp_dport = 27015
    },
    {
        enabled = true,
        action = 0,

        icmp_enabled = true,
        icmp_code = 0
    },
    {
        enabled = true,
        action = 0,
        src_ip = "10.50.0.4"
    }
);

ip_drop_ranges = ( "192.168.1.0/24", "10.3.0.0/24" );
```

## 🔧 The `xdpfw-add` & `xdpfw-del` Utilities
When the main BPF maps are pinned to the file system (depending on the `pin_maps` runtime option detailed above), this allows you to add or delete rules while the firewall is running using the `xdpfw-add` and `xdpfw-del` utilities.

### General CLI Usage
The following general CLI arguments are supported with these utilities.

| Name | Example | Description |
| ---- | ------- | ----------- |
| -c, --cfg | `-c ./local/conf` | The path to the configuration file (required if the save argument is specified or if you're using dynamic filters mode). |
| -s, --save | `-s` | Updates the runtime config file. |
| -m, --mode | `-m 1` | The mode to use (0 = dynamic filters, 1 = IP range drop list, 2 = source IP block list). |
| -i, --idx | `-i 3` | The index to update or delete when running in filters mode. |
| -d, --ip | `-d 192.168.1.0/24` | The IP range or source IP when running in IP range drop list or source IP block list modes. |
| -v, --v6 | `-v` | Parses and adds the IP address as IPv6 when running in source IP block list mode. |

### The `xdpfw-add` Tool
This CLI tool allows you to add dynamic rules, IP ranges to the drop list, and source IPs to the block list. I'd recommend using `xdpfw-add -h` for more information.

#### Additional CLI Usage
The following CLI arguments are supported.

| Name | Example | Description |
| ---- | ------- | ----------- |
| -e, --expires | `-e 60` | When the source IP block expires in seconds when running in IP block list mode. |
| --enabled | `--enabled 0` | Enables or disables dynamic filter. |
| --action | `--action 1` | The action to perform on packets that match the filter (0 = drop, 1 = allow). |
| --log | `--log 1` | Enables or disables logging for the dynamic filter. |
| --block-time | `--block-time 60` | How long to block the source IP for if the packet is matched and the action is drop in the dynamic filter (0 = no time). | 
| --sip | `--sip 192.168.1.0/24` | The source IPv4 address/range to match with the dynamic filter. |
| --dip | `--dip 10.90.0.0/24` | The destination IPv4 address/range to match with the dynamic filter. |
| --sip6 | `--sip6 192.168.1.0/24` | The source IPv6 address to match with the dynamic filter. |
| --dip6 | `--dip6 192.168.1.0/24` | The destination IPv6 address to match with the dynamic filter. |
| --min-ttl | `--min-ttl 0` | The IP's minimum TTL to match with the dynamic filter. |
| --max-ttl | `--max-ttl 6` | The IP's maximum TTL to match with the dynamic filter. |
| --min-len | `--min-len 42` | The packet's mimimum length to match with the dynamic filter. |
| --max-len | `--max-len 96` | The packet's maximum length to match with the dynamic filter. |
| --tos | `--tos 1` | The IP's Type of Service to match with the dynamic filter. |
| --ip-pps | `--ip-pps 10000` | The minimum PPS rate of a source IP to match with the dynamic filter. |
| --ip-bps | `--ip-bps 126000` | The minimum BPS rate of a source IP to match with the dynamic filter. |
| --flow-pps | `--flow-pps 3000` | The minimum PPS rate of a source flow to match with the dynamic filter. |
| --flow-bps | `--flow-bps 26000` | The minimum BPS rate of a source flow to match with the dynamic filter. |
| --tcp | `--tcp 1` | Enables or disables TCP matching with the dynamic filter. |
| --tsport | `--tsport 22` | The TCP source port to match with the dynamic filter. |
| --tdport | `--tdport 443` | The TCP destination port to match with the dynamic filter. |
| --urg | `--urg 1` | Enables or disables TCP URG flag matching with the dynamic filter. |
| --ack | `--ack 1` | Enables or disables TCP ACK flag matching with the dynamic filter. |
| --rst | `--rst 1` | Enables or disables TCP RST flag matching with the dynamic filter. |
| --psh | `--psh 1` | Enables or disables TCP PSH flag matching with the dynamic filter. |
| --syn | `--syn 1` | Enables or disables TCP SYN flag matching with the dynamic filter. |
| --fin | `--fin 1` | Enables or disables TCP FIN flag matching with the dynamic filter. |
| --ece | `--ece 1` | Enables or disables TCP ECE flag matching with the dynamic filter. |
| --cwr | `--cwr 1` | Enables or disables TCP CWR flag matching with the dynamic filter. |
| --udp | `--udp 1` | Enables or disables UDP matching with the dynamic filter. |
| --usport | `--usport 53` | The UDP source port to match with the dynamic filter. |
| --udport | `--udport 27015` | The UDP destination port to match with the dynamic filter. |
| --icmp | `--icmp 1` | Enables or disables ICMP matching with the dynamic filter. |
| --code | `--code 1` | The ICMP code to match with the dynamic filter. |
| --type | `--type 8` | The ICMP type to match with the dynamic filter. |

### The `xdpfw-del` Tool
This CLI tool allows you to delete dynamic rules, IP ranges from the drop list, and source IPs from the block list.

There is no additional CLI usage for this tool. Please refer to the general CLI usage above.

## 📝 Notes
### XDP Attach Modes
By default, the firewall attaches to the Linux kernel's XDP hook using **DRV** mode (AKA native; occurs before [SKB creation](http://vger.kernel.org/~davem/skb.html)). If the host's network configuration or network interface card (NIC) doesn't support DRV mode, the program will attempt to attach to the XDP hook using **SKB** mode (AKA generic; occurs after SKB creation which is where IPTables and NFTables are processed via the `netfilter` kernel module). You may use overrides through the command-line to force SKB or offload modes.

Reasons for a host's network configuration not supporting XDP's DRV mode may be the following.

* Running an outdated kernel that doesn't support your NIC's driver.
* Your NIC's driver not yet being supported. [Here's](https://github.com/iovisor/bcc/blob/master/docs/kernel-versions.md#xdp) a NIC driver XDP support list. With enough Linux kernel development knowledge, you could try implementing XDP DRV support into your non-supported NIC's driver (I'd highly recommend giving [this](https://www.youtube.com/watch?v=ayFWnFj5fY8) video a watch!).
* You don't have enough RX/TX queues (e.g. not enabling multi-queue) or your RX/TX queue counts aren't matching. From the information I gathered, it's recommended to have one RX and TX queue per CPU core/thread. You could try learning how to use [ethtool](https://man7.org/linux/man-pages/man8/ethtool.8.html) and try altering the NIC's RX/TX queue settings ([this](https://www.linode.com/docs/guides/multiqueue-nic/) article may be helpful!).

#### Offload Information
Offloading your XDP/BPF program to your system's NIC allows for the fastest packet processing you can achieve due to the NIC dropping the packets with its hardware. However, for one, there are **not** many NIC manufacturers that do support this feature **and** you're limited to the NIC's memory/processing (e.g. your BPF map sizes will be extremely limited). Additionally, there are usually stricter BPF verifier limitations for offloaded BPF programs, but you may try reaching out to the NIC's manufacturer to see if they will give you a special version of their NIC driver raising these limitations (this is what I did with one manufacturer I used).

As of this time, I am not aware of any NIC manufacturers that will be able to offload this firewall completely to the NIC due to its BPF complexity. To be honest, in the current networking age, I believe it's best to leave offloaded programs to BPF map lookups and minimum packet inspection. For example, a BPF blacklist map lookup for malicious source IPs or ports. However, XDP is still very new and I would imagine we're going to see these limitations loosened or lifted in the next upcoming years. This is why I added support for offload mode on this firewall. 

### BPF Loop Support + Performance Notes
The dynamic filter rules feature requires general loop support along with support for the [`bpf_loop()`](https://docs.ebpf.io/linux/helper-function/bpf_loop/) function. Older kernels will not support general loops and output an error such as the following.

```vim
libbpf: load bpf program failed: Invalid argument
libbpf: -- BEGIN DUMP LOG ---
libbpf:
back-edge from insn 113 to 100

libbpf: -- END LOG --
libbpf: failed to load program 'xdp_prog'
libbpf: failed to load object '/etc/xdpfwd/xdp_prog.o'
```

It looks like general BPF loop [support](https://lwn.net/Articles/794934/) was added in kernel 5.3. Therefore, you'll need kernel 5.3 or above for this tool to run properly.

With that said, the `bpf_loop()` function was added in kernel `5.17`, but *may* still require `6.4` or above due to support for open coded iterators. If you do not wish to upgrade your kernel to 6.4 or above, you will need to disable/comment out the `USE_NEW_LOOP` constant in the [`config.h`](./src/common/config.h) file. Please note if you do this, you will be **extremely limited** in how many filter rules you can create at once (I recommend up to 60). Therefore, it is recommended you use `bpf_loop()` since you will be able to create many more filter rules (over 1000)!

#### Performance With Loops & Dynamic Filters
Due to the usage of a [`for` loop](https://github.com/gamemann/XDP-Firewall/blob/master/src/xdp/prog.c#L339) inside the XDP program that handles looping through all filtering rules inside of a BPF array map, performance will be impacted depending on how many filtering rules you have configured (ultimately, the firewall **doesn't scale** that well). This firewall was designed to be as flexible as possible regarding configuration and is most effective when configured to add malicious source IPs to the block map for a certain amount of time which are then dropped at the beginning of the XDP program for the best performance.

Unfortunately, we can't really eliminate the `for` loop with the current amount of flexibility we allow (especially minimum/maximum TTL, packet lengths, IDs, etc.), unless if we were to create more BPF maps and insert many more entries which would result in a lot more memory consumed and isn't ideal at all. If we were to remove flexibility, the best approach would be to store filtering rules inside a hashed BPF map using the packet's destination IP/port as the entry's key in my opinion (this would then eliminate flexibility related to being able to specify a filtering rule to match against a single destination IP without a port, unless if we implemented multiple BPF map lookups inside the XDP program which would then impact performance). However, there are currently no plans to switch to this format due to the amount of flexibility lost and also not having the time on my side (if somebody else creates a PR to implement this, I'd be willing to have a separate branch with the new functionality for others to use if the current branch isn't working out for their needs).

The firewall is still decent at filtering non-spoofed attacks, especially when a block time is specified so that malicious IPs are filtered at the beginning of the program for some time.

### Rate Limiting
This firewall supports both source **flow-based** (`flow_pps` and `flow_bps` settings) and **IP-based** (`ip_pps` and `ip_bps` settings) rate limiting. However, source IP-based rate limiting is disabled by default and can be enabled inside of the [`config.h`](https://github.com/gamemann/XDP-Firewall/blob/master/src/common/config.h#L40) file.

The reason source IP-based rate limiting is disabled by default is because both methods require seperate calculations which isn't ideal if both methods aren't used inside of filter rules. I've found most users prefer flow-based rate limiting which is why I decided to only enable that by default.

Additionally, if you're encountering a large amount of spoofed packets, it is **highly recommended** that you disable rate limiting entirely, at least temporarily until you stop receiving the spoofed packets. This is because a large amount of spoofed packets from different IPs and ports will cause the rate limit BPF maps to rapidly recycle entries and this can cause very high CPU usage depending on how many spoofed packets are being sent and the host's hardware.

### Filter Logging
This tool uses `bpf_ringbuf_reserve()` and `bpf_ringbuf_submit()` for filter match logging. At this time, there is no rate limit for the amount of log messages that may be sent. Therefore, if you're encountering a spoofed attack that is matching a filter rule with logging enabled, it will cause additional processing and disk load.

I recommend only enabling filter logging at this time for debugging. If you'd like to disable filter logging entirely (which will improve performance slightly), you may comment out the `ENABLE_FILTER_LOGGING` line [here](https://github.com/gamemann/XDP-Firewall/blob/master/src/common/config.h#L32).

```C
//#define ENABLE_FILTER_LOGGING
```

I will most likely implement functionality to rate limit log messages from XDP in the future.

### LibBPF Logging
When loading the BPF/XDP program through LibXDP/LibBPF, logging is disabled unless if the `verbose` log setting is set to `5` or higher.

If the tool fails to load or attach the XDP program, it is recommended you set `verbose` to 5 or above so LibXDP outputs specific warnings and errors.

## ❓ F.A.Q.
### I receive an error related to failing to load shared libraries. How do I fix this?
If you receive an error similar to the one below when running the program and have built the program using the no static option, make sure you have LibXDP globally installed onto your system via [XDP Tools](https://github.com/xdp-project/xdp-tools). You can execute `make libxdp && sudo make libxdp_install` to build and install both LibXDP and LibBPF onto your system separately.

```bash
./xdpfw: error while loading shared libraries: libxdp.so.1: cannot open shared object file: No such file or directory
```

If you still run into issues, try adding `/usr/local/lib` to your `LD_LIBRARY_PATH` since that's where LibXDP installs the shared objects from my testing. Here's an example.

```bash
export LD_LIBRARY_PATH=/usr/local/lib

sudo xdpfw
```

### I receive an error related to toolchain hardening. How do I fix this?
As stated in issue [#38](https://github.com/gamemann/XDP-Firewall/issues/38) by [g00g1](https://github.com/g00g1), if you have toolchain hardening enabled, you may receive the following error when compiling.

```
error: <unknown>:0:0: in function xdp_prog_main i32 (ptr): A call to built-in function '__stack_chk_fail' is not supported.
```

In order to fix this, you'll need to pass the `-fno-stack-protector` flag to Clang when building LibBPF and the firewall itself. You'll want to modify the `Makefile` for each project to add this flag. Patches for this may be found [here](https://github.com/gamemann/XDP-Firewall/issues/38#issuecomment-1547965524)!

### I have issues running the firewall on Ubuntu 20.04. What could be the cause?
If you have issues on Ubuntu 20.04 or earlier, please refer to the reply on [this](https://github.com/gamemann/XDP-Firewall/issues/41#issuecomment-1758701008) issue.

Basically, Clang/LLVM 12 or above is required and I'd recommend running Linux kernel 5.3 or above.

### Will you make this firewall stateful?
At this time, there are no plans to make this firewall stateful. There is a chance I may make a separate firewall with basic connection tracking, but I have no ETA on that and haven't started its development. With that said, I cannot share code for things like layer-7 filters or a full TCP proxy with SYN cookies support.

## 🌟 My Other XDP Projects
I just wanted to share other open source projects I've made which also utilize XDP and AF_XDP sockets for those interested. I hope code from these other projects help programmers trying to utilize XDP in their own projects!

### [XDP Proxy](https://github.com/gamemann/XDP-Proxy)
A *stateless*, high-performance NAT-like proxy that uses **source-port mapping**, similar to [IPTables](https://linux.die.net/man/8/iptables) and [NFTables](https://wiki.nftables.org/wiki-nftables/index.php/Main_Page), to forward packets to different destination IPs and ports based on configurable rules.


### [XDP Stats](https://github.com/gamemann/xdpstats-rs)
A packet and byte counting tool that utilizes XDP and AF_XDP sockets for calculating stats. This project is used for benchmarking and testing XDP programs and AF_XDP socket performance.


### [Packet Batch (AF_XDP)](https://github.com/Packet-Batch/pktbatch-rs)
A tool that generates and sends packets using technologies such as **fast [AF_XDP](https://docs.kernel.org/networking/af_xdp.html) Linux sockets**. This is used for penetration testing including [Denial of Service](https://www.cloudflare.com/learning/ddos/glossary/denial-of-service/) (DoS), network monitoring, and more!


### [Kilimanjaro](https://github.com/gamemann/Kilimanjaro)
This is a complex packet processing/forwarding/dropping project I made for a gaming community I was a part of that utilizes XDP, AF_XDP, and the IPIP network protocol. I no longer work on/maintain the project, but the source code may be very helpful to other XDP developers, especially when it comes to manipulating packets inside of XDP and such.

## 🔀 Merge notes: what's not carried over
The compile-time-flag-based firewall this repo used to be (single `filter.c`, no runtime config) had a few subsystems that are **still not** ported into this merge — each is either a substantial, standalone piece of state/logic in its own right, or (for the UDP challenge/response system) was deliberately redesigned rather than ported verbatim. Tracked as follow-up work, not silently dropped:

* **Spoof-resistant UDP challenge/response was reimplemented, not ported verbatim.** The old design sent a crafted cookie-echo reply packet (`XDP_TX`) and expected the real client to echo it back — reconstructing that exactly from memory, with no compiler or test environment to verify it, risked silently breaking every real client's connection if any protocol-level detail was wrong. This merge instead uses a passive "seen-twice within a plausible retry window" validator — see [The `game` filter option](#-the-game-filter-option)'s "Spoof-resistant challenge/response" section for the full design rationale and its tradeoffs versus the original active-challenge approach.
* **SYN-flood OS-fingerprint weighting.** The old design gave a cheaper per-IP rate-limit "cost" to SYN packets shaped like a real Windows client and a stricter cost to implausible ones, on top of a flat pps/bps threshold. This engine's `ip_pps`/`flow_pps` rate limiting is flat-cost per packet; weighting would need a change to how `update_ip_stats()`/`update_flow_stats()` account for a packet — a change to the core rate-limiting accounting shared by every filter rule, not a self-contained addition like the other protections in this merge.
* **Tor relay (ORPort) connection-flood mitigation.** A dual time-window new-connection-rate blacklist plus a live concurrent-connection cap, tuned for a specific low-packet-rate/high-connection-count attack pattern against Tor relays. This is deployment-specific (not a "game" or generic protection) and would need its own maps and its own companion sync script (to populate a known-relay allowlist from Tor's consensus) — a bigger, more self-contained follow-up than something to bolt on here.
* **Full TCP handshake verification.** Rejecting any non-SYN TCP packet whose flow never had a real SYN → SYN-ACK → ACK observed (catches pure ACK-floods). Needs a second, TC-egress-hook BPF program (this engine is XDP-ingress-only) sharing a flow-state map with the main program, plus a loader-side second attach step. Was optional/off-by-default even in the old design due to its own explicit performance tradeoffs (a map lookup on every established-connection packet).
* **`monitor.py`'s TUI dashboard and Prometheus exporter.** This engine's loader already prints live stats to stdout and every protection in this merge shows up in the same `map_stats` counters, but there's no live curses dashboard or `/metrics` HTTP endpoint here yet.
* **A few secondary payload signatures** from the old design (an alternate 2-byte SAMP magic, a bare Source-engine-style Rust query prefix, two additional flood-tool fingerprints beyond the `"flood"` string) were reviewed but not carried over — they came from one specific production config the old design was ported from, which this merge no longer has access to re-verify against. A wrong signature is worse than no signature. Several games (see the `game` option's table above) are intentionally port-scope-only for the same reason — no publicly confirmed payload signature to check.
* **IPv6 known-DNS/NTP-resolver exemption** for `ENABLE_AMP_PROTECTION` — the IPv4 path exempts Google/Cloudflare's well-known resolvers from the size-based DNS check; the IPv6 path is deliberately conservative (no exemption at all) rather than guessing at IPv6 resolver addresses without re-verifying them.
* **Not compiled or verifier-tested.** Same caveat as this whole project always carries: this merge's new code (`xdp/utils/games.h`, `bogon.h`, `payload.h`, `amp.h`, `antispoof.h`, `icmp_protect.h`, `challenge.h`, and the `filter_t`/config-parsing/`update_filter()` changes) was written and reasoned through carefully, but there is no Linux/eBPF/`libconfig` toolchain available in the environment it was written in. Build it (`make`) and check `dmesg`/the BPF verifier output on a real box before relying on it in production.

## 🙌 Credits
* [Christian Deacon](https://github.com/gamemann) - Creator of the original XDP-Firewall this was merged with.
* [Phil](https://github.com/Nasty07) - Contributor to the original XDP-Firewall.
