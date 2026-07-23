#pragma once

#include <common/int_types.h>

// Game IDs for the per-filter `game` config option (see filter_t.game_id in
// types.h). Shared between the loader (name string -> ID, see
// loader/utils/helpers.c's game_id_from_name()) and the XDP program (ID ->
// payload signature check, see xdp/utils/games.h) — keep both in sync, and
// keep GAME_PROFILES below in sync too, if you add an entry here.
enum game_id
{
    GAME_NONE = 0,
    GAME_RUST,             // RakNet OFFLINE_MESSAGE_DATA_ID handshake magic
    GAME_FIVEM,            // Same RakNet magic (FiveM/RedM build on the same base protocol as Rust)
    GAME_SOURCE_ENGINE,    // Steam A2S query, 0xFFFFFFFF prefix (CS:GO/CS2, TF2, GMod, L4D, Insurgency, etc.)
    GAME_MINECRAFT_BE,     // Same RakNet magic (Bedrock's unconnected ping)
    GAME_MINECRAFT_JAVA,   // TCP, proprietary varint handshake -- no public magic bytes, port-scope only
    GAME_SAMP,             // "SAMP" 4-byte magic
    GAME_TS3,              // TeamSpeak 3 UDP handshake preamble ("TS3INIT1")
    GAME_ARK,              // ARK: Survival Evolved -- port-scope only, no confirmed public payload signature
    GAME_SQUAD,            // port-scope only
    GAME_MORDHAU,          // port-scope only
    GAME_HLL,              // Hell Let Loose -- port-scope only
    GAME_UNTURNED,         // RakNet-based
    GAME_ALTV,             // port-scope only
    GAME_RAGNAROK,         // TCP (rAthena defaults), proprietary binary protocol -- port-scope only
    GAME_WARZ,             // RakNet-based (same magic as Rust); default port below is an UNVERIFIED best guess

    GAME_MAX
} typedef game_id_t;

#define GAME_PROTO_NONE 0
#define GAME_PROTO_UDP 1
#define GAME_PROTO_TCP 2

// A game's default profile: which protocol/port range a bare `game = "x"`
// filter option auto-fills (only into fields the user didn't already set
// explicitly -- see loader/utils/xdp.c's update_filter()), whether
// xdp/utils/games.h has a real payload signature check for it (vs. a
// port-scope-only pass-through), and whether it's eligible for the
// spoof-resistant UDP challenge/response system (only offered where the
// first-packet shape is well-understood enough to validate -- see
// xdp/utils/challenge.h). Ports here are the game's conventional/documented
// default -- always overridable per-rule in xdpfw.conf.
struct game_profile
{
    u8 protocol;
    u16 port_min;
    u16 port_max;
    u8 has_signature;
    u8 needs_challenge;
} typedef game_profile_t;

static const game_profile_t GAME_PROFILES[GAME_MAX] = {
    [GAME_NONE]           = { GAME_PROTO_NONE, 0,     0,     0, 0 },
    [GAME_RUST]           = { GAME_PROTO_UDP,  28015, 28015, 1, 1 },
    [GAME_FIVEM]          = { GAME_PROTO_UDP,  30120, 30120, 1, 1 },
    [GAME_SOURCE_ENGINE]  = { GAME_PROTO_UDP,  27015, 27015, 1, 1 },
    [GAME_MINECRAFT_BE]   = { GAME_PROTO_UDP,  19132, 19132, 1, 1 },
    [GAME_MINECRAFT_JAVA] = { GAME_PROTO_TCP,  25565, 25565, 0, 0 },
    [GAME_SAMP]           = { GAME_PROTO_UDP,  7777,  7777,  1, 1 },
    [GAME_TS3]            = { GAME_PROTO_UDP,  9987,  9987,  1, 1 },
    [GAME_ARK]            = { GAME_PROTO_UDP,  7777,  7777,  0, 0 },
    [GAME_SQUAD]          = { GAME_PROTO_UDP,  7787,  7787,  0, 0 },
    [GAME_MORDHAU]        = { GAME_PROTO_UDP,  7777,  7777,  0, 0 },
    [GAME_HLL]            = { GAME_PROTO_UDP,  7777,  7777,  0, 0 },
    [GAME_UNTURNED]       = { GAME_PROTO_UDP,  27015, 27015, 1, 1 },
    [GAME_ALTV]           = { GAME_PROTO_UDP,  7788,  7788,  0, 0 },
    [GAME_RAGNAROK]       = { GAME_PROTO_TCP,  6900,  6900,  0, 0 },
    [GAME_WARZ]           = { GAME_PROTO_UDP,  33000, 33000, 1, 1 },
};
