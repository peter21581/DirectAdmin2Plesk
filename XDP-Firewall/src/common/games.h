#pragma once

// Game IDs for the per-filter `game` config option (see filter_t.game_id in
// types.h). Shared between the loader (name string -> ID, see
// loader/utils/games.c) and the XDP program (ID -> payload signature check,
// see xdp/utils/games.h) — keep both in sync if you add an entry here.
enum game_id
{
    GAME_NONE = 0,
    GAME_RUST,           // RakNet OFFLINE_MESSAGE_DATA_ID handshake magic
    GAME_FIVEM,          // Same RakNet magic (FiveM/RedM build on the same base protocol as Rust)
    GAME_SOURCE_ENGINE,  // Steam A2S query, 0xFFFFFFFF prefix (CS:GO/CS2, TF2, GMod, L4D, Insurgency, etc.)
    GAME_MINECRAFT_BE,   // Same RakNet magic (Bedrock's unconnected ping)
    GAME_SAMP,           // "SAMP" 4-byte magic
    GAME_TS3,            // TeamSpeak 3 UDP handshake preamble ("TS3INIT1")

    GAME_MAX
} typedef game_id_t;
