#pragma once

#include <common/all.h>

#include <xdp/utils/helpers.h>

// Per-game UDP/TCP payload signature checks -- the runtime-configurable
// equivalent of a compile-time GAME_* flag from the project this was merged
// with. A filter rule with `game = "rust"` (do_game/game_id in filter_t)
// requires the payload to actually match this signature, not just the
// port -- catching floods that hit the right port with garbage/empty
// payloads, which a port-only rule can't tell apart from a real client.
//
// Only signatures confirmed against public protocol documentation are
// included here (same bar used throughout this project) -- a wrong
// signature is worse than no signature. A couple of secondary/alternate
// signatures from the source this was merged with (an alternate SAMP
// magic, a bare-prefix Rust variant) were reviewed but not carried over
// since they came from one specific production config this merge no
// longer has access to re-verify against -- see README's merge notes.
//
// Each check is a fixed-size direct byte comparison rather than a generic
// length-parameterized loop -- more predictable for the BPF verifier than
// unrolling a loop whose bound only becomes constant after inlining.

/**
 * RakNet's OFFLINE_MESSAGE_DATA_ID -- the fixed magic every RakNet-based
 * game (Rust, FiveM/RedM, Minecraft Bedrock, Unturned, etc.) prefixes its
 * unconnected ping/pong and connection-request packets with. Stable across
 * the whole RakNet ecosystem, documented in RakNet's own source.
 */
static __always_inline int payload_is_raknet(void *payload, void *data_end)
{
    u8 *p = payload;

    if (p + 16 > (u8 *)data_end)
    {
        return 0;
    }

    return p[0] == 0x00 && p[1] == 0xff && p[2] == 0xff && p[3] == 0x00 &&
        p[4] == 0xfe && p[5] == 0xfe && p[6] == 0xfe && p[7] == 0xfe &&
        p[8] == 0xfd && p[9] == 0xfd && p[10] == 0xfd && p[11] == 0xfd &&
        p[12] == 0x12 && p[13] == 0x34 && p[14] == 0x56 && p[15] == 0x78;
}

/**
 * Steam's Server Query Protocol (A2S) -- every query starts with this
 * 4-byte prefix. Covers any Source-engine/Steam game (CS:GO, CS2, TF2,
 * GMod, L4D/L4D2, Insurgency, etc.).
 */
static __always_inline int payload_is_a2s(void *payload, void *data_end)
{
    u8 *p = payload;

    if (p + 4 > (u8 *)data_end)
    {
        return 0;
    }

    return p[0] == 0xff && p[1] == 0xff && p[2] == 0xff && p[3] == 0xff;
}

/**
 * TeamSpeak 3's UDP handshake preamble (client -> server INIT packet).
 */
static __always_inline int payload_is_ts3init(void *payload, void *data_end)
{
    u8 *p = payload;

    if (p + 8 > (u8 *)data_end)
    {
        return 0;
    }

    return p[0] == 'T' && p[1] == 'S' && p[2] == '3' && p[3] == 'I' &&
        p[4] == 'N' && p[5] == 'I' && p[6] == 'T' && p[7] == '1';
}

/**
 * San Andreas Multiplayer's query/handshake magic.
 */
static __always_inline int payload_is_samp(void *payload, void *data_end)
{
    u8 *p = payload;

    if (p + 4 > (u8 *)data_end)
    {
        return 0;
    }

    return p[0] == 'S' && p[1] == 'A' && p[2] == 'M' && p[3] == 'P';
}

/**
 * Checks whether a packet's payload matches the given game's known
 * protocol signature.
 *
 * @param game_id One of the game_id_t values (GAME_NONE/unknown always
 *                 matches -- callers should only invoke this when do_game
 *                 is set).
 * @param payload Pointer to the first byte after the transport header.
 * @param data_end The packet's data_end pointer (bounds check).
 *
 * @return 1 if the payload matches, 0 if not.
 */
static __always_inline int payload_matches_game(u8 game_id, void *payload, void *data_end)
{
    // No payload to check (e.g. an ICMP packet, or a rule that set `game`
    // without udp_enabled/tcp_enabled) -- can't match, and every signature
    // check below assumes a non-NULL base pointer.
    if (!payload)
    {
        return 0;
    }

    switch (game_id)
    {
        case GAME_RUST:
        case GAME_FIVEM:
        case GAME_MINECRAFT_BE:
            return payload_is_raknet(payload, data_end);

        case GAME_SOURCE_ENGINE:
            return payload_is_a2s(payload, data_end);

        case GAME_TS3:
            return payload_is_ts3init(payload, data_end);

        case GAME_SAMP:
            return payload_is_samp(payload, data_end);

        default:
            return 1;
    }
}
