#pragma once

#include <common/all.h>

#include <xdp/utils/helpers.h>

#ifdef ENABLE_BAD_PAYLOAD_FILTER

/**
 * Checks whether a UDP payload's first bytes are all printable ASCII -- the
 * signature shape of chargen-reflection floods and generic junk-padded UDP
 * floods. No supported game protocol here opens with plain text (they all
 * start with binary magic bytes -- see xdp/utils/games.h).
 *
 * @param payload Pointer to the first byte after the UDP header.
 * @param data_end The packet's data_end pointer.
 *
 * @return 1 if it looks like an ASCII garbage flood, 0 if not.
 */
static __always_inline int is_ascii_garbage_flood(void *payload, void *data_end)
{
    u8 *p = payload;

    if (p + 24 > (u8 *)data_end)
    {
        return 0;
    }

    #pragma unroll
    for (int i = 0; i < 24; i++)
    {
        if (p[i] < 0x20 || p[i] > 0x7e)
        {
            return 0;
        }
    }

    return 1;
}

/**
 * Checks a UDP payload against a small set of known-bad signatures.
 *
 * Only the literal "flood" filler-string fingerprint is carried over here --
 * a couple of other opaque-but-validated flood-tool fingerprints from the
 * project this was merged with weren't re-verifiable against their original
 * source and were left out rather than guessed at (see README's merge
 * notes) -- a wrong signature is worse than no signature.
 *
 * @param payload Pointer to the first byte after the UDP header.
 * @param data_end The packet's data_end pointer.
 *
 * @return 1 if it matches a known-bad signature, 0 if not.
 */
static __always_inline int is_known_bad_udp_payload(void *payload, void *data_end)
{
    u8 *p = payload;

    if (p + 5 > (u8 *)data_end)
    {
        return 0;
    }

    if (p[0] == 'f' && p[1] == 'l' && p[2] == 'o' && p[3] == 'o' && p[4] == 'd')
    {
        return 1;
    }

    return 0;
}

#endif
