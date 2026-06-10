/*
 * packet_parser.c  –  PATCHED implementation
 *
 * All five BUG-N issues from the vulnerable version are corrected.
 * Each fix is tagged [FIX-N] and cross-references the original bug.
 */

#include "packet_parser.h"

#include <stdlib.h>
#include <string.h>
#include <stdio.h>

static uint16_t read_u16_be(const uint8_t *p)
{
    return (uint16_t)((p[0] << 8) | p[1]);
}

/* ================================================================
 * packet_parse
 * ================================================================ */
Packet *packet_parse(const uint8_t *data, size_t size)
{
    if (!data || size < 4)
        return NULL;

    const uint8_t *p   = data;
    const uint8_t *end = data + size;

    uint16_t magic = read_u16_be(p); p += 2;
    if (magic != MAGIC_HEADER)
        return NULL;

    Packet *pkt = (Packet *)calloc(1, sizeof(Packet));
    if (!pkt) return NULL;

    pkt->magic      = magic;
    pkt->version    = *p++;

    uint8_t raw_num_fields = *p++;

    /* [FIX-2] Clamp num_fields to MAX_FIELDS before storing.
     *         Any excess fields in the wire stream are simply ignored.       */
    pkt->num_fields = (raw_num_fields <= MAX_FIELDS)
                      ? raw_num_fields
                      : (uint8_t)MAX_FIELDS;

    for (uint8_t i = 0; i < pkt->num_fields; i++) {
        if (p + 3 > end) {
            /* Truncate num_fields to what we actually parsed */
            pkt->num_fields = i;
            break;
        }

        uint8_t  ftype = *p++;
        uint16_t flen  = read_u16_be(p); p += 2;

        /* [FIX-1] Use flen (full uint16_t) as the malloc size AND the
         *         memcpy length.  Also cap at MAX_FIELD_LEN to avoid
         *         runaway allocations from malformed input.                   */
        if (flen > MAX_FIELD_LEN) {
            /* Skip over this field in the wire stream */
            if (p + flen > end) {
                pkt->num_fields = i;
                break;
            }
            p += flen;
            pkt->num_fields = i;   /* field not stored */
            break;
        }

        if (p + flen > end) {
            pkt->num_fields = i;
            break;
        }

        uint8_t *val = (uint8_t *)malloc(flen ? flen : 1);  /* avoid malloc(0) */
        if (!val) {
            /* Clean up already-allocated fields, then free packet */
            for (uint8_t j = 0; j < i; j++)
                free(pkt->fields[j].value);
            free(pkt);
            return NULL;
        }

        memcpy(val, p, flen);   /* FIX-1: copy exactly flen bytes */
        p += flen;

        pkt->fields[i].type   = ftype;
        pkt->fields[i].length = flen;
        pkt->fields[i].value  = val;
    }

    /* [FIX-5] Use strncpy with explicit limit; always NUL-terminate.         */
    if (p < end) {
        strncpy(pkt->label, (const char *)p, sizeof(pkt->label) - 1);
        pkt->label[sizeof(pkt->label) - 1] = '\0';
    }

    return pkt;
}

/* ================================================================
 * packet_free
 * ================================================================ */
void packet_free(Packet *pkt)
{
    if (!pkt) return;

    /* [FIX-3] Only iterate up to the clamped num_fields; NULLs are safe
     *         because calloc zeroed the struct.  The real fix is that
     *         packet_parse no longer calls packet_free on the partial packet
     *         internally – it manually cleans up, returning NULL without
     *         freeing pkt through this function, eliminating the double-free
     *         scenario entirely.                                               */
    uint8_t safe_count = (pkt->num_fields <= MAX_FIELDS)
                         ? pkt->num_fields
                         : (uint8_t)MAX_FIELDS;
    for (uint8_t i = 0; i < safe_count; i++) {
        free(pkt->fields[i].value);
        pkt->fields[i].value = NULL;   /* poison: catch stale pointers early  */
    }
    free(pkt);
}

/* ================================================================
 * packet_get_field  (no bug here, kept identical)
 * ================================================================ */
int packet_get_field(const Packet *pkt, uint8_t type,
                     uint8_t *out_buf, size_t out_sz)
{
    if (!pkt || !out_buf) return -1;
    for (uint8_t i = 0; i < pkt->num_fields && i < MAX_FIELDS; i++) {
        if (pkt->fields[i].type == type) {
            size_t copy = pkt->fields[i].length < out_sz
                          ? pkt->fields[i].length : out_sz;
            memcpy(out_buf, pkt->fields[i].value, copy);
            return (int)pkt->fields[i].length;
        }
    }
    return -1;
}

/* ================================================================
 * packet_summary
 * ================================================================ */
char *packet_summary(const Packet *pkt)
{
    if (!pkt) return NULL;

    /* [FIX-4] Compute a provably-sufficient buffer size.
     *
     *  Header line:  ~80 chars worst case (version=255, magic=0xFFFF,
     *                fields=255, label=31 chars)
     *  Per-field:    "  field[255] type=0xFF len=65535\n" ≈ 40 chars
     *  Slack:        +64 bytes
     *
     *  Use MAX_FIELDS (clamped) × 48 + 128 to be safe.                       */
    uint8_t safe_count = (pkt->num_fields <= MAX_FIELDS)
                         ? pkt->num_fields
                         : (uint8_t)MAX_FIELDS;

    size_t total_len = 128 + (size_t)safe_count * 48;
    char  *buf = (char *)malloc(total_len);
    if (!buf) return NULL;

    int offset = snprintf(buf, total_len,
                          "Packet v%u  magic=0x%04X  fields=%u  label='%s'\n",
                          pkt->version, pkt->magic,
                          pkt->num_fields, pkt->label);

    for (uint8_t i = 0; i < safe_count; i++) {
        int written = snprintf(buf + offset,
                               total_len - (size_t)offset,
                               "  field[%u] type=0x%02X len=%u\n",
                               i, pkt->fields[i].type, pkt->fields[i].length);
        if (written < 0 || (size_t)written >= total_len - (size_t)offset)
            break;   /* truncate gracefully rather than overflow */
        offset += written;
    }

    return buf;
}
