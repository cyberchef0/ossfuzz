/*
 * packet_parser.c  –  VULNERABLE implementation
 *
 * This file contains FIVE intentional OSS-Fuzz-class vulnerabilities.
 * Each is tagged with a [BUG-N] comment.  See docs/vulnerabilities.md
 * for full analysis.
 *
 * Vulnerability index
 * -------------------
 *  BUG-1  Heap buffer overflow (write)   – integer truncation on field length
 *  BUG-2  Out-of-bounds read             – missing bounds check on num_fields
 *  BUG-3  Use-after-free                 – double packet_free path
 *  BUG-4  Integer overflow → OOB write   – unchecked arithmetic in summary
 *  BUG-5  Stack buffer overflow          – unbounded strcpy into label[]
 */

#include "packet_parser.h"

#include <stdlib.h>
#include <string.h>
#include <stdio.h>

/* ------------------------------------------------------------------
 * Wire format (all values big-endian):
 *
 *   [magic:2][version:1][num_fields:1]
 *   for each field:
 *     [type:1][length:2][value:length bytes]
 *   [label: NUL-terminated string, remaining bytes]
 * ------------------------------------------------------------------ */

/* ---- helpers ---- */
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
    pkt->num_fields = *p++;   /* raw byte, 0-255 */

    /* ---- [BUG-2] No check: num_fields can exceed MAX_FIELDS (16).
     *              The loop below will write past pkt->fields[].     */
    for (uint8_t i = 0; i < pkt->num_fields; i++) {
        if (p + 3 > end) break;   /* basic length guard for header */

        uint8_t  ftype  = *p++;
        uint16_t flen   = read_u16_be(p); p += 2;

        /* ---- [BUG-1] flen is a 16-bit value (0–65535).
         *              malloc receives flen but the copy uses (uint8_t)flen,
         *              truncating to 0–255.  If flen > 255, the allocation is
         *              correct but memcpy writes flen bytes into a buffer only
         *              (flen & 0xFF) bytes long → heap overflow.             */
        uint8_t *val = (uint8_t *)malloc(flen);   /* correct size allocated  */
        if (!val) { packet_free(pkt); return NULL; }

        size_t copy_len = (uint8_t)flen;          /* BUG-1: truncation here  */
        if (p + flen > end) {
            free(val);
            break;
        }
        memcpy(val, p, copy_len);  /* copies truncated length but flen > 255 */
                                   /* means bytes in 'val' past copy_len are  */
                                   /* uninitialized – real issue is the malloc */
                                   /* above can be made to be 'copy_len' size  */
                                   /* in practice by controlling flen, leading */
                                   /* to memcpy OOB write (see docs).          */
        p += flen;

        pkt->fields[i].type   = ftype;   /* BUG-2 lands here when i>=16      */
        pkt->fields[i].length = flen;
        pkt->fields[i].value  = val;
    }

    /* ---- [BUG-5] label is a NUL-terminated tail of the packet.
     *              pkt->label is 32 bytes; no length limit on strcpy.        */
    if (p < end) {
        strcpy(pkt->label, (const char *)p);   /* BUG-5: unbounded copy       */
    }

    return pkt;
}

/* ================================================================
 * packet_free
 * ================================================================ */
void packet_free(Packet *pkt)
{
    if (!pkt) return;
    for (uint8_t i = 0; i < pkt->num_fields; i++) {
        /* ---- [BUG-3] If packet_parse freed pkt via the early-exit path
         *              (malloc failure on field value), pkt->num_fields was
         *              already set but some pkt->fields[i].value pointers are
         *              NULL (calloc zeroed them) and others are valid.
         *              The real UAF scenario: callers who call packet_free
         *              twice (easy to trigger through the error path above,
         *              which calls packet_free(pkt) and then returns NULL –
         *              if the caller stored pkt before the NULL return they
         *              hold a dangling pointer and free it again).
         *
         *              More direct: packet_parse itself calls packet_free(pkt)
         *              on the inner malloc failure THEN returns NULL.  The
         *              memory is freed; the local 'pkt' still points to it.   */
        free(pkt->fields[i].value);            /* BUG-3: potential double-free */
    }
    free(pkt);
}

/* ================================================================
 * packet_get_field
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
 * packet_summary  –  returns heap-allocated human-readable string
 * ================================================================ */
char *packet_summary(const Packet *pkt)
{
    if (!pkt) return NULL;

    /* ---- [BUG-4] total_len calculation can overflow.
     *              num_fields is uint8_t (max 255 – but BUG-2 lets it be set
     *              to any value 0-255).  Each field contributes up to 32 chars.
     *              255 * 32 = 8160, fine alone.  But pkt->fields[i].length is
     *              uint16_t (max 65535) and is printed as decimal (%u).
     *              A single field can produce >5 digits.  The loop accumulates
     *              num_fields * (MAX_FIELD_LEN=64) which can reach 16320 – but
     *              we only allocate 'total_len' computed as:
     *                  64 + num_fields * 32          (misses per-field value)
     *              Then snprintf writes more bytes than allocated → overflow.  */
    size_t total_len = 64 + pkt->num_fields * 32;   /* BUG-4: underestimates  */
    char  *buf = (char *)malloc(total_len);
    if (!buf) return NULL;

    int offset = snprintf(buf, total_len,
                          "Packet v%u  magic=0x%04X  fields=%u  label='%s'\n",
                          pkt->version, pkt->magic,
                          pkt->num_fields, pkt->label);

    for (uint8_t i = 0; i < pkt->num_fields && i < MAX_FIELDS; i++) {
        /* BUG-4 materialises: each iteration can write up to 64+ bytes       */
        offset += snprintf(buf + offset, total_len - (size_t)offset,
                           "  field[%u] type=0x%02X len=%u\n",
                           i, pkt->fields[i].type, pkt->fields[i].length);
    }

    return buf;
}
