#ifndef PACKET_PARSER_H
#define PACKET_PARSER_H

#include <stdint.h>
#include <stddef.h>

/* ---------------------------------------------------------------
 * packet_parser.h  –  Mini network packet parsing library
 * (VULNERABLE version – intentional OSS-Fuzz-class bugs inside)
 * --------------------------------------------------------------- */

#define MAX_FIELDS      16
#define MAX_FIELD_LEN   64
#define MAGIC_HEADER    0xDEAD

/* TLV field parsed out of a packet */
typedef struct {
    uint8_t  type;
    uint16_t length;
    uint8_t *value;          /* heap-allocated copy */
} Field;

/* Parsed packet representation */
typedef struct {
    uint16_t magic;
    uint8_t  version;
    uint8_t  num_fields;
    Field    fields[MAX_FIELDS];
    char     label[32];      /* human-readable label string */
} Packet;

/* Public API */
Packet *packet_parse(const uint8_t *data, size_t size);
void    packet_free(Packet *pkt);
int     packet_get_field(const Packet *pkt, uint8_t type,
                         uint8_t *out_buf, size_t out_sz);
char   *packet_summary(const Packet *pkt);

#endif /* PACKET_PARSER_H */
