/*
 * fuzz_packet_parser.c  –  libFuzzer / OSS-Fuzz harness
 *
 * Build (with ASan + libFuzzer):
 *   clang -g -O1 -fsanitize=address,fuzzer \
 *         fuzz_packet_parser.c ../vulnerable/packet_parser.c \
 *         -I../vulnerable -o fuzz_packet_parser
 *
 * Run:
 *   mkdir corpus && ./fuzz_packet_parser corpus/ -max_len=512 -timeout=10
 *
 * Seed corpus entries live in corpus/seeds/.
 */

#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include "packet_parser.h"

/* libFuzzer entry point */
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    /* Exercise parse path */
    Packet *pkt = packet_parse(data, size);
    if (!pkt)
        return 0;

    /* Exercise summary path */
    char *summary = packet_summary(pkt);
    free(summary);

    /* Exercise field-lookup path */
    uint8_t out[128];
    for (int t = 0; t < 256; t++) {
        packet_get_field(pkt, (uint8_t)t, out, sizeof(out));
    }

    /* Exercise free path */
    packet_free(pkt);

    return 0;
}
