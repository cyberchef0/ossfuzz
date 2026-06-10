# Makefile for ossfuzz-lab
#
# Targets:
#   make vuln      – build vulnerable fuzzer binary
#   make patched   – build patched fuzzer binary
#   make seeds     – generate seed corpus
#   make fuzz-vuln – fuzz the vulnerable build (expect crashes quickly)
#   make fuzz-fix  – validate the patched build (should survive 500k runs)
#   make clean

CC      = clang
CFLAGS  = -g -O1 -fsanitize=address,fuzzer -I vulnerable
HARNESS = harness/fuzz_packet_parser.c

.PHONY: all vuln patched seeds fuzz-vuln fuzz-fix clean

all: vuln patched

vuln: $(HARNESS) vulnerable/packet_parser.c
	$(CC) $(CFLAGS) $^ -o fuzz_vulnerable

patched: $(HARNESS) patched/packet_parser.c
	$(CC) $(CFLAGS) $^ -o fuzz_patched

seeds:
	cd harness && python3 generate_seeds.py

fuzz-vuln: vuln seeds
	mkdir -p findings
	./fuzz_vulnerable corpus/seeds/ \
		-artifact_prefix=findings/ \
		-max_len=512 -timeout=10 -runs=200000

fuzz-fix: patched seeds
	./fuzz_patched corpus/seeds/ \
		-max_len=512 -timeout=30 -runs=500000

clean:
	rm -f fuzz_vulnerable fuzz_patched
	rm -rf corpus/ findings/
