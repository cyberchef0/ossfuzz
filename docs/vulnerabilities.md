# OSS-Fuzz Lab – Vulnerability & Patch Analysis

## Repository layout

```
ossfuzz-lab/
├── vulnerable/         ← original code with 5 bugs
│   ├── packet_parser.h
│   └── packet_parser.c
├── patched/            ← corrected implementation
│   └── packet_parser.c
├── harness/
│   ├── fuzz_packet_parser.c   ← libFuzzer entry point
│   └── generate_seeds.py      ← seed corpus generator
└── docs/
    └── vulnerabilities.md     ← this file
```

---

## Bug catalogue

### BUG-1 – Heap Buffer Overflow (write) via integer truncation

| Attribute | Detail |
|-----------|--------|
| **CWE**   | CWE-122 (Heap-based Buffer Overflow) |
| **CVSS**  | ~8.1 High |
| **ASan signal** | `heap-buffer-overflow WRITE` |
| **File / line** | `vulnerable/packet_parser.c`, `packet_parse()`, field-copy loop |

#### Root cause

The wire format encodes field lengths as `uint16_t` (0–65535).  
The vulnerable code allocates the correct number of bytes with `malloc(flen)` but then
casts `flen` to `uint8_t` before passing it to `memcpy`:

```c
uint8_t *val = (uint8_t *)malloc(flen);          // e.g. malloc(256) → 256 bytes
size_t copy_len = (uint8_t)flen;                 // 256 & 0xFF == 0  ← BUG
memcpy(val, p, copy_len);                        // copies 0 bytes
```

When `flen` is exactly 256 the truncated copy is 0 bytes—no overflow in this
specific case but data is silently lost.  When an attacker controls `flen` to be,
say, 300 and the allocation path is shaped so the allocator returns a chunk of 44
bytes (e.g., through heap grooming), the `memcpy` writes 300 bytes into 44 bytes.

A simpler demonstration: set `flen = 257`; `(uint8_t)257 == 1`; `malloc(257)`
returns a 257-byte buffer; `memcpy(val, p, 1)` is safe but if the intent was to
copy 257 bytes and the buffer is only 257 long, an off-by-one in a related
path overflows.

#### Fix (FIX-1)

Remove the cast entirely.  Use `flen` (uint16_t) as both the allocation size and
the copy length.  Cap at `MAX_FIELD_LEN` to bound allocation size:

```c
if (flen > MAX_FIELD_LEN) { /* skip field */ break; }
uint8_t *val = (uint8_t *)malloc(flen ? flen : 1);
memcpy(val, p, flen);     // ← correct: copies exactly flen bytes
```

---

### BUG-2 – Out-of-Bounds Write via unchecked `num_fields`

| Attribute | Detail |
|-----------|--------|
| **CWE**   | CWE-787 (Out-of-bounds Write) |
| **CVSS**  | ~9.0 Critical |
| **ASan signal** | `heap-buffer-overflow WRITE` on `pkt->fields[i]` |
| **File / line** | `vulnerable/packet_parser.c`, `packet_parse()`, field loop |

#### Root cause

`num_fields` is read from a single attacker-controlled byte (0–255).  
`pkt->fields` is declared as `Field fields[MAX_FIELDS]` where `MAX_FIELDS = 16`.  
The loop iterates `i < pkt->num_fields` without capping at 16, so a packet
claiming 17+ fields causes writes past the end of the `fields` array.

```c
pkt->num_fields = *p++;  // attacker sets this to e.g. 255
// ...
for (uint8_t i = 0; i < pkt->num_fields; i++) {   // no MAX_FIELDS cap
    pkt->fields[i].value = val;                     // OOB when i >= 16
```

The `Packet` struct is heap-allocated, so this corrupts the heap immediately
after the `fields` array—potentially overwriting the `label` array or heap
metadata.

#### Fix (FIX-2)

Clamp before storing:

```c
pkt->num_fields = (raw_num_fields <= MAX_FIELDS) ? raw_num_fields
                                                  : (uint8_t)MAX_FIELDS;
```

---

### BUG-3 – Double-Free / Use-After-Free

| Attribute | Detail |
|-----------|--------|
| **CWE**   | CWE-415 (Double Free) / CWE-416 (Use After Free) |
| **CVSS**  | ~7.5 High |
| **ASan signal** | `heap-use-after-free` or `double-free` |
| **File / line** | `vulnerable/packet_parser.c`, `packet_parse()` error path |

#### Root cause

Inside `packet_parse()`, when a `malloc` for a field value fails, the code calls
`packet_free(pkt)` to clean up and then `return NULL`.  However, `packet_free`
iterates over `pkt->fields[0..num_fields-1]`.  Some of those `value` pointers are
already NULL (calloc-zeroed), and some were already freed.  The `free(NULL)` calls
are harmless, but:

1. The function has already called `packet_free(pkt)` on a partially-built struct.
2. If a caller mistakenly cached `pkt` before passing it here (possible in
   multi-threaded or re-entrant code), they now hold a dangling pointer.
3. In the vulnerable code the `packet_free` path itself does not NULL-out the
   pointers, so a second call to `packet_free` on any retained pointer double-frees
   the field values.

#### Fix (FIX-3)

Replace the internal `packet_free` call with an explicit inline cleanup loop that
only frees already-allocated entries, then frees `pkt` directly:

```c
// On malloc failure for field i:
for (uint8_t j = 0; j < i; j++)
    free(pkt->fields[j].value);
free(pkt);
return NULL;
// Never call packet_free() internally.
```

Additionally, in `packet_free()`, NULL-out each pointer after freeing:

```c
free(pkt->fields[i].value);
pkt->fields[i].value = NULL;
```

---

### BUG-4 – Integer Overflow → Heap Buffer Overflow (write) in `packet_summary`

| Attribute | Detail |
|-----------|--------|
| **CWE**   | CWE-131 (Incorrect Calculation of Buffer Size) |
| **CVSS**  | ~7.0 High |
| **ASan signal** | `heap-buffer-overflow WRITE` in `snprintf` |
| **File / line** | `vulnerable/packet_parser.c`, `packet_summary()` |

#### Root cause

The summary buffer size is computed as:

```c
size_t total_len = 64 + pkt->num_fields * 32;
```

With BUG-2 still in place `num_fields` can be up to 255, giving
`64 + 255*32 = 8224` bytes—seems large, but the snprintf format string
`"  field[%u] type=0x%02X len=%u\n"` can itself emit up to ~40 bytes per
iteration.  The real overflow is the header line: with `label` up to 31 chars and
version=255, the header alone can be ~80 bytes, leaving the loop with less room
than calculated.  More critically, if `num_fields` is crafted to 200 and each
field has a large `length` (printed as decimal), `total_len` can be exhausted
before the loop finishes—writing `snprintf` output past the allocated buffer.

#### Fix (FIX-4)

Use a conservative per-field constant and add a header slack:

```c
size_t total_len = 128 + (size_t)safe_count * 48;
```

And add an overflow guard inside the loop:

```c
if (written < 0 || (size_t)written >= total_len - (size_t)offset)
    break;
```

---

### BUG-5 – Stack Buffer Overflow via unbounded `strcpy`

| Attribute | Detail |
|-----------|--------|
| **CWE**   | CWE-121 (Stack-based Buffer Overflow) |
| **CVSS**  | ~8.8 High |
| **ASan signal** | `stack-buffer-overflow WRITE` |
| **File / line** | `vulnerable/packet_parser.c`, `packet_parse()`, label copy |

#### Root cause

```c
strcpy(pkt->label, (const char *)p);   // pkt->label is [32]
```

The tail of a packet is a NUL-terminated string of arbitrary length.  If the
attacker omits the NUL terminator (or places it beyond 31 bytes), `strcpy` reads
past the end of the input buffer and writes past `pkt->label`, corrupting adjacent
heap memory (or triggering a crash on the read overrun).

Note: although `pkt` is heap-allocated, the overflow still corrupts heap metadata
immediately following the struct.

#### Fix (FIX-5)

```c
strncpy(pkt->label, (const char *)p, sizeof(pkt->label) - 1);
pkt->label[sizeof(pkt->label) - 1] = '\0';
```

---

## Build & fuzz instructions

### Prerequisites

```
apt install clang llvm  # Ubuntu / Debian
```

### Compile with AddressSanitizer + libFuzzer

```bash
# Vulnerable build (expect crashes)
clang -g -O1 -fsanitize=address,fuzzer \
      harness/fuzz_packet_parser.c vulnerable/packet_parser.c \
      -I vulnerable -o fuzz_vulnerable

# Patched build (should not crash)
clang -g -O1 -fsanitize=address,fuzzer \
      harness/fuzz_packet_parser.c patched/packet_parser.c \
      -I vulnerable -o fuzz_patched
```

### Generate seed corpus & fuzz

```bash
cd harness && python3 generate_seeds.py && cd ..

mkdir -p findings
./fuzz_vulnerable corpus/seeds/ -artifact_prefix=findings/ \
                                -max_len=512 -timeout=10 -runs=100000
```

### Reproduce a crash

```bash
./fuzz_vulnerable findings/crash-<hash>
```

### Validate the patch is clean

```bash
./fuzz_patched corpus/seeds/ -max_len=512 -runs=500000
# Expected: no crashes, no sanitizer errors
```

---

## Diff summary (vulnerable → patched)

| BUG | Change |
|-----|--------|
| BUG-1 | Remove `(uint8_t)` cast; cap `flen` at `MAX_FIELD_LEN` |
| BUG-2 | Clamp `num_fields = min(raw, MAX_FIELDS)` before loop |
| BUG-3 | Replace internal `packet_free` with explicit cleanup; NULL-poison pointers |
| BUG-4 | `total_len = 128 + count*48`; guard `snprintf` return value |
| BUG-5 | `strcpy` → `strncpy` with explicit NUL termination |
