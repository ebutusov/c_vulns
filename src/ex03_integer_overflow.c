/*
 * ex03_integer_overflow.c
 *
 * Integer overflow / signedness / truncation leading to heap overflow
 *   CWE-190  Integer Overflow or Wraparound
 *   CWE-681  Incorrect Conversion between Numeric Types
 *   CWE-195  Signed to Unsigned Conversion Error
 *   CWE-197  Numeric Truncation Error
 *   CWE-680  Integer Overflow to Buffer Overflow
 *   CWE-122  Heap-based Buffer Overflow (the consequence)
 *
 * ===========================================================================
 * 1. WHAT IS IT?
 * ===========================================================================
 * C integers have a fixed width, and the language does very little to tell
 * you when a value does not fit. Four closely related mistakes show up again
 * and again in real-world CVEs (image/font/archive parsers, network daemons,
 * kernels, browsers):
 *
 *  (a) UNSIGNED WRAPAROUND in size arithmetic.
 *      Unsigned overflow is well defined in C: the result is reduced modulo
 *      2^N. That makes it "legal" but still a bug when the result is used as
 *      an allocation size:
 *
 *          uint32_t total = count * elem_size;   // may wrap to a tiny value
 *          buf = malloc(total);                  // tiny allocation
 *          for (i = 0; i < count; i++)           // ...but loop runs 'count' times
 *              memcpy(buf + i * elem_size, ...); // heap overflow
 *
 *      This is the classic malloc(n * sizeof(T)) bug.
 *
 *  (b) SIGNED OVERFLOW is UNDEFINED BEHAVIOUR.
 *      `INT_MAX + 1` is not "wraps to INT_MIN" as far as the compiler is
 *      concerned: the optimiser may assume it never happens, and delete your
 *      overflow check (e.g. `if (a + b < a)` for signed a, b can be removed
 *      entirely). Never test for signed overflow AFTER the fact; test BEFORE.
 *
 *  (c) SIGNED / UNSIGNED CONFUSION and SIGN EXTENSION.
 *      A negative int converted to size_t becomes a gigantic positive value:
 *
 *          int len = -1;
 *          if (len > 64) reject();       // -1 > 64 is false -> check "passes"
 *          memcpy(dst, src, len);        // len -> (size_t)-1 = 0xFFFF...FFFF
 *
 *      The check validated only the upper bound; nobody checked "len < 0".
 *      A narrow signed type (char, short) that is widened first sign-extends
 *      (0xFFF0 stored in int16_t is -16, and becomes 0xFFFFFFFFFFFFFFF0).
 *      Mixed comparisons (`int` vs `size_t`) silently convert the int to
 *      unsigned and give surprising answers (-Wsign-compare catches these).
 *
 *  (d) TRUNCATION.
 *      Storing a wide value into a narrower variable silently drops the high
 *      bits: `uint16_t n = (uint16_t)some_size_t;` turns 0x10010 into 0x0010.
 *      The code allocates 16 bytes and then copies 65552.
 *
 * ===========================================================================
 * 2. HOW IS IT EXPLOITED?
 * ===========================================================================
 * Toy record format used by this demo (all fields little endian):
 *
 *      offset 0   uint32_t count       number of elements that follow
 *      offset 4   uint32_t elem_size   size of each element in bytes
 *      offset 8   payload              count * elem_size bytes (nominally)
 *
 * A 32-bit length field is typical for file formats and network protocols
 * (PNG chunk lengths, TLS/DTLS, ELF/PE tables, TIFF, ...). Note that the
 * attacker controls BOTH factors.
 *
 * The wrap-around arithmetic with 32-bit values:
 *
 *      count     = 0x40000001  (1073741825)
 *      elem_size = 4
 *      count * elem_size = 0x1_0000_0004   (true product, needs 33 bits)
 *      mod 2^32          = 0x0000_0004     (what a uint32_t keeps)
 *
 *   -> malloc(4) succeeds and returns a 4-byte object (really a 16- or 24-byte
 *      malloc chunk).  The loop below then believes it may write
 *      0x40000001 * 4 bytes = ~4 GiB.
 *
 * Crafted malicious header (hex bytes as they appear in the file/packet):
 *
 *      01 00 00 40   04 00 00 00   <attacker-controlled payload ...>
 *      \_ count __/  \_elem_size_/
 *
 * Why not use a size_t-sized field instead?  With a 64-bit size_t you need
 * operands whose product reaches 2^64, e.g. count = 0x4000000000000001 and
 * size = 4. If the file format uses 32-bit fields but the code multiplies in
 * uint32_t (or on a 32-bit platform where size_t is 32 bits!) the small
 * numbers above are enough. Beware: 32-bit targets (embedded, WASM, 32-bit
 * Windows builds) are still common, and `int`/`unsigned` arithmetic is
 * 32-bit even on 64-bit CPUs.
 *
 * What the attacker gets from the overflowing copy loop:
 *   - Heap metadata corruption: the bytes right after a 4-byte chunk are the
 *     next chunk's header (size field, free-list pointers, tcache/fastbin
 *     links on glibc; LFH/segment-heap headers on Windows). Corrupting them
 *     leads to arbitrary write primitives on a later free()/malloc().
 *   - Adjacent object overwrite: if the heap layout is groomed so that an
 *     object containing a function pointer or vtable pointer (or an
 *     `is_admin` flag, a length field, a pointer to a buffer...) sits right
 *     behind our buffer, the attacker overwrites it with controlled data.
 *   - Combined with an info leak and ASLR bypass this becomes Remote Code
 *     Execution. Even a "crash only" version is a denial of service.
 *   - The overflow length is controlled by the attacker too: when the
 *     input stream simply ends (truncated file), the loop stops early, so
 *     the attacker can pick exactly how many bytes to overflow with.
 *
 * ---------------------------------------------------------------------------
 * HOW THIS DEMO STAYS SAFE
 * ---------------------------------------------------------------------------
 * The REAL bug is an actual heap overflow. This file does NOT perform it,
 * because that would corrupt the allocator's own metadata of the process.
 * Instead every write in the "vulnerable" parser goes through
 * checked_write(), which compares the write against the REAL size that was
 * allocated (the wrapped, tiny value) and, if the write would land outside
 * the allocation, prints "WOULD HAVE OVERFLOWED" and SKIPS the write.
 * So you see exactly what the unmodified program would have done, while the
 * demo process stays healthy. In the real vulnerable program the line
 *
 *        checked_write(buf, total, off, elem_size, 'A', ...)
 *
 * is simply a memcpy(buf + off, src, elem_size) with no check at all.
 * (Run the project's sanitizer build -DCVULNS_SANITIZE=ON and replace
 * checked_write by memset to watch AddressSanitizer report the
 * heap-buffer-overflow immediately.)
 * For the same reason the demo loop is limited to a few iterations and the
 * remaining overflow size is computed arithmetically instead of by
 * iterating 1,073,741,825 times.
 *
 * The signed-length bug (c) and the truncation bug (d) are demonstrated by
 * merely COMPUTING and PRINTING the converted value. memcpy is never called
 * with the huge length.
 *
 * ===========================================================================
 * 3. HOW TO AVOID IT
 * ===========================================================================
 *  - Check multiplication/addition BEFORE you perform it, in the type that
 *    is used for the allocation (size_t):
 *
 *        if (elem_size != 0 && count > SIZE_MAX / elem_size) -> reject
 *        total = count * elem_size;
 *
 *    (SEI CERT INT30-C: ensure unsigned integer operations do not wrap;
 *     INT32-C: ensure signed operations do not overflow; INT31-C: ensure
 *     integer conversions do not result in lost or misinterpreted data;
 *     MEM35-C: allocate sufficient memory for an object.)
 *  - Prefer APIs that do it for you:
 *        calloc(n, size)            checks n * size for overflow (and zeroes)
 *        reallocarray(p, n, size)   same for realloc (glibc 2.26+, BSDs, musl)
 *  - Compiler/library helpers for checked arithmetic:
 *        __builtin_mul_overflow(a, b, &r)   GCC >= 5, Clang
 *        ckd_mul(&r, a, b)                  C23 <stdckdint.h>
 *        SizeTMult(a, b, &r)                MSVC <intsafe.h> (also UIntMult..)
 *    These are non-portable; this demo uses a plain-C11 helper with the
 *    SIZE_MAX / b division which works with every compiler.
 *  - Use size_t (unsigned, pointer sized) for sizes, counts and indexes
 *    consistently. Do not mix int and size_t in comparisons or arithmetic;
 *    do not store sizes in int, short or uint16_t.
 *  - Validate lengths against PROTOCOL / FORMAT MAXIMUMS first (e.g. "at most
 *    1024 records of at most 256 bytes"), BEFORE doing any arithmetic with
 *    them. A sane maximum makes overflow impossible by construction.
 *  - Validate both bounds of signed values: `if (len < 0 || len > MAX)`, or
 *    better, parse lengths into unsigned types from the start.
 *  - Never rely on signed overflow wrapping; don't check for it afterwards.
 *    (-fwrapv exists as a band-aid, but fix the code instead.)
 *  - Compile with warnings: -Wall -Wextra -Wconversion -Wsign-conversion
 *    -Wsign-compare (GCC/Clang); /W4 with C4018, C4244, C4267 (MSVC).
 *  - Test with sanitizers: -fsanitize=undefined detects signed overflow,
 *    -fsanitize=integer (Clang) additionally flags unsigned wraparound and
 *    implicit truncation/sign changes; -fsanitize=address detects the heap
 *    overflow that results. Fuzz parsers (libFuzzer/AFL++) with them on.
 *
 * ===========================================================================
 * 4. BEST PRACTICES SUMMARY AND CWE IDs
 * ===========================================================================
 *   1. Maximums first, arithmetic second, allocation third, copy last.
 *   2. One checked-multiply helper, used for EVERY size computation.
 *   3. size_t everywhere for sizes; explicit casts only after a range check.
 *   4. Reject zero/negative/oversized values explicitly.
 *   5. Allocate with calloc/reallocarray when they fit the job.
 *   6. Compile with conversion warnings as errors; run sanitizers and fuzzers.
 *
 *   CWE-190 Integer Overflow or Wraparound
 *   CWE-191 Integer Underflow
 *   CWE-195 Signed to Unsigned Conversion Error
 *   CWE-196 Unsigned to Signed Conversion Error
 *   CWE-197 Numeric Truncation Error
 *   CWE-680 Integer Overflow to Buffer Overflow
 *   CWE-681 Incorrect Conversion between Numeric Types
 *   CWE-131 Incorrect Calculation of Buffer Size
 *   CWE-122 Heap-based Buffer Overflow
 *   CERT C: INT30-C, INT31-C, INT32-C, MEM35-C, ARR30-C
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <limits.h>
#include "cvulns.h"

/* ------------------------------------------------------------------------- */
/* Toy record format                                                         */
/* ------------------------------------------------------------------------- */

typedef struct {
    uint32_t count;      /* number of elements (attacker controlled)        */
    uint32_t elem_size;  /* bytes per element  (attacker controlled)        */
} record_header;

#define HEADER_WIRE_SIZE 8u

/* Protocol maximums used by the hardened parser (validate BEFORE arithmetic). */
#define MAX_COUNT      1024u
#define MAX_ELEM_SIZE  256u
#define MAX_TOTAL      (1024u * 1024u)

/* Number of loop iterations the demo really executes before it switches to
 * pure arithmetic (see "HOW THIS DEMO STAYS SAFE" above). */
#define DEMO_ITER_CAP  6u
/* How many individual "would overflow" lines we print. */
#define DEMO_REPORT_CAP 3u

/* Wire format is little endian; (de)serialise byte by byte so the demo does
 * not depend on host endianness or struct padding. */
static void put_le32(uint8_t *p, uint32_t v) {
    p[0] = (uint8_t)(v & 0xFFu);
    p[1] = (uint8_t)((v >> 8) & 0xFFu);
    p[2] = (uint8_t)((v >> 16) & 0xFFu);
    p[3] = (uint8_t)((v >> 24) & 0xFFu);
}

static uint32_t get_le32(const uint8_t *p) {
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) |
           ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

/* Build the 8 header bytes an attacker (or a benign client) would send. */
static void build_header_bytes(uint8_t out[HEADER_WIRE_SIZE], uint32_t count, uint32_t elem_size) {
    put_le32(out, count);
    put_le32(out + 4, elem_size);
}

static void parse_header_bytes(const uint8_t in[HEADER_WIRE_SIZE], record_header *h) {
    h->count = get_le32(in);
    h->elem_size = get_le32(in + 4);
}

static void print_bytes(const uint8_t *p, size_t n) {
    for (size_t i = 0; i < n; i++) printf("%02x%s", (unsigned)p[i], i + 1 < n ? " " : "");
}

/* ------------------------------------------------------------------------- */
/* Safe-demo write wrapper                                                   */
/* ------------------------------------------------------------------------- */

/*
 * Stand-in for `memcpy(buf + off, src, n)` in the vulnerable parser.
 * It knows the REAL allocation size and refuses to write outside it, so the
 * demo never corrupts the heap. Returns 1 if the write was performed, 0 if it
 * would have overflowed (and was skipped). `reports` limits console output.
 */
static int checked_write(unsigned char *buf, uint32_t alloc_size, uint64_t off,
                         uint32_t n, unsigned char value, uint64_t index,
                         unsigned *reports) {
    uint64_t end = off + (uint64_t)n;
    if (end <= (uint64_t)alloc_size) {
        memset(buf + off, value, n);
        return 1;
    }
    if (*reports < DEMO_REPORT_CAP) {
        uint64_t beyond = end - (off > (uint64_t)alloc_size ? off : (uint64_t)alloc_size);
        BAD("element %llu: write of %u bytes at offset %llu, allocation is only %u bytes: "
            "WOULD HAVE OVERFLOWED the heap by %llu bytes (write skipped)",
            (unsigned long long)index, (unsigned)n, (unsigned long long)off,
            (unsigned)alloc_size, (unsigned long long)beyond);
        (*reports)++;
    }
    return 0;
}

/* ------------------------------------------------------------------------- */
/* VULNERABLE parser                                                         */
/* ------------------------------------------------------------------------- */

/*
 * Vulnerable pattern (CWE-190 -> CWE-680 -> CWE-122):
 *   - 32-bit multiplication that silently wraps,
 *   - allocation sized from the wrapped value,
 *   - loop bound taken from the ORIGINAL (unwrapped) count.
 */
static int parse_vulnerable(const record_header *h) {
    /* BUG: unsigned 32-bit wraparound. Well defined in C, still wrong. */
    uint32_t total = h->count * h->elem_size;

    uint64_t true_total = (uint64_t)h->count * (uint64_t)h->elem_size;  /* for narration only */
    INFO("count=0x%llx elem_size=%llu", (unsigned long long)h->count,
         (unsigned long long)h->elem_size);
    INFO("32-bit total = count * elem_size = 0x%llx (%llu bytes); true product = 0x%llx (%llu bytes)",
         (unsigned long long)total, (unsigned long long)total,
         (unsigned long long)true_total, (unsigned long long)true_total);

    unsigned char *buf = (unsigned char *)malloc(total ? total : 1u);
    if (!buf) {
        INFO("malloc(%llu) failed", (unsigned long long)total);
        return 0;
    }
    INFO("malloc(%llu) succeeded, the parser now trusts 'count' for the loop bound",
         (unsigned long long)total);

    unsigned reports = 0;
    uint64_t overflowed_iters = 0;
    uint32_t i = 0;
    for (; i < h->count && i < DEMO_ITER_CAP; i++) {
        /* Real code: memcpy(buf + (size_t)i * elem_size, payload + ..., elem_size); */
        uint64_t off = (uint64_t)i * (uint64_t)h->elem_size;
        if (!checked_write(buf, total, off, h->elem_size, 'A', i, &reports))
            overflowed_iters++;
    }
    if (i < h->count) {
        /* Do not iterate a billion times: compute what the rest would do. */
        uint64_t remaining = (uint64_t)h->count - i;
        INFO("... demo stops after %u iterations; the real loop would continue for %llu more",
             (unsigned)i, (unsigned long long)remaining);
    }

    if (true_total > (uint64_t)total) {
        uint64_t over = true_total - (uint64_t)total;
        BAD("the real loop would write %llu bytes into a %llu byte buffer: "
            "heap overflow of %llu bytes (~%llu MiB) with attacker-chosen data",
            (unsigned long long)true_total, (unsigned long long)total,
            (unsigned long long)over, (unsigned long long)(over >> 20));
        BAD("-> next chunk's metadata / adjacent objects get overwritten -> RCE primitive");
    } else {
        GOOD("all %u element(s) written inside the %llu byte allocation, no overflow",
             (unsigned)h->count, (unsigned long long)total);
    }
    (void)overflowed_iters;
    free(buf);
    return 0;
}

/* ------------------------------------------------------------------------- */
/* FIXED parser                                                              */
/* ------------------------------------------------------------------------- */

/* Portable checked multiplication for size_t (CERT INT30-C). */
static int mul_size_checked(size_t a, size_t b, size_t *out) {
    if (a != 0 && b > SIZE_MAX / a) return 0;   /* a * b would exceed SIZE_MAX */
    *out = a * b;
    return 1;
}

/* Same for 32-bit operands, e.g. to emulate what a 32-bit target would see. */
static int mul_u32_checked(uint32_t a, uint32_t b, uint32_t *out) {
    if (a != 0 && b > UINT32_MAX / a) return 0;
    *out = a * b;
    return 1;
}

/*
 * Hardened parser. Order matters:
 *   1. validate each field against the format's maximums,
 *   2. do the multiplication with an overflow check, in size_t,
 *   3. only then allocate and copy, using the SAME size_t values.
 */
static int parse_fixed(const record_header *h) {
    INFO("count=0x%llx elem_size=%llu", (unsigned long long)h->count,
         (unsigned long long)h->elem_size);

    if (h->elem_size == 0 || h->elem_size > MAX_ELEM_SIZE) {
        GOOD("rejected: elem_size %llu outside 1..%u", (unsigned long long)h->elem_size, MAX_ELEM_SIZE);
        return 0;
    }
    if (h->count == 0 || h->count > MAX_COUNT) {
        GOOD("rejected: count %llu outside 1..%u (checked BEFORE any arithmetic)",
             (unsigned long long)h->count, MAX_COUNT);
        return 0;
    }

    size_t count = (size_t)h->count;
    size_t elem_size = (size_t)h->elem_size;
    size_t total;
    if (!mul_size_checked(count, elem_size, &total)) {
        GOOD("rejected: count * elem_size overflows size_t");
        return 0;
    }
    if (total > MAX_TOTAL) {
        GOOD("rejected: total %llu exceeds MAX_TOTAL %u", (unsigned long long)total, MAX_TOTAL);
        return 0;
    }

    unsigned char *buf = (unsigned char *)malloc(total);
    if (!buf) {
        INFO("malloc(%llu) failed", (unsigned long long)total);
        return 0;
    }
    for (size_t i = 0; i < count; i++)
        memset(buf + i * elem_size, 'A', elem_size);   /* real code: memcpy from input */
    GOOD("accepted: allocated and filled %llu bytes (%llu elements x %llu), exactly in bounds",
         (unsigned long long)total, (unsigned long long)count, (unsigned long long)elem_size);
    free(buf);
    return 0;
}

/* Show the helper itself on the exact numbers from the header comment. */
static void demo_checked_helpers(const record_header *h) {
    uint32_t r32 = 0;
    size_t rsz = 0;
    if (mul_u32_checked(h->count, h->elem_size, &r32))
        INFO("mul_u32_checked: ok, product %llu", (unsigned long long)r32);
    else
        GOOD("mul_u32_checked: 0x%llx * %llu does not fit in 32 bits -> detected, nothing allocated",
             (unsigned long long)h->count, (unsigned long long)h->elem_size);
    if (mul_size_checked((size_t)h->count, (size_t)h->elem_size, &rsz))
        INFO("mul_size_checked: no overflow in this build's size_t (%u bits); product %llu is "
             "then rejected by the format maximums",
             (unsigned)(sizeof(size_t) * CHAR_BIT), (unsigned long long)rsz);
    else
        GOOD("mul_size_checked: overflow of size_t detected");
}

/* ------------------------------------------------------------------------- */
/* Signed length check bypass (CWE-195) and truncation (CWE-197)             */
/* ------------------------------------------------------------------------- */

#define SIGNED_DEMO_MAX 64

static void signed_length_demo(vuln_mode mode) {
    SECTION("signed length check bypass");
    int len = (mode == MODE_VULN) ? 10 : -1;   /* -1: attacker supplies a negative length */
    INFO("int len = %d; destination buffer holds %d bytes", len, SIGNED_DEMO_MAX);

    if (mode != MODE_FIXED) {
        /* BUG: only the upper bound is validated. -1 > 64 is false. */
        if (len > SIGNED_DEMO_MAX) {
            GOOD("rejected: len > %d", SIGNED_DEMO_MAX);
        } else {
            size_t n = (size_t)len;   /* what memcpy's third parameter would receive */
            if (len >= 0) {
                GOOD("check passed and memcpy(dst, src, %llu) is within the buffer", (unsigned long long)n);
            } else {
                BAD("check `len > %d` PASSED for len=%d", SIGNED_DEMO_MAX, len);
                BAD("memcpy(dst, src, len) would receive size_t = %llu (0x%llx): "
                    "copies until it hits unmapped memory (memcpy NOT called by this demo)",
                    (unsigned long long)n, (unsigned long long)n);
            }
        }
    } else {
        /* FIX: check both bounds, then convert once, explicitly. */
        if (len < 0 || len > SIGNED_DEMO_MAX) {
            GOOD("rejected: len=%d is outside 0..%d (both bounds checked)", len, SIGNED_DEMO_MAX);
        } else {
            size_t n = (size_t)len;
            GOOD("accepted len=%llu", (unsigned long long)n);
        }
    }

    /* Sign extension of a narrow signed field (e.g. a 16-bit length on the wire). */
    int16_t wire_len = (mode == MODE_VULN) ? (int16_t)10 : (int16_t)-16;  /* wire bytes F0 FF */
    if (mode != MODE_FIXED) {
        size_t widened = (size_t)wire_len;   /* sign-extends: -16 -> 0xFFFF...FFF0 */
        if (wire_len < 0)
            BAD("int16_t length %d (wire bytes f0 ff) widened to size_t = %llu (0x%llx)",
                (int)wire_len, (unsigned long long)widened, (unsigned long long)widened);
        else
            GOOD("int16_t length %d widened to size_t = %llu, harmless", (int)wire_len,
                 (unsigned long long)widened);
    } else {
        /* FIX: read length fields as UNSIGNED (uint16_t) from the start. */
        uint16_t ulen = (uint16_t)wire_len;   /* same wire bytes, interpreted as unsigned */
        GOOD("read as uint16_t the same bytes mean %u: a plain upper-bound check is now enough (%u > %d -> reject)",
             (unsigned)ulen, (unsigned)ulen, SIGNED_DEMO_MAX);
    }
}

static void truncation_demo(vuln_mode mode) {
    SECTION("truncation size_t -> uint16_t");
    size_t want = (mode == MODE_VULN) ? (size_t)100 : (size_t)0x10010;   /* 65552 */
    INFO("caller needs %llu bytes (0x%llx)", (unsigned long long)want, (unsigned long long)want);

    if (mode != MODE_FIXED) {
        uint16_t alloc16 = (uint16_t)want;   /* BUG: silently drops the high bits */
        if ((size_t)alloc16 != want)
            BAD("stored in uint16_t it becomes %u: malloc(%u) then copy of %llu bytes -> "
                "overflow of %llu bytes (not performed here)",
                (unsigned)alloc16, (unsigned)alloc16, (unsigned long long)want,
                (unsigned long long)(want - alloc16));
        else
            GOOD("value %u fits in uint16_t, no truncation", (unsigned)alloc16);
    } else {
        if (want > UINT16_MAX)
            GOOD("rejected: %llu does not fit the 16-bit field (range checked before the cast)",
                 (unsigned long long)want);
        else
            GOOD("accepted");
    }
}

/* ------------------------------------------------------------------------- */
/* Demo driver                                                               */
/* ------------------------------------------------------------------------- */

static int run(vuln_mode mode) {
    uint8_t wire[HEADER_WIRE_SIZE];
    record_header h;

    if (mode == MODE_VULN) {
        SECTION("benign record: 3 elements of 4 bytes");
        build_header_bytes(wire, 3u, 4u);
        INFO("header bytes: "); print_bytes(wire, sizeof wire); printf("\n");
        parse_header_bytes(wire, &h);
        parse_vulnerable(&h);
        signed_length_demo(mode);
        truncation_demo(mode);
        return 0;
    }

    /* Malicious header: count = 0x40000001, elem_size = 4 -> 32-bit product 4. */
    build_header_bytes(wire, 0x40000001u, 4u);
    SECTION(mode == MODE_EXPLOIT ? "malicious record vs VULNERABLE parser"
                                 : "malicious record vs FIXED parser");
    INFO("crafted header bytes (little endian):");
    printf("    "); print_bytes(wire, sizeof wire); printf("\n");
    parse_header_bytes(wire, &h);

    if (mode == MODE_EXPLOIT) {
        parse_vulnerable(&h);
    } else {
        demo_checked_helpers(&h);
        parse_fixed(&h);

        SECTION("benign record vs FIXED parser (still works)");
        build_header_bytes(wire, 3u, 4u);
        parse_header_bytes(wire, &h);
        parse_fixed(&h);
    }

    signed_length_demo(mode);
    truncation_demo(mode);
    return 0;
}

const vuln_example ex03_example = {
    "integer-overflow",
    "Integer overflow / signedness leading to heap overflow (CWE-190/CWE-681/CWE-195)",
    run
};
