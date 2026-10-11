/*
 * ex06_info_leak.c - Information leak: uninitialized memory and struct padding
 *                    (CWE-457, CWE-200, CWE-201, also CWE-226 / CWE-244)
 *
 * ======================================================================
 * 1. WHAT IS THE BUG?
 * ======================================================================
 * Memory that a program has not explicitly written still contains
 * *something*: whatever the previous owner left there. When such bytes end
 * up in output (a file, a network message, a log, a reply to another
 * process) the program discloses data it never meant to share.
 * Three common shapes of the mistake:
 *
 *  (a) Uninitialized variables and malloc'd memory.
 *      `int x;` and `malloc(n)` give you indeterminate contents. malloc()
 *      does NOT zero memory (calloc() does). Reading an indeterminate value
 *      is undefined behaviour (CERT EXP33-C), and in practice yields stale
 *      data from earlier allocations or earlier stack frames.
 *
 *  (b) Struct padding.
 *      The compiler inserts padding bytes to align members:
 *
 *          struct record { char tag; int value; };
 *          offset: 0 = tag, 1..3 = PADDING, 4..7 = value  (typical ABI)
 *
 *      Assigning members never has to write the padding. If the whole
 *      struct is then written with fwrite()/send()/memcpy() to a file or
 *      socket, the padding bytes travel along carrying whatever was in
 *      memory before. (CERT DCL39-C: do not pass uninitialized padding
 *      across a trust boundary.) Even `struct record r = {0};` does not
 *      guarantee zeroed padding: the C standard only requires members to be
 *      initialised, and compilers are free to leave padding alone.
 *
 *  (c) Stale data in reused buffers.
 *      A buffer once held a secret. It is released (or just recycled)
 *      without being cleared, then reused for a shorter, harmless message.
 *      If the code transmits the WHOLE buffer length instead of only the
 *      bytes it actually wrote, the tail of the old secret goes out too.
 *
 * ======================================================================
 * 2. IMPACT (conceptual)
 * ======================================================================
 * The leftover bytes may contain passwords, session tokens, private keys,
 * personal data, or pointers. Leaked pointers are especially useful for
 * attackers because they reveal where code and data live in memory, which
 * weakens ASLR and makes other bugs easier to exploit. Leaks are often
 * low-severity on their own and serious as a building block.
 * They are also hard to notice: the program "works", the output looks
 * right, and the extra bytes are invisible unless someone inspects the raw
 * data.
 *
 * ======================================================================
 * 3. HOW TO AVOID IT
 * ======================================================================
 *  - Initialise everything: use calloc() instead of malloc()+use, give
 *    locals an initial value, and memset() a whole struct to 0 BEFORE
 *    filling its members (this also clears padding).
 *  - `= {0}` is fine for members but may not zero padding (see above), so
 *    do not rely on it for anything that gets copied out as raw bytes.
 *  - Serialise field by field into an explicit byte buffer with a defined
 *    layout and endianness; never fwrite()/send() a raw struct.
 *  - Send/store only the number of bytes actually used, not the capacity.
 *  - Erase secrets as soon as they are no longer needed:
 *        explicit_bzero()  (glibc 2.25+, BSDs)
 *        memset_s()        (C11 Annex K, where available)
 *        SecureZeroMemory()/RtlSecureZeroMemory()  (Windows)
 *    A plain memset() of a buffer that is never read again is a "dead
 *    store" and compilers may legally remove it. If none of the above is
 *    available, call memset through a volatile function pointer, as the
 *    secure_zero() helper in this file does.
 *  - Build/diagnose: -Wall -Wextra (-Wuninitialized, -Wmaybe-uninitialized),
 *    clang/gcc -ftrivial-auto-var-init=zero (hardening for locals, not a
 *    substitute for fixing the code), MemorySanitizer (-fsanitize=memory,
 *    clang) and Valgrind memcheck ("conditional jump depends on
 *    uninitialised value"), plus static analysers.
 *
 *  CERT C: EXP33-C (do not read uninitialized memory), MEM03-C (clear
 *  sensitive information stored in reusable resources), DCL39-C (avoid
 *  information leakage when passing a structure across a trust boundary).
 *
 * ======================================================================
 * 4. BEST PRACTICES AND CWE IDS
 * ======================================================================
 *  CWE-457  Use of Uninitialized Variable
 *  CWE-200  Exposure of Sensitive Information to an Unauthorized Actor
 *  CWE-201  Insertion of Sensitive Information Into Sent Data
 *  CWE-226  Sensitive Information in Resource Not Removed Before Reuse
 *  CWE-244  Improper Clearing of Heap Memory Before Release
 *  CWE-14   Compiler Removal of Code to Clear Buffers
 *  Practices: treat every outbound byte as an explicit decision; keep
 *  secrets in as few places and for as short a time as possible; prefer
 *  designs where the output length is computed from what was written.
 *
 * ======================================================================
 * ABOUT THIS DEMO
 * ======================================================================
 * The demo is deterministic. To avoid really reading indeterminate memory
 * (which is undefined behaviour), the "leftover data" is simulated: the
 * demo fills its own buffers with a known pattern (0xAA) or a fake secret
 * first, exactly as a previous user of that memory might have. Nothing
 * outside the demo's own buffers is read.
 *   vuln    : fresh, clean memory - output looks well formed (by luck).
 *   exploit : the same code on memory with leftovers - bytes leak.
 *   fixed   : zero first / serialise per field / clear + send used length.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stddef.h>
#include "cvulns.h"

#define LEFTOVER 0xAA /* byte pattern simulating stale heap contents */

/* ---------------------------------------------------------------------- */
/* Helpers                                                                */
/* ---------------------------------------------------------------------- */

/* Classic hexdump: offset, 16 bytes per row in hex, then printable ASCII. */
static void hexdump(const char *label, const unsigned char *p, size_t n) {
    size_t i, j;
    printf("    %s (%lu bytes)\n", label, (unsigned long)n);
    for (i = 0; i < n; i += 16) {
        printf("    %04lx  ", (unsigned long)i);
        for (j = 0; j < 16; j++) {
            if (i + j < n) printf("%02X ", (unsigned int)p[i + j]);
            else printf("   ");
        }
        printf(" |");
        for (j = 0; j < 16 && i + j < n; j++) {
            unsigned char c = p[i + j];
            putchar((c >= 0x20 && c < 0x7F) ? (int)c : '.');
        }
        printf("|\n");
    }
}

static size_t count_byte(const unsigned char *p, size_t n, unsigned char v) {
    size_t i, c = 0;
    for (i = 0; i < n; i++)
        if (p[i] == v) c++;
    return c;
}

/*
 * Secure erase fallback. Calling memset through a volatile function
 * pointer forces the compiler to assume an unknown function is called, so
 * it cannot prove the store is dead and drop it. Prefer explicit_bzero(),
 * memset_s() or SecureZeroMemory() when your platform provides them.
 */
static void *(*volatile memset_volatile)(void *, int, size_t) = memset;

static void secure_zero(void *p, size_t n) {
    if (p != NULL && n != 0) memset_volatile(p, 0, n);
}

/* ---------------------------------------------------------------------- */
/* Part A: struct padding                                                 */
/* ---------------------------------------------------------------------- */

struct record {
    char tag;  /* 1 byte, then (typically) 3 bytes of padding */
    int value; /* 4 bytes, 4-aligned */
};

/*
 * Safe serialisation: fixed layout, little-endian, no padding.
 * Returns the number of bytes written (always 5).
 */
static size_t serialize_record(const struct record *r, unsigned char *out) {
    unsigned int v = (unsigned int)r->value;
    out[0] = (unsigned char)r->tag;
    out[1] = (unsigned char)(v & 0xFFu);
    out[2] = (unsigned char)((v >> 8) & 0xFFu);
    out[3] = (unsigned char)((v >> 16) & 0xFFu);
    out[4] = (unsigned char)((v >> 24) & 0xFFu);
    return 5;
}

/*
 * dirty: 1 = the allocation contains leftovers (simulated with 0xAA),
 *        0 = the allocation happens to be clean (zeros).
 * clear_first: 1 = hardened code path (memset the struct before filling).
 */
static int padding_demo(int dirty, int clear_first) {
    const size_t size = sizeof(struct record);
    unsigned char *mem = (unsigned char *)malloc(size);
    struct record *r;
    size_t leaked;

    if (mem == NULL) {
        BAD("out of memory");
        return 1;
    }
    /* Simulate what malloc() may hand back: stale bytes from an earlier use. */
    memset(mem, dirty ? LEFTOVER : 0x00, size);

    r = (struct record *)mem;
    if (clear_first) memset(r, 0, sizeof *r); /* clears padding too */
    r->tag = 'A';
    r->value = 0x01020304;

    INFO("sizeof(struct record) = %lu, offsetof(value) = %lu, padding = %lu bytes",
         (unsigned long)size, (unsigned long)offsetof(struct record, value),
         (unsigned long)(size - 1 - sizeof(int)));

    /* The "wire form" of the buggy code: the raw struct, as fwrite(&r,...) would emit. */
    hexdump("raw struct as written to the wire", mem, size);
    leaked = count_byte(mem, size, LEFTOVER);
    if (leaked > 0)
        BAD("%lu padding byte(s) of stale data (0xAA) are part of the message", (unsigned long)leaked);
    else
        GOOD("no stale bytes in the raw struct%s",
             clear_first ? " (struct was memset to 0 before filling)" : " (only because the memory was clean)");

    if (clear_first) {
        unsigned char wire[8];
        size_t n = serialize_record(r, wire);
        INFO("hardened path also serialises field by field (defined layout, no padding):");
        hexdump("serialised record", wire, n);
        GOOD("exactly %lu bytes, all of them intentional", (unsigned long)n);
    }

    free(mem);
    return 0;
}

/* ---------------------------------------------------------------------- */
/* Part B: stale data in a reused buffer                                  */
/* ---------------------------------------------------------------------- */

#define SECRET "hunter2-demo-secret"
#define BUF_CAP 48

struct session_buf {
    unsigned char data[BUF_CAP];
    int in_use;
};

static struct session_buf g_buf; /* the demo's private "heap block" */

/* Demo stand-in for free(): marks the block reusable, does NOT touch contents. */
static void demo_release(struct session_buf *b) {
    b->in_use = 0;
}

/* Hardened release: erase first, then mark reusable. */
static void demo_release_clean(struct session_buf *b) {
    secure_zero(b->data, sizeof b->data);
    b->in_use = 0;
}

static int reuse_demo(int store_secret_first, int hardened) {
    struct session_buf *b = &g_buf;
    size_t used, to_send;
    const char *reply = "OK: pong";

    /* Start from a known state. */
    memset(b->data, 0, sizeof b->data);
    b->in_use = 1;

    if (store_secret_first) {
        INFO("step 1: buffer holds a secret: \"%s\"", SECRET);
        memcpy(b->data, SECRET, sizeof SECRET); /* includes the NUL */
        hexdump("buffer contents", b->data, BUF_CAP);
        if (hardened) {
            INFO("step 2: released with secure_zero() before reuse");
            demo_release_clean(b);
        } else {
            INFO("step 2: released like free(): contents are NOT cleared");
            demo_release(b);
        }
    } else {
        INFO("step 1: fresh, zeroed buffer (no previous secret)");
        demo_release(b);
    }

    /* Reuse for a new, shorter response. */
    b->in_use = 1;
    snprintf((char *)b->data, sizeof b->data, "%s", reply);
    used = strlen(reply) + 1; /* text plus terminating NUL */
    INFO("step 3: buffer reused for the reply \"%s\" (%lu bytes used of %lu)",
         reply, (unsigned long)used, (unsigned long)BUF_CAP);

    /* BUG: send the capacity. FIX: send only what was written. */
    to_send = hardened ? used : (size_t)BUF_CAP;
    hexdump("bytes handed to send()", b->data, to_send);

    if (to_send > used && count_byte(b->data + used, to_send - used, 0x00) != to_send - used) {
        BAD("the reply carries leftover bytes after the message: the secret leaks");
    } else if (to_send > used) {
        GOOD("extra bytes sent but they are zeros (nothing leaked, still sloppy: send only the used length)");
    } else {
        GOOD("only the %lu bytes that were written are sent", (unsigned long)to_send);
    }

    demo_release_clean(b);
    return 0;
}

/* ---------------------------------------------------------------------- */
/* Entry point                                                            */
/* ---------------------------------------------------------------------- */

static int run(vuln_mode mode) {
    int rc = 0;

    switch (mode) {
    case MODE_VULN:
        INFO("benign case: memory happens to be clean, so the output looks fine");
        SECTION("A. struct padding");
        rc |= padding_demo(0, 0);
        SECTION("B. reused buffer");
        rc |= reuse_demo(0, 0);
        INFO("it only looks correct because nothing sensitive lived there before");
        break;

    case MODE_EXPLOIT:
        INFO("same code, but the memory contains leftovers from earlier use");
        SECTION("A. struct padding");
        rc |= padding_demo(1, 0);
        SECTION("B. reused buffer");
        rc |= reuse_demo(1, 0);
        break;

    case MODE_FIXED:
        INFO("hardened code on the same dirty memory");
        SECTION("A. struct padding");
        rc |= padding_demo(1, 1);
        SECTION("B. reused buffer");
        rc |= reuse_demo(1, 1);
        break;
    }
    return rc;
}

const vuln_example ex06_example = {
    "info-leak",
    "Information leak: uninitialized memory and struct padding (CWE-457/CWE-200/CWE-201)",
    run
};
