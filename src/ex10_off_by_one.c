/*
 * ex10_off_by_one.c - Off-by-one errors and missing NUL terminators
 *                     (CWE-193, CWE-170, CWE-805, CWE-131, CWE-125/787)
 *
 * ======================================================================
 * 1. WHAT IS IT?
 * ======================================================================
 * C strings are "pointer to bytes, ended by a 0 byte".  Every buffer that
 * holds a string must therefore be ONE BYTE LARGER than the text it holds.
 * Humans (and APIs with confusing size semantics) get that "+1" wrong all the
 * time.  These are the classic fencepost errors:
 *
 *   - Loop bound:        for (i = 0; i <= n; i++) buf[i] = ...;     // n+1 writes
 *                        (buf has n elements: valid indices are 0..n-1)
 *   - Terminator index:  buf[sizeof buf] = '\0';                    // one past the end
 *                        (must be buf[sizeof buf - 1])
 *   - Allocation:        p = malloc(strlen(s)); strcpy(p, s);       // forgot +1
 *                        (must be malloc(strlen(s) + 1))
 *   - strncpy():         strncpy(d, s, sizeof d);  does NOT write a NUL when
 *                        strlen(s) >= sizeof d.  The result is NOT a string.
 *                        (When src is SHORTER it pads the whole rest of the
 *                        buffer with zeros - harmless but wasteful: copying
 *                        "a" into a 4 KiB buffer writes 4096 bytes.)
 *                        strncpy was designed for fixed-width, possibly
 *                        unterminated record fields (old Unix utmp/tar
 *                        headers), NOT as a "safe strcpy".
 *   - strncat():         the size is the number of characters to APPEND,
 *                        i.e. the REMAINING SPACE EXCLUDING the NUL that
 *                        strncat always writes.  So
 *                            strncat(d, s, sizeof d);          // WRONG
 *                        can write sizeof d + strlen(d) + 1 bytes.  Right:
 *                            strncat(d, s, sizeof d - strlen(d) - 1);
 *   - strlen() on an unterminated buffer keeps reading into whatever
 *     happens to be adjacent (CWE-126 over-read / information leak).
 *   - sizeof(ptr) vs. array length:  void f(char *p) { sizeof p == 8 } - the
 *     size of a POINTER, not of the buffer it points at.  Likewise
 *     sizeof(buf) counts BYTES, so for wchar_t buf[N] you must divide by
 *     sizeof(wchar_t) (2 on Windows, 4 on Linux!) before using it as an
 *     element count; passing sizeof(wbuf) as the "count" to wcsncpy /
 *     MultiByteToWideChar overflows by a factor of 2 or 4.
 *   - Off-by-one in the OTHER direction (a "short by one" length check:
 *     `if (len < MAX)` vs `if (len <= MAX)`, `>` vs `>=`) - same bug class.
 *
 * ======================================================================
 * 2. HOW IS IT EXPLOITED?
 * ======================================================================
 * "It is only ONE byte, and it is only a zero" - this is the usual excuse
 * and it is wrong.  A single overwritten byte is often enough:
 *
 *   (a) Missing terminator -> information leak.  If a username buffer is not
 *       terminated, every later strlen/printf/strcat/strcpy of it continues
 *       into the adjacent object - e.g. the password / session key / token
 *       stored right after it - and sends it to the screen, the log file or
 *       the network.  Sample malicious input: a username of exactly
 *       sizeof(username) characters, "AAAAAAAAAAAAAAAA" for a 16-byte field.
 *       strncpy copies 16 'A's, writes no NUL, and "Hello AAAA...A" now
 *       continues with the password bytes.  (Part A of this demo.)
 *
 *   (b) A NUL written one past the end clobbers the neighbour.  On a
 *       little-endian machine (x86, ARM) the byte directly after a buffer is
 *       the LEAST significant byte of the next integer/pointer/length, so
 *       writing a 0 there rewrites it to a "round" value:
 *         - a flag / counter / access level becomes 0 (e.g. "failed login
 *           counter reached its limit -> account locked" becomes "0 failed
 *           attempts -> account open"; "is_guest = 1" becomes 0).
 *         - a saved frame pointer (EBP/RBP) is lowered by up to 255 bytes so
 *           that, when the caller returns, its frame is mistaken for a
 *           location inside the attacker-controlled buffer -> control of the
 *           return address (the classic "frame pointer off-by-one").
 *           Historic examples: the Apache mod_ssl/mod_rewrite era bugs,
 *           OpenSSH 2.x channel code (CVE-2002-0083, an off-by-one in the
 *           channel array bound check -> privilege escalation), ProFTPD
 *           (CVE-2006-6563-era and earlier off-by-ones in directory/ASCII
 *           handling), and many glibc/ld.so issues.
 *         - the "poison null byte": a NUL written over the low byte of a
 *           heap chunk's size field (glibc malloc) shrinks the chunk so that
 *           later free()/consolidation corrupts the allocator and gives the
 *           attacker overlapping chunks.  This is the foundation of many CTF
 *           and real-world heap exploits (e.g. in the Linux dynamic loader
 *           and various servers).  malloc(strlen(s)) + strcpy is the classic
 *           way to produce it; with a request such as 24 or 40 bytes (sizes
 *           that exactly fill a chunk's usable area) the extra NUL lands on
 *           the next chunk's header.  (Part C models this safely.)
 *       Sample malicious input for part B: an 8-character name, "AAAAAAAA",
 *       to an 8-byte field whose loop runs `i <= sizeof name`: the loop copies
 *       the source terminator into name[8] = the neighbouring counter.
 *
 *   (c) Overflow by an attacker-chosen small amount via strncat/strncpy
 *       arithmetic errors, or a length computed as `len - 1` when len == 0
 *       (wraps to SIZE_MAX).  Test the boundary values 0, 1, N-1, N, N+1.
 *
 * ======================================================================
 * 3. HOW TO AVOID IT
 * ======================================================================
 *   - Size is ALWAYS sizeof(dest) (for arrays) or an explicit capacity
 *     parameter - never strlen(src), never sizeof(pointer).  Keep the capacity
 *     next to the pointer (struct {char *p; size_t cap, len;} or the
 *     (ptr,len) pair of CERT API design) and never recompute it.
 *   - If you must use strncpy/strncat, terminate explicitly:
 *         strncpy(dest, src, sizeof dest - 1);
 *         dest[sizeof dest - 1] = '\0';                 // index = size - 1
 *   - Prefer functions that ALWAYS terminate and report truncation:
 *       * snprintf(dst, sizeof dst, "%s", src);  returns the length that
 *         WOULD have been written; `ret >= sizeof dst` means truncated.
 *       * strlcpy/strlcat (OpenBSD, FreeBSD, macOS, glibc >= 2.38) or a tiny
 *         helper such as safe_copy() below.
 *       * memccpy(dst, src, '\0', sizeof dst) (C23/POSIX): returns NULL when
 *         no NUL was copied -> then set dst[sizeof dst - 1] = '\0'.
 *       * strdup()/asprintf() or "size_t n = strlen(s) + 1; malloc(n)" with
 *         checked arithmetic; calloc for arrays.
 *   - C11 Annex K (strncpy_s, strcpy_s, ...) is optional, almost nobody
 *     implements it except MSVC (whose versions differ from the standard);
 *     glibc and musl do not.  Do not rely on it for portable code.
 *   - Use named constants: `char name[NAME_MAX_LEN + 1]` and loop with `<`
 *     against the SAME constant; never type the bare number twice.  Write
 *     array loops as `for (i = 0; i < ARRAY_LEN(a); i++)`.  Remember
 *     `sizeof` of a wchar_t array is bytes, not elements.
 *   - Test the boundary values (0, 1, N-1, N, N+1) in unit tests; fuzz every
 *     parser; run under AddressSanitizer/UBSan/Valgrind (ASan catches heap and
 *     stack off-by-ones, though NOT overflows from one member of a struct into
 *     the next member - use -fsanitize=bounds, or static analysis, for
 *     those); compile with -Wall -Wextra -Wstringop-truncation
 *     -Wstringop-overflow -Warray-bounds (gcc), /analyze (MSVC), and run
 *     clang-tidy (bugprone-not-null-terminated-result,
 *     bugprone-sizeof-expression) / Coverity / CodeQL.
 *   - Harden: -D_FORTIFY_SOURCE=2/3, -fstack-protector-strong, modern allocators
 *     with safe-unlinking and tcache checks (they make poison-null-byte harder
 *     but do NOT fix the bug).
 *
 * ======================================================================
 * 4. BEST PRACTICES AND REFERENCES
 * ======================================================================
 *   CWE-193  Off-by-one Error                 CWE-170  Improper Null Termination
 *   CWE-805  Buffer Access with Incorrect Length Value
 *   CWE-131  Incorrect Calculation of Buffer Size
 *   CWE-120/121/122 Classic / stack / heap buffer overflow
 *   CWE-125/126 Out-of-bounds Read / Buffer Over-read (the leak)
 *   CWE-787  Out-of-bounds Write
 *   CERT C:  STR03-C  Do not inadvertently truncate a string
 *            STR31-C  Guarantee storage for strings has sufficient space for
 *                     character data and the null terminator
 *            STR32-C  Do not pass a non-null-terminated character sequence to
 *                     a library function that expects a string
 *            ARR30-C  Do not form or use out-of-bounds pointers or array
 *                     subscripts
 *            ARR38-C  Guarantee that library functions do not form invalid
 *                     pointers
 *            MEM35-C  Allocate sufficient memory for an object
 *            MSC? - there is no single rule; see also MSC06-C (beware of
 *            compiler optimisations) and API00-C.  MISRA C:2012 Rules 18.1
 *            and 21.17 / 21.18 (string.h functions shall not access beyond
 *            the bounds of the objects).
 *
 * ======================================================================
 * DEMO LAYOUT AND SAFETY
 * ======================================================================
 * All victim data lives in structs OWNED BY THIS DEMO and made only of char
 * arrays and uint8_t (alignment 1), so there is no padding between members
 * and the layout is identical on every compiler.  STRICTLY SPEAKING, reading
 * or writing past the end of one array member into the next member of the same
 * struct is undefined behaviour (C11 6.5.6p8) even though it stays inside the
 * object; the demo relies on the "flat array" layout that every real compiler
 * produces at -O0.  The demo VERIFIES this at run time with offsetof and
 * sizeof and skips itself with a notice if the layout is different.
 * Every "unsafe" read of an unterminated string is capped with printf's
 * "%.*s" precision / memchr, so the demo never reads beyond its own object.
 *
 * Parts:
 *   A  strncpy without termination  -> adjacent password leaks   (CWE-170)
 *   B  `<=` loop writes NUL past the buffer, clears the neighbour (CWE-193)
 *   C  malloc(strlen(s)) missing +1, modelled on an arena         (CWE-131)
 */
#include <stdio.h>
#include <string.h>
#include <stddef.h>
#include <stdint.h>
#include "cvulns.h"

/* ------------------------------------------------------------------ */
/* Hardened helper: copy with guaranteed termination.                   */
/* Returns 0 on success, 1 if the source had to be truncated.           */
/* ------------------------------------------------------------------ */
static int safe_copy(char *dst, size_t dstsz, const char *src)
{
    size_t n;
    if (dstsz == 0)                /* no room even for the NUL: nothing to do */
        return 1;
    n = strlen(src);               /* src is a valid string by contract */
    if (n >= dstsz) {              /* needs n + 1 bytes; we have dstsz */
        memcpy(dst, src, dstsz - 1);
        dst[dstsz - 1] = '\0';     /* index is size - 1, never size */
        return 1;                  /* truncated */
    }
    memcpy(dst, src, n + 1);       /* +1 copies the terminator too */
    return 0;
}

/* Bounded "strlen": length of the string at p, looking at no more than max
 * bytes.  Returns max when no NUL was found, i.e. the data is unterminated.
 * Used so that the demo itself never walks off its own object. */
static size_t bounded_len(const char *p, size_t max)
{
    const char *z = (const char *)memchr(p, '\0', max);
    return z ? (size_t)(z - p) : max;
}

/* ================================================================== */
/* PART A: strncpy leaves the field unterminated -> information leak   */
/* ================================================================== */
struct session {
    char username[16];   /* attacker-influenced */
    char password[16];   /* secret, directly after username, no padding */
    uint8_t is_admin;
};

static int part_a(vuln_mode mode)
{
    struct session s;
    const char *src = (mode == MODE_VULN) ? "alice" : "AAAAAAAAAAAAAAAA"; /* 16 chars */
    size_t span, len;

    SECTION("A: strncpy(dst, src, sizeof dst) does not terminate");
    memset(&s, 0, sizeof s);
    strcpy(s.password, "hunter2-s3cret");           /* 14 chars + NUL, fits in 16 */

    if (offsetof(struct session, password) != sizeof s.username) {
        INFO("Unexpected struct padding on this compiler: skipping part A.");
        return 0;
    }
    INFO("username[%zu] is followed directly by password[%zu] (offset %zu)",
         sizeof s.username, sizeof s.password, offsetof(struct session, password));
    INFO("input username = \"%s\" (%zu chars, field holds at most %zu + NUL)",
         src, strlen(src), sizeof s.username - 1);

    if (mode == MODE_FIXED) {
        /* HARDENED: helper always terminates and tells us about truncation. */
        int trunc = safe_copy(s.username, sizeof s.username, src);
        len = bounded_len(s.username, sizeof s.username);
        GOOD("safe_copy: stored \"%.*s\" (%zu chars)%s", (int)len, s.username, len,
             trunc ? ", input was TRUNCATED (and reported)" : "");

        /* snprintf always terminates, and its return value reveals truncation. */
        {
            char tmp[16];
            int r = snprintf(tmp, sizeof tmp, "%s", src);
            GOOD("snprintf: tmp=\"%s\", would-need=%d, truncated=%s",
                 tmp, r, (r < 0 || (size_t)r >= sizeof tmp) ? "yes" : "no");
        }
    } else {
        /* VULNERABLE: when strlen(src) >= 16, no NUL is written at all.
         * (For short input strncpy zero-pads the rest, so it "works" in
         * testing - that is exactly why the bug survives.) */
        strncpy(s.username, src, sizeof s.username);
        /* A typical consumer would now do printf("Hello %s", s.username) or
         * strlen(s.username).  We emulate that, but capped to the extent of
         * the two fields so the demo can never leave its own struct. */
        span = sizeof s.username + sizeof s.password;
        len = bounded_len(s.username, span);
        if (len <= sizeof s.username - 1) {
            GOOD("username = \"%.*s\" (terminated, %zu chars)", (int)len, s.username, len);
        } else {
            BAD("no NUL inside username[]: the 'string' runs on for %zu bytes!", len);
            BAD("Hello %.*s", (int)len, s.username);
            BAD("^ the password was printed/logged/sent along with the name");
        }
    }
    return 0;
}

/* ================================================================== */
/* PART B: the `<=` loop writes the terminator one byte too far        */
/* ================================================================== */
struct record {
    char name[8];
    uint8_t failed_logins;   /* account is LOCKED when failed_logins >= LOCK_LIMIT */
};
#define LOCK_LIMIT 3

/* VULNERABLE: "copy at most cap characters, then terminate" written with
 * `<=`.  The loop copies src[0..cap] inclusive, i.e. cap + 1 bytes.  When
 * the source is exactly cap characters long, src[cap] is its terminator and
 * it is copied into dst[cap] - one byte past the end of the array. */
static void vuln_copy_name(char *dst, size_t cap, const char *src)
{
    size_t i;
    for (i = 0; i <= cap; i++) {            /* BUG: should be i < cap */
        dst[i] = src[i];
        if (src[i] == '\0')
            break;
    }
}

static int part_b(vuln_mode mode)
{
    struct record r;
    const char *src = (mode == MODE_VULN) ? "bob" : "AAAAAAAA";   /* 8 chars: fills name[] */
    size_t len;

    SECTION("B: `i <= sizeof buf` writes one NUL past the end");
    memset(&r, 0, sizeof r);
    r.failed_logins = LOCK_LIMIT;           /* this account is locked */

    if (offsetof(struct record, failed_logins) != sizeof r.name) {
        INFO("Unexpected struct padding on this compiler: skipping part B.");
        return 0;
    }
    INFO("name[%zu] is followed directly by failed_logins (offset %zu), value = %u (locked when >= %d)",
         sizeof r.name, offsetof(struct record, failed_logins),
         (unsigned)r.failed_logins, LOCK_LIMIT);
    INFO("input name = \"%s\" (%zu chars)", src, strlen(src));

    if (mode == MODE_FIXED) {
        /* HARDENED: capacity-aware copy; strict `<` against the real size. */
        int trunc = safe_copy(r.name, sizeof r.name, src);
        len = bounded_len(r.name, sizeof r.name);
        GOOD("stored name \"%.*s\"%s", (int)len, r.name,
             trunc ? " (truncated and reported, 7 chars + NUL)" : "");
    } else {
        vuln_copy_name(r.name, sizeof r.name, src);
        len = bounded_len(r.name, sizeof r.name);       /* cap the demo's own read */
        INFO("stored name \"%.*s\"", (int)len, r.name);
    }

    if (r.failed_logins >= LOCK_LIMIT) {
        GOOD("failed_logins = %u -> account still LOCKED", (unsigned)r.failed_logins);
    } else {
        BAD("failed_logins = %u -> account UNLOCKED! One stray NUL byte cleared the", (unsigned)r.failed_logins);
        BAD("least significant (here: the only) byte of the neighbouring counter.");
        BAD("Same trick on a saved frame pointer or a malloc chunk size = code execution.");
    }
    return 0;
}

/* ================================================================== */
/* PART C: malloc(strlen(s)) forgetting the +1  (modelled on an arena)  */
/* ================================================================== */
/*
 * The vulnerable idiom in real code:
 *
 *     char *copy = malloc(strlen(s));        // BUG: no room for the NUL
 *     strcpy(copy, s);                       // writes strlen(s) + 1 bytes
 *
 * On glibc a request of e.g. 24 bytes returns a chunk whose usable size is
 * exactly 24, so the NUL lands on the low byte of the NEXT chunk's size field
 * ("poison null byte").  We must not corrupt a real heap in a teaching
 * program, so we model the allocator with a tiny arena: a 32 byte array in
 * which a neighbouring "header" byte (0xAA) sits directly after the requested
 * block.  The request is carved from the start of the arena.
 */
struct arena {
    char mem[48];
};

/* Like real allocators, round the request up to a multiple of 8 ("usable
 * size"); the byte right after the usable block is the neighbour.  Slack is
 * why the missing +1 hides for most inputs and only bites at the boundary. */
static char *arena_alloc(struct arena *a, size_t n, size_t *usable)
{
    memset(a->mem, 0xAA, sizeof a->mem);    /* 0xAA marks "neighbouring metadata" */
    *usable = (n + 7u) & ~(size_t)7u;
    if (*usable == 0) *usable = 8;
    return (*usable < sizeof a->mem) ? a->mem : NULL;
}

static int part_c(vuln_mode mode)
{
    struct arena ar;
    /* benign: 2 chars (slack absorbs the NUL); attack: 16 chars = exact multiple of 8 */
    const char *s = (mode == MODE_VULN) ? "hi" : "ABCDEFGHIJKLMNOP";
    size_t need, usable = 0;
    char *copy;
    unsigned char neighbour;

    SECTION("C: malloc(strlen(s)) forgot the +1 (arena model)");
    INFO("input string = \"%s\" (strlen %zu)", s, strlen(s));

    /* BUG (vuln/exploit): missing + 1.  FIX: room for the terminator. */
    need = (mode == MODE_FIXED) ? strlen(s) + 1 : strlen(s);

    copy = arena_alloc(&ar, need, &usable);
    if (!copy) {
        INFO("arena too small: skipping part C.");
        return 0;
    }
    INFO("requested %zu bytes, allocator rounds to %zu usable bytes", need, usable);

    strcpy(copy, s);                            /* writes strlen(s) + 1 bytes */

    neighbour = (unsigned char)ar.mem[usable];  /* usable < 48: in bounds */
    if (neighbour == 0xAA) {
        GOOD("neighbour byte intact (0x%02X)", (unsigned)neighbour);
        if (mode == MODE_VULN)
            INFO("the missing +1 is invisible here (allocator slack) - which is why it survives testing");
    } else {
        BAD("neighbour byte overwritten: 0xAA -> 0x%02X (the terminator)", (unsigned)neighbour);
        BAD("with glibc this is the low byte of the next chunk size: the poison-null-byte primitive");
    }
    return 0;
}

/* ------------------------------------------------------------------ */

static int run(vuln_mode mode)
{
    int rc = 0;
    rc |= part_a(mode);
    rc |= part_b(mode);
    rc |= part_c(mode);

    SECTION("Summary");
    if (mode == MODE_FIXED) {
        GOOD("Always size with sizeof(dest), terminate at size-1, prefer snprintf/strlcpy,");
        GOOD("and test the boundary values 0, N-1, N and N+1.");
    } else if (mode == MODE_EXPLOIT) {
        BAD("Three one-byte mistakes: missing terminator, `<=` loop bound, missing +1.");
    } else {
        INFO("With short benign input the same code looks fine - boundary tests are needed.");
    }
    return rc;
}

const vuln_example ex10_example = {
    "off-by-one",
    "Off-by-one and missing NUL terminator: strncpy/strncat misuse (CWE-193/CWE-170/CWE-805)",
    run
};
