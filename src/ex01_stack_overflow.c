/*
 * ex01_stack_overflow.c
 * ======================================================================
 * MISTAKE: Stack buffer overflow via unchecked copies (strcpy/gets-style)
 * CWE-121 (Stack-based Buffer Overflow), CWE-120 (Buffer Copy without
 * Checking Size of Input, "Classic Buffer Overflow"), CWE-787 (Out-of-
 * bounds Write).
 *
 * ----------------------------------------------------------------------
 * 1. WHAT IT IS
 * ----------------------------------------------------------------------
 * C arrays and local ("automatic") variables carry NO bounds information
 * at runtime. `char name[16]` is nothing more than "16 bytes starting at
 * this address" -- the compiler does not remember the 16 anywhere the
 * program can check it, and the standard library functions that copy
 * bytes into it (strcpy, strcat, sprintf, gets, memcpy with a bad length,
 * manual loops with an off-by-one, ...) take a *source* and a
 * *destination pointer* only. Nothing stops the source from containing
 * more bytes than the destination can hold.
 *
 * C permits this because its design philosophy is "trust the programmer,
 * stay close to the machine, pay no runtime tax". There is no mandatory
 * bounds check, no fat pointer, no runtime array-length metadata --
 * unlike (say) a Rust slice or a Java array. That is also exactly why C
 * is still used for OSes and embedded systems, and exactly why it is
 * also the source of the single most common class of security bugs in
 * the software industry's history.
 *
 * A typical stack frame (conceptual, grows "downward" on most ABIs --
 * exact order/padding is ABI- and compiler-dependent, this is a mental
 * model, not a guarantee):
 *
 *      [ caller's frame                      ]
 *      +---------------------------------------+  <- higher addresses
 *      | saved return address (where to go     |
 *      |   back to when this function returns) |
 *      +---------------------------------------+
 *      | saved frame pointer / stack canary    |
 *      +---------------------------------------+
 *      | local variable: is_admin (int)        |  <- adjacent local
 *      +---------------------------------------+
 *      | local buffer: name[16]                |  <- the vulnerable
 *      |   writes here can run OFF THE END --> |     buffer: overflow
 *      |   and keep going upward in address    |     keeps writing UP
 *      |   space, into whatever is next        |     into the items
 *      +---------------------------------------+  <- lower addresses    above
 *
 * When `strcpy(name, attacker_input)` writes more bytes than `name` has
 * room for, those extra bytes land in whatever memory is adjacent --
 * other local variables, saved registers, a saved frame pointer, and
 * ultimately the saved return address or, on some layouts, a function
 * pointer stored nearby. The attacker chooses the bytes, so the attacker
 * chooses what those adjacent locations become.
 *
 * ----------------------------------------------------------------------
 * 2. HOW IT IS EXPLOITED
 * ----------------------------------------------------------------------
 * Preconditions an attacker needs: (a) a code path that copies
 * attacker-controlled data into a fixed-size stack buffer without a
 * length check, and (b) the ability to control the length and/or content
 * of that data (a network packet, a command-line argument, an
 * environment variable, a config file, user input...).
 *
 * Classic escalation ladder, from mild to severe:
 *   - Overwrite an adjacent "boring" local variable (e.g. a flag like
 *     `is_admin`) to flip program logic. This is what this file
 *     demonstrates, because it is 100% safe to show live: worst case,
 *     one integer in our own struct gets the "wrong" value.
 *   - Overwrite a saved function pointer / vtable entry living on the
 *     stack or reachable via it, redirecting a later indirect call.
 *   - Overwrite the saved return address itself. When the vulnerable
 *     function returns, the CPU pops that address and jumps to it. If
 *     the attacker put a useful address there, they now control
 *     execution.
 *
 * What goes in that controlled address / nearby bytes depends on the era
 * and the mitigations in place:
 *   - "Classic shellcode": the attacker places a small hand-written
 *     machine-code payload directly in the overflowing buffer (or
 *     nearby) and overwrites the return address with the address of
 *     that payload. The CPU jumps straight into attacker-supplied code.
 *     This only works when the stack (or wherever the payload lives) is
 *     executable, and when the attacker can predict/guess the address.
 *   - "ROP" (Return-Oriented Programming): once stacks/heaps are marked
 *     non-executable (NX/DEP, see below), attackers can no longer jump
 *     into injected code. Instead they chain together addresses of tiny
 *     existing code fragments ("gadgets", each ending in `ret`) already
 *     present in the binary/libraries, stitching them into the
 *     overwritten stack to perform arbitrary computation purely by
 *     controlling the sequence of return addresses -- no new code is
 *     injected, so NX does not stop it.
 *
 * Example SAFE/EDUCATIONAL payload shape (illustrates padding math, not
 * a working weaponized exploit -- see the code below for the exact
 * offsetof()-derived version actually used in `exploit` mode):
 *
 *   victim_t { char name[16]; int is_admin; };
 *   padding_needed = offsetof(victim_t, is_admin);     // bytes to fill
 *                                                       // name[] + any
 *                                                       // compiler padding
 *   payload = ('A' * padding_needed)                   // fills name[]
 *           + ('A' * sizeof(int))                      // lands on is_admin,
 *                                                       // 0x41414141 != 0
 *
 *   # Build such a payload offline, e.g.:
 *   #   python3 -c "import sys; sys.stdout.write('A'*20)"
 *   #   printf 'A%.0s' $(seq 1 20)
 *   # (20 here is a placeholder -- the real code computes the exact
 *   # number from offsetof() so it is correct on every compiler/ABI.)
 *
 * In a real stack-smashing exploit targeting the return address, the
 * tail of the payload would instead be the address of shellcode or the
 * first ROP gadget, repeated/aligned to match the stack layout -- found
 * via a debugger, a crash offset ("pattern_create"/"pattern_offset"
 * style tools), or source analysis.
 *
 * MITIGATIONS, AND WHY THEY ARE NOT A FIX:
 *   - Stack canaries (-fstack-protector-strong): a random value is
 *     placed just before the saved return address; the function checks
 *     it before returning and aborts if it changed. This stops *some*
 *     sequential overflows from hijacking the return address, but does
 *     NOT stop the overflow from happening, and does not protect data
 *     that lives *before* the canary (like our is_admin flag in this
 *     demo, or any struct member overflowed without crossing the
 *     canary). Non-linear or targeted writes can also route around it.
 *   - ASLR (Address Space Layout Randomization): randomizes where code
 *     and libraries are loaded, making it harder to guess an address to
 *     jump to. Defeated by information leaks (leak one address, derive
 *     the rest), brute force on 32-bit, or non-address-dependent
 *     corruption (like flipping a boolean, as below).
 *   - NX/DEP (non-executable stack/heap): stops the CPU from executing
 *     bytes that live in data memory, blocking classic shellcode
 *     injection. Defeated by ROP (reusing existing executable code) and
 *     irrelevant to pure data corruption (our is_admin case).
 *   - CFG (Control-Flow Guard) / CFI: validates indirect call/jump
 *     targets against a precomputed set of legal targets, narrowing
 *     where a hijacked function pointer or return can go. Raises the
 *     bar for code-reuse attacks but does not stop the memory corruption
 *     itself, and coarse-grained CFI still allows many legitimate-looking
 *     gadgets through.
 *   All of these are *mitigations*: they make exploitation harder or
 *   less reliable. They do not make the underlying bug (writing past the
 *   end of a buffer) go away. The only real fix is to never perform an
 *   unbounded write in the first place -- see section 3.
 *
 * ----------------------------------------------------------------------
 * 3. HOW TO AVOID IT
 * ----------------------------------------------------------------------
 *   - Never use `gets()` -- it has NO length parameter at all and was
 *     removed from the C standard in C11. (Not used anywhere in this
 *     file, including the "vulnerable" function below, precisely
 *     because it is unsafe to even link against on some platforms; it
 *     is discussed here only in comments.)
 *   - Avoid `strcpy`/`strcat`/unbounded `sprintf`. Prefer:
 *       * `snprintf(dst, sizeof dst, "%s", src)` -- always NUL-
 *         terminates, truncates safely, and the size is checked at the
 *         call site every time because `sizeof dst` is textually right
 *         there.
 *       * A `strlcpy`-style helper (BSD/OpenBSD; not standard C, but a
 *         few lines to implement) that copies at most N-1 bytes and
 *         always NUL-terminates, returning the length it *wanted* to
 *         copy so truncation is detectable.
 *       * `fgets(buf, sizeof buf, stream)` instead of `gets()` for line
 *         input -- it takes an explicit size.
 *       * C11 Annex K `strcpy_s`/`strncpy_s` *if* your library actually
 *         implements it (Annex K is optional; MSVC has its own similar
 *         `_s` functions but they are not quite Annex K; glibc largely
 *         does not implement Annex K at all) -- treat Annex K as "nice
 *         if available", not something to depend on for portability.
 *   - Always validate/clamp lengths explicitly before copying, and
 *     reject (don't silently truncate) input you cannot safely process
 *     when correctness matters more than availability.
 *   - Compile with hardening ON in real projects (this demo deliberately
 *     disables them -- see CMakeLists.txt comment -- so the bug behaves
 *     like the textbook case): `-fstack-protector-strong`,
 *     `-D_FORTIFY_SOURCE=2` (glibc: adds runtime bounds checks to many
 *     *_s/_chk variants of string/memory functions when sizes are known
 *     at compile time), `/GS` (MSVC canary, on by default).
 *   - Use AddressSanitizer (`-fsanitize=address`) and static analysis
 *     (clang-tidy, cppcheck, Coverity, MSVC /analyze) during development
 *     and CI to catch overflows long before they ship.
 *   - Where feasible, use a safer abstraction/language for new code that
 *     handles untrusted input: a length-carrying string type, a
 *     bounds-checked container, or a memory-safe language (Rust, Go,
 *     etc.) at the boundary that parses untrusted data.
 *
 * Best practices / relevant rule IDs:
 *   - CWE-121 (Stack-based Buffer Overflow), CWE-120 (Classic Buffer
 *     Overflow), CWE-787 (Out-of-bounds Write), CWE-676 (Use of
 *     Potentially Dangerous Function, e.g. gets/strcpy).
 *   - CERT C: STR31-C "Guarantee that storage for strings has sufficient
 *     space for character data and the null terminator", STR32-C
 *     "Do not pass a non-null-terminated character sequence to a
 *     library function that expects a string", ARR38-C "Guarantee that
 *     library functions do not form invalid pointers", MSC24-C "Do not
 *     use deprecated or obsolescent functions" (gets, strcpy, etc.).
 *   - MISRA C: Rule 21.17/21.18 (restrictions on string-handling
 *     functions and buffer bounds).
 *   - OWASP: "Buffer Overflow" under the Memory Management category of
 *     the Secure Coding Practices.
 * ======================================================================
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stddef.h>   /* offsetof */

#include "cvulns.h"

static int run(vuln_mode mode);

const vuln_example ex01_example = {
    "stack-overflow",
    "Stack buffer overflow via strcpy/gets (CWE-121/CWE-120)",
    run
};

/*
 * The "victim" struct: a small login record living on the stack. The
 * demo overflows `name` and observes whether `is_admin` gets corrupted.
 * This keeps the corruption fully contained to a struct *we* own, so the
 * process never crashes even in `exploit` mode, per the project rules in
 * cvulns.h. We intentionally do NOT rely on a packed layout: real
 * compilers may insert padding between `name` and `is_admin`, and the
 * code below computes the exact byte count to fill using offsetof() so
 * the demo is correct regardless of padding/ABI (gcc, clang, MSVC, 32 or
 * 64 bit all compute offsetof() for us at compile time).
 */
typedef struct {
    char name[16];
    int  is_admin;
} victim_t;

/* ---------------------------------------------------------------------
 * VULNERABLE: copies attacker-controlled input into a fixed buffer with
 * no length check at all, exactly like real-world `strcpy(dst, src)`
 * misuse. If `input` is longer than `sizeof v->name` (minus the NUL),
 * the extra bytes overflow into whatever memory follows `name` inside
 * `victim_t` -- here, `is_admin`.
 * ------------------------------------------------------------------- */
static void vulnerable_login(victim_t *v, const char *input) {
    /* THE BUG: no bound on how many bytes get written into v->name. */
    strcpy(v->name, input);
}

/* ---------------------------------------------------------------------
 * FIXED: bounded, always NUL-terminated, and rejects input that would
 * not fit instead of silently truncating it (truncating a user name
 * could itself cause subtle bugs elsewhere, so here we fail loudly).
 * ------------------------------------------------------------------- */
static void fixed_login(victim_t *v, const char *input) {
    size_t len = strlen(input);
    if (len >= sizeof v->name) {
        BAD("fixed_login: rejecting input of %lu bytes (buffer holds %lu, "
            "incl. NUL) -- refusing to copy",
            (unsigned long)len, (unsigned long)sizeof v->name);
        /* Leave v->name in a known-safe, empty state. */
        v->name[0] = '\0';
        return;
    }
    /* snprintf always NUL-terminates and never writes past the given
     * size, even if (hypothetically) len had been miscomputed above. */
    int n = snprintf(v->name, sizeof v->name, "%s", input);
    (void)n; /* n is the "would-be" length; unused here, input already
                validated above. */
}

static int run(vuln_mode mode) {
    SECTION("ex01: stack-overflow (CWE-121/CWE-120)");

    size_t gap = offsetof(victim_t, is_admin);
    INFO("victim_t layout on this compiler: offsetof(name)=%lu, "
         "offsetof(is_admin)=%lu, sizeof(victim_t)=%lu",
         (unsigned long)offsetof(victim_t, name),
         (unsigned long)gap,
         (unsigned long)sizeof(victim_t));

    switch (mode) {
    case MODE_VULN: {
        INFO("Running vulnerable_login() with BENIGN input \"alice\"");
        victim_t v;
        memset(&v, 0, sizeof v);
        vulnerable_login(&v, "alice");
        INFO("name=\"%s\" is_admin=%d", v.name, v.is_admin);
        if (v.is_admin == 0)
            GOOD("Benign input behaved normally: no corruption, is_admin "
                 "still 0.");
        else
            BAD("Unexpected: is_admin corrupted even with benign input!");
        return 0;
    }

    case MODE_EXPLOIT: {
        /* Build a payload sized exactly from offsetof(), so it reliably
         * overflows `name` and lands on `is_admin` no matter how the
         * compiler pads the struct. Every byte is 'A' (0x41); since
         * 0x41414141 != 0 on any endianness, this deterministically
         * flips is_admin to "true" without needing to know the
         * machine's byte order. The payload is a plain, printable ASCII
         * C string (no embedded NUL bytes), equivalent to typing it at
         * a prompt or sending it over a socket -- this is exactly how a
         * real strcpy() overflow is triggered. */
        /* One byte short of the end of is_admin: strcpy() appends a NUL, and
         * that terminator must still land INSIDE the struct (is_admin ends up
         * 0x00414141 little-endian / 0x41414100 big-endian - non-zero either
         * way) so the demo never writes past the object it owns. */
        size_t fill_len = gap + sizeof(((victim_t *)0)->is_admin) - 1;
        char *payload = malloc(fill_len + 1);
        if (!payload) {
            BAD("malloc failed building demo payload");
            return 1;
        }
        memset(payload, 'A', fill_len);
        payload[fill_len] = '\0';

        INFO("Crafted payload: %lu bytes of 'A' (sample build command: "
             "python3 -c \"print('A'*%lu, end='')\")",
             (unsigned long)fill_len, (unsigned long)fill_len);
        INFO("Payload layout: [0..%lu) overflows name[16] and any "
             "padding, [%lu..%lu) overwrites is_admin with 'A' bytes + NUL",
             (unsigned long)gap, (unsigned long)gap, (unsigned long)fill_len);

        victim_t v;
        memset(&v, 0, sizeof v);
        INFO("Before attack: name=\"%s\" is_admin=%d", v.name, v.is_admin);

        vulnerable_login(&v, payload); /* THE OVERFLOW HAPPENS HERE */

        INFO("After attack:  name=\"%s\" is_admin=%d (0x%08X)",
             v.name, v.is_admin, (unsigned)v.is_admin);
        if (v.is_admin != 0)
            BAD("Exploit succeeded: unauthenticated input flipped "
                "is_admin to non-zero by overflowing an adjacent stack "
                "buffer -- demonstrated safely, process did not crash.");
        else
            BAD("Exploit did not corrupt is_admin on this build (layout "
                "differs) -- memory was still overrun past name[], which "
                "is itself the bug being demonstrated.");

        free(payload);
        return 0;
    }

    case MODE_FIXED: {
        /* One byte short of the end of is_admin: strcpy() appends a NUL, and
         * that terminator must still land INSIDE the struct (is_admin ends up
         * 0x00414141 little-endian / 0x41414100 big-endian - non-zero either
         * way) so the demo never writes past the object it owns. */
        size_t fill_len = gap + sizeof(((victim_t *)0)->is_admin) - 1;
        char *payload = malloc(fill_len + 1);
        if (!payload) {
            BAD("malloc failed building demo payload");
            return 1;
        }
        memset(payload, 'A', fill_len);
        payload[fill_len] = '\0';

        INFO("Replaying the SAME %lu-byte malicious payload against "
             "fixed_login()", (unsigned long)fill_len);

        victim_t v;
        memset(&v, 0, sizeof v);
        INFO("Before attack: name=\"%s\" is_admin=%d", v.name, v.is_admin);

        fixed_login(&v, payload); /* bounded: rejects, does not overflow */

        INFO("After attack:  name=\"%s\" is_admin=%d", v.name, v.is_admin);
        if (v.is_admin == 0)
            GOOD("Hardened code rejected the oversized input: is_admin "
                 "stayed 0, no memory outside name[] was touched.");
        else
            BAD("Unexpected: is_admin corrupted even with the hardened "
                "function!");

        free(payload);
        return 0;
    }
    }

    return 0;
}
