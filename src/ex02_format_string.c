/*
 * ex02_format_string.c - Uncontrolled format string (CWE-134)
 *
 * ======================================================================
 * 1. WHAT IS IT?
 * ======================================================================
 * printf-family functions (printf, fprintf, sprintf, snprintf, syslog, and
 * every wrapper around them) take a FORMAT STRING that is a tiny program:
 * each %-conversion tells the function to fetch the next variadic argument
 * and interpret it as some type.
 *
 * The bug:
 *
 *     printf(user_input);          // WRONG: data used as code
 *     printf("%s", user_input);    // RIGHT: format is a constant
 *
 * C variadic functions have NO type and NO arity checking at run time. The
 * callee cannot know how many arguments the caller passed. If the format
 * string asks for more conversions than there are arguments, the function
 * simply keeps reading whatever sits in the next argument slots (registers
 * or stack words), which is undefined behaviour (C11 7.21.6.1p2).
 * If the attacker controls the format string, the attacker controls what
 * the function does with those slots.
 *
 * ======================================================================
 * 2. WHAT CAN GO WRONG? (conceptual overview)
 * ======================================================================
 *  a) Information disclosure.
 *     %x / %p print the next argument slot as a number. Chained, they dump
 *     stack words: saved pointers, stack canaries, return addresses and
 *     secrets. Leaked code/stack pointers defeat ASLR.
 *
 *  b) Arbitrary read / crash.
 *     %s treats a slot as a char* and reads until NUL. If the slot holds an
 *     unmapped value the process crashes (cheap denial of service). If the
 *     attacker can place a chosen pointer where the slot is read from (the
 *     format string itself usually lives on the stack or heap and is often
 *     reachable through the slots), %s becomes a read primitive.
 *     Positional arguments (%7$p, %7$s - POSIX) let the attacker jump
 *     directly to the N-th slot instead of printing everything before it.
 *
 *  c) Arbitrary write.
 *     %n stores "number of characters written so far" into the int* taken
 *     from the next slot. The attacker controls the count with width or
 *     precision fields (e.g. %100x), and %hn / %hhn write 2 / 1 byte at a
 *     time. Combined with a controllable pointer, this is a write-what-where
 *     primitive. The classic targets are values that influence control
 *     flow: function pointers, GOT/PLT entries (hence "RELRO" below),
 *     return addresses, or security flags such as is_admin. This is why a
 *     format string bug is usually rated as remote code execution, not just
 *     an information leak.
 *
 *  How an attacker works, in outline: first probe for the bug by sending a
 *  harmless-looking marker followed by a few %p conversions and watching
 *  whether the marker's bytes reappear in the output; this reveals the
 *  slot offset at which attacker-controlled data begins. Tooling such as
 *  pwntools' fmtstr module automates the later steps. This file
 *  intentionally does NOT include a ready-made payload builder; the demo
 *  below only shows the mechanism against data the demo owns.
 *
 *  Sample inputs (what a tester types into a vulnerable field):
 *     "%p %p %p %p"        -> leaks four slot values (probe for the bug)
 *     "AAAA %p %p %p %p"   -> look for 0x41414141 to find where input starts
 *     "%7$p"               -> POSIX positional: print slot 7 directly
 *     "AAAA%32u%n"         -> %n stores 36 (4 + 32) into the next int* slot;
 *                             this is the exact input used by the demo below
 *     (the width field, e.g. %32u, is how the written value is controlled)
 *
 *  Platform notes on %n:
 *   - MSVC's CRT disables %n by default (invalid-parameter handler is
 *     invoked unless _set_printf_count_output(1) was called). This demo
 *     therefore skips the %n part on MSVC and only explains it.
 *   - glibc with _FORTIFY_SOURCE=2 (or 3) aborts when a format string that
 *     contains %n lives in writable memory (*** %n in writable segment
 *     detected ***), and the fortified variants also reject positional
 *     arguments that skip slots. The demo build disables FORTIFY on purpose.
 *   - musl, BSD libcs and MinGW's msvcrt still honour %n.
 *
 * ======================================================================
 * 3. HOW TO AVOID IT
 * ======================================================================
 *  - ALWAYS pass a constant format string: printf("%s", s).
 *  - For plain text use fputs(s, stdout) / puts(s) / fwrite - no format
 *    parsing at all. (Mind that puts adds a newline.)
 *  - Wrap printf-style APIs in your own logging functions and declare them
 *    so the compiler checks every call site:
 *        void log_msg(const char *fmt, ...) __attribute__((format(printf,1,2)));
 *    (GCC/Clang; MSVC: _Printf_format_string_ annotation from <sal.h>).
 *    Never let a wrapper take a format that originates from external data.
 *  - Compile with  -Wformat=2 -Wformat-security -Werror=format-security
 *    (this project turns -Wformat-security OFF only so the bug compiles).
 *  - Run static analysis (clang-tidy, cppcheck, CodeQL, Coverity,
 *    /analyze) and fuzz / sanitize logging code paths.
 *  - Defence in depth (does not fix the bug, only raises the cost):
 *    -D_FORTIFY_SOURCE=2 (or 3), full RELRO (-Wl,-z,relro,-z,now) so the
 *    GOT is read-only, PIE + ASLR, stack protector, CFI.
 *  - Never store format strings in writable memory or load them from
 *    untrusted files / network / translation catalogs without validation.
 *    If localisation requires dynamic formats, validate that the
 *    conversions match the expected set.
 *
 * ======================================================================
 * 4. BEST PRACTICES AND REFERENCES
 * ======================================================================
 *  - CWE-134: Use of Externally-Controlled Format String
 *  - CERT C FIO30-C: Exclude user input from format strings
 *  - CERT C FIO47-C: Use valid format strings
 *  - CERT C MSC00-C: Compile cleanly at high warning levels
 *  - OWASP: Format String Attack; MISRA C:2012 Rule 21.6 (the Standard
 *    Library input/output functions shall not be used).
 *  - Treat compiler warnings from -Wformat-security as errors in CI.
 *
 * ======================================================================
 * ABOUT THE DEMO CODE (how it stays safe and deterministic)
 * ======================================================================
 * Really leaking the stack of the process is non-deterministic and
 * undefined behaviour, so we do NOT call printf/snprintf with missing
 * arguments. Instead, the "victim" function calls the REAL snprintf with
 * an attacker-chosen format string AND with a handful of demo-owned values
 * as the variadic neighbours. This models what is sitting in the argument
 * slots in a real program (secrets, pointers) without reading anything we
 * do not own. For the write demo the matching vararg is the address of a
 * demo-owned int; in a real attack the attacker has to obtain that address
 * through leaks or by planting it in the format string buffer.
 * Output always goes to a local buffer first and is printed with "%s".
 */
#include <stdio.h>
#include <string.h>
#include <stdarg.h>
#include <stddef.h>
#include "cvulns.h"

#define OUT_SZ 256

/* A secret that lives in the demo, standing in for "whatever is on the stack". */
typedef struct {
    unsigned int  session_key;   /* pretend this is a stack canary / key  */
    unsigned int  other_word;    /* another neighbouring word             */
    int           counter;       /* victim of the %n write demo           */
} victim_state;

/* --------------------------------------------------------------------- *
 * VULNERABLE pattern #1: a logging wrapper that forwards a caller-chosen
 * format. Declared with the format attribute so that a *literal* format
 * would be checked; the bug is calling it with non-literal data.
 * --------------------------------------------------------------------- */
#if defined(__GNUC__)
__attribute__((format(printf, 1, 2)))
#endif
static void log_msg(const char *fmt, ...) {
    char buf[OUT_SZ];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, sizeof buf, fmt, ap);
    va_end(ap);
    printf("    LOG: %s\n", buf);
}

/* Benign use: the intended call shape, literal format + argument. */
static void log_user_safe(const char *user) {
    log_msg("user said: %s", user);
}

/* VULNERABLE: the user's text IS the format. With benign text this looks
 * fine, which is exactly why the bug survives code review and testing. */
static void log_user_vulnerable(const char *user) {
    log_msg(user);
}

/* --------------------------------------------------------------------- *
 * VULNERABLE pattern #2 (the attacker-controlled format reaches snprintf
 * together with demo-owned "neighbour" arguments, see header comment).
 * --------------------------------------------------------------------- */
static void format_vulnerable(char *out, size_t n, const char *user,
                              victim_state *st) {
    /* BUG: 'user' is used as the format string. The extra arguments model
     * the argument slots an attacker can reach in a real program. */
    snprintf(out, n, user, st->session_key, st->other_word, (void *)st);
}

/* FIXED: constant format, user text is only ever data. */
static void format_fixed(char *out, size_t n, const char *user) {
    snprintf(out, n, "%s", user);
}

/* Write-primitive model: the matching vararg is a demo-owned int*. */
static void write_vulnerable(char *out, size_t n, const char *user,
                             unsigned int filler, int *target) {
    snprintf(out, n, user, filler, target);
}

static int run(vuln_mode mode) {
    victim_state st;
    char out[OUT_SZ];
    st.session_key = 0xC0FFEE42u;
    st.other_word  = 0x0BADF00Du;
    st.counter     = 0;

    if (mode == MODE_VULN) {
        SECTION("Benign input to the vulnerable logger");
        INFO("Input has no %% conversions, so the bug is invisible.");
        log_user_vulnerable("hello from alice");
        INFO("Intended, safe call shape for comparison:");
        log_user_safe("hello from alice");
        GOOD("Works. The flaw only shows once the input contains '%%'.");
        return 0;
    }

    /* Attacker-supplied "formats". Only a few conversions, each matched
     * by a demo-owned argument, so nothing here can crash. */
    const char *leak_input  = "key=%08x other=%08x ptr=%p";
    const char *write_input = "AAAA%32u%n";

    if (mode == MODE_EXPLOIT) {
        SECTION("Information leak via %x / %p");
        INFO("Attacker input: \"%s\"", leak_input);
        format_vulnerable(out, sizeof out, leak_input, &st);
        BAD("Output: %s", out);
        BAD("The 'secret' session key 0x%08X was disclosed to the attacker.",
            st.session_key);
        INFO("In a real program the numbers come from unrelated stack/register");
        INFO("slots (canary, saved pointers); %%N$p reaches slot N directly.");

        SECTION("Memory write via %n");
#ifdef _MSC_VER
        INFO("MSVC's CRT disables %%n by default, so this part is skipped.");
        INFO("On other libcs %%n stores the count of characters printed so far");
        INFO("into an int* taken from the argument list.");
#else
        INFO("Attacker input: \"%s\"", write_input);
        INFO("counter before: %d", st.counter);
        write_vulnerable(out, sizeof out, write_input, 0u, &st.counter);
        BAD("counter after:  %d  (4 'A' + width 32 = 36 chars written)",
            st.counter);
        BAD("The attacker changed a variable through a format string. With a");
        BAD("controllable pointer this becomes write-what-where (GOT, return");
        BAD("address, is_admin...). Width controls the value written.");
#endif
        return 0;
    }

    /* MODE_FIXED */
    SECTION("Same attacker inputs against the fixed code");
    INFO("Fix: constant format string \"%%s\"; input is treated as plain data.");
    format_fixed(out, sizeof out, leak_input);
    GOOD("Leak input printed literally: %s", out);
    format_fixed(out, sizeof out, write_input);
    GOOD("Write input printed literally: %s", out);
    GOOD("counter is still %d: nothing was leaked and nothing was written.",
         st.counter);
    INFO("For plain text without any formatting, fputs(s, stdout) is even simpler.");
    INFO("Build with -Wformat -Wformat-security -Werror=format-security to catch this.");
    return 0;
}

const vuln_example ex02_example = {
    "format-string", "Uncontrolled format string (CWE-134)", run
};
