/*
 * ex09_weak_random.c - Predictable randomness and hard-coded secrets
 *
 *   CWE-338  Use of Cryptographically Weak PRNG
 *   CWE-330  Use of Insufficiently Random Values
 *   CWE-798  Use of Hard-coded Credentials
 *   CWE-208  Observable Timing Discrepancy (non-constant-time compare)
 *
 * ===========================================================================
 * 1. WHAT IS THE PROBLEM?
 * ===========================================================================
 * Security features such as session IDs, password-reset codes, API tokens,
 * CSRF tokens, encryption keys, IVs and nonces all rely on values that an
 * attacker must not be able to guess. Several classic mistakes break that:
 *
 *  - Using rand()/random()/drand48() or any non-cryptographic PRNG.
 *    These generators are designed for simulations and games: they are fast
 *    and statistically "random-looking", but they are completely
 *    deterministic. Their entire output stream is a function of the seed
 *    (and, for simple generators, a small internal state).
 *
 *  - Seeding with a low-entropy value, typically srand(time(NULL)). The
 *    current time in seconds has very few plausible values, and it is often
 *    known or observable to outsiders (HTTP Date headers, account creation
 *    timestamps, process start times, PIDs). A "random" token seeded from it
 *    effectively has only as many possibilities as there are candidate seeds,
 *    no matter how long the token looks.
 *
 *  - Modulo bias: computing `rand() % n` when n does not divide RAND_MAX+1
 *    evenly makes some results slightly more likely than others. For dice
 *    this is harmless; for keys, nonces or lottery-style secrets it leaks
 *    information and shrinks the effective keyspace.
 *
 *  - Hard-coded secrets: passwords, API keys, signing keys or tokens
 *    written as string literals in the source. They end up in the compiled
 *    binary (readable with `strings`, a hex editor or a disassembler), in the
 *    version-control history, in container images and in crash dumps. They
 *    cannot be rotated without a rebuild and redeploy, and every copy of the
 *    program shares the same secret.
 *
 *  - Non-constant-time comparison of secrets (CWE-208): memcmp()/strcmp()
 *    return as soon as they find a differing byte, so the response time can
 *    depend on how many leading bytes were correct. Over a network this is
 *    hard but not impossible to measure; locally it is easier. Use a
 *    comparison whose running time does not depend on the data.
 *
 * ===========================================================================
 * 2. IMPACT (conceptual)
 * ===========================================================================
 *  - The output of a non-cryptographic PRNG with a guessable seed is
 *    REPRODUCIBLE: anyone who can reconstruct or narrow down the seed obtains
 *    the same values the server produced. Tokens, reset codes and "random"
 *    keys then stop being secrets, which can lead to account takeover,
 *    session hijacking or decryption of protected data.
 *  - A hard-coded key is readable by everyone who has the binary, a
 *    repository checkout or a leaked backup. One leak compromises every
 *    installation at once.
 *  - Timing side channels can let an attacker confirm a secret piece by
 *    piece instead of all at once.
 *  This demo deliberately stays at the conceptual level: it shows that the
 *  same seed gives the same output and how small the seed space is. It does
 *  not recover seeds or predict anyone's tokens.
 *
 * ===========================================================================
 * 3. HOW TO AVOID IT
 * ===========================================================================
 *  - Take security-relevant randomness from the operating system CSPRNG:
 *      Linux:         getrandom(2)        (glibc >= 2.25, <sys/random.h>)
 *      BSD / macOS:   getentropy(3), arc4random_buf(3)
 *      POSIX generic: read from /dev/urandom (what this file does)
 *      Windows:       BCryptGenRandom(NULL, buf, len,
 *                         BCRYPT_USE_SYSTEM_PREFERRED_RNG)
 *      Libraries:     OpenSSL RAND_bytes(), libsodium randombytes_buf()
 *  - CHECK the return value and FAIL CLOSED: if no secure randomness can be
 *    obtained, abort the operation. Never silently fall back to rand() or
 *    to a zeroed buffer.
 *  - Avoid modulo bias with rejection sampling: discard values from the
 *    unbiased tail of the generator's range, then reduce (see
 *    secure_uniform() below). Or just use bytes/hex/base64 of the full
 *    random data and never reduce at all.
 *  - Use enough bits: 128 bits (16 bytes) or more for tokens and keys.
 *  - Do not embed secrets in source code. Load them at run time from the
 *    environment, a protected config file, a secret manager or a KMS/HSM,
 *    and keep them out of logs and version control.
 *  - Design for rotation: support multiple active keys (key IDs), expire
 *    tokens, and make replacing a leaked secret a configuration change.
 *  - Compare secrets (tokens, MACs, password hashes) in constant time, e.g.
 *    CRYPTO_memcmp (OpenSSL), sodium_memcmp (libsodium), or a loop that ORs
 *    the XOR of all bytes (see ct_equal() below).
 *
 *  CERT C rules:
 *    MSC30-C  Do not use the rand() function for generating pseudorandom
 *             numbers
 *    MSC32-C  Properly seed pseudorandom number generators
 *    MSC41-C  Never hard code sensitive information
 *
 * ===========================================================================
 * 4. BEST PRACTICES (checklist)
 * ===========================================================================
 *  [ ] Never use rand()/srand()/random()/drand48() for anything secret.
 *  [ ] Never seed with time(), PID, or any value an outsider can observe.
 *  [ ] Use the OS CSPRNG or a vetted crypto library; check every return code.
 *  [ ] Fail closed when randomness is unavailable.
 *  [ ] Use rejection sampling instead of `% n` when you need a bounded value.
 *  [ ] No credentials, API keys or private keys in source or binaries;
 *      scan repositories for secrets and rotate anything that leaked.
 *  [ ] Constant-time comparison for secrets; rate-limit guessing attempts.
 *  [ ] Give tokens a short lifetime and make them single-use.
 *
 *  Related CWEs: CWE-338, CWE-330, CWE-331 (insufficient entropy),
 *                CWE-335 (incorrect PRNG seeds), CWE-798, CWE-259
 *                (hard-coded password), CWE-321 (hard-coded crypto key),
 *                CWE-208.
 */

#ifndef _WIN32
#define _POSIX_C_SOURCE 200809L
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stddef.h>
#include <stdint.h>
#include <limits.h>
#include <time.h>

#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <bcrypt.h>
#endif

#include "cvulns.h"

/* ------------------------------------------------------------------------
 * Portable OS-backed CSPRNG.
 * Returns 0 on success, -1 on failure (the caller MUST check and fail closed).
 * ---------------------------------------------------------------------- */
static int secure_random_bytes(void *buf, size_t n) {
    if (buf == NULL) return -1;
    if (n == 0) return 0;
#ifdef _WIN32
    if (n > (size_t)ULONG_MAX) return -1;
    /* BCryptGenRandom returns an NTSTATUS; 0 (STATUS_SUCCESS) means success. */
    if (BCryptGenRandom(NULL, (PUCHAR)buf, (ULONG)n,
                        BCRYPT_USE_SYSTEM_PREFERRED_RNG) != 0)
        return -1;
    return 0;
#else
    FILE *f = fopen("/dev/urandom", "rb");
    if (f == NULL) return -1;
    size_t got = fread(buf, 1, n, f);
    int closed = fclose(f);
    if (got != n || closed != 0) return -1;
    return 0;
#endif
}

/* Unbiased random integer in [0, upper) using rejection sampling.
 * Returns 0 on success, -1 on error. */
static int secure_uniform(uint32_t upper, uint32_t *out) {
    if (upper == 0 || out == NULL) return -1;
    /* 2^32 mod upper: values below this threshold are the biased "short"
     * range and are rejected, so every residue is equally likely. */
    uint32_t threshold = (uint32_t)(0u - upper) % upper;
    for (;;) {
        unsigned char b[4];
        if (secure_random_bytes(b, sizeof b) != 0) return -1;
        uint32_t r = ((uint32_t)b[0] << 24) | ((uint32_t)b[1] << 16)
                   | ((uint32_t)b[2] << 8)  |  (uint32_t)b[3];
        if (r >= threshold) { *out = r % upper; return 0; }
    }
}

/* Constant-time equality for two byte strings of known length.
 * Returns 1 if equal, 0 otherwise. Time depends only on the length. */
static int ct_equal(const void *a, const void *b, size_t n) {
    const unsigned char *pa = (const unsigned char *)a;
    const unsigned char *pb = (const unsigned char *)b;
    unsigned char diff = 0;
    for (size_t i = 0; i < n; i++) diff |= (unsigned char)(pa[i] ^ pb[i]);
    return diff == 0;
}

static void to_hex(const unsigned char *in, size_t n, char *out) {
    static const char digits[] = "0123456789abcdef";
    for (size_t i = 0; i < n; i++) {
        out[2 * i]     = digits[in[i] >> 4];
        out[2 * i + 1] = digits[in[i] & 0x0F];
    }
    out[2 * n] = '\0';
}

#define TOKEN_BYTES 16
#define TOKEN_HEX   (2 * TOKEN_BYTES + 1)

/* A fixed, made-up "server time" so the demo output is deterministic.
 * Real code that did srand(time(NULL)) would have the same weakness, with a
 * seed that merely looks less obvious. */
#define DEMO_SERVER_TIME 1700000000u

/* ---- VULNERABLE: token from rand() seeded with a guessable value -------- */
static void weak_token_after_seed(unsigned seed, char out[TOKEN_HEX]) {
    unsigned char raw[TOKEN_BYTES];
    srand(seed);                                   /* CWE-335: guessable seed */
    for (size_t i = 0; i < sizeof raw; i++)
        raw[i] = (unsigned char)(rand() % 256);    /* CWE-338: non-crypto PRNG */
    to_hex(raw, sizeof raw, out);
}

/* ---- FIXED: token from the OS CSPRNG ------------------------------------ */
static int strong_token(char out[TOKEN_HEX]) {
    unsigned char raw[TOKEN_BYTES];
    if (secure_random_bytes(raw, sizeof raw) != 0) return -1;   /* fail closed */
    to_hex(raw, sizeof raw, out);
    return 0;
}

/* ---- Hard-coded secret (BAD) vs. environment (better) ------------------- */
/* DEMO VALUE ONLY, not a real credential. Anyone can find it with `strings`. */
static const char API_KEY[] = "DEMO-hardcoded-key-0000";   /* CWE-798, MSC41-C */

static int run(vuln_mode mode) {
    char t1[TOKEN_HEX], t2[TOKEN_HEX];

    switch (mode) {

    case MODE_VULN:
        SECTION("Issuing a reset token (vulnerable generator)");
        weak_token_after_seed(DEMO_SERVER_TIME, t1);
        INFO("seed = srand(%u) (a fixed demo 'server time')", DEMO_SERVER_TIME);
        INFO("issued token: %s", t1);
        INFO("it looks random and 128 bits long, which is exactly the trap");
        INFO("hard-coded key in this binary: \"%s\"", API_KEY);
        BAD("the key above is baked into the executable (try: strings cvulns)");
        return 0;

    case MODE_EXPLOIT:
        SECTION("Consequence: same seed => identical 'random' tokens");
        weak_token_after_seed(DEMO_SERVER_TIME, t1);
        weak_token_after_seed(DEMO_SERVER_TIME, t2);
        INFO("generation #1: %s", t1);
        INFO("generation #2: %s", t2);
        if (strcmp(t1, t2) == 0)
            BAD("tokens are IDENTICAL: the output is reproducible from the seed");
        else
            INFO("tokens differ on this C library (unexpected for a fixed seed)");
        {
            unsigned long seeds_per_day = 24ul * 60ul * 60ul;
            BAD("a one-second-resolution clock seed has only %lu values per day",
                seeds_per_day);
            INFO("a CSPRNG token of %d bytes has 2^%d possible values (~3.4e38 for 128 bits)",
                 TOKEN_BYTES, TOKEN_BYTES * 8);
            BAD("effective strength: ~%lu possibilities instead of 2^128", seeds_per_day);
        }
        INFO("(this demo stops here: it shows reproducibility, not an attack)");
        return 0;

    case MODE_FIXED: {
        SECTION("Hardened: OS CSPRNG, unbiased sampling, constant-time compare");
        if (strong_token(t1) != 0 || strong_token(t2) != 0) {
            BAD("secure randomness unavailable: failing closed, no token issued");
            return 1;
        }
        INFO("CSPRNG token #1: %s", t1);
        INFO("CSPRNG token #2: %s", t2);
        if (!ct_equal(t1, t2, TOKEN_BYTES * 2))
            GOOD("tokens differ on every call and are not derived from a guessable seed");
        else
            BAD("two CSPRNG tokens collided (astronomically unlikely, check the RNG)");

        uint32_t code;
        if (secure_uniform(1000000u, &code) != 0) {
            BAD("secure randomness unavailable: failing closed");
            return 1;
        }
        GOOD("6-digit code via rejection sampling (no modulo bias): %06u", (unsigned)code);

        if (ct_equal(t1, t1, TOKEN_BYTES * 2))
            GOOD("constant-time compare accepts the matching token");
        if (!ct_equal(t1, t2, TOKEN_BYTES * 2))
            GOOD("constant-time compare rejects a different token");

        {
            const char *key = getenv("CVULNS_DEMO_API_KEY");
            if (key != NULL && *key != '\0')
                GOOD("API key loaded from the environment (%zu chars, value not printed)",
                     strlen(key));
            else
                INFO("CVULNS_DEMO_API_KEY not set: real code would refuse to start (fail closed)");
            GOOD("no `static const char API_KEY[] = \"...\"` literal needed in the binary;");
            GOOD("prefer a secret manager/KMS and rotate keys regularly");
        }
        return 0;
    }
    }
    return 0;
}

const vuln_example ex09_example = {
    "weak-random",
    "Predictable randomness and hard-coded secrets (CWE-338/CWE-330/CWE-798)",
    run
};
