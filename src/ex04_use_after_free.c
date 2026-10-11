/*
 * ex04_use_after_free.c - Use after free (CWE-416)
 *
 * =========================================================================
 * 1. WHAT IS IT?
 * =========================================================================
 * A use-after-free (UAF) happens when a program keeps using a pointer after
 * the memory it points to has been released with free(). The pointer is then
 * "dangling": it still holds the old address, but the allocator is free to
 * hand that address out again at any time.
 *
 * The key insight is that free() does NOT erase the pointer, and usually does
 * not erase the memory either. The stale pointer keeps "working" -- until the
 * allocator reuses the block for something else. Allocators like to reuse
 * recently freed blocks of the same size (it is fast and cache friendly), so
 * the next allocation of a similar size very often lands on exactly the
 * address that is still being held by the stale pointer.
 *
 * Typical ways programs end up with a dangling pointer (all of them are
 * really "ownership confusion": nobody is sure who is responsible for the
 * object):
 *
 *   - Two owners: two data structures hold a pointer to the same object;
 *     one frees it, the other does not know.
 *   - Cached / borrowed pointers: a pointer stored in a cache, a callback
 *     context, an iterator or a global outlives the object it refers to.
 *   - Early free on error paths: an error branch frees a buffer and returns,
 *     but a caller (or a later cleanup path) still uses or frees it.
 *   - Freeing inside a callee while the caller continues to use the object
 *     (e.g. "close()" that also deallocates the handle).
 *   - Containers that reallocate: a pointer into a growing array becomes
 *     invalid after realloc() moves it.
 *
 * (The closely related double free, CWE-415, is the same ownership bug
 * where the stale pointer is passed to free() a second time.)
 *
 * =========================================================================
 * 2. IMPACT (conceptual)
 * =========================================================================
 * Once the block is reused, the stale pointer and the new, legitimate
 * pointer refer to the SAME bytes while the program believes they are two
 * unrelated objects of two different types. Consequently:
 *
 *   - Reads through the stale pointer return data that belongs to someone
 *     else (information disclosure), or values the program never meant to
 *     be interpreted that way (e.g. a "flag" field that is really part of
 *     another object, so a security decision is made on bogus data).
 *   - Writes through the stale pointer silently corrupt the new owner's
 *     data, which later shows up as a seemingly unrelated bug far from the
 *     real cause (integrity loss, crashes, hard-to-reproduce behaviour).
 *
 * UAF is consistently among the most common root causes of exploited
 * vulnerabilities in large C/C++ code bases such as browsers, kernels and
 * network daemons: it is easy to introduce in code with complex object
 * lifetimes, the failure depends on allocator state and timing (so tests
 * pass), and the consequences range from a crash to complete compromise.
 * This file demonstrates ONLY the stale read/write consequence, in a
 * contained and deterministic toy; nothing here goes beyond that.
 *
 * =========================================================================
 * 3. HOW TO AVOID IT
 * =========================================================================
 *   - Set the pointer to NULL right after freeing it (see FREE_AND_NULL
 *     below). A later dereference then fails fast and loudly (and a second
 *     free(NULL) is harmless) instead of silently using reused memory. This
 *     only protects the pointer you nulled, NOT other copies of it -- so it
 *     is a safety net, not a design.
 *   - Single-owner discipline: every object has exactly one owner that is
 *     responsible for freeing it; everyone else only borrows, and borrows
 *     must not outlive the owner. Document ownership in function contracts
 *     ("takes ownership", "returns a new object", "borrowed, do not free").
 *   - Reference counting when sharing is unavoidable: the object is released
 *     only when the last holder drops its reference.
 *   - Handles instead of raw pointers (index + generation counter, as in the
 *     fixed demo below): the handle is validated on each use, so a stale one
 *     is detected and refused rather than silently aliasing a new object.
 *   - Arena / region allocation: allocate many short-lived objects together
 *     and free them all at once at a well-defined point, so individual
 *     lifetimes cannot get out of order.
 *   - Single exit with `goto cleanup`: free resources in one place, in
 *     reverse order of acquisition, so error paths cannot free twice or free
 *     early and keep going.
 *   - Tooling: AddressSanitizer (-fsanitize=address, see CVULNS_SANITIZE in
 *     CMakeLists.txt), Valgrind, hardware memory tagging (ARM MTE) and
 *     hardened allocators (quarantine of freed blocks, randomization,
 *     scudo, hardened_malloc, Windows segment heap) turn many UAFs into
 *     immediate, diagnosable crashes. Static analysis (clang-tidy, Clang
 *     Static Analyzer, CodeQL, Coverity, gcc -fanalyzer, -Wuse-after-free)
 *     finds many of them before the code ships. Fuzz with sanitizers on.
 *   - For new code, prefer memory-safe languages (Rust, Go, Java, C#, ...)
 *     or at least safer abstractions where object lifetimes are checked by
 *     the compiler/runtime.
 *
 * =========================================================================
 * 4. BEST PRACTICES AND REFERENCES
 * =========================================================================
 *   - CERT C MEM30-C: Do not access freed memory.
 *   - CERT C MEM01-C: Store a new value in pointers immediately after free().
 *   - CERT C MEM00-C: Allocate and free memory in the same module, at the
 *     same level of abstraction.
 *   - CERT C MEM34-C: Only free memory allocated dynamically (double free
 *     relatives).
 *   - Never use a pointer value after passing it to free() or realloc(),
 *     not even to compare it (its value is indeterminate).
 *   - Make ownership explicit in names and comments; keep lifetimes simple.
 *   - Run tests, fuzzers and CI under ASan/UBSan (and Valgrind where
 *     available).
 *   - CWE-416: Use After Free.   CWE-415: Double Free.
 *     CWE-825: Expired Pointer Dereference.   CWE-672: Operation on a
 *     Resource after Expiration or Release.   CWE-362: Race Condition
 *     (multi-threaded UAF often needs a lifetime/locking fix).
 *
 * =========================================================================
 * About this demo
 * =========================================================================
 * Real UAF behaviour depends on the C library, so a demo built on malloc()
 * would be undefined behaviour and non-deterministic. Instead this file
 * contains a tiny SLAB ALLOCATOR over a static array with a LIFO free list.
 * It is a MODEL of how real allocators keep per-size-class free lists and
 * hand the most recently freed block back first. Because all "heap" memory
 * is an ordinary static array, reading a freed slot is well defined here and
 * the output is identical on every run and every compiler.
 *
 * Two toy objects have the same size and therefore share a size class:
 *   session { username, is_admin }   -- an authenticated user session
 *   note    { text, priority }       -- unrelated data from another subsystem
 * Both start with a char[32] followed by an int, so the stale read through
 * the old `session *` of a slot now owned by a `note` is a well-defined read
 * of the note's bytes.
 */
#include <stdio.h>
#include <string.h>
#include <stddef.h>
#include "cvulns.h"

/* ------------------------------------------------------------------ */
/* Toy slab allocator (model of a size-class allocator, NOT real malloc) */
/* ------------------------------------------------------------------ */

#define TEXT_LEN    32
#define SLAB_SLOTS  4

typedef struct {
    char username[TEXT_LEN];
    int  is_admin;               /* 0 = ordinary user */
} session;

typedef struct {
    char text[TEXT_LEN];
    int  priority;               /* sits at the same offset as is_admin */
} note;

/* One slot is big enough for either object (they share a size class). */
typedef union {
    session s;
    note    n;
} slot_t;

static slot_t   g_slab[SLAB_SLOTS];
static int      g_used[SLAB_SLOTS];       /* 1 while allocated              */
static unsigned g_gen[SLAB_SLOTS];        /* bumped on every free           */
static size_t   g_free_stack[SLAB_SLOTS]; /* LIFO free list of slot indices */
static size_t   g_free_top;               /* number of entries in the stack */

static void slab_reset(void) {
    memset(g_slab, 0, sizeof g_slab);
    memset(g_used, 0, sizeof g_used);
    memset(g_gen, 0, sizeof g_gen);
    g_free_top = 0;
    /* Push in reverse so that slot 0 is handed out first. */
    for (size_t i = SLAB_SLOTS; i > 0; i--) g_free_stack[g_free_top++] = i - 1;
}

/* Pops the most recently freed slot (LIFO): the "reuse" behaviour that
 * makes use-after-free practical in real allocators. Memory is zeroed on
 * allocation, like calloc(). Returns NULL when the slab is exhausted. */
static void *slab_alloc(void) {
    size_t idx;
    if (g_free_top == 0) return NULL;
    idx = g_free_stack[--g_free_top];
    g_used[idx] = 1;
    memset(&g_slab[idx], 0, sizeof g_slab[idx]);
    return &g_slab[idx];
}

static int slab_index_of(const void *p, size_t *idx) {
    size_t i;
    for (i = 0; i < SLAB_SLOTS; i++) {
        if ((const void *)&g_slab[i] == p) { *idx = i; return 1; }
    }
    return 0;
}

/* Releases a slot. Like real free(), it does NOT erase the contents and
 * does NOT touch the caller's pointer variable. */
static void slab_free(void *p) {
    size_t idx;
    if (p == NULL) return;                       /* free(NULL) is a no-op */
    if (!slab_index_of(p, &idx)) {
        BAD("slab_free: pointer does not belong to the slab");
        return;
    }
    if (!g_used[idx]) {
        BAD("slab_free: slot %lu is already free (double free)", (unsigned long)idx);
        return;
    }
    g_used[idx] = 0;
    g_gen[idx]++;
    g_free_stack[g_free_top++] = idx;
}

/* Mitigation 1: forget the pointer as soon as it has been freed (MEM01-C).
 * Note: `p` is evaluated twice, so do not pass expressions with side effects. */
#define FREE_AND_NULL(p) do { slab_free(p); (p) = NULL; } while (0)

/* Mitigation 2: a generation-checked handle instead of a raw pointer. */
typedef struct {
    size_t   index;
    unsigned gen;
} slab_handle;

static slab_handle slab_handle_for(const void *p) {
    slab_handle h;
    size_t idx = 0;
    h.index = 0;
    h.gen = 0;
    if (slab_index_of(p, &idx)) {
        h.index = idx;
        h.gen = g_gen[idx];
    }
    return h;
}

/* Returns the object only if the handle still refers to the same allocation
 * (slot in use AND generation unchanged); otherwise NULL. */
static void *slab_get(slab_handle h) {
    if (h.index >= SLAB_SLOTS) return NULL;
    if (!g_used[h.index] || g_gen[h.index] != h.gen) return NULL;
    return &g_slab[h.index];
}

/* ------------------------------------------------------------------ */
/* Small helpers                                                        */
/* ------------------------------------------------------------------ */

static void set_text(char *dst, const char *src) {
    /* Bounded copy, always NUL-terminated. */
    snprintf(dst, TEXT_LEN, "%s", src);
}

static session *session_create(const char *user) {
    session *s = (session *)slab_alloc();
    if (s == NULL) return NULL;
    set_text(s->username, user);
    s->is_admin = 0;
    return s;
}

static note *note_create(const char *text, int priority) {
    note *n = (note *)slab_alloc();
    if (n == NULL) return NULL;
    set_text(n->text, text);
    n->priority = priority;
    return n;
}

/* ------------------------------------------------------------------ */
/* Modes                                                                */
/* ------------------------------------------------------------------ */

/* Benign: the lifetime is respected, nothing is used after free. */
static int demo_vuln(void) {
    session *s;
    note *n;

    SECTION("Normal use: no access after free");
    s = session_create("alice");
    if (s == NULL) { BAD("out of slots"); return 1; }
    INFO("session created: user='%s' is_admin=%d", s->username, s->is_admin);
    INFO("session used while it is alive");
    FREE_AND_NULL(s);
    INFO("session freed and pointer set to NULL");

    n = note_create("buy milk", 1);
    if (n == NULL) { BAD("out of slots"); return 1; }
    INFO("note created (reuses the freed slot): text='%s' priority=%d", n->text, n->priority);
    GOOD("every pointer was used only while its object was alive");
    FREE_AND_NULL(n);
    return 0;
}

/* Vulnerable: the session is freed, a note takes over the slot, and the
 * old session pointer (a "second owner", e.g. a cache) is used anyway. */
static int demo_exploit(void) {
    session *s;
    session *cached;   /* second reference to the same object */
    note *n;

    SECTION("Dangling pointer after free");
    s = session_create("alice");
    if (s == NULL) { BAD("out of slots"); return 1; }
    cached = s;        /* e.g. stored in a lookup cache: no ownership transfer */
    INFO("session created: user='%s' is_admin=%d", s->username, s->is_admin);

    INFO("logout code frees the session; the cache is not told");
    slab_free(s);      /* BUG: 'cached' (and 's') still hold the old address */

    INFO("another subsystem allocates a same-size note; LIFO reuse gives it the freed slot");
    n = note_create("meeting notes: buy milk", 7);
    if (n == NULL) { BAD("out of slots"); return 1; }
    INFO("note: text='%s' priority=%d", n->text, n->priority);

    if ((void *)cached == (void *)n)
        BAD("the stale session pointer and the new note pointer are the SAME address");

    /* Use after free: the session type is applied to the note's bytes. */
    BAD("stale read: cached->username = '%s'", cached->username);
    BAD("stale read: cached->is_admin = %d (this is really note->priority)", cached->is_admin);
    if (cached->is_admin)
        BAD("a permission check on the stale session would now say: ADMIN");

    /* Stale write: the 'logout' code clears the flag via the dangling pointer. */
    INFO("stale write: cached->is_admin = 0 (cleanup code touching the old session)");
    cached->is_admin = 0;
    BAD("note->priority was silently changed from 7 to %d", n->priority);

    slab_free(n);
    return 0;
}

/* Hardened: pointer nulled after free, and the cache keeps a generation
 * checked handle, so stale use is detected and refused. */
static int demo_fixed(void) {
    session *s;
    slab_handle cache;     /* cache holds a handle, not a raw pointer */
    session *via_cache;
    note *n;

    SECTION("Same sequence, hardened");
    s = session_create("alice");
    if (s == NULL) { BAD("out of slots"); return 1; }
    cache = slab_handle_for(s);
    INFO("session created: user='%s' is_admin=%d (cache holds handle index=%lu gen=%u)",
         s->username, s->is_admin, (unsigned long)cache.index, cache.gen);

    INFO("logout code frees the session with FREE_AND_NULL");
    FREE_AND_NULL(s);

    INFO("another subsystem allocates a same-size note in the reused slot");
    n = note_create("meeting notes: buy milk", 7);
    if (n == NULL) { BAD("out of slots"); return 1; }
    INFO("note: text='%s' priority=%d", n->text, n->priority);

    /* 1) The owner's pointer was nulled: misuse is caught before dereference. */
    if (s == NULL)
        GOOD("owner pointer is NULL: stale use through it is refused");

    /* 2) The cache's handle no longer matches the slot's generation. */
    via_cache = (session *)slab_get(cache);
    if (via_cache == NULL)
        GOOD("cache lookup refused: handle generation %u is stale (slot is now gen %u)",
             cache.gen, g_gen[cache.index]);
    else
        BAD("cache lookup unexpectedly succeeded");

    GOOD("note data is intact: text='%s' priority=%d", n->text, n->priority);
    FREE_AND_NULL(n);
    return via_cache == NULL ? 0 : 1;
}

static int run(vuln_mode mode) {
    slab_reset();
    switch (mode) {
    case MODE_VULN:    return demo_vuln();
    case MODE_EXPLOIT: return demo_exploit();
    case MODE_FIXED:   return demo_fixed();
    }
    return 1;
}

const vuln_example ex04_example = { "use-after-free", "Use after free (CWE-416)", run };
