/*
 * ex05_double_free.c - Double free and memory-management errors on error paths
 *                      (CWE-415 Double Free, CWE-401 Memory Leak,
 *                       related: CWE-590 / CWE-761 free() of bad pointers,
 *                       CWE-416 use after free)
 *
 * =========================================================================
 * 1. WHAT IS IT?
 * =========================================================================
 * A double free happens when the same heap pointer is passed to free() twice
 * without an intervening allocation that legitimately returned that address.
 * The C standard says the behaviour is undefined (C11 7.22.3.3p2).
 *
 * In real code nobody writes "free(p); free(p);" on adjacent lines. The bug
 * hides in ERROR-HANDLING / CLEANUP paths where two layers both believe they
 * own the same object:
 *
 *      static void reject(char *buf) { log(...); free(buf); }   // helper frees
 *
 *      int process(void) {
 *          char *buf = malloc(N);
 *          ...
 *          if (bad_input) { reject(buf); goto out; }            // free #1
 *          ...
 *      out:
 *          free(buf);                                           // free #2 !!
 *          return rc;
 *      }
 *
 * Typical causes:
 *   - a cleanup helper frees memory that the caller still owns (and the
 *     caller's own cleanup frees it again);
 *   - several cleanup labels / "goto fail" ladders that fall through into
 *     one another and release the same pointer twice;
 *   - an object stored in two containers (list + hash table) and destroyed by
 *     both owners;
 *   - a callee that takes ownership on success but also on some failures,
 *     with callers that cannot tell which case happened;
 *   - `realloc()` failure handling: freeing the old pointer after realloc
 *     already freed/moved it.
 *
 * Closely related memory-management errors on the same code paths:
 *   - CWE-401 Memory leak: early `return -1;` skips the cleanup, so the
 *     allocation is never freed. Harmless once, but a remote client that can
 *     trigger it repeatedly gets a denial of service (CWE-400, memory
 *     exhaustion). The "fix" for leaks is exactly the same discipline that
 *     prevents double frees: ONE owner, ONE cleanup point.
 *   - CWE-590 / CWE-761: free() of a pointer that was not returned by
 *     malloc (stack/global/`&struct.field`), or of a pointer that was moved
 *     into the middle of a block (`p++` while parsing, then `free(p)`).
 *     The allocator then interprets attacker-influenced bytes in front of
 *     that address as a chunk header. Same exploitation family.
 *   - CWE-416 Use after free: using `buf` after the first free (reading the
 *     "freed" data, or writing into a chunk that has already been handed to
 *     somebody else).
 *
 * =========================================================================
 * 2. HOW IS IT EXPLOITED?
 * =========================================================================
 * Heap allocators keep freed chunks on free lists (glibc: tcache and
 * fastbins for small sizes; other allocators: similar LIFO bins). Freeing a
 * chunk stores a "next" pointer INSIDE the freed chunk's user data and makes
 * the chunk the head of the list. malloc() of a matching size pops the head.
 *
 *   free(p);   list:  head -> p -> A -> B
 *   free(p);   list:  head -> p -> p -> A -> B ...   (p is in the list TWICE)
 *
 * (This is exactly what a naive LIFO allocator does; `p -> p` is a cycle.)
 *
 * Consequence #1: two owners for ONE piece of memory (primitive: aliasing)
 *   q1 = malloc(n);   // returns p, list head becomes p again
 *   q2 = malloc(n);   // returns p AGAIN
 *   q1 == q2, but the program thinks they are two independent objects.
 *   If q1 is e.g. a "user name" buffer filled from attacker input and q2 is
 *   a security-relevant structure (credentials, session, function-pointer
 *   table, vtable, file descriptor, length field), the attacker simply
 *   writes through q1 and the victim code reads the forged data through q2.
 *   This demo shows exactly that: attacker-written username bytes flip the
 *   `is_admin` field of a creds structure.
 *
 * Consequence #2: allocator metadata poisoning (primitive: arbitrary write)
 *   While p is still on the free list (the second, duplicate entry) the
 *   attacker can obtain p from malloc and WRITE to it. The first 8 bytes of
 *   a freed chunk are the list's "next" pointer, so the attacker's data
 *   becomes the next pointer:
 *
 *   Sample sequence against a tcache/fastbin-style allocator (simplified):
 *     1. Trigger the buggy error path:           free(p); free(p);
 *        bins: head -> p -> p
 *     2. a = malloc(n)   -> returns p.           bins: head -> p
 *        (p is allocated but ALSO still the head of the free list)
 *     3. Write 8 attacker-chosen bytes into a, i.e. the "next" pointer of the
 *        chunk that the allocator still believes is free:
 *        *(void **)a = TARGET - 0x10;    // e.g. address near __free_hook,
 *                                        // GOT entry, return address, a
 *                                        // function pointer in a struct
 *        bins: head -> p -> TARGET   (the allocator trusts the pointer)
 *     4. b = malloc(n)   -> returns p again (list head popped).
 *        bins: head -> TARGET
 *     5. c = malloc(n)   -> returns TARGET: the allocator hands out an
 *        address of the attacker's choice as a "fresh" chunk.
 *     6. Write attacker data through c: arbitrary write primitive, usually
 *        converted to code execution by overwriting a function pointer
 *        (older glibc: __malloc_hook / __free_hook, GOT entries, atexit
 *        handlers, C++ vtables, ...), or to a data-only attack by flipping
 *        an authorisation flag.
 *
 * Modern glibc hardening (and how attackers deal with it, conceptually):
 *   - tcache double-free detection (glibc >= 2.29): when a chunk is freed
 *     into tcache, glibc stores a random per-thread `key` value in the
 *     chunk's second word (e->key). On every free it checks whether that
 *     key is already present in the chunk; if so it walks the bin and aborts
 *     with "free(): double free detected in tcache 2". That is why a plain
 *     free(p); free(p); crashes on current systems instead of silently
 *     corrupting the heap.
 *   - Typical bypasses: (a) overwrite the key field between the two frees
 *     (needs a use-after-free write or a heap overflow into the chunk, so
 *     the double free is combined with a second bug); (b) free the chunk
 *     into a different bin/size class in between (e.g. fill the tcache bin
 *     with 7 other chunks so the chunk goes to the fastbin, where only the
 *     "top of bin == chunk" check applies, then free A, B, A so that the
 *     chunk is not at the top when it is freed again: the classic
 *     "fastbin dup"); (c) corrupt the chunk's size field first so it lands
 *     in a bin without the check. Newer glibc (>= 2.32) adds "safe linking"
 *     (next pointers are XOR-ed with the address >> 12), which forces
 *     attackers to leak a heap address first. These are mitigations, not
 *     fixes: the root cause remains, and non-glibc allocators (embedded
 *     libcs, custom pool allocators, older systems) often have none of them.
 *   - Even with perfect detection the bug is still a reliability problem
 *     (abort() = denial of service for the whole server).
 *
 * =========================================================================
 * 3. HOW TO AVOID IT
 * =========================================================================
 *   a) OWNERSHIP RULES. Decide, and DOCUMENT in the function comment, who
 *      owns every pointer: "whoever allocates frees" (CERT MEM00-C: allocate
 *      and free memory in the same module, at the same level of abstraction).
 *      A callee that merely uses a buffer must NEVER free it; take a
 *      `const char *` to make that visible. When ownership is transferred
 *      (e.g. a function that stores the buffer in a struct, or "returns a
 *      malloc'ed string"), say so explicitly and set the source pointer to
 *      NULL at the moment of transfer (`*out = obj; obj = NULL;`).
 *   b) NULL AFTER FREE (CERT MEM01-C). free(NULL) is defined as a no-op, so
 *      a pointer that is reset to NULL right after free can never be freed
 *      twice by accident, and a use after free becomes a clean NULL deref
 *      instead of silent heap corruption. Wrap it in a macro/function so it
 *      cannot be forgotten (see SAFE_FREE below). Limitation: copies of the
 *      pointer in other variables are not cleared; this does not replace
 *      having one owner.
 *   c) SINGLE EXIT POINT with `goto cleanup` (CERT MEM12-C). Initialise
 *      every resource pointer to NULL at the top, jump to ONE label on any
 *      error, and free everything there. This both prevents leaks (every
 *      early exit passes through the cleanup) and double frees (the cleanup
 *      is the only place that frees, and it frees each pointer once).
 *   d) Do not write cleanup helpers that free memory the caller owns. If a
 *      helper must release something, pass the ADDRESS of the pointer
 *      (`void release(char **p)`) so it can set it to NULL for the caller,
 *      or use a destructor `foo_destroy(foo **pp)` that is safe to call on
 *      NULL and idempotent.
 *   e) RAII-like patterns: pair each constructor with one destructor that
 *      owns the full teardown of the object (including members); GCC/Clang
 *      `__attribute__((cleanup(fn)))` can run it automatically at scope
 *      exit (not portable to MSVC, so not used here).
 *   f) Arenas / pools: allocate many short-lived objects from one arena and
 *      release the whole arena in one call. There are no per-object frees,
 *      so there is nothing to double free, and error paths just destroy the
 *      arena. (Trade-off: lifetime must really be "everything at once".)
 *   g) Never free memory you did not get from the allocator, and never free
 *      an interior pointer. Keep the original base pointer in its own
 *      variable and walk a separate cursor (`const char *p = base; ...`).
 *   h) TOOLING. These bugs are found easily by tools, use them in CI:
 *        - AddressSanitizer (-fsanitize=address; cmake -DCVULNS_SANITIZE=ON)
 *          reports "attempting double-free" with both stack traces;
 *        - Valgrind memcheck ("Invalid free() / delete / delete[]"), and
 *          `--leak-check=full` for CWE-401;
 *        - glibc runtime switches: MALLOC_CHECK_=3 (extra consistency checks,
 *          abort on error), MALLOC_PERTURB_=<byte> (fills freed and new
 *          memory with a pattern so use-after-free and uninitialised use
 *          show up as garbage instead of "seems to work");
 *        - Windows: Application Verifier / page heap (gflags +hpa), MSVC
 *          /fsanitize=address, Dr. Memory, CRT debug heap (_CrtDumpMemoryLeaks);
 *        - static analysis: clang-tidy / clang static analyzer
 *          (unix.Malloc), cppcheck, GCC -fanalyzer (-Wanalyzer-double-free,
 *          -Wanalyzer-malloc-leak), Coverity, CodeQL (cpp/double-free,
 *          cpp/memory-may-not-be-freed).
 *
 * =========================================================================
 * 4. BEST PRACTICES AND REFERENCES
 * =========================================================================
 *   - CERT C: MEM31-C "Free dynamically allocated memory exactly once";
 *     MEM30-C "Do not access freed memory"; MEM34-C "Only free memory
 *     allocated dynamically"; MEM00-C "Allocate and free memory in the same
 *     module, at the same level of abstraction"; MEM01-C "Store a new value
 *     in pointers immediately after free()"; MEM12-C "Consider using a goto
 *     chain when leaving a function on error when using and releasing
 *     resources"; MEM11-C/MEM35-C for related allocation mistakes.
 *   - MISRA C:2012 Rule 22.1 (all dynamically allocated resources shall be
 *     released), Rule 22.2 (a block of memory shall only be freed if it was
 *     allocated by a Standard Library function); Dir 4.12 (dynamic memory
 *     allocation shall not be used) for the strictest embedded profiles.
 *   - CWE-415 Double Free, CWE-416 Use After Free, CWE-401 Missing Release
 *     of Memory after Effective Lifetime, CWE-590 Free of Memory not on the
 *     Heap, CWE-761 Free of Pointer not at Start of Buffer, CWE-763 Release
 *     of Invalid Pointer or Reference, CWE-672 Operation on a Resource after
 *     Expiration or Release.
 *   - OWASP: "Doubly freeing memory" (Vulnerabilities > Memory management).
 *   - Always test the ERROR paths (fault injection: make every malloc fail
 *     in turn, feed malformed input) under ASan/Valgrind; the happy path
 *     almost never contains these bugs.
 *
 * =========================================================================
 * HOW THIS DEMO WORKS
 * =========================================================================
 * Deliberately double-freeing with the real allocator is undefined
 * behaviour and aborts on modern libc, so it would be neither deterministic
 * nor safe. Instead the demo uses a tiny MODEL ALLOCATOR (model_heap below):
 * a static array of 8 fixed-size slots with a LIFO free list. By default it
 * behaves like an old or minimal allocator WITHOUT double-free detection
 * (like glibc before 2.29, dlmalloc without checks, many embedded libcs).
 * A "checking" flag turns on a detection mode that works like glibc's
 * tcache key check: it aborts the request when it sees a double free.
 *
 *   vuln    : normal request, no error path taken, everything is fine.
 *   exploit : malformed request -> error path double-frees buf -> two later
 *             allocations (creds + username) get the SAME slot -> attacker
 *             written username bytes turn into is_admin != 0.
 *   fixed   : (1) same attack against the corrected code: no aliasing.
 *             (2) the BUGGY code on a detecting allocator: the second free
 *                 is caught and the request is aborted, heap stays sane.
 *             (3) correct code with the REAL malloc/free: goto-cleanup,
 *                 ownership transfer, destructor, and a leak counter that
 *                 proves every error path releases everything exactly once.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include "cvulns.h"

/* ====================================================================== */
/* MODEL ALLOCATOR (educational model, NOT a real allocator)               */
/* ====================================================================== */
/*
 * Models what happens inside an allocator that keeps freed chunks on a LIFO
 * free list. Real allocators store the list's "next" link inside the freed
 * chunk itself; the model keeps the links in a separate array so that the
 * demo's own data can never corrupt the model (contained and deterministic).
 *
 * UNPROTECTED mode (checking == 0): ma_free() blindly pushes the slot on
 * the free list. Freeing the same slot twice therefore creates a cycle
 * ("slot -> slot -> ..."), and ma_alloc() can return that slot many times.
 * This is the behaviour of allocators without double-free detection.
 *
 * CHECKING mode (checking == 1): ma_free() remembers which slots are free
 * and refuses to free one twice (like the tcache `key` check in glibc,
 * "free(): double free detected in tcache 2" followed by abort()).
 */
#define MA_SLOTS     8
#define MA_SLOT_SIZE 32

/* A union guarantees suitable alignment for any ordinary object type. */
typedef union {
    unsigned char bytes[MA_SLOT_SIZE];
    long long     align_ll;
    double        align_d;
    void         *align_p;
} ma_slot;

typedef struct {
    ma_slot       slot[MA_SLOTS];
    int           next[MA_SLOTS];     /* free-list links (-1 = end of list)   */
    unsigned char is_free[MA_SLOTS];  /* used ONLY in checking mode           */
    int           head;               /* first free slot, -1 if none          */
    int           checking;           /* 0 = no detection, 1 = glibc-like     */
    int           fatal;              /* set when the model "abort()ed"       */
} model_heap;

static void ma_init(model_heap *h, int checking) {
    memset(h, 0, sizeof *h);          /* deterministic initial contents */
    for (int i = 0; i < MA_SLOTS; i++) {
        h->next[i] = (i + 1 < MA_SLOTS) ? i + 1 : -1;
        h->is_free[i] = 1;
    }
    h->head = 0;
    h->checking = checking;
    h->fatal = 0;
}

/* Slot number that p points to, or -1 if p is not the start of a slot. */
static int ma_index(const model_heap *h, const void *p) {
    for (int i = 0; i < MA_SLOTS; i++)
        if ((const void *)&h->slot[i] == p) return i;
    return -1;
}

/* malloc(): pop the head of the free list (LIFO). Memory is NOT cleared,
 * just like malloc(): stale data from a previous owner stays in place. */
static void *ma_alloc(model_heap *h) {
    int i = h->head;
    if (i < 0) return NULL;
    h->head = h->next[i];
    h->is_free[i] = 0;
    return h->slot[i].bytes;
}

/* free(): returns 0 on success, -1 if a double free was detected (checking
 * mode only), -2 if p was not allocated by this allocator (CWE-590/761). */
static int ma_free(model_heap *h, void *p) {
    int i;
    if (p == NULL) return 0;                     /* free(NULL) is a no-op */
    i = ma_index(h, p);
    if (i < 0) {
        BAD("allocator: free() of a pointer it never returned (CWE-590/761)");
        return -2;                               /* real libc: abort/corrupt */
    }
    if (h->checking && h->is_free[i]) {
        GOOD("allocator: double free of slot %d detected -> abort() "
             "(glibc: \"free(): double free detected in tcache 2\")", i);
        h->fatal = 1;
        return -1;                               /* list left untouched */
    }
    /* Unprotected path: push on the free list without asking questions. */
    h->is_free[i] = 1;
    h->next[i] = h->head;      /* if slot i is already head: next[i] == i  */
    h->head = i;
    return 0;
}

/* Print the first few links of the free list; a repeating slot = cycle. */
static void ma_dump(const model_heap *h) {
    char line[128];
    size_t n;
    int cur = h->head;
    int hops = 0;
    int w = snprintf(line, sizeof line, "free list: head");
    n = (w > 0) ? (size_t)w : 0;
    while (cur >= 0 && hops < 4 && n < sizeof line) {
        w = snprintf(line + n, sizeof line - n, " -> [%d]", cur);
        if (w < 0) break;
        n += (size_t)w;
        cur = h->next[cur];
        hops++;
    }
    if (n < sizeof line) {
        snprintf(line + n, sizeof line - n, "%s", cur >= 0 ? " -> ..." : " -> (end)");
    }
    INFO("%s", line);
}

/* ====================================================================== */
/* The victim data: credentials structure living in a heap slot            */
/* ====================================================================== */
typedef struct {
    char role[16];       /* offset  0 .. 15 */
    int  is_admin;       /* offset 16 .. 19 : the security decision */
} creds_t;               /* sizeof == 20 <= MA_SLOT_SIZE */

/*
 * One login attempt, using two heap objects of the SAME size class:
 *   - creds    : server-side authorisation state (initialised by the server)
 *   - username : copy of the client supplied name
 * The copy into `username` is perfectly bounds-checked. There is NO buffer
 * overflow here. If the two allocations are distinct, nothing the client
 * sends can reach `creds`. The bug is elsewhere (the earlier double free).
 *
 * (Note on strict aliasing: the model stores objects in an array of unions
 * and accesses them through creds_t *. This mirrors what malloc() storage
 * allows and is fine for this -O0 demo.)
 */
static int login_attempt(model_heap *h, const char *name) {
    creds_t *c = (creds_t *)ma_alloc(h);
    char *uname = (char *)ma_alloc(h);
    size_t len = strlen(name);
    int is_admin;

    if (!c || !uname || len >= MA_SLOT_SIZE) {   /* bounded copy, see above */
        INFO("login: allocation failed or name too long, rejected");
        ma_free(h, uname);
        ma_free(h, c);
        return -1;
    }

    /* The server initialises its own credentials: guest, NOT admin. */
    memset(c, 0, sizeof *c);
    memcpy(c->role, "guest", sizeof "guest");
    c->is_admin = 0;
    INFO("server:   creds    in slot %d, role=\"%s\", is_admin=0", ma_index(h, c), c->role);

    /* The server stores the client supplied username (bounded copy). */
    memcpy(uname, name, len + 1);
    INFO("client:   username in slot %d, %zu bytes written", ma_index(h, uname), len);

    if ((void *)c == (void *)uname)
        BAD("creds and username are the SAME memory (slot %d): aliasing!", ma_index(h, c));
    else
        GOOD("creds and username are distinct objects");

    /* The authorisation decision reads creds->is_admin. */
    is_admin = c->is_admin;
    INFO("server:   creds now: role=\"%.16s\", is_admin=0x%08x",
         c->role, (unsigned)c->is_admin);

    ma_free(h, uname);
    ma_free(h, c);   /* if aliased, this is itself a double free: harmless in the model */
    return is_admin;
}

/* ====================================================================== */
/* VULNERABLE request handler                                              */
/* ====================================================================== */

/*
 * VULNERABLE helper: "rejects" a request and, being helpful, releases the
 * buffer. But the buffer is owned by the CALLER (it allocated it and its own
 * cleanup frees it). Nothing in the signature tells the caller that
 * ownership moved: CWE-415 waiting to happen.
 */
static void vuln_reject(model_heap *h, char *buf) {
    INFO("reject(): malformed request \"%.12s\", releasing buffer", buf);
    ma_free(h, buf);                       /* free #1 (helper) */
}

static int vuln_process_request(model_heap *h, const char *req) {
    int rc = -1;
    char *buf = (char *)ma_alloc(h);
    if (!buf) return -1;
    snprintf(buf, MA_SLOT_SIZE, "%s", req);

    if (buf[0] != 'G') {                   /* only "GET ..." is valid */
        vuln_reject(h, buf);               /* BUG: frees buf ...      */
        goto out;                          /* ... and falls into the common exit */
    }
    INFO("request \"%.12s\" processed", buf);
    rc = 0;
out:
    ma_free(h, buf);                       /* free #2 on the error path (BUG);
                                              on the success path this is the
                                              only free, which is correct */
    return rc;
}

/* ====================================================================== */
/* FIXED request handler                                                   */
/* ====================================================================== */

/* NULL-after-free (CERT MEM01-C). free(NULL) is a no-op, so repeating it is
 * harmless. Evaluates p twice: do not pass expressions with side effects. */
#define SAFE_FREE(h, p) do { ma_free((h), (p)); (p) = NULL; } while (0)

/* Fixed helper: only BORROWS the buffer (const char *), never frees it. */
static void fixed_log_reject(const char *buf) {
    INFO("reject(): malformed request \"%.12s\" (buffer stays owned by caller)", buf);
}

/*
 * Ownership: this function allocates `buf` and is the only one that frees
 * it, at the single cleanup label. Resources start as NULL, every error
 * jumps to `cleanup`.
 */
static int fixed_process_request(model_heap *h, const char *req) {
    int rc = -1;
    char *buf = NULL;

    buf = (char *)ma_alloc(h);
    if (!buf) goto cleanup;
    snprintf(buf, MA_SLOT_SIZE, "%s", req);

    if (buf[0] != 'G') {
        fixed_log_reject(buf);             /* borrow only */
        goto cleanup;
    }
    INFO("request \"%.12s\" processed", buf);
    rc = 0;

cleanup:
    SAFE_FREE(h, buf);                     /* the one and only release */
    SAFE_FREE(h, buf);                     /* demonstration: a repeated cleanup is
                                              now a harmless free(NULL) */
    return rc;
}

/* ====================================================================== */
/* Real-world shaped, CORRECT code using the real malloc/free              */
/* ====================================================================== */
/*
 * A parser that builds a heap object out of several allocations. Every
 * failure path leaves through `cleanup` (no leaks, CWE-401), each pointer is
 * freed exactly once (no double free, CWE-415), and on success ownership of
 * the finished record is TRANSFERRED to the caller (`*out = rec; rec = NULL;`).
 *
 * The cnt_* wrappers just count live allocations so the demo can prove that
 * nothing leaks. They behave like calloc/free.
 */
static size_t g_live;                      /* number of live allocations */

static void *cnt_alloc(size_t n) {
    void *p = calloc(1, n ? n : 1);
    if (p) g_live++;
    return p;
}

static void cnt_free(void *p) {
    if (p) { g_live--; free(p); }          /* NULL is accepted, like free() */
}

static char *cnt_strndup(const char *s, size_t n) {
    char *d;
    if (n == SIZE_MAX) return NULL;        /* n + 1 would wrap */
    d = (char *)cnt_alloc(n + 1);          /* calloc: terminator is already 0 */
    if (d) memcpy(d, s, n);
    return d;
}

typedef struct {
    char *name;                            /* owned by the record */
    char *data;                            /* owned by the record */
} record;

/* Destructor: owns the whole teardown, safe on NULL, idempotent because it
 * resets the caller's pointer. */
static void record_destroy(record **pr) {
    if (pr == NULL || *pr == NULL) return;
    cnt_free((*pr)->name);
    cnt_free((*pr)->data);
    cnt_free(*pr);
    *pr = NULL;
}

/*
 * Parses "name:data". Returns 0 and a new record in *out on success (caller
 * owns it and must call record_destroy); returns -1 and *out == NULL on
 * failure (nothing to free for the caller).
 */
static int parse_record(const char *in, record **out) {
    int rc = -1;
    record *rec = NULL;
    const char *colon;

    if (in == NULL || out == NULL) return -1;
    *out = NULL;

    colon = strchr(in, ':');
    if (colon == NULL || colon == in) {
        INFO("parse(\"%s\"): no name/separator -> error (nothing allocated yet)", in);
        goto cleanup;
    }

    rec = (record *)cnt_alloc(sizeof *rec);
    if (!rec) goto cleanup;
    rec->name = cnt_strndup(in, (size_t)(colon - in));
    if (!rec->name) goto cleanup;
    rec->data = cnt_strndup(colon + 1, strlen(colon + 1));
    if (!rec->data) goto cleanup;

    if (rec->data[0] == '\0') {            /* late validation failure: 3 allocations exist */
        INFO("parse(\"%s\"): empty data -> error after 3 allocations", in);
        goto cleanup;
    }

    *out = rec;                            /* ownership transfer to the caller ... */
    rec = NULL;                            /* ... so cleanup must not free it     */
    rc = 0;

cleanup:
    record_destroy(&rec);                  /* no-op after a successful transfer */
    return rc;
}

static int real_malloc_demo(void) {
    static const char *const inputs[] = { "alice:hello", "nocolon", "alice:" };
    int bad = 0;

    g_live = 0;
    for (size_t i = 0; i < sizeof inputs / sizeof inputs[0]; i++) {
        record *r = NULL;
        int rc = parse_record(inputs[i], &r);
        if (rc == 0) {
            INFO("parse(\"%s\") ok: name=\"%s\" data=\"%s\", live allocations=%zu",
                 inputs[i], r->name, r->data, g_live);
            record_destroy(&r);            /* the caller owns r now */
            record_destroy(&r);            /* second call: r is NULL, harmless */
        }
        if (g_live == 0) {
            GOOD("after \"%s\": live allocations = 0 (no leak, no double free)", inputs[i]);
        } else {
            BAD("after \"%s\": %zu allocation(s) leaked", inputs[i], g_live);
            bad = 1;
        }
    }
    return bad;
}

/* ====================================================================== */
/* Demo driver                                                             */
/* ====================================================================== */
static const char *const GOOD_REQUEST = "GET /index.html";
static const char *const BAD_REQUEST  = "BAD-REQUEST";
/* 24 non-zero bytes: valid as a username (fits in a 32 byte slot) but they
 * cover creds->is_admin at offset 16..19 if the memory is shared. */
static const char *const ATTACKER_NAME = "AAAAAAAAAAAAAAAAAAAAAAAA";

static int run(vuln_mode mode) {
    model_heap h;
    int admin;

    switch (mode) {
    case MODE_VULN:
        SECTION("Vulnerable code, benign input");
        INFO("model allocator WITHOUT double-free detection (educational model)");
        ma_init(&h, 0);
        vuln_process_request(&h, GOOD_REQUEST);
        ma_dump(&h);
        GOOD("buffer freed once on the normal path: list is sane");
        admin = login_attempt(&h, "alice");
        if (admin == 0) GOOD("alice is not admin, as expected");
        return 0;

    case MODE_EXPLOIT:
        SECTION("Vulnerable code, malicious input");
        INFO("model allocator WITHOUT double-free detection (educational model)");
        ma_init(&h, 0);
        INFO("step 1: attacker sends a malformed request, error path runs");
        vuln_process_request(&h, BAD_REQUEST);
        ma_dump(&h);
        BAD("slot 0 is on the free list TWICE (a cycle): double free (CWE-415)");
        INFO("step 2: attacker logs in with a crafted 24 byte username");
        admin = login_attempt(&h, ATTACKER_NAME);
        if (admin != 0)
            BAD("PRIVILEGE ESCALATION: is_admin != 0 although the server set it to 0");
        else
            INFO("is_admin == 0: no escalation this time");
        INFO("on a real allocator the same primitive also yields arbitrary write");
        INFO("(overwrite the free chunk's next pointer, see the header comment)");
        return 0;

    case MODE_FIXED:
        SECTION("Fixed code, malicious input");
        INFO("(1) corrected handler on the unprotected model allocator");
        ma_init(&h, 0);
        fixed_process_request(&h, BAD_REQUEST);
        ma_dump(&h);
        GOOD("slot 0 is on the free list exactly once");
        admin = login_attempt(&h, ATTACKER_NAME);
        if (admin == 0) GOOD("is_admin stays 0: the attacker's bytes cannot reach creds");
        else BAD("unexpected: is_admin != 0");

        INFO("(2) defence in depth: the BUGGY handler on a checking allocator");
        ma_init(&h, 1);
        vuln_process_request(&h, BAD_REQUEST);
        if (h.fatal) {
            GOOD("request terminated at the second free; free list was not corrupted");
            ma_dump(&h);
            admin = login_attempt(&h, ATTACKER_NAME);
            if (admin == 0) GOOD("no aliasing, is_admin == 0");
        } else {
            BAD("double free was not detected");
        }
        INFO("detection turns silent corruption into a crash (DoS), it is not a fix");

        INFO("(3) correct code with the real malloc/free (goto cleanup, ownership transfer)");
        return real_malloc_demo();
    }
    return 0;
}

const vuln_example ex05_example = {
    "double-free",
    "Double free and memory-management errors on error paths (CWE-415/CWE-401)",
    run
};
