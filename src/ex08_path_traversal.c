/*
 * ex08_path_traversal.c - Path traversal and TOCTOU file races
 *                         (CWE-22, CWE-23, CWE-36, CWE-59, CWE-367, CWE-377)
 *
 * =============================================================================
 * 1. WHAT IS IT?
 * =============================================================================
 * A program has a "base directory" (say ./public) and lets the user pick a
 * file NAME ("hello.txt").  The lazy implementation is
 *
 *        snprintf(path, sizeof path, "%s/%s", base, user_name);
 *        fopen(path, "rb");
 *
 * The author assumes that the result is "somewhere inside base".  But the file
 * system interprets the whole string, and the user controls part of it:
 *
 *   - "../" sequences climb out of the base directory:
 *         public/../../../etc/passwd         ->  /etc/passwd
 *   - absolute names: if the code uses the user string as the path (or the
 *     joining logic is smarter than you think, e.g. Python's os.path.join)
 *         /etc/passwd
 *   - Windows specifics (CWE-36 / CWE-23 / CWE-66):
 *         ..\..\Windows\win.ini           backslash is a separator too
 *         C:\Windows\win.ini              drive letter (absolute)
 *         C:win.ini                       drive-RELATIVE path (!)
 *         \\server\share\file             UNC path (also leaks NTLM hashes)
 *         \\?\C:\...  and  \\.\PhysicalDrive0   device / extended namespace
 *         file.txt::$DATA, file.txt:stream   NTFS alternate data streams
 *         CON, NUL, COM1, "file.txt. " (trailing dot/space is stripped)
 *   - encodings that are decoded AFTER your check (or twice):
 *         %2e%2e%2f   (= ../)     %252e%252e%252f   (double encoded)
 *         ..%c0%af  (overlong UTF-8 '/'), ..%5c (= ..\)
 *   - symbolic links / junctions (CWE-59 "link following"): a file inside the
 *     base directory that is a symlink to /etc/shadow passes every string
 *     check, because the NAME is innocent - the TARGET is not.
 *   - naive filters.  "Remove every ../ from the input" is the classic:
 *         ....//secret.txt   --strip one "../"-->   ../secret.txt
 *     (the filter itself assembles the attack).  Also: filtering only once,
 *     filtering before decoding, case-sensitive checks on a case-insensitive
 *     file system, checking only for "../" but not "..\" on Windows.
 *   - TOCTOU: Time-Of-Check / Time-Of-Use race (CWE-367).
 *         if (access(path, R_OK) == 0) {   // CHECK  (is it OK for me?)
 *             f = fopen(path, "r");        // USE    (a different file maybe!)
 *     Between the two calls another process can replace `path` (rename, or
 *     delete + symlink).  This matters mostly in directories that other users
 *     can write to, like /tmp, /var/tmp, C:\Windows\Temp, shared upload dirs,
 *     where the attacker can pre-create, replace or race names.  Related:
 *     predictable temp file names (CWE-377 / CWE-379): tmpnam(), tempnam(),
 *     mktemp(), "/tmp/myapp.<pid>", "/tmp/myapp.log" - the attacker creates a
 *     symlink with that name pointing to ~victim/.bashrc, and the privileged
 *     program happily "creates" (=overwrites) the target.
 *
 * =============================================================================
 * 2. HOW IS IT EXPLOITED?   (sample payloads, all just file-name strings)
 * =============================================================================
 *   GET /download?file=../../etc/passwd
 *   GET /download?file=..\..\Windows\win.ini
 *   GET /download?file=%2e%2e%2f%2e%2e%2fetc%2fpasswd
 *   GET /download?file=%252e%252e%252fetc%252fpasswd       (double decoded)
 *   GET /download?file=....//....//etc/passwd               (naive strip)
 *   GET /download?file=/etc/passwd
 *   GET /download?file=C:\Windows\win.ini
 *   GET /download?file=\\attacker\share\x    (SMB: NTLM credential theft)
 *   GET /download?file=report.pdf%00.txt     (NUL byte truncation, old stacks)
 *
 * Impact: read config files, source code, private keys, /proc/self/environ
 * (secrets), databases; with write primitives (upload, log, "save as"):
 * overwrite ~/.ssh/authorized_keys, cron files, web-root scripts -> RCE.
 * Famous examples: countless web servers / archive extractors ("Zip Slip",
 * CVE-2018-1002200 - entries named ../../x inside an archive), Apache
 * CVE-2021-41773 (encoded %2e), tar/unzip symlink bugs.
 *
 * TOCTOU exploitation (the attacker loops forever, no luck needed):
 *     victim (setuid / root daemon)            attacker (unprivileged)
 *     -------------------------------          ----------------------------
 *     access("/tmp/job.txt", R_OK) -> ok       (file is a harmless regular
 *                                               file owned by the attacker)
 *                                              unlink("/tmp/job.txt");
 *                                              symlink("/etc/shadow",
 *                                                      "/tmp/job.txt");
 *     fopen("/tmp/job.txt", "r")   -> reads /etc/shadow with root privileges
 *   The window is tiny, but loops of rename()/symlink() win it quickly,
 *   especially on multicore machines or when the attacker slows the victim
 *   down (huge directory, CPU pressure, FUSE/NFS, inotify + SIGSTOP).
 *   NOTE: access() checks with the REAL uid, open() uses the EFFECTIVE uid; it
 *   is a classic *misuse* even without a race (CERT FIO45-C, POS35-C).
 *
 * =============================================================================
 * 3. HOW TO AVOID IT
 * =============================================================================
 *  a) Best: do not use user input in paths at all.  Map an opaque ID or an
 *     index to a file via a table you control ("1" -> "report.pdf").
 *  b) If a file name is expected, it is a NAME, not a path: allow-list it
 *     (e.g. [A-Za-z0-9._-]{1,100}), forbid ANY directory separator ('/' and
 *     '\\'), ':' (drive, stream), NUL, a leading '.', "..", trailing '.'/' '.
 *     Validate AFTER all decoding was done, and only decode once.  Allow-lists
 *     beat block-lists (strstr("../")) - you cannot enumerate all evil.
 *  c) Defense in depth: CANONICALISE, then CHECK, then use the canonical path:
 *         POSIX:    realpath()               (resolves ., .., AND symlinks)
 *         Windows:  _fullpath() (lexical) and, for links/junctions,
 *                   open the file and call GetFinalPathNameByHandleW()
 *     and verify the result is still inside the (also canonicalised) base
 *     directory.  The prefix match MUST respect component boundaries:
 *            base = /srv/public     evil = /srv/public_backup/x
 *     strncmp(evil, base, strlen(base)) == 0  is TRUE and WRONG.  After the
 *     prefix, the next character must be a separator (and compare
 *     case-insensitively on Windows / macOS default volumes).
 *  d) Avoid the race instead of checking for it:
 *       - never access()/stat()/lstat() and then open() the same name.
 *         OPEN FIRST, then examine the *descriptor*: fstat(fd) (is it a
 *         regular file? owner? link count?) - the fd cannot be swapped.
 *       - open(path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC) refuses a symlink in
 *         the last component; O_EXCL | O_CREAT never reuses an existing
 *         file/symlink (create-only); Linux: openat2() with RESOLVE_BENEATH /
 *         RESOLVE_NO_SYMLINKS, FreeBSD: O_RESOLVE_BENEATH / O_BENEATH, or walk
 *         the components yourself with openat(dirfd, comp, O_NOFOLLOW) so
 *         nothing can escape the directory fd you hold.
 *       - temp files: mkstemp() (POSIX, 0600, O_EXCL), tmpfile(), or on
 *         Windows CreateFile(CREATE_NEW) / FILE_FLAG_DELETE_ON_CLOSE in a
 *         per-user directory; never mktemp()/tmpnam()/tempnam(); private
 *         0700 directory made by mkdtemp() when you need several files.
 *         Always set a restrictive umask / mode (0600/0700).
 *  e) Least privilege and containment: do not run the file-serving code as
 *     root/SYSTEM; drop privileges before touching user-chosen files; use
 *     chroot, containers, namespaces, seccomp, Landlock (Linux 5.13+),
 *     pledge/unveil (OpenBSD), AppContainer / restricted tokens (Windows), so
 *     that a missed bug cannot reach /etc anyway.  Set fs permissions so the
 *     service account simply cannot read secrets.
 *  f) Do not forward user-controlled paths to shells or other tools
 *     ("cat %s"), and extract archives with entry-name validation (Zip Slip).
 *
 *  Rules / references:
 *   CERT FIO02-C  Canonicalize path names originating from tainted sources
 *   CERT FIO01-C  Be careful using functions that use file names for
 *                 identification (use fd-based calls instead)
 *   CERT FIO21-C  Do not create temporary files in shared directories
 *   CERT FIO45-C  Avoid TOCTOU race conditions while accessing files
 *   CERT POS35-C  Avoid race conditions while checking for the existence of a
 *                 symbolic link
 *   CERT FIO32-C  Do not perform operations on devices only appropriate for
 *                 files;  FIO22-C Close files before spawning processes
 *   CWE-22   Improper Limitation of a Pathname to a Restricted Directory
 *   CWE-23   Relative Path Traversal        CWE-36  Absolute Path Traversal
 *   CWE-41   Improper Resolution of Path Equivalence (trailing dot, 8.3 names)
 *   CWE-59   Improper Link Resolution Before File Access ("link following")
 *   CWE-73   External Control of File Name or Path
 *   CWE-367  TOCTOU Race Condition      CWE-377/379  Insecure Temporary File
 *   CWE-426/427 are the sibling bugs for search paths (DLL / PATH hijacking)
 *   OWASP: Path Traversal;  OWASP ASVS V12 (File and Resources)
 *
 * =============================================================================
 * 4. BEST PRACTICES IN A NUTSHELL
 * =============================================================================
 *   - Treat every file name as tainted data. Name != path.
 *   - Allow-list, then canonicalise, then contain-check (component boundary),
 *     then open with no-follow flags, then fstat() the descriptor.
 *   - Never stat/access before open; handle the error from open() instead
 *     ("easier to ask forgiveness": EAFP beats LBYL for the file system).
 *   - Private temp files via mkstemp/mkdtemp; no predictable names; no /tmp
 *     for secrets.
 *   - Run with least privilege and sandbox the process.
 *   - Test with fuzzed names: "..", "...", "..;/", "%2e", "\\", ":", NUL,
 *     symlink and junction fixtures, very long names.
 *
 * =============================================================================
 * THIS DEMO
 * =============================================================================
 * Sandbox (created at run time in the temp directory, removed at the end):
 *
 *     <tmp>/cvulns_ex08/public/hello.txt    <- the "web root", fine to serve
 *     <tmp>/cvulns_ex08/secret.txt          <- sibling OUTSIDE public/
 *                                              contains a fake secret
 *     <tmp>/cvulns_ex08/public/link.txt     <- POSIX only: symlink to
 *                                              ../secret.txt  (CWE-59)
 *
 * Real system files are never opened.  The payload "../secret.txt" escapes
 * public/ into its sibling, exactly like "../../etc/passwd" would on a server.
 * The TOCTOU pattern is shown in a function and executed once WITHOUT an
 * attacker (the race itself is not demonstrated - it would be non-deterministic
 * and has no place in a demo that must be repeatable).
 */

#ifndef _WIN32
#define _XOPEN_SOURCE 700 /* POSIX.1-2008 + XSI: realpath, symlink, O_NOFOLLOW, fstat... */
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "cvulns.h"

#ifdef _WIN32
#include <direct.h> /* _mkdir, _rmdir */
#include <io.h>     /* _access */
#define MKDIR(p) _mkdir(p)
#define RMDIR(p) _rmdir(p)
#define CV_ACCESS(p) _access((p), 4) /* 4 = read permission */
#else
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#define MKDIR(p) mkdir((p), 0700)
#define RMDIR(p) rmdir(p)
#define CV_ACCESS(p) access((p), R_OK)
#ifndef O_NOFOLLOW
#define O_NOFOLLOW 0
#endif
#ifndef O_CLOEXEC
#define O_CLOEXEC 0
#endif
#endif

#define SECRET_TEXT "TOP-SECRET-DEMO-DATA"
#define PATH_BUF 640
#define DATA_BUF 256

/* ------------------------------------------------------------------------- */
/* Sandbox management (portable, everything lives under <tmp>/cvulns_ex08)    */
/* ------------------------------------------------------------------------- */

typedef struct {
    char root[PATH_BUF];   /* <tmp>/cvulns_ex08               */
    char base[PATH_BUF];   /* <tmp>/cvulns_ex08/public        */
    char hello[PATH_BUF];  /* .../public/hello.txt            */
    char secret[PATH_BUF]; /* .../cvulns_ex08/secret.txt      */
    char link[PATH_BUF];   /* .../public/link.txt (POSIX)     */
    int  have_link;
} sandbox;

static int is_sep(char c) { return c == '/' || c == '\\'; }

/* out = a + "/" + b, fails (-1) instead of truncating. */
static int join(char *out, size_t outsz, const char *a, const char *b) {
    int n = snprintf(out, outsz, "%s/%s", a, b);
    return (n < 0 || (size_t)n >= outsz) ? -1 : 0;
}

static int write_file(const char *path, const char *text) {
    FILE *f = fopen(path, "wb");
    if (!f) return -1;
    size_t len = strlen(text);
    int ok = fwrite(text, 1, len, f) == len;
    if (fclose(f) != 0) ok = 0;
    return ok ? 0 : -1;
}

static int sandbox_setup(sandbox *sb) {
    memset(sb, 0, sizeof *sb); /* so cleanup is safe even if setup fails early */
    const char *tmp = getenv("TMPDIR");
    if (!tmp || !*tmp) tmp = getenv("TEMP");
    if (!tmp || !*tmp) tmp = getenv("TMP");
    if (!tmp || !*tmp) {
#ifdef _WIN32
        tmp = ".";
#else
        tmp = "/tmp";
#endif
    }

    char t[400];
    int n = snprintf(t, sizeof t, "%s", tmp);
    if (n < 0 || (size_t)n >= sizeof t) return -1;
    size_t len = strlen(t);
    while (len > 1 && is_sep(t[len - 1])) t[--len] = '\0'; /* no trailing '/' */

    if (join(sb->root, sizeof sb->root, t, "cvulns_ex08") ||
        join(sb->base, sizeof sb->base, sb->root, "public") ||
        join(sb->hello, sizeof sb->hello, sb->base, "hello.txt") ||
        join(sb->secret, sizeof sb->secret, sb->root, "secret.txt") ||
        join(sb->link, sizeof sb->link, sb->base, "link.txt"))
        return -1;

    /* EEXIST (leftover from an earlier run) is fine; real errors show up when
     * the files are written below. */
    (void)MKDIR(sb->root);
    (void)MKDIR(sb->base);

    if (write_file(sb->hello, "Hello, this file is meant to be public.\n") != 0) return -1;
    if (write_file(sb->secret, SECRET_TEXT "\n") != 0) return -1;

#ifndef _WIN32
    /* A planted symlink inside the web root pointing outside of it. */
    (void)unlink(sb->link);
    sb->have_link = (symlink("../secret.txt", sb->link) == 0);
#endif
    return 0;
}

static void sandbox_cleanup(sandbox *sb) {
    if (sb->have_link) (void)remove(sb->link); /* removes the link, not the target */
    (void)remove(sb->hello);
    (void)remove(sb->secret);
    (void)RMDIR(sb->base);
    (void)RMDIR(sb->root);
}

static void show_data(const char *data) {
    char line[DATA_BUF];
    snprintf(line, sizeof line, "%s", data);
    size_t n = strlen(line);
    while (n > 0 && (line[n - 1] == '\n' || line[n - 1] == '\r')) line[--n] = '\0';
    INFO("    file content: \"%s\"", line);
}

/* ------------------------------------------------------------------------- */
/* VULNERABLE: base + "/" + user input, then fopen()                          */
/* ------------------------------------------------------------------------- */

/*
 * CWE-22 / CWE-73.  Nothing prevents "../secret.txt", absolute paths,
 * "..\\secret.txt" on Windows, or a symlink planted in `base`.
 */
static int vulnerable_read(const char *base, const char *user_name, char *out, size_t outsz) {
    char path[PATH_BUF];
    snprintf(path, sizeof path, "%s/%s", base, user_name); /* BUG: no validation */
    FILE *f = fopen(path, "rb");                           /* BUG: follows ../ and links */
    if (!f) return -1;
    size_t n = fread(out, 1, outsz - 1, f);
    fclose(f);
    out[n] = '\0';
    return 0;
}

/*
 * A typical "security filter" that does not work.  It removes "../" ONCE and
 * does not re-scan its own output, so "....//" collapses into "../".  It also
 * ignores "..\\", absolute paths, encodings and symlinks.
 */
static void naive_strip_dotdot(char *s) {
    char *r = s, *w = s;
    while (*r) {
        if (r[0] == '.' && r[1] == '.' && r[2] == '/') {
            r += 3; /* drop "../" */
            continue;
        }
        *w++ = *r++;
    }
    *w = '\0';
}

/*
 * The classic check-then-use race (CWE-367, CERT FIO45-C).  SHOWN, NOT RACED.
 *
 * Why it is broken:
 *   1. access() answers a question about a NAME at time T1.
 *   2. fopen() resolves the NAME again at time T2 > T1.  Anything can happen
 *      in between: rename(), unlink() + symlink(), mount over a directory...
 *   3. access() uses the real uid; in setuid programs it is exactly the wrong
 *      tool (and the man page itself warns about this).
 *
 * Safe replacement (implemented in read_regular_nofollow() below):
 *      fd = open(path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);  // just try it
 *      if (fd < 0) handle errno;                           // EACCES, ENOENT...
 *      fstat(fd, &st); check S_ISREG(st.st_mode) (+ owner, nlink, size);
 *      read(fd, ...);                                      // same object
 * The decision is taken on the OPEN FILE (descriptor), which an attacker can no
 * longer exchange.  For creation use O_CREAT | O_EXCL (mkstemp for temp files).
 */
static int toctou_insecure_pattern(const char *path, char *out, size_t outsz) {
    if (CV_ACCESS(path) != 0) /* CHECK: "may I read it?"                   */
        return -1;
    /* <<< RACE WINDOW: attacker replaces `path` by a symlink right here >>> */
    FILE *f = fopen(path, "rb"); /* USE: may now open a different object   */
    if (!f) return -1;
    size_t n = fread(out, 1, outsz - 1, f);
    fclose(f);
    out[n] = '\0';
    return 0;
}

/* ------------------------------------------------------------------------- */
/* FIXED: allow-list + canonicalise + component-boundary check + safe open   */
/* ------------------------------------------------------------------------- */

/* Step 1: the input must be a plain, boring file NAME. */
static int valid_file_name(const char *name, const char **why) {
    size_t len = strlen(name);
    if (len == 0) { *why = "empty name"; return 0; }
    if (len > 100) { *why = "name too long"; return 0; }
    if (name[0] == '.') { *why = "leading '.' (hidden file / '..')"; return 0; }
    if (name[len - 1] == '.' || name[len - 1] == ' ') {
        *why = "trailing '.' or ' ' (stripped by Windows -> path equivalence)";
        return 0;
    }
    for (size_t i = 0; i < len; i++) {
        char c = name[i];
        int ok = (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
                 (c >= '0' && c <= '9') || c == '.' || c == '_' || c == '-';
        if (!ok) {
            /* '/', '\\' (separators), ':' (drive/stream), '%' (encodings),
             * NUL cannot occur in a C string, control chars, spaces... */
            *why = is_sep(c) ? "directory separator in file name"
                             : "character outside the allow-list [A-Za-z0-9._-]";
            return 0;
        }
    }
    if (strstr(name, "..")) { *why = "contains '..'"; return 0; }
    /* Windows reserved device names (CON, NUL, COM1...) should be rejected
     * too in a real Windows-facing service; omitted here for brevity. */
    return 1;
}

/* Step 2: canonical (absolute, no ., .., and on POSIX no symlinks) path. */
static int canonicalize(const char *in, char *out, size_t outsz) {
#ifdef _WIN32
    /* _fullpath() is lexical only: it resolves ".." and '/', but not
     * junctions or symlinks.  For those, open the file and compare
     * GetFinalPathNameByHandleW() with the base directory's final path. */
    return _fullpath(out, in, outsz) ? 0 : -1;
#else
    char *r = realpath(in, NULL); /* POSIX.1-2008: allocates the result */
    if (!r) return -1;            /* does not exist / unreadable        */
    size_t n = strlen(r);
    if (n >= outsz) { free(r); return -1; }
    memcpy(out, r, n + 1);
    free(r);
    return 0;
#endif
}

/*
 * Step 3: is `file` inside `base`?  Both must be canonical.
 * The character after the prefix MUST be a separator, otherwise
 * "/srv/public_backup/x" would pass as being inside "/srv/public".
 */
static int inside_dir(const char *base, const char *file) {
    size_t n = strlen(base);
#ifdef _WIN32
    if (_strnicmp(file, base, n) != 0) return 0; /* NTFS is case-insensitive */
#else
    if (strncmp(file, base, n) != 0) return 0;
#endif
    if (n > 0 && is_sep(base[n - 1])) return file[n] != '\0'; /* base is a root: "/" */
    return is_sep(file[n]);                                    /* boundary! */
}

/* Step 4: open first, then look at the descriptor (never stat-then-open). */
static int read_regular_nofollow(const char *path, char *out, size_t outsz) {
#ifdef _WIN32
    FILE *f = fopen(path, "rb");
    if (!f) return -1;
    size_t n = fread(out, 1, outsz - 1, f);
    fclose(f);
    out[n] = '\0';
    return 0;
#else
    int fd = open(path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
    if (fd < 0) return -1;
    struct stat st;
    if (fstat(fd, &st) != 0 || !S_ISREG(st.st_mode)) { /* check the OPEN object */
        close(fd);
        return -1;
    }
    ssize_t n = read(fd, out, outsz - 1);
    close(fd);
    if (n < 0) return -1;
    out[n] = '\0';
    return 0;
#endif
}

/* Returns 0 on success, -1 if rejected (reason in *why). */
static int safe_read(const char *base, const char *user_name, char *out, size_t outsz,
                     const char **why) {
    char path[PATH_BUF], base_real[PATH_BUF], file_real[PATH_BUF];

    if (!valid_file_name(user_name, why)) return -1; /* allow-list */

    if (join(path, sizeof path, base, user_name) != 0) { *why = "path too long"; return -1; }
    if (canonicalize(base, base_real, sizeof base_real) != 0) { *why = "bad base dir"; return -1; }
    if (canonicalize(path, file_real, sizeof file_real) != 0) {
        *why = "cannot canonicalise (does not exist?)";
        return -1;
    }
    if (!inside_dir(base_real, file_real)) { /* catches symlinks leaving base */
        *why = "canonical path escapes the base directory";
        return -1;
    }
    /* Use the CANONICAL path from here on, not the original string. */
    if (read_regular_nofollow(file_real, out, outsz) != 0) {
        *why = "open/fstat failed or not a regular file";
        return -1;
    }
    return 0;
}

/* ------------------------------------------------------------------------- */
/* Demo driver                                                                */
/* ------------------------------------------------------------------------- */

static int run(vuln_mode mode) {
    sandbox sb;
    char data[DATA_BUF];
    int rc = 0;

    if (sandbox_setup(&sb) != 0) {
        BAD("could not create the sandbox under the temp directory");
        sandbox_cleanup(&sb);
        return 1;
    }
    INFO("sandbox: %s", sb.root);
    INFO("web root (base dir): %s", sb.base);

    if (mode == MODE_VULN) {
        SECTION("Benign request against the vulnerable code");
        INFO("request: \"hello.txt\"");
        if (vulnerable_read(sb.base, "hello.txt", data, sizeof data) == 0) {
            GOOD("served a file from inside the base directory");
            show_data(data);
        } else {
            BAD("unexpected: could not read hello.txt");
            rc = 1;
        }
        INFO("so far everything looks fine - that is why this bug survives testing.");

    } else if (mode == MODE_EXPLOIT) {
        SECTION("Path traversal against the vulnerable code");

        INFO("request: \"../secret.txt\"   (stands for ../../etc/passwd)");
        if (vulnerable_read(sb.base, "../secret.txt", data, sizeof data) == 0) {
            BAD("escaped the web root and read a file outside of it!");
            show_data(data);
        } else {
            INFO("read failed (unexpected for this demo)");
        }

        SECTION("Bypassing a naive '../' filter");
        char evil[64] = "....//secret.txt";
        INFO("raw request:        \"%s\"", evil);
        naive_strip_dotdot(evil);
        INFO("after naive filter: \"%s\"   <- the filter built the attack", evil);
        if (vulnerable_read(sb.base, evil, data, sizeof data) == 0) {
            BAD("filter bypassed, secret leaked");
            show_data(data);
        } else {
            INFO("read failed (unexpected for this demo)");
        }

#ifndef _WIN32
        SECTION("Symlink inside the web root (CWE-59)");
        INFO("request: \"link.txt\"   (a harmless-looking NAME; target is ../secret.txt)");
        if (sb.have_link && vulnerable_read(sb.base, "link.txt", data, sizeof data) == 0) {
            BAD("followed the symlink out of the web root");
            show_data(data);
        } else {
            INFO("symlink demo not available on this system");
        }
#else
        INFO("(Windows: try \"..\\\\secret.txt\", \"C:\\\\Windows\\\\win.ini\", "
             "\"file.txt::$DATA\" - same bug, other spellings)");
#endif

        SECTION("TOCTOU: check-then-use (shown, not raced)");
        INFO("access(path) followed by fopen(path) - the name is resolved twice.");
        if (toctou_insecure_pattern(sb.hello, data, sizeof data) == 0) {
            INFO("worked here because no attacker is racing us.");
            INFO("an attacker who swaps the file for a symlink between the two");
            INFO("calls makes fopen() open a file the access() check never saw.");
        }

    } else { /* MODE_FIXED */
        SECTION("Same attacks against the hardened code");
        struct {
            const char *label;
            const char *name;
        } attacks[8];
        size_t na = 0;
        attacks[na].label = "parent directory";   attacks[na++].name = "../secret.txt";
        attacks[na].label = "backslash variant";  attacks[na++].name = "..\\secret.txt";
        attacks[na].label = "naive-filter bypass"; attacks[na++].name = "....//secret.txt";
        attacks[na].label = "absolute path";      attacks[na++].name = sb.secret;
        attacks[na].label = "URL-encoded ../";    attacks[na++].name = "%2e%2e%2fsecret.txt";
        attacks[na].label = "stream/drive syntax"; attacks[na++].name = "hello.txt::$DATA";
        attacks[na].label = "planted symlink";    attacks[na++].name = "link.txt";

        for (size_t i = 0; i < na; i++) {
            const char *why = "";
            INFO("request (%s): \"%s\"", attacks[i].label, attacks[i].name);
            if (safe_read(sb.base, attacks[i].name, data, sizeof data, &why) == 0) {
                BAD("NOT blocked! leaked data");
                show_data(data);
                rc = 1;
            } else {
                GOOD("rejected: %s", why);
            }
        }

        SECTION("Legitimate request still works");
        {
            const char *why = "";
            INFO("request: \"hello.txt\"");
            if (safe_read(sb.base, "hello.txt", data, sizeof data, &why) == 0) {
                GOOD("served from inside the base directory");
                show_data(data);
            } else {
                BAD("legitimate request rejected: %s", why);
                rc = 1;
            }
        }

        SECTION("Component-boundary check");
        INFO("inside_dir(\"/srv/public\", \"/srv/public/a.txt\")        = %d (expect 1)",
             inside_dir("/srv/public", "/srv/public/a.txt"));
        INFO("inside_dir(\"/srv/public\", \"/srv/public_backup/a.txt\") = %d (expect 0)",
             inside_dir("/srv/public", "/srv/public_backup/a.txt"));
        GOOD("a plain strncmp() prefix test would have accepted the second one");
        INFO("TOCTOU: safe_read() canonicalises, then open()s with O_NOFOLLOW and fstat()s");
        INFO("the descriptor; no stat/access on the name precedes the open.");
    }

    (void)toctou_insecure_pattern; /* referenced in every mode (silences -Wunused) */
    sandbox_cleanup(&sb);
    INFO("sandbox removed.");
    return rc;
}

const vuln_example ex08_example = {
    "path-traversal",
    "Path traversal and TOCTOU file races (CWE-22/CWE-59/CWE-367)",
    run
};
