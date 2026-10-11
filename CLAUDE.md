# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

An educational C project: ten deliberately vulnerable demos of common C security mistakes, each in its own heavily commented file (what / how exploited / how to avoid / best practices + CWE & CERT refs). The vulnerable code is intentional — do not "fix" it in `vuln`/`exploit` paths; the hardened version lives alongside it for `fixed` mode.

## Build and run

CMake, portable to Linux (gcc/clang) and Windows (MSVC). There is no test suite; verification is running the binary.

```sh
cmake -B build && cmake --build build
build/cvulns list                      # numbers and ids
build/cvulns 4 exploit                 # one example, one mode (number or id)
build/cvulns all                       # everything; must exit 0
```

Modes: `vuln` (benign input), `exploit` (malicious input vs vulnerable code), `fixed` (same input vs hardened code), `all` (default).

On Windows with Build Tools, load the compiler first (`vcvars64.bat`) and pass `-G Ninja`. `-DCVULNS_SANITIZE=ON` adds ASan+UBSan on gcc/clang (needs a glibc toolchain; Alpine/musl gcc lacks the runtimes).

## Architecture

- `include/cvulns.h` defines the contract: `vuln_example { id, title, run(vuln_mode) }`, the `INFO/GOOD/BAD/SECTION` output macros, and `extern` declarations for `ex01_example`…`ex10_example`.
- `src/main.c` has a hard-coded table of the ten descriptors and dispatches by number/id/mode. **Adding an example means editing three places**: new `src/exNN_*.c` (CMake globs `src/ex*.c`), the extern in `cvulns.h`, and the table in `main.c`.
- Each `src/exNN_<name>.c` is self-contained: a large header comment, a vulnerable function, a fixed function, and a `static int run(vuln_mode)` exported through its descriptor.
- `CMakeLists.txt` deliberately **disables hardening** (`-fno-stack-protector`, `-D_FORTIFY_SOURCE=0`, `/GS-`) and suppresses related warnings so the bugs behave like the textbook versions. Don't "improve" these flags.

## Conventions that matter

- Demos must be **safe and deterministic**: corrupt only demo-owned memory (victim data placed in the same struct, sized via `offsetof`), use a model allocator for heap bugs (ex04, ex05) rather than real UB, sandbox files under the temp dir (ex08), and run only `echo` (ex07). Payload sizes must leave the NUL terminator inside the owned object — ex01 aborted under MSVC `/RTC1` when it spilled one byte.
- Exploit detail is intentionally limited for ex04 (no function-pointer hijack), ex06 (no Heartbleed-style over-read) and ex09 (no seed search/prediction); keep it that way.
- `CMAKE_C_EXTENSIONS` is OFF (strict C11), so POSIX APIs need a feature-test macro before any include, inside `#ifndef _WIN32`: ex07/ex09 use `_POSIX_C_SOURCE 200809L`; ex08 needs `_XOPEN_SOURCE 700` for `realpath` (without it the pointer return is truncated to `int` and crashes on 64-bit).
- Platform branches use `#ifdef _WIN32` (ex07 spawn, ex08 paths/symlinks, ex09 `BCryptGenRandom`; CMake links `bcrypt` on Windows). ex02 skips the `%n` demo on MSVC.
- Print `size_t` via casts with `%lu`/`%llu` in code meant for old MSVC (newer files use `%zu`, which MSVC 2015+ accepts).
- Both platforms must build warning-free and `cvulns all` must exit 0 on each; changes to an example should be run in all three modes.
