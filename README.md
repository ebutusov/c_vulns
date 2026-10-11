# cvulns — 10 common C mistakes that become security vulnerabilities

An educational project. Each example is a single, heavily commented C file that explains
**what** the mistake is, **how** it is exploited (with sample exploit input/code), and
**how to avoid** it, with best practices and CWE / CERT C references.

> Every demo is self-contained and safe: it corrupts only memory the demo owns,
> works in a temp sandbox directory, and only runs harmless commands (`echo`).
> The code is *deliberately vulnerable* — never copy the "vulnerable" functions into real projects.

## Examples

| # | id                  | Topic                                              | File |
|---|---------------------|----------------------------------------------------|------|
| 1 | `stack-overflow`    | Stack buffer overflow (CWE-121)                    | `src/ex01_stack_overflow.c` |
| 2 | `format-string`     | Uncontrolled format string (CWE-134)               | `src/ex02_format_string.c` |
| 3 | `integer-overflow`  | Integer overflow / signedness → heap overflow (CWE-190) | `src/ex03_integer_overflow.c` |
| 4 | `use-after-free`    | Use after free (CWE-416)                           | `src/ex04_use_after_free.c` |
| 5 | `double-free`       | Double free / error-path memory bugs (CWE-415)     | `src/ex05_double_free.c` |
| 6 | `info-leak`         | Uninitialized memory, padding, over-read (CWE-200/457) | `src/ex06_info_leak.c` |
| 7 | `command-injection` | OS command injection (CWE-78)                      | `src/ex07_command_injection.c` |
| 8 | `path-traversal`    | Path traversal & TOCTOU (CWE-22/367)               | `src/ex08_path_traversal.c` |
| 9 | `weak-random`       | Predictable randomness, hard-coded secrets (CWE-338/798) | `src/ex09_weak_random.c` |
| 10 | `off-by-one`       | Off-by-one, missing NUL, strncpy misuse (CWE-193/170) | `src/ex10_off_by_one.c` |

## Build (Linux, macOS, Windows)

```sh
cmake -B build
cmake --build build            # add --config Release with Visual Studio generators
```

With Visual Studio Build Tools, run the same commands from an
"x64 Native Tools Command Prompt" (or after `vcvars64.bat`); add `-G Ninja` for a
single-config build. Tested with MSVC 19.5 on Windows 11.

Optional sanitizer build (gcc/clang) that *detects* the bugs:

```sh
cmake -B build-asan -DCVULNS_SANITIZE=ON && cmake --build build-asan
```

## Run

```sh
cvulns list                     # show examples
cvulns 1                        # example by number, all three modes
cvulns stack-overflow exploit   # one mode: vuln | exploit | fixed | all
cvulns all                      # everything
```

Modes: `vuln` = benign input; `exploit` = malicious input against the vulnerable code;
`fixed` = the same malicious input against the hardened code.

On Windows with Visual Studio generators the binary is `build\Debug\cvulns.exe`
(or `Release`).

## Compiler flags

The CMake file turns **off** hardening (stack protector, FORTIFY_SOURCE, `/GS`) so the
bugs behave like the textbook versions. Real projects should do the opposite:
`-fstack-protector-strong -D_FORTIFY_SOURCE=2 -Wformat-security -fPIE -pie -Wl,-z,relro,-z,now`
(gcc/clang) or `/GS /guard:cf /sdl` (MSVC), plus ASan/UBSan in CI and fuzzing.

## Other classic mistakes (not covered)

Race conditions beyond TOCTOU, unchecked return values, `memcpy` with overlapping
buffers, missing `NULL` checks, and uncontrolled recursion.
