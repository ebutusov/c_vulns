/*
 * cvulns.h - shared interface for all vulnerability examples.
 *
 * Every example lives in src/exNN_<name>.c and exports ONE descriptor
 * (`const vuln_example exNN_example`). main.c lists them in a table.
 *
 * Run modes (second CLI argument):
 *   vuln    - run the vulnerable code with BENIGN input (shows normal behaviour)
 *   exploit - run the vulnerable code with a malicious input, in a SAFE,
 *             self-contained way (corrupts only memory/files the demo owns
 *             and prints what happened). Default mode.
 *   fixed   - run the hardened version with the same malicious input.
 *   all     - run vuln, exploit, fixed in sequence.
 *
 * Rules for example authors:
 *  - Demos must be deterministic and must NOT crash the process in
 *    `exploit` mode where avoidable: place the victim data (e.g. an
 *    `is_admin` flag, a function pointer, a secret) inside a struct the demo
 *    owns, so corruption is observable but contained.
 *  - Never touch real user files, the network, or run destructive commands.
 *    Use harmless payloads (e.g. `echo`, files in a temp sandbox directory).
 *  - Portable C11 for Linux (gcc/clang) and Windows (MSVC/MinGW). Wrap
 *    platform-specific code in #ifdef _WIN32.
 *  - A `return` value of 0 means the demo itself ran OK.
 */
#ifndef CVULNS_H
#define CVULNS_H

#include <stdio.h>

typedef enum { MODE_VULN, MODE_EXPLOIT, MODE_FIXED } vuln_mode;

typedef struct {
    const char *id;       /* CLI name, e.g. "stack-overflow" */
    const char *title;    /* human title incl. CWE, e.g. "Stack buffer overflow (CWE-121)" */
    int (*run)(vuln_mode mode);
} vuln_example;

/* Small helpers so output of all examples looks uniform. */
#define SECTION(s) printf("\n=== %s ===\n", (s))
#define INFO(...)  do { printf("[*] "); printf(__VA_ARGS__); printf("\n"); } while (0)
#define GOOD(...)  do { printf("[+] "); printf(__VA_ARGS__); printf("\n"); } while (0)
#define BAD(...)   do { printf("[!] "); printf(__VA_ARGS__); printf("\n"); } while (0)

extern const vuln_example ex01_example;
extern const vuln_example ex02_example;
extern const vuln_example ex03_example;
extern const vuln_example ex04_example;
extern const vuln_example ex05_example;
extern const vuln_example ex06_example;
extern const vuln_example ex07_example;
extern const vuln_example ex08_example;
extern const vuln_example ex09_example;
extern const vuln_example ex10_example;

#endif
