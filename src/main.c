/* main.c - CLI dispatcher for the "10 common C security mistakes" demo. */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "cvulns.h"

static const vuln_example *const examples[] = {
    &ex01_example, &ex02_example, &ex03_example, &ex04_example, &ex05_example,
    &ex06_example, &ex07_example, &ex08_example, &ex09_example, &ex10_example,
};
#define N_EXAMPLES (sizeof examples / sizeof examples[0])

static void usage(const char *prog) {
    printf("Usage: %s <list | all | N | id> [vuln|exploit|fixed|all]\n\n", prog);
    printf("  list      show the available examples\n");
    printf("  N | id    run example by number (1-%zu) or id; default mode: all\n", N_EXAMPLES);
    printf("  all       run every example (mode defaults to all)\n\n");
    printf("Modes: vuln=benign input, exploit=malicious input vs vulnerable code,\n");
    printf("       fixed=malicious input vs hardened code, all=the three in order.\n\n");
    for (size_t i = 0; i < N_EXAMPLES; i++)
        printf("  %2zu  %-18s %s\n", i + 1, examples[i]->id, examples[i]->title);
}

static const vuln_example *find(const char *key) {
    char *end;
    long n = strtol(key, &end, 10);
    if (*key && *end == '\0' && n >= 1 && (size_t)n <= N_EXAMPLES) return examples[n - 1];
    for (size_t i = 0; i < N_EXAMPLES; i++)
        if (strcmp(key, examples[i]->id) == 0) return examples[i];
    return NULL;
}

static int run_one(const vuln_example *e, const char *mode) {
    static const vuln_mode all[] = { MODE_VULN, MODE_EXPLOIT, MODE_FIXED };
    static const char *names[] = { "vuln", "exploit", "fixed" };
    int rc = 0;
    printf("\n################ %s ################\n", e->title);
    for (int i = 0; i < 3; i++) {
        if (strcmp(mode, "all") != 0 && strcmp(mode, names[i]) != 0) continue;
        printf("\n---- mode: %s ----\n", names[i]);
        fflush(stdout);
        rc |= e->run(all[i]);
        fflush(stdout);
    }
    return rc;
}

int main(int argc, char **argv) {
    if (argc < 2 || strcmp(argv[1], "list") == 0 || strcmp(argv[1], "-h") == 0
        || strcmp(argv[1], "--help") == 0) {
        usage(argv[0]);
        return argc < 2 ? 1 : 0;
    }
    const char *mode = argc > 2 ? argv[2] : "all";
    if (strcmp(mode, "vuln") && strcmp(mode, "exploit") && strcmp(mode, "fixed") && strcmp(mode, "all")) {
        fprintf(stderr, "Unknown mode '%s'\n", mode);
        return 2;
    }
    if (strcmp(argv[1], "all") == 0) {
        int rc = 0;
        for (size_t i = 0; i < N_EXAMPLES; i++) rc |= run_one(examples[i], mode);
        return rc;
    }
    const vuln_example *e = find(argv[1]);
    if (!e) { fprintf(stderr, "Unknown example '%s'\n\n", argv[1]); usage(argv[0]); return 2; }
    return run_one(e, mode);
}
