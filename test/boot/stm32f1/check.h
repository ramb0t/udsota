/* Minimal assert harness for the host tests: each test file is one executable. */
#ifndef CHECK_H
#define CHECK_H

#include <inttypes.h>
#include <stdio.h>

static int check_failures;

#define CHECK(cond)                                                                                \
    do {                                                                                           \
        if (!(cond)) {                                                                             \
            fprintf(stderr, "%s:%d: CHECK(%s) failed\n", __FILE__, __LINE__, #cond);               \
            check_failures++;                                                                      \
        }                                                                                          \
    } while (0)

#define CHECK_EQ_U32(actual, expected)                                                             \
    do {                                                                                           \
        uint32_t a_ = (uint32_t)(actual);                                                          \
        uint32_t e_ = (uint32_t)(expected);                                                        \
        if (a_ != e_) {                                                                            \
            fprintf(stderr, "%s:%d: %s = 0x%08" PRIX32 ", expected 0x%08" PRIX32 "\n", __FILE__,   \
                    __LINE__, #actual, a_, e_);                                                    \
            check_failures++;                                                                      \
        }                                                                                          \
    } while (0)

#define CHECK_DONE()                                                                               \
    do {                                                                                           \
        if (check_failures != 0) {                                                                 \
            fprintf(stderr, "%d check(s) failed\n", check_failures);                              \
            return 1;                                                                              \
        }                                                                                          \
        printf("all checks passed\n");                                                             \
        return 0;                                                                                  \
    } while (0)

#endif /* CHECK_H */
