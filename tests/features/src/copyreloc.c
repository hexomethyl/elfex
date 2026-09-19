/* Copy relocations.
 *
 * A non-PIE executable that reads exported *data* from a shared object gets a
 * private copy of that object in .bss plus an R_X86_64_COPY (R_386_COPY)
 * relocation telling the loader to initialize it. Linked against
 * libfeature.so. */

#include <stdio.h>

extern int feature_counter;  /* exported data in libfeature.so */
extern int feature_common(void);

int main(void) {
    printf("%d %d\n", feature_counter, feature_common());
    return 0;
}
