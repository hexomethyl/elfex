/* GNU indirect functions: STT_GNU_IFUNC symbols and R_X86_64_IRELATIVE
 * relocations resolved by a function call at load time. */

#include <stdlib.h>

static int impl_generic(void) { return 1; }
static int impl_fast(void) { return 2; }

/* The resolver runs during relocation processing and picks an implementation.
 * Reading the environment keeps both implementations live. */
static void *resolve_pick(void) {
    return getenv("ELFEX_GENERIC") != NULL ? (void *) &impl_generic : (void *) &impl_fast;
}

int picked(void) __attribute__((ifunc("resolve_pick")));

int main(void) { return picked() > 0 ? 0 : 1; }
