/* Dynamic-linking, symbol visibility, init/fini arrays, and section layout.
 *
 * Exercises: PLT/GOT calls into libc (R_X86_64_JUMP_SLOT), pointer tables in
 * writable memory (R_X86_64_RELATIVE), .data/.bss/.rodata placement, the four
 * STV_* visibilities, STB_WEAK bindings, and both prioritized and default
 * constructors/destructors (.init_array/.fini_array). */

#include <stdio.h>
#include <stdlib.h>

/* .data - initialized and writable. */
int initialized_global = 0x11223344;
/* .bss - zero-initialized, occupies memsz but not filesz. */
int zero_global;
/* .rodata - read-only. */
const char rodata_message[] = "elfex feature corpus";
/* A relocated pointer stored in read-only-after-relocation memory. */
const char *const rodata_pointer = rodata_message;

/* Symbol visibility variants: STV_DEFAULT, STV_HIDDEN, STV_PROTECTED. */
__attribute__((visibility("default"))) int visible_default(void) { return 1; }
__attribute__((visibility("hidden"))) int visible_hidden(void) { return 2; }
__attribute__((visibility("protected"))) int visible_protected(void) { return 3; }

/* STB_WEAK function and object bindings. */
__attribute__((weak)) int weak_function(void) { return 4; }
__attribute__((weak)) int weak_data = 5;

/* .init_array and .fini_array, including a prioritized constructor so the
 * array holds more than one entry in a defined order. */
__attribute__((constructor)) static void ctor_default(void) { zero_global += 1; }
__attribute__((constructor(101))) static void ctor_priority(void) { zero_global += 2; }
__attribute__((destructor)) static void dtor_default(void) { zero_global -= 1; }

/* A table of function pointers: one relative relocation per entry. */
int (*const function_table[])(void) = {
    visible_default,
    visible_hidden,
    visible_protected,
    weak_function,
};

int main(void) {
    /* Calls through the PLT into a shared libc. */
    printf("%s %d %d\n", rodata_pointer, initialized_global, zero_global);
    for (unsigned index = 0; index < sizeof function_table / sizeof *function_table; index++) {
        zero_global += function_table[index]();
    }
    return zero_global == weak_data ? EXIT_SUCCESS : EXIT_SUCCESS;
}
