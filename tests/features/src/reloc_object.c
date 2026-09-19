/* Relocation variety inside an unlinked object (ET_REL).
 *
 * An unlinked object keeps its section-based relocation tables, which are the
 * richest source of relocation types: PC-relative calls, GOT-relative data
 * access, and absolute 64-bit pointer slots. Compiled for both x86-64 (RELA,
 * explicit addends) and i386 (REL, implicit addends). */

extern int external_symbol;
extern int external_function(int value);

int local_data = 1;
static int static_data = 2;
const char literal[] = "reloc";

/* Absolute pointer slots needing full-width relocations. */
int *const data_pointer = &local_data;
int (*const func_pointer)(int) = external_function;

int use_everything(int value) {
    /* PC-relative call to an undefined symbol. */
    int called = external_function(value);
    /* Data access mixing an undefined global with local and static storage. */
    int summed = external_symbol + local_data + static_data;
    return called + summed + (int) literal[0] + *data_pointer + func_pointer(value);
}
