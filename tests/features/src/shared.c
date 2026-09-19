/* Shared-object features: exported and hidden symbols, symbol versioning,
 * DT_SONAME, position-independent data relocations, a shared-object
 * constructor, and general-dynamic thread-local storage.
 *
 * Linked with `libfeature.map` so the dynamic symbol table carries two version
 * definitions and everything unlisted is localized. */

/* Exported, versioned entry points. */
int feature_v1(void) { return 1; }
int feature_v2(void) { return 2; }

/* Exported data. External references produce a global-data relocation. */
int feature_counter = 0x99;

/* Internal linkage: present in .symtab, absent from .dynsym. */
__attribute__((visibility("hidden"))) int feature_internal(void) { return 3; }

int feature_common(void) {
    feature_counter += feature_internal();
    return feature_v1() + feature_v2() + feature_counter;
}

/* Thread-local storage in a shared object keeps the general-dynamic model,
 * which the linker cannot relax to local-exec. */
__thread int feature_tls = 0x11;

int feature_tls_get(void) {
    feature_tls += 1;
    return feature_tls;
}

/* A constructor inside a shared object populates its own .init_array. */
__attribute__((constructor)) static void so_ctor(void) { feature_counter += 1; }
