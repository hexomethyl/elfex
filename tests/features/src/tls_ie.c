/* Initial-exec thread-local storage inside a shared object.
 *
 * The initial-exec model resolves the thread pointer offset at load time
 * rather than through __tls_get_addr, so the dynamic relocation is
 * R_X86_64_TPOFF64 (R_386_TLS_TPOFF) instead of the general-dynamic
 * DTPMOD64/DTPOFF64 pair. */

__attribute__((tls_model("initial-exec"))) __thread int ie_counter = 3;
__attribute__((tls_model("initial-exec"))) __thread long ie_wide[4];

int ie_bump(void) {
    ie_counter += 1;
    ie_wide[0] += ie_counter;
    return (int) ie_wide[0];
}
