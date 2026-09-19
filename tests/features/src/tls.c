/* Thread-local storage: .tdata, .tbss, PT_TLS, and the TLS access models.
 *
 * Compiled both as an executable (where the linker relaxes most accesses to
 * local-exec) and as an unlinked object, which retains the unrelaxed
 * general-dynamic TLS relocations. */

#include <stdio.h>

/* .tdata - initialized thread-local storage. */
__thread int tls_initialized = 0x55667788;
/* .tbss - zero-initialized thread-local storage. */
__thread int tls_zero;
/* A larger, more strictly aligned TLS object so PT_TLS has a non-trivial
 * memsz and p_align. */
__thread double tls_aligned[8] = {1.0, 2.0};

/* Explicit TLS access models. */
__attribute__((tls_model("initial-exec"))) __thread int tls_initial_exec = 7;
__attribute__((tls_model("global-dynamic"))) __thread int tls_global_dynamic = 9;

int tls_sum(void) {
    tls_zero += 1;
    return tls_initialized + tls_zero + tls_initial_exec + tls_global_dynamic + (int) tls_aligned[0];
}

int main(void) {
    printf("%d\n", tls_sum());
    return 0;
}
