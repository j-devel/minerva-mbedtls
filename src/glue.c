#include <stdio.h>

#include "mbedtls/pk.h"
#include "mbedtls/ecp.h"
#include "mbedtls/x509_crt.h"

#include "test/random.h"

extern mbedtls_pk_context * glue_get_pk_of(mbedtls_x509_crt *crt) {
#ifdef MINERVA_MBEDTLS_GLUE_V3
    // https://github.com/ARMmbed/mbedtls/blob/development/docs/3.0-migration-guide.md#most-structure-fields-are-now-private
    return &crt->MBEDTLS_PRIVATE(pk);
#else
    return &crt->pk;
#endif
}

extern size_t glue_sizeof_int() { return sizeof(int); }

extern size_t glue_sizeof_mbedtls_pk_context() { return sizeof(mbedtls_pk_context); }
extern size_t glue_sizeof_mbedtls_ecp_keypair() { return sizeof(mbedtls_ecp_keypair); }
extern size_t glue_sizeof_mbedtls_ecp_group() { return sizeof(mbedtls_ecp_group); }
extern size_t glue_sizeof_mbedtls_ecp_point() { return sizeof(mbedtls_ecp_point); }
extern size_t glue_sizeof_mbedtls_mpi() { return sizeof(mbedtls_mpi); }

extern size_t glue_sizeof_mbedtls_x509_crt() { return sizeof(mbedtls_x509_crt); }
extern size_t glue_sizeof_mbedtls_x509_buf() { return sizeof(mbedtls_x509_buf); }
extern size_t glue_sizeof_mbedtls_x509_name() { return sizeof(mbedtls_x509_name); }
extern size_t glue_sizeof_mbedtls_x509_time() { return sizeof(mbedtls_x509_time); }

extern void glue_debug_sizeof(void) {
    printf("glue_debug_sizeof(): ^^\n");

    printf("sizeof(int): %zu\n", glue_sizeof_int());

    printf("sizeof(mbedtls_pk_context): %zu\n", glue_sizeof_mbedtls_pk_context());
    printf("sizeof(mbedtls_ecp_keypair): %zu\n", glue_sizeof_mbedtls_ecp_keypair());
    printf("  sizeof(mbedtls_ecp_group): %zu\n", glue_sizeof_mbedtls_ecp_group());
    printf("  sizeof(mbedtls_mpi): %zu\n", glue_sizeof_mbedtls_mpi());
    printf("  sizeof(mbedtls_ecp_point): %zu\n", glue_sizeof_mbedtls_ecp_point());

    printf("sizeof(mbedtls_x509_crt): %zu\n", glue_sizeof_mbedtls_x509_crt());
    printf("  sizeof(mbedtls_x509_buf): %zu\n", glue_sizeof_mbedtls_x509_buf());
    printf("  sizeof(mbedtls_x509_name): %zu\n", glue_sizeof_mbedtls_x509_name());
    printf("  sizeof(mbedtls_x509_time): %zu\n", glue_sizeof_mbedtls_x509_time());
}

extern void * glue_test_f_rng_ptr() {
    return (void *)mbedtls_test_rnd_std_rand;
}