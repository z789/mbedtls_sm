
#include "mbedtls/build_info.h"

#include "psa/crypto.h"

#include "mbedtls/platform_util.h" // for mbedtls_platform_zeroize

#include <stdlib.h>
#include <stdio.h>

/* Print the contents of a buffer in hex */
static void print_buf(const char *title, uint8_t *buf, size_t len)
{
    printf("%s:", title);
    for (size_t i = 0; i < len; i++) {
        printf("%02x", buf[i]);
    }
    printf("\n");
}

int main(void)
{
    psa_status_t status;
    psa_algorithm_t alg = PSA_ALG_SM3;
    psa_hash_operation_t operation = PSA_HASH_OPERATION_INIT;
    unsigned char input[] = { 'a', 'b', 'c' };
    unsigned char actual_hash[PSA_HASH_MAX_SIZE];
    size_t actual_hash_len;

    printf("Hash a message...\t");
    print_buf("msg:", input, sizeof(input));
    fflush(stdout);

    /* Initialize PSA Crypto */
    status = psa_crypto_init();
    if (status != PSA_SUCCESS) {
        printf("Failed to initialize PSA Crypto\n");
        return -1;
    }

    /* Compute hash of message  */
    status = psa_hash_setup(&operation, alg);
    if (status != PSA_SUCCESS) {
        printf("Failed to begin hash operation\n");
        return -1;
    }
    status = psa_hash_update(&operation, input, sizeof(input));
    if (status != PSA_SUCCESS) {
        printf("Failed to update hash operation\n");
        return -1;
    }
    status = psa_hash_finish(&operation, actual_hash, sizeof(actual_hash),
                             &actual_hash_len);
    if (status != PSA_SUCCESS) {
        printf("Failed to finish hash operation\n");
        return -1;
    }
    print_buf("digest:", actual_hash, actual_hash_len);

    printf("Hashed a message\n");

    /* Clean up hash operation context */
    psa_hash_abort(&operation);

    mbedtls_psa_crypto_free();
    return 0;
}
