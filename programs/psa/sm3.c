
#include "mbedtls/build_info.h"

#include "psa/crypto.h"

#include "mbedtls/platform_util.h" // for mbedtls_platform_zeroize

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

/*
 * http://www.gmbz.org.cn/upload/2018-07-24/1532401392982079739.pdf 
 * Annex A example 
*/

/* "abc" */
static unsigned char msg1[] = {0x61, 0x62, 0x63};                   
static unsigned char degest_msg1[] = {0x66, 0xc7, 0xf0, 0xf4, 0x62, 0xee, 0xed, 0xd9, 0xd1, 0xf2, 0xd4, 0x6b, 0xdc, 0x10, 0xe4, 0xe2,
                               0x41, 0x67, 0xc4, 0x87, 0x5c, 0xf2, 0xf7, 0xa2, 0x29, 0x7d, 0xa0, 0x2b, 0x8f, 0x4b, 0xa8, 0xe0};

/* "abcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcd" */
static unsigned char msg2[] = {0x61, 0x62, 0x63, 0x64, 0x61, 0x62, 0x63, 0x64, 0x61, 0x62, 0x63, 0x64, 0x61, 0x62, 0x63, 0x64,
                        0x61, 0x62, 0x63, 0x64, 0x61, 0x62, 0x63, 0x64, 0x61, 0x62, 0x63, 0x64, 0x61, 0x62, 0x63, 0x64,
                        0x61, 0x62, 0x63, 0x64, 0x61, 0x62, 0x63, 0x64, 0x61, 0x62, 0x63, 0x64, 0x61, 0x62, 0x63, 0x64,
                        0x61, 0x62, 0x63, 0x64, 0x61, 0x62, 0x63, 0x64, 0x61, 0x62, 0x63, 0x64, 0x61, 0x62, 0x63, 0x64};                   
static unsigned char degest_msg2[] = {0xde, 0xbe, 0x9f, 0xf9, 0x22, 0x75, 0xb8, 0xa1, 0x38, 0x60, 0x48, 0x89, 0xc1, 0x8e, 0x5a, 0x4d,
                               0x6f, 0xdb, 0x70, 0xe5, 0x38, 0x7e, 0x57, 0x65, 0x29, 0x3d, 0xcb, 0xa3, 0x9c, 0x0c, 0x57, 0x32};

/* Print the contents of a buffer in hex */
static void print_buf(const char *title, unsigned char *buf, size_t len)
{
    printf("%s", title);
    for (size_t i = 0; i < len; i++) {
        printf("%02x", buf[i]);
    }
    printf("\n");
}

static int test_hash(uint8_t  *input, size_t input_len, unsigned char *degest, size_t degest_len)
{
    psa_status_t status;
    psa_algorithm_t alg = PSA_ALG_SM3;
    psa_hash_operation_t operation = PSA_HASH_OPERATION_INIT;
    unsigned char actual_hash[PSA_HASH_MAX_SIZE] = {0};
    size_t actual_hash_len;

    printf("Hash a message...\n");
    print_buf("msg:",  input, input_len);
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
    status = psa_hash_update(&operation, input, input_len);
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

    if (actual_hash_len == degest_len) {
	if (memcmp(degest, actual_hash, actual_hash_len)) {
	    printf("Hashed Fail\n");
        } else {
	    printf("Hashed Succ\n");
        }
    } else {
        printf("Inval param\n");
    }

    /* Clean up hash operation context */
    psa_hash_abort(&operation);

    mbedtls_psa_crypto_free();
    return 0;
}

int main(void)
{
	test_hash(msg1, sizeof(msg1), degest_msg1, sizeof(degest_msg1));
	test_hash(msg2, sizeof(msg2), degest_msg2, sizeof(degest_msg2));
	return 0;
}
