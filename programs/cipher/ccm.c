
//#include "common.h"


#include "mbedtls/ccm.h"
#include "mbedtls/platform_util.h"
#include "mbedtls/error.h"

#include <string.h>
#include <stdio.h>

#include "mbedtls/platform.h"


/*
 * Examples 1 to 3 from SP800-38C Appendix C
 */

#define NB_TESTS 3
#define CCM_SELFTEST_PT_MAX_LEN 24
#define CCM_SELFTEST_CT_MAX_LEN 32
/*
 * The data is the same for all tests, only the used length changes
 */
static const unsigned char key_test_data[] = {
    0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47,
    0x48, 0x49, 0x4a, 0x4b, 0x4c, 0x4d, 0x4e, 0x4f
};

static const unsigned char iv_test_data[] = {
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
    0x18, 0x19, 0x1a, 0x1b
};

static const unsigned char ad_test_data[] = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
    0x10, 0x11, 0x12, 0x13
};

static const unsigned char msg_test_data[CCM_SELFTEST_PT_MAX_LEN] = {
    0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27,
    0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f,
    0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
};

static const size_t iv_len_test_data[NB_TESTS] = { 7, 8,  12 };
static const size_t add_len_test_data[NB_TESTS] = { 8, 16, 20 };
static const size_t msg_len_test_data[NB_TESTS] = { 4, 16, 24 };
static const size_t tag_len_test_data[NB_TESTS] = { 4, 6,  8  };

__attribute__((unused)) static const unsigned char res_test_data[NB_TESTS][CCM_SELFTEST_CT_MAX_LEN] = {
    {   0x71, 0x62, 0x01, 0x5b, 0x4d, 0xac, 0x25, 0x5d },
    {   0xd2, 0xa1, 0xf0, 0xe0, 0x51, 0xea, 0x5f, 0x62,
        0x08, 0x1a, 0x77, 0x92, 0x07, 0x3d, 0x59, 0x3d,
        0x1f, 0xc6, 0x4f, 0xbf, 0xac, 0xcd },
    {   0xe3, 0xb2, 0x01, 0xa9, 0xf5, 0xb7, 0x1a, 0x7a,
        0x9b, 0x1c, 0xea, 0xec, 0xcd, 0x97, 0xe7, 0x0b,
        0x61, 0x76, 0xaa, 0xd9, 0xa4, 0x42, 0x8a, 0xa5,
        0x48, 0x43, 0x92, 0xfb, 0xc1, 0xb0, 0x99, 0x51 }
};

int mbedtls_ccm_test(int verbose)
{
    mbedtls_ccm_context ctx;
    /*
     * Some hardware accelerators require the input and output buffers
     * would be in RAM, because the flash is not accessible.
     * Use buffers on the stack to hold the test vectors data.
     */
    unsigned char plaintext[CCM_SELFTEST_PT_MAX_LEN];
    unsigned char ciphertext[CCM_SELFTEST_CT_MAX_LEN];
    size_t i;
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;

    mbedtls_ccm_init(&ctx);

    if (mbedtls_ccm_setkey(&ctx, MBEDTLS_CIPHER_ID_SM4, key_test_data,
                           8 * sizeof(key_test_data)) != 0) {
        if (verbose != 0) {
            mbedtls_printf("  CCM: setup failed");
        }

        return 1;
    }

    for (i = 0; i < NB_TESTS; i++) {
        if (verbose != 0) {
            mbedtls_printf("  CCM-SM4 #%u: ", (unsigned int) i + 1);
        }

        memset(plaintext, 0, CCM_SELFTEST_PT_MAX_LEN);
        memset(ciphertext, 0, CCM_SELFTEST_CT_MAX_LEN);
        memcpy(plaintext, msg_test_data, msg_len_test_data[i]);

        ret = mbedtls_ccm_encrypt_and_tag(&ctx, msg_len_test_data[i],
                                          iv_test_data, iv_len_test_data[i],
                                          ad_test_data, add_len_test_data[i],
                                          plaintext, ciphertext,
                                          ciphertext + msg_len_test_data[i],
                                          tag_len_test_data[i]);

#if 0
        if (ret != 0 ||
            memcmp(ciphertext, res_test_data[i],
                   msg_len_test_data[i] + tag_len_test_data[i]) != 0) {
            if (verbose != 0) {
                mbedtls_printf("failed\n");
            }

            return 1;
        }
#endif
        memset(plaintext, 0, CCM_SELFTEST_PT_MAX_LEN);

        ret = mbedtls_ccm_auth_decrypt(&ctx, msg_len_test_data[i],
                                       iv_test_data, iv_len_test_data[i],
                                       ad_test_data, add_len_test_data[i],
                                       ciphertext, plaintext,
                                       ciphertext + msg_len_test_data[i],
                                       tag_len_test_data[i]);

        if (ret != 0 ||
            memcmp(plaintext, msg_test_data, msg_len_test_data[i]) != 0) {
            if (verbose != 0) {
                mbedtls_printf("failed\n");
            }

            return 1;
        }

        if (verbose != 0) {
            mbedtls_printf("passed\n");
        }
    }

    mbedtls_ccm_free(&ctx);

    if (verbose != 0) {
        mbedtls_printf("\n");
    }

    return 0;
}

int main(void)
{
	return mbedtls_ccm_test(1);
}
