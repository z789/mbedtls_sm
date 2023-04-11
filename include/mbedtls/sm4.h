#ifndef MBEDTLS_SM4_H
#define MBEDTLS_SM4_H
#include "mbedtls/private_access.h"

#include "mbedtls/build_info.h"

#include <stddef.h>
#include <stdint.h>

#include "mbedtls/platform_util.h"

#define MBEDTLS_SM4_ENCRYPT     1 /**< SM4 encryption. */
#define MBEDTLS_SM4_DECRYPT     0 /**< SM4 decryption. */

/** Bad input data. */
#define MBEDTLS_ERR_SM4_BAD_INPUT_DATA -0x008C

/** Invalid data input length. */
#define MBEDTLS_ERR_SM4_INVALID_INPUT_LENGTH -0x008E

#define MBEDTLS_SM4_KEYSIZE		16
#define MBEDTLS_SM4_BLOCKSIZE		16
#define MBEDTLS_SM4_NUM_ROUNDS		32

#ifdef __cplusplus
extern "C" {
#endif

#if !defined(MBEDTLS_SM4_ALT)
// Regular implementation
//

typedef struct mbedtls_sm4_context {
	uint32_t MBEDTLS_PRIVATE(ekey)[MBEDTLS_SM4_NUM_ROUNDS];
	uint32_t MBEDTLS_PRIVATE(dkey)[MBEDTLS_SM4_NUM_ROUNDS];
}
mbedtls_sm4_context;

#else  /* MBEDTLS_SM4_ALT */
#include "sm4_alt.h"
#endif /* MBEDTLS_SM4_ALT */

void mbedtls_sm4_init(mbedtls_sm4_context *ctx);
void mbedtls_sm4_free(mbedtls_sm4_context *ctx);

int mbedtls_sm4_setkey_enc(mbedtls_sm4_context *ctx,
                            const unsigned char *key,
                            unsigned int keybits);
int mbedtls_sm4_setkey_dec(mbedtls_sm4_context *ctx,
                            const unsigned char *key,
                            unsigned int keybits);

int mbedtls_sm4_crypt_ecb(mbedtls_sm4_context *ctx,
                           int mode,
                           const unsigned char input[MBEDTLS_SM4_BLOCKSIZE],
                           unsigned char output[MBEDTLS_SM4_BLOCKSIZE]);

#if defined(MBEDTLS_CIPHER_MODE_CBC)
int mbedtls_sm4_crypt_cbc(mbedtls_sm4_context *ctx,
                           int mode,
                           size_t length,
                           unsigned char iv[MBEDTLS_SM4_BLOCKSIZE],
                           const unsigned char *input,
                           unsigned char *output);
#endif /* MBEDTLS_CIPHER_MODE_CBC */

#if defined(MBEDTLS_CIPHER_MODE_CFB)
int mbedtls_sm4_crypt_cfb128(mbedtls_sm4_context *ctx,
                              int mode,
                              size_t length,
                              size_t *iv_off,
                              unsigned char iv[MBEDTLS_SM4_BLOCKSIZE],
                              const unsigned char *input,
                              unsigned char *output);
#endif /* MBEDTLS_CIPHER_MODE_CFB */

#if defined(MBEDTLS_CIPHER_MODE_CTR)
int mbedtls_sm4_crypt_ctr(mbedtls_sm4_context *ctx,
                           size_t length,
                           size_t *nc_off,
                           unsigned char nonce_counter[MBEDTLS_SM4_BLOCKSIZE],
                           unsigned char stream_block[MBEDTLS_SM4_BLOCKSIZE],
                           const unsigned char *input,
                           unsigned char *output);
#endif /* MBEDTLS_CIPHER_MODE_CTR */

#if defined(MBEDTLS_SELF_TEST)
int mbedtls_sm4_self_test(int verbose);
#endif /* MBEDTLS_SELF_TEST */

#ifdef __cplusplus
}
#endif

#endif
