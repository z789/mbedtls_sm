#ifndef MBEDTLS_SM3_H
#define MBEDTLS_SM3_H

#include "mbedtls/private_access.h"
#include "mbedtls/build_info.h"

#include <stddef.h>
#include <stdint.h>
#include <unistd.h>

/** Bad input data. */
#define MBEDTLS_ERR_SM3_BAD_INPUT_DATA -0x009C

/** Invalid data input length. */
#define MBEDTLS_ERR_SM3_INVALID_INPUT_LENGTH -0x009E

#define SM3_DIGEST_SIZE		32
#define SM3_BLOCK_SIZE		64
#define SM3_CBLOCK		(SM3_BLOCK_SIZE)
#define SM3_HMAC_SIZE		(SM3_DIGEST_SIZE)

#ifdef __cplusplus
extern "C" {
#endif

#if !defined(MBEDTLS_SM3_ALT)
// Regular implementation
//

typedef struct mbedtls_sm3_context { 
	uint32_t MBEDTLS_PRIVATE(digest)[8];
	uint64_t MBEDTLS_PRIVATE(nblocks);
	unsigned char MBEDTLS_PRIVATE(block)[64];
	int MBEDTLS_PRIVATE(num);
}
mbedtls_sm3_context;

#else  /* MBEDTLS_SM3_ALT */
#include "sm3_alt.h"
#endif /* MBEDTLS_SM3_ALT */

void mbedtls_sm3_init(mbedtls_sm3_context *ctx);
void mbedtls_sm3_free(mbedtls_sm3_context *ctx);
void mbedtls_sm3_clone(mbedtls_sm3_context *dst,
                       const mbedtls_sm3_context *src);

int mbedtls_sm3_starts(mbedtls_sm3_context *ctx);

int mbedtls_sm3_update(mbedtls_sm3_context *ctx,
                       const unsigned char *input,
                       size_t ilen);
int mbedtls_sm3_finish(mbedtls_sm3_context *ctx,
                       unsigned char output[SM3_DIGEST_SIZE]);

int mbedtls_internal_sm3_process(mbedtls_sm3_context *ctx,
                                 const unsigned char data[SM3_BLOCK_SIZE]);
int mbedtls_sm3(const unsigned char *input,
                size_t ilen,
                unsigned char output[SM3_DIGEST_SIZE]);

#if defined(MBEDTLS_SELF_TEST)
int mbedtls_sm3_self_test(int verbose);
#endif /* MBEDTLS_SELF_TEST */

#ifdef __cplusplus
}
#endif

#endif
