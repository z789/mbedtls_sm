#include "common.h"

#if defined(MBEDTLS_SM3_C)

#include "mbedtls/sm3.h"
#include "mbedtls/platform_util.h"
#include "mbedtls/error.h"

#include <string.h>
#include <stdint.h>
#include <stdlib.h>

#include "mbedtls/platform.h"

#if !defined(MBEDTLS_SM3_ALT)

/* Parameter validation macros */
#define SM3_VALIDATE_RET(cond)                                       \
    MBEDTLS_INTERNAL_VALIDATE_RET(cond, MBEDTLS_ERR_SM3_BAD_INPUT_DATA)
#define SM3_VALIDATE(cond)                                           \
    MBEDTLS_INTERNAL_VALIDATE(cond)

#define ARRAY_SIZE(arr) (sizeof(arr)/sizeof(arr[0]))
void mbedtls_sm3_init(mbedtls_sm3_context *ctx)
{
	if (ctx)
		memset(ctx, 0, sizeof(mbedtls_sm3_context));
}

void mbedtls_sm3_free(mbedtls_sm3_context *ctx)
{
	if (ctx)
		mbedtls_platform_zeroize(ctx, sizeof(mbedtls_sm3_context));
}

void mbedtls_sm3_clone(mbedtls_sm3_context *dst,
                       const mbedtls_sm3_context *src)
{
	if (dst && src)
		*dst = *src;
}

/*
 * SM3 context setup
 */
int mbedtls_sm3_starts(mbedtls_sm3_context *ctx)
{
	SM3_VALIDATE_RET(ctx != NULL);

	ctx->digest[0] = 0x7380166F;
	ctx->digest[1] = 0x4914B2B9;
	ctx->digest[2] = 0x172442D7;
	ctx->digest[3] = 0xDA8A0600;
	ctx->digest[4] = 0xA96F30BC;
	ctx->digest[5] = 0x163138AA;
	ctx->digest[6] = 0xE38DEE4D;
	ctx->digest[7] = 0xB0FB0E4E;

	ctx->nblocks = 0;
	ctx->num = 0;

	return 0;
}

#if !defined(MBEDTLS_SM3_PROCESS_ALT)

#define ROTATELEFT(X, n)  (((X)<<(n)) | ((X)>>(32-(n))))

#define P0(x) ((x) ^  ROTATELEFT((x), 9)  ^ ROTATELEFT((x), 17))
#define P1(x) ((x) ^  ROTATELEFT((x), 15) ^ ROTATELEFT((x), 23))

#define FF0(x, y, z) ((x) ^ (y) ^ (z))
#define FF1(x, y, z) (((x) & (y)) | ((x) & (z)) | ((y) & (z)))

#define GG0(x, y, z) ((x) ^ (y) ^ (z))
#define GG1(x, y, z) (((x) & (y)) | ((~(x)) & (z)))

static const uint32_t T16_table[16] = {
        0x79CC4519, 0xF3988A32, 0xE7311465, 0xCE6228CB,
        0x9CC45197, 0x3988A32F, 0x7311465E, 0xE6228CBC,
        0xCC451979, 0x988A32F3, 0x311465E7, 0x6228CBCE,
        0xC451979C, 0x88A32F39, 0x11465E73, 0x228CBCE6,
};

static const uint32_t T64_table[64] = {
        0x0, 0x0, 0x0, 0x0,
        0x0, 0x0, 0x0, 0x0,
        0x0, 0x0, 0x0, 0x0,
        0x0, 0x0, 0x0, 0x0,
        0x9D8A7A87, 0x3B14F50F, 0x7629EA1E, 0xEC53D43C,
        0xD8A7A879, 0xB14F50F3, 0x629EA1E7, 0xC53D43CE,
        0x8A7A879D, 0x14F50F3B, 0x29EA1E76, 0x53D43CEC,
        0xA7A879D8, 0x4F50F3B1, 0x9EA1E762, 0x3D43CEC5,
        0x7A879D8A, 0xF50F3B14, 0xEA1E7629, 0xD43CEC53,
        0xA879D8A7, 0x50F3B14F, 0xA1E7629E, 0x43CEC53D,
        0x879D8A7A, 0x0F3B14F5, 0x1E7629EA, 0x3CEC53D4,
        0x79D8A7A8, 0xF3B14F50, 0xE7629EA1, 0xCEC53D43,
        0x9D8A7A87, 0x3B14F50F, 0x7629EA1E, 0xEC53D43C,
        0xD8A7A879, 0xB14F50F3, 0x629EA1E7, 0xC53D43CE,
        0x8A7A879D, 0x14F50F3B, 0x29EA1E76, 0x53D43CEC,
        0xA7A879D8, 0x4F50F3B1, 0x9EA1E762, 0x3D43CEC5,
};

#define W16_INIT(WP, pb)                                         \
	do {                                                     \
		WP[0] = MBEDTLS_GET_UINT32_BE(((void*)pb), 0);   \
		WP[1] = MBEDTLS_GET_UINT32_BE(((void*)pb), 4);   \
		WP[2] = MBEDTLS_GET_UINT32_BE(((void*)pb), 8);   \
		WP[3] = MBEDTLS_GET_UINT32_BE(((void*)pb), 12);  \
		WP[4] = MBEDTLS_GET_UINT32_BE(((void*)pb), 16);  \
		WP[5] = MBEDTLS_GET_UINT32_BE(((void*)pb), 20);  \
		WP[6] = MBEDTLS_GET_UINT32_BE(((void*)pb), 24);  \
		WP[7] = MBEDTLS_GET_UINT32_BE(((void*)pb), 28);  \
		WP[8] = MBEDTLS_GET_UINT32_BE(((void*)pb), 32);  \
		WP[9] = MBEDTLS_GET_UINT32_BE(((void*)pb), 36);  \
		WP[10] = MBEDTLS_GET_UINT32_BE(((void*)pb), 40);  \
		WP[11] = MBEDTLS_GET_UINT32_BE(((void*)pb), 44);  \
		WP[12] = MBEDTLS_GET_UINT32_BE(((void*)pb), 48);  \
		WP[13] = MBEDTLS_GET_UINT32_BE(((void*)pb), 52);  \
		WP[14] = MBEDTLS_GET_UINT32_BE(((void*)pb), 56);  \
		WP[15] = MBEDTLS_GET_UINT32_BE(((void*)pb), 60);  \
	} while (0)

#define W68_UNIT(WP, jp)                                              \
	(WP[jp] = P1(WP[jp-16] ^ WP[jp-9] ^ ROTATELEFT(WP[jp-3], 15)) \
		 ^ ROTATELEFT(WP[jp - 13], 7) ^ WP[jp-6])

#define W68_INIT(WP)                               \
	do {                                       \
		W68_UNIT(WP, 16);                  \
		W68_UNIT(WP, 17);                  \
		W68_UNIT(WP, 18);                  \
		W68_UNIT(WP, 19);                  \
		W68_UNIT(WP, 20);                  \
		W68_UNIT(WP, 21);                  \
		W68_UNIT(WP, 22);                  \
		W68_UNIT(WP, 23);                  \
		W68_UNIT(WP, 24);                  \
		W68_UNIT(WP, 25);                  \
		W68_UNIT(WP, 26);                  \
		W68_UNIT(WP, 27);                  \
		W68_UNIT(WP, 28);                  \
		W68_UNIT(WP, 29);                  \
		W68_UNIT(WP, 30);                  \
		W68_UNIT(WP, 31);                  \
		W68_UNIT(WP, 32);                  \
		W68_UNIT(WP, 33);                  \
		W68_UNIT(WP, 34);                  \
		W68_UNIT(WP, 35);                  \
		W68_UNIT(WP, 36);                  \
		W68_UNIT(WP, 37);                  \
		W68_UNIT(WP, 38);                  \
		W68_UNIT(WP, 39);                  \
		W68_UNIT(WP, 40);                  \
		W68_UNIT(WP, 41);                  \
		W68_UNIT(WP, 42);                  \
		W68_UNIT(WP, 43);                  \
		W68_UNIT(WP, 44);                  \
		W68_UNIT(WP, 45);                  \
		W68_UNIT(WP, 46);                  \
		W68_UNIT(WP, 47);                  \
		W68_UNIT(WP, 48);                  \
		W68_UNIT(WP, 49);                  \
		W68_UNIT(WP, 50);                  \
		W68_UNIT(WP, 51);                  \
		W68_UNIT(WP, 52);                  \
		W68_UNIT(WP, 53);                  \
		W68_UNIT(WP, 54);                  \
		W68_UNIT(WP, 55);                  \
		W68_UNIT(WP, 56);                  \
		W68_UNIT(WP, 57);                  \
		W68_UNIT(WP, 58);                  \
		W68_UNIT(WP, 59);                  \
		W68_UNIT(WP, 60);                  \
		W68_UNIT(WP, 61);                  \
		W68_UNIT(WP, 62);                  \
		W68_UNIT(WP, 63);                  \
		W68_UNIT(WP, 64);                  \
		W68_UNIT(WP, 65);                  \
		W68_UNIT(WP, 66);                  \
		W68_UNIT(WP, 67);                  \
	} while (0)
	
#define FOR16_UNIT(jp)                                                             \
	do {                                                                       \
		SS1 = ROTATELEFT((ROTATELEFT(A, 12) + E + T16_table[jp]), 7);      \
		SS2 = SS1 ^ ROTATELEFT(A, 12);                                     \
		TT1 = FF0(A, B, C) + D + SS2 + (W[jp] ^ W[jp+4]);                  \
		TT2 = GG0(E, F, G) + H + SS1 + W[jp];                              \
		D = C;                                                             \
		C = ROTATELEFT(B, 9);                                              \
		B = A;                                                             \
		A = TT1;                                                           \
		H = G;                                                             \
		G = ROTATELEFT(F, 19);                                             \
		F = E;                                                             \
		E = P0(TT2);                                                       \
	} while (0)                                                                
                                                                                   
#define FOR64_UNIT(jp)                                                             \
	do {                                                                       \
		SS1 = ROTATELEFT((ROTATELEFT(A, 12) + E + T64_table[jp]), 7);      \
		SS2 = SS1 ^ ROTATELEFT(A, 12);                                     \
		TT1 = FF1(A, B, C) + D + SS2 + (W[jp] ^ W[jp+4]);                  \
		TT2 = GG1(E, F, G) + H + SS1 + W[jp];                              \
		D = C;                                                             \
		C = ROTATELEFT(B, 9);                                              \
		B = A;                                                             \
		A = TT1;                                                           \
		H = G;                                                             \
		G = ROTATELEFT(F, 19);                                             \
		F = E;                                                             \
		E = P0(TT2);                                                       \
	} while (0)                                                                

#define FOR16                  \
	do {                   \
		FOR16_UNIT(0); \
		FOR16_UNIT(1); \
		FOR16_UNIT(2); \
		FOR16_UNIT(3); \
		FOR16_UNIT(4); \
		FOR16_UNIT(5); \
		FOR16_UNIT(6); \
		FOR16_UNIT(7); \
		FOR16_UNIT(8); \
		FOR16_UNIT(9); \
		FOR16_UNIT(10); \
		FOR16_UNIT(11); \
		FOR16_UNIT(12); \
		FOR16_UNIT(13); \
		FOR16_UNIT(14); \
		FOR16_UNIT(15); \
	} while (0)

#define FOR64                   \
	do {                    \
		FOR64_UNIT(16); \
		FOR64_UNIT(17); \
		FOR64_UNIT(18); \
		FOR64_UNIT(19); \
		FOR64_UNIT(20); \
		FOR64_UNIT(21); \
		FOR64_UNIT(22); \
		FOR64_UNIT(23); \
		FOR64_UNIT(24); \
		FOR64_UNIT(25); \
		FOR64_UNIT(26); \
		FOR64_UNIT(27); \
		FOR64_UNIT(28); \
		FOR64_UNIT(29); \
		FOR64_UNIT(30); \
		FOR64_UNIT(31); \
		FOR64_UNIT(32); \
		FOR64_UNIT(33); \
		FOR64_UNIT(34); \
		FOR64_UNIT(35); \
		FOR64_UNIT(36); \
		FOR64_UNIT(37); \
		FOR64_UNIT(38); \
		FOR64_UNIT(39); \
		FOR64_UNIT(40); \
		FOR64_UNIT(41); \
		FOR64_UNIT(42); \
		FOR64_UNIT(43); \
		FOR64_UNIT(44); \
		FOR64_UNIT(45); \
		FOR64_UNIT(46); \
		FOR64_UNIT(47); \
		FOR64_UNIT(48); \
		FOR64_UNIT(49); \
		FOR64_UNIT(50); \
		FOR64_UNIT(51); \
		FOR64_UNIT(52); \
		FOR64_UNIT(53); \
		FOR64_UNIT(54); \
		FOR64_UNIT(55); \
		FOR64_UNIT(56); \
		FOR64_UNIT(57); \
		FOR64_UNIT(58); \
		FOR64_UNIT(59); \
		FOR64_UNIT(60); \
		FOR64_UNIT(61); \
		FOR64_UNIT(62); \
		FOR64_UNIT(63); \
	} while (0)

int mbedtls_internal_sm3_process(mbedtls_sm3_context *ctx,
                                 const unsigned char data[64])
{
	uint32_t W[68];
	const uint32_t *pblock = NULL;
	uint32_t *digest = NULL;

	SM3_VALIDATE_RET(ctx != NULL);
	SM3_VALIDATE_RET(data != NULL);

	pblock = (const uint32_t *)data;
	digest = ctx->digest; 

	uint32_t A = digest[0];
	uint32_t B = digest[1];
	uint32_t C = digest[2];
	uint32_t D = digest[3];
	uint32_t E = digest[4];
	uint32_t F = digest[5];
	uint32_t G = digest[6];
	uint32_t H = digest[7];
	uint32_t SS1, SS2, TT1, TT2;

	W16_INIT(W, pblock);
	W68_INIT(W);

	FOR16;
	FOR64;

	digest[0] ^= A;
	digest[1] ^= B;
	digest[2] ^= C;
	digest[3] ^= D;
	digest[4] ^= E;
	digest[5] ^= F;
	digest[6] ^= G;
	digest[7] ^= H;

	return 0;
}
#endif /* !MBEDTLS_SM3_PROCESS_ALT */

/*
 * SM3 process buffer
 */
int mbedtls_sm3_update(mbedtls_sm3_context *ctx,
                       const unsigned char *input,
                       size_t ilen)
{
	SM3_VALIDATE_RET(ctx != NULL);
	SM3_VALIDATE_RET(input != NULL);
	SM3_VALIDATE_RET(ilen >= 0);

	if (ilen == 0)
		return 0;

	if (ctx->num) {
		unsigned int left = SM3_BLOCK_SIZE - ctx->num;

		if (ilen < left) {
			memcpy(ctx->block + ctx->num, input, ilen);
			ctx->num += ilen;
			return 0;
		} else {
			memcpy(ctx->block + ctx->num, input, left);
			mbedtls_internal_sm3_process(ctx, ctx->block);
			ctx->nblocks++;
			input += left;
			ilen -= left;
		}
	}

	while (ilen >= SM3_BLOCK_SIZE) {
		mbedtls_internal_sm3_process(ctx, input);
		ctx->nblocks++;
		input += SM3_BLOCK_SIZE;
		ilen -= SM3_BLOCK_SIZE;
	}
	ctx->num = ilen;
	if (ilen)
		memcpy(ctx->block, input, ilen);

	return 0;
}

int mbedtls_sm3_finish(mbedtls_sm3_context *ctx,
                       unsigned char output[SM3_DIGEST_SIZE])
{
	unsigned long i;
	uint32_t *pdigest;
	uint64_t *count;
	uint64_t num = 0;

	SM3_VALIDATE_RET(ctx != NULL);
	SM3_VALIDATE_RET(output != NULL);

	pdigest = (uint32_t *)output;
	count = (uint64_t *)(ctx->block + SM3_BLOCK_SIZE - 8);

	ctx->block[ctx->num] = 0x80;

	if (ctx->num + 9 <= SM3_BLOCK_SIZE) {
		memset(ctx->block + ctx->num + 1, 0, SM3_BLOCK_SIZE - ctx->num - 9);
	} else {
		memset(ctx->block + ctx->num + 1, 0, SM3_BLOCK_SIZE - ctx->num - 1);
		mbedtls_internal_sm3_process(ctx, ctx->block);
		memset(ctx->block, 0, SM3_BLOCK_SIZE - 8);
	}

	num = (ctx->nblocks << 9) + (ctx->num << 3);
	count[0] = MBEDTLS_GET_UINT64_BE((void*)&num, 0);

	mbedtls_internal_sm3_process(ctx, ctx->block);
	for (i = 0; i < ARRAY_SIZE(ctx->digest); i++)
		pdigest[i] = MBEDTLS_GET_UINT32_BE(&ctx->digest[i], 0);

	return 0;
}
#endif /* !MBEDTLS_SM3_ALT */

/*
 * output = SM3( input buffer )
 */
int mbedtls_sm3(const unsigned char *input,
                size_t ilen,
                unsigned char output[SM3_DIGEST_SIZE])
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    mbedtls_sm3_context ctx;

    mbedtls_sm3_init(&ctx);

    if ((ret = mbedtls_sm3_starts(&ctx)) != 0) {
        goto exit;
    }

    if ((ret = mbedtls_sm3_update(&ctx, input, ilen)) != 0) {
        goto exit;
    }

    if ((ret = mbedtls_sm3_finish(&ctx, output)) != 0) {
        goto exit;
    }

exit:
    mbedtls_sm3_free(&ctx);

    return ret;
}

#endif /* MBEDTLS_SM3_C */
