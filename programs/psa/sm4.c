
#include "psa/crypto.h"

#include <string.h>
#include <stdio.h>
#include <stdlib.h>

/*
 * The paper http://www.gmbz.org.cn/upload/2018-04-04/1522788048733065051.pdf
 * Annex A (informative) Examples
*/
uint8_t plain[] = {0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, 0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10};
uint8_t key_buf[] = {0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, 0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10};
uint8_t cipher[] = {0x68, 0x1E, 0xDF, 0x34, 0xD2, 0x06, 0x96, 0x5E, 0x86, 0xB3, 0xE9, 0x4F, 0x53, 0x6E, 0x42, 0x46};
uint8_t cipher1000000[] = {0x59, 0x52, 0x98, 0xC7, 0xC6, 0xFD, 0x27, 0x1F, 0x04, 0x02, 0xF8, 0x04, 0xC3, 0x3D, 0x3F, 0x66};

static void print_buf(const char *title, uint8_t *buf, size_t len)
{
    if (title)
	printf("%s", title);
    for (size_t i = 0; i < len; i++) {
        printf("%02X", buf[i]);
    }
    printf("\n");
}


void encrypt_with_symmetric_ciphers(int round)
{
    enum {
        block_size = PSA_BLOCK_CIPHER_BLOCK_LENGTH(PSA_KEY_TYPE_SM4),
    };
    psa_status_t status;
    psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;
    psa_algorithm_t alg = PSA_ALG_ECB_NO_PADDING;

    uint8_t output[block_size];
    size_t output_len;
    uint8_t plaintext[block_size] = {0};
    ssize_t plaintext_len;
    psa_key_id_t key_id;
    psa_cipher_operation_t operation = PSA_CIPHER_OPERATION_INIT;
    int count = round;

    printf("Encrypt %d round...\n", round);
    fflush(stdout);

    /* Initialize PSA Crypto */
    status = psa_crypto_init();
    if (status != PSA_SUCCESS)
    {
        printf("Failed to initialize PSA Crypto\n");
        return;
    }

    /* Import a key */
    psa_set_key_usage_flags(&attributes, PSA_KEY_USAGE_ENCRYPT);
    psa_set_key_algorithm(&attributes, alg);
    psa_set_key_type(&attributes, PSA_KEY_TYPE_SM4);
    psa_set_key_bits(&attributes, 128);
    status = psa_import_key(&attributes, key_buf, sizeof(key_buf), &key_id);
    if (status != PSA_SUCCESS) {
        printf("Failed to import a key\n");
        return;
    }
    psa_reset_key_attributes(&attributes);

    memcpy(plaintext, plain, sizeof(plain));
    plaintext_len = sizeof(plain);
    print_buf("SM4 plain:", plaintext, plaintext_len);
    print_buf("SM4 key:", key_buf, sizeof(key_buf));

    /* Encrypt the plaintext */
    status = psa_cipher_encrypt_setup(&operation, key_id, alg);
    if (status != PSA_SUCCESS) {
        printf("Failed to begin cipher operation\n");
        return;
    }

    while (count-- > 0) {
	    status = psa_cipher_update(&operation, plaintext, plaintext_len,
			    output, sizeof(output), &output_len);
	    if (status != PSA_SUCCESS) {
		    printf("Failed to update cipher operation\n");
		    return;
	    }
            
	    memcpy(plaintext, output, output_len);
    }
    print_buf("SM4 cipher:", output, output_len);

    if (round == 1) {
           if (memcmp(output, cipher, sizeof(cipher)))
    		printf("Encrypted round %d Fail\n", round);
	   else 
    		printf("Encrypted round %d Succ\n", round);
    } else if (round == 1000000) {
           if (memcmp(output, cipher1000000, sizeof(cipher1000000)))
    		printf("Encrypted round %d Fail\n", round);
	   else 
    		printf("Encrypted round %d Succ\n", round);
    }

    status = psa_cipher_finish(&operation, output + output_len,
                               sizeof(output) - output_len, &output_len);
    if (status != PSA_SUCCESS) {
        printf("Failed to finish cipher operation\n");
        return;
    }
    if (output_len > 0)
	    print_buf("SM4 cipher:", output, output_len);
    printf("\n");

    /* Clean up cipher operation context */
    psa_cipher_abort(&operation);

    /* Destroy the key */
    psa_destroy_key(key_id);

    mbedtls_psa_crypto_free();
}

void decrypt_with_symmetric_ciphers(int round)
{
    enum {
        block_size = PSA_BLOCK_CIPHER_BLOCK_LENGTH(PSA_KEY_TYPE_SM4),
    };
    psa_status_t status;
    psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;
    psa_algorithm_t alg = PSA_ALG_ECB_NO_PADDING;
    psa_cipher_operation_t operation = PSA_CIPHER_OPERATION_INIT;

    uint8_t ciphertext[block_size] = {0};
    ssize_t ciphertext_len;

    uint8_t output[block_size];
    size_t output_len;
    psa_key_id_t key_id;
    int count = round;

    printf("Decrypt %d round ...\n", round);
    fflush(stdout);

    /* Initialize PSA Crypto */
    status = psa_crypto_init();
    if (status != PSA_SUCCESS)
    {
        printf("Failed to initialize PSA Crypto\n");
        return;
    }

    /* Import a key */
    psa_set_key_usage_flags(&attributes, PSA_KEY_USAGE_DECRYPT);
    psa_set_key_algorithm(&attributes, alg);
    psa_set_key_type(&attributes, PSA_KEY_TYPE_SM4);
    psa_set_key_bits(&attributes, 128);
    status = psa_import_key(&attributes, key_buf, sizeof(key_buf), &key_id);
    if (status != PSA_SUCCESS) {
        printf("Failed to import a key\n");
        return;
    }
    psa_reset_key_attributes(&attributes);

    if (round == 1) {
	    memcpy(ciphertext, cipher, sizeof(cipher));
    } if (round == 1000000) {
	    memcpy(ciphertext, cipher1000000, sizeof(cipher1000000));
    }
    ciphertext_len = sizeof(cipher);
   
    print_buf("SM4 cipher:", ciphertext, ciphertext_len);
    print_buf("SM4 key:", key_buf, sizeof(key_buf));

    /* Decrypt the ciphertext */
    status = psa_cipher_decrypt_setup(&operation, key_id, alg);
    if (status != PSA_SUCCESS) {
        printf("Failed to begin cipher operation\n");
        return;
    }

    while (count-- > 0) {
	    status = psa_cipher_update(&operation, ciphertext, ciphertext_len,
			    output, sizeof(output), &output_len);
	    if (status != PSA_SUCCESS) {
		    printf("Failed to update cipher operation\n");
		    return;
	    }
            
	    memcpy(ciphertext, output, output_len);
    }
    print_buf("SM4 decrypt:", output, output_len);

    if (memcmp(output, plain, sizeof(plain)))
	    printf("Decrypted round %d FaiL\n", round);
    else 
	    printf("Decrypted round %d Succ\n", round);

    status = psa_cipher_finish(&operation, output + output_len,
                               sizeof(output) - output_len, &output_len);
    if (status != PSA_SUCCESS) {
        printf("Failed to finish cipher operation\n");
        return;
    }
    printf("\n");

    /* Clean up cipher operation context */
    psa_cipher_abort(&operation);

    /* Destroy the key */
    psa_destroy_key(key_id);

    mbedtls_psa_crypto_free();
}

int main(void)
{
	encrypt_with_symmetric_ciphers(1);
	encrypt_with_symmetric_ciphers(1000000);
	decrypt_with_symmetric_ciphers(1);
	decrypt_with_symmetric_ciphers(1000000);
	return 0;
}
