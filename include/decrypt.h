#ifndef DECRYPT_H
#define DECRYPT_H

#include <stddef.h>
#include <openssl/evp.h>
#include "constants.h"

int init_decryption(EVP_CIPHER_CTX **ctx_out, unsigned char salt[SALT_SIZE], unsigned char nonce[NONCE_SIZE]);
int decrypt(EVP_CIPHER_CTX *ctx, unsigned char *output_buffer, int *output_length, const unsigned char *input_buffer, size_t input_length);
int decrypt_file(const char *source, const char *destination);

#endif