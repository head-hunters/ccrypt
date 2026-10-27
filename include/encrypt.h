#ifndef ENCRYPT_H
#define ENCRYPT_H

#include <stddef.h>
#include <openssl/evp.h>
#include "constants.h"

int init_encryption(EVP_CIPHER_CTX **ctx_out, unsigned char salt[SALT_SIZE], unsigned char nonce[NONCE_SIZE]);
int encrypt(EVP_CIPHER_CTX *ctx, unsigned char *output_buffer, int *output_length, const unsigned char *input_buffer, size_t input_length);
int encrypt_file(const char *source, const char *destination);

#endif