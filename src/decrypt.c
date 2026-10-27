#include "decrypt.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdint.h>
#include <limits.h>

#include <openssl/evp.h>
#include <openssl/crypto.h>

#include <argon2.h>
#include <termios.h>

int init_decryption(EVP_CIPHER_CTX **ctx_out, unsigned char salt[SALT_SIZE], unsigned char nonce[NONCE_SIZE]) // output params filling the caller's variables
{
    // checking pointers
    if (ctx_out == NULL || salt == NULL || nonce == NULL)
    {
        fprintf(stderr, "Invalid initialisation parameters\n");
        return 1;
    }
    *ctx_out = NULL;

    struct termios old_tty;
    int echo_disabled = 0; // to ensure terminal settings are only restored if echo was successfully disabled
    int status = 1;        // tracking if the function was successful

    EVP_CIPHER_CTX *ctx = NULL;

    // KDF params
    uint32_t t_cost = 2;
    uint32_t m_cost = (1 << 16);
    uint32_t parallelism = 1;
    unsigned char pwd[PWD_SIZE] = {0};
    unsigned char key[KEY_SIZE] = {0};

    // Accepting user password

    // getting terminal attributes
    if (tcgetattr(STDIN_FILENO, &old_tty) == -1)
    {
        perror("Error saving terminal settings");
        return 1;
    }
    struct termios tty = old_tty;
    tty.c_lflag &= ~ECHO;

    if (tcsetattr(STDIN_FILENO, TCSAFLUSH, &tty) == -1)
    {
        perror("Error disabling ECHO");
        return 1;
    }
    echo_disabled = 1;

    printf("Enter Decryption Password: ");
    fflush(stdout);

    if (fgets((char *)pwd, PWD_SIZE, stdin) == NULL)
    {
        fprintf(stderr, "Error reading password\n");

        goto cleanup;
    }

    char *newline = strchr((char *)pwd, '\n');
    if (newline != NULL)
    {
        *newline = '\0';
    }
    else
    {
        int ch = getchar(); // reads the next character in stdin not taken by fgets
        if (ch != EOF && ch != '\n')
        {
            while (ch != EOF && ch != '\n')
            {
                ch = getchar(); // Release the rest of the input
            }
            fprintf(stderr, "Password is too large!\n");

            goto cleanup;
        }
        if (ch == EOF && ferror(stdin))
        {
            fprintf(stderr, "\nError reading password\n");

            goto cleanup;
        }
    }

    if (pwd[0] == '\0')
    {
        fprintf(stderr, "Password cannot be empty\n");
        goto cleanup;
    }

    printf("\n");

    // generating key
    int result = argon2id_hash_raw(t_cost, m_cost, parallelism, pwd, strlen((char *)pwd), salt, SALT_SIZE, key, KEY_SIZE);
    if (result != ARGON2_OK)
    {
        fprintf(stderr, "Error generating Key: %s\n", argon2_error_message(result));
        goto cleanup;
    }
    OPENSSL_cleanse(pwd, sizeof(pwd));

    // creating a decryption context
    ctx = EVP_CIPHER_CTX_new();
    if (ctx == NULL)
    {
        fprintf(stderr, "Error creating decryption context\n");
        goto cleanup;
    }

    // decryption initialisation
    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, key, nonce) != 1)
    {
        fprintf(stderr, "Error initialising decryption\n");
        goto cleanup;
    }

    // restore terminal settings before passing context
    if (echo_disabled)
    {
        if (tcsetattr(STDIN_FILENO, TCSAFLUSH, &old_tty) == -1)
        {
            perror("Error restoring terminal settings");
            goto cleanup;
        }
        echo_disabled = 0; // so that restoration doesn't happen twice
    }

    // pass the initialised context to the caller
    *ctx_out = ctx;
    ctx = NULL;

    status = 0;

cleanup:
    if (echo_disabled)
    {
        if (tcsetattr(STDIN_FILENO, TCSAFLUSH, &old_tty) == -1)
        {
            perror("Error restoring terminal settings");
            status = 1;
        }
    }
    EVP_CIPHER_CTX_free(ctx);
    OPENSSL_cleanse(pwd, sizeof(pwd));
    OPENSSL_cleanse(key, sizeof(key));
    return status;
}

int decrypt(EVP_CIPHER_CTX *ctx, unsigned char *output_buffer, int *output_length, const unsigned char *input_buffer, size_t input_length)
{
    if (ctx == NULL || output_buffer == NULL || output_length == NULL || input_buffer == NULL)
    {
        fprintf(stderr, "Invalid Initialisation Parameters\n");
        return 1;
    }
    if (input_length > INT_MAX)
    {
        fprintf(stderr, "Input Length is too large\n");
        return 1;
    }
    if (EVP_DecryptUpdate(ctx, output_buffer, output_length, input_buffer, (int)input_length) != 1)
    {
        fprintf(stderr, "Error decrypting chunk");
        return 1;
    }
    return 0;
}

int decrypt_file(const char *source, const char *destination)
{

    int status = 1;
    int renamed = 0;

    char *template = NULL;
    int tmp = -1;
    size_t template_size = strlen(destination) + TEMPLATE_SIZE; // size of the temp file

    EVP_CIPHER_CTX *ctx = NULL;
    unsigned char salt[SALT_SIZE];
    unsigned char nonce[NONCE_SIZE];
    unsigned char tag[TAG_SIZE];

    unsigned char input_buffer[BUFFER_SIZE];
    unsigned char output_buffer[BUFFER_SIZE + EVP_MAX_BLOCK_LENGTH];
    size_t input_length; // number of bytes read
    int output_length;   // number of bytes encrypted

    FILE *encrypt_ptr = NULL; // source
    FILE *decrypt_ptr = NULL; // destination

    // Validating args
    if (source == NULL || destination == NULL)
    {
        fprintf(stderr, "Invalid source or destination\n");
        return 1;
    }

    // Open Source (Encrypted File)
    encrypt_ptr = fopen(source, "rb");
    if (encrypt_ptr == NULL)
    {
        perror("Invalid source filename or the source file doesn't exist");
        goto cleanup;
    }

    // Calculating the size of the file
    if (fseeko(encrypt_ptr, 0L, SEEK_END) != 0)
    {
        fprintf(stderr, "Error placing file pointer at the end of file");
        goto cleanup;
    }
    off_t size = ftello(encrypt_ptr);
    if (size == (off_t)-1)
    {
        fprintf(stderr, "Error calculating file size");
        goto cleanup;
    }
    if (size < (off_t)MIN_FILE_SIZE)
    {
        fprintf(stderr, "File size is too small");
        goto cleanup;
    }

    // Reading salt and nonce
    if (fseeko(encrypt_ptr, 0, SEEK_SET) != 0)
    {
        fprintf(stderr, "Error rewinding file pointer");
        goto cleanup;
    }
    size_t bytes_read = fread(salt, 1, SALT_SIZE, encrypt_ptr);
    if (bytes_read < SALT_SIZE)
    {
        if (ferror(encrypt_ptr))
        {
            perror("Error reading salt");
            goto cleanup;
        }
        else
        {
            fprintf(stderr, "Unexpected EOF while reading salt");
            goto cleanup;
        }
    }
    bytes_read = fread(nonce, 1, NONCE_SIZE, encrypt_ptr);
    if (bytes_read < NONCE_SIZE)
    {
        if (ferror(encrypt_ptr))
        {
            perror("Error reading nonce");
            goto cleanup;
        }
        else
        {
            fprintf(stderr, "Unexpected EOF while reading nonce");
            goto cleanup;
        }
    }

    // Initialising decryption context
    if (init_decryption(&ctx, salt, nonce) != 0)
    {
        fprintf(stderr, "Error initialising the decryption context ");
        goto cleanup;
    }

    // Allocating memory for a temp file + Creating a temp file
    template = malloc(template_size);
    if (template == NULL)
    {
        fprintf(stderr, "Failed to allocate memory for temporary file");
        goto cleanup;
    }
    snprintf(template, template_size, "%s.XXXXXX", destination); // Adds new temp file definition to the template buffer
    tmp = mkstemp(template);
    if (tmp == -1)
    {
        perror("Error creating file stream");
        goto cleanup;
    }
    decrypt_ptr = fdopen(tmp, "wb");

    if (decrypt_ptr == NULL)
    {
        perror("Failed stream creation");
        goto cleanup;
    }
    tmp = -1;

    // Read Ciphertext (Source)

    off_t remaining_size = size - (off_t)MIN_FILE_SIZE;
    size_t chunk_size;

    while (remaining_size > 0)
    {
        // only read either BUFFER_SIZE amount of bytes or what's below it
        if (remaining_size > BUFFER_SIZE)
        {
            chunk_size = BUFFER_SIZE;
        }
        else
        {
            chunk_size = remaining_size;
        }

        // Read only ONE chunk
        input_length = fread(input_buffer, 1, chunk_size, encrypt_ptr);

        if (input_length != chunk_size)
        {
            if (ferror(encrypt_ptr))
            {
                perror("Error reading source");
                goto cleanup;
            }
            else
            {
                fprintf(stderr, "Unexpected EOF while reading source");
                goto cleanup;
            }
        }
        // Decrypt chunks
        if (decrypt(ctx, output_buffer, &output_length, input_buffer, input_length) != 0)
        {
            fprintf(stderr, "File Decryption has failed.");
            goto cleanup;
        }
        // Write Decrypted chunks to Destination from the output buffer
        if (fwrite(output_buffer, 1, output_length, decrypt_ptr) != (size_t)output_length)
        {
            perror("Error writing to destination file");
            goto cleanup;
        }
        remaining_size -= input_length; // updating the number of ciphertext bytes left to be read
    }
    if (ferror(encrypt_ptr))
    {
        perror("Error reading the source file");
        goto cleanup;
    }

    // Reading Authentication Tag
    bytes_read = fread(tag, 1, TAG_SIZE, encrypt_ptr);
    if (bytes_read < TAG_SIZE)
    {
        if (ferror(encrypt_ptr))
        {
            perror("Error reading tag");
            goto cleanup;
        }
        else
        {
            fprintf(stderr, "Unexpected EOF while reading tag");
            goto cleanup;
        }
    }

    // Authenticating plaintext
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, TAG_SIZE, tag) != 1)
    {
        fprintf(stderr, "Error setting tag (Authentication Failure)\n");
        goto cleanup;
    }

    if (EVP_DecryptFinal_ex(ctx, output_buffer, &output_length) != 1)
    {
        fprintf(stderr, "Decryption failed: incorrect password or corrupted file.\n");
        goto cleanup;
    }

    // Writing leftover plaintext bytes from output_buffer after finalisation
    if (fwrite(output_buffer, 1, (size_t)output_length, decrypt_ptr) != (size_t)output_length)
    {
        perror("Error writing final bytes to destination file");
        goto cleanup;
    }

    // Closing files
    int success = fclose(encrypt_ptr);
    encrypt_ptr = NULL;
    if (success == EOF)
    {
        perror("Error closing the source file");
        goto cleanup;
    }
    success = fclose(decrypt_ptr);
    decrypt_ptr = NULL;
    if (success == EOF)
    {
        perror("Error closing the destination file");
        goto cleanup;
    }

    // Renaming the temp file
    if (rename(template, destination) != 0)
    {
        perror("Error renaming temp file to destination");
        goto cleanup;
    }

    renamed = 1; // successful renaming

    status = 0;

cleanup:
    if (tmp != -1) // closing file descriptor if fdopen failed
    {
        close(tmp);
    }

    if (encrypt_ptr != NULL)
    {
        fclose(encrypt_ptr);
        encrypt_ptr = NULL;
    }
    if (decrypt_ptr != NULL)
    {
        fclose(decrypt_ptr);
        decrypt_ptr = NULL;
    }

    if (renamed == 0 && template != NULL) // (unsuccessful renaming) as after successful renaming template is moved
    {

        if (unlink(template) == -1) // removes temp file
        {
            perror("Error unlinking temp file");
        }
    }
    free(template); // frees template string buffer
    template = NULL;
    EVP_CIPHER_CTX_free(ctx);

    return status;
}