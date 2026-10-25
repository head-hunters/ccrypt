#include <stdio.h>
#include <string.h>
#include <termios.h>
#include <unistd.h>
#include <stdint.h>
#include <limits.h>

#include <openssl/evp.h>
#include <openssl/rand.h>

#include <argon2.h>

#define BUFFER_SIZE 4096
#define SALT_SIZE 16
#define KEY_SIZE 32
#define PWD_SIZE 128
#define NONCE_SIZE 12
#define TAG_SIZE 16

int init_encryption(EVP_CIPHER_CTX **ctx_out, unsigned char salt[SALT_SIZE], unsigned char nonce[NONCE_SIZE]) // output params filling the caller's variables
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

    // getting user password

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

    printf("Enter Encryption Password: ");
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

    // generating salt
    if (RAND_bytes(salt, SALT_SIZE) != 1)
    {
        fprintf(stderr, "Error generating salt\n");
        goto cleanup;
    }

    // generating key
    int result = argon2id_hash_raw(t_cost, m_cost, parallelism, pwd, strlen((char *)pwd), salt, SALT_SIZE, key, KEY_SIZE);
    if (result != ARGON2_OK)
    {
        fprintf(stderr, "Error generating Key: %s\n", argon2_error_message(result));
        goto cleanup;
    }
    OPENSSL_cleanse(pwd, sizeof(pwd));

    // creating an encryption context
    ctx = EVP_CIPHER_CTX_new();
    if (ctx == NULL)
    {
        fprintf(stderr, "Error creating encryption context\n");
        goto cleanup;
    }

    // generating nonce
    if (RAND_bytes(nonce, NONCE_SIZE) != 1)
    {
        fprintf(stderr, "Error generating nonce\n");
        goto cleanup;
    }

    // cipher initialisation
    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, key, nonce) != 1)
    {
        fprintf(stderr, "Error initialising encryption\n");
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

int encrypt(EVP_CIPHER_CTX *ctx, unsigned char *output_buffer, int *output_length, const unsigned char *input_buffer, size_t input_length)
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
    if (EVP_EncryptUpdate(ctx, output_buffer, output_length, input_buffer, (int)input_length) != 1)
    {
        fprintf(stderr, "Error encrypting chunk");
        return 1;
    }
    return 0;
}

int encrypt_file(const char *source, const char *destination)
{

    int status = 1;

    if (strcmp(source, destination) == 0)
    {
        fprintf(stderr, "The source and destination file cannot be the same\n");
        goto cleanup;
    }

    EVP_CIPHER_CTX *ctx = NULL;
    unsigned char salt[SALT_SIZE];
    unsigned char nonce[NONCE_SIZE];
    unsigned char tag[TAG_SIZE];

    unsigned char input_buffer[BUFFER_SIZE];
    unsigned char output_buffer[BUFFER_SIZE + EVP_MAX_BLOCK_LENGTH];
    size_t input_length; // number of bytes read
    int output_length;   // number of bytes encrypted

    FILE *plain_ptr = NULL;   // source
    FILE *encrypt_ptr = NULL; // destination

    // Initialise the cipher
    if (init_encryption(&ctx, salt, nonce) != 0)
    {
        fprintf(stderr, "Error initialising the cipher");
        goto cleanup;
    }

    // Open Source and Destination files
    plain_ptr = fopen(source, "rb");
    if (plain_ptr == NULL)
    {
        perror("Invalid source filename or the source file doesn't exist");
        goto cleanup;
    }
    encrypt_ptr = fopen(destination, "wb");

    if (encrypt_ptr == NULL)
    {
        perror("Invalid destination filename or the destination file doesn't exist");
        goto cleanup;
    }

    // Write salt and nonce to Destination
    if (fwrite(salt, 1, SALT_SIZE, encrypt_ptr) != SALT_SIZE)
    {
        perror("Error writing salt to destination file");
        goto cleanup;
    }

    if (fwrite(nonce, 1, NONCE_SIZE, encrypt_ptr) != NONCE_SIZE)
    {
        perror("Error writing nonce to destination");
        goto cleanup;
    }

    // Read Source
    while ((input_length = fread(input_buffer, 1, BUFFER_SIZE, plain_ptr)) > 0)
    {
        // Encrypt chunks
        if (encrypt(ctx, output_buffer, &output_length, input_buffer, input_length) != 0)
        {
            fprintf(stderr, "File Encryption has failed.");
            goto cleanup;
        }
        // Write Encrypted chunks to Destination from the output buffer
        if (fwrite(output_buffer, 1, output_length, encrypt_ptr) != (size_t)output_length)
        {
            perror("Error writing to destination file");
            goto cleanup;
        }
    }

    if (ferror(plain_ptr))
    {
        perror("Error reading the source file");
        goto cleanup;
    }

    // Finalise Encryption
    if (EVP_EncryptFinal_ex(ctx, output_buffer, &output_length) != 1)
    {
        fprintf(stderr, "Error finalising encryption\n");
        goto cleanup;
    }

    // Writing leftover bytes from output_buffer after finalisation
    if (fwrite(output_buffer, 1, output_length, encrypt_ptr) != (size_t)output_length)
    {
        perror("Error writing to destination file");
        goto cleanup;
    }

    // Retrieving Authentication tag and writing it to destination
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, TAG_SIZE, tag) <= 0)
    {
        fprintf(stderr, "Error retrieving authentication tag\n");
        goto cleanup;
    }
    if (fwrite(tag, 1, TAG_SIZE, encrypt_ptr) != TAG_SIZE)
    {
        fprintf(stderr, "Error writing authentication tag\n");
        goto cleanup;
    }

    // Closing files
    int success = fclose(plain_ptr);
    plain_ptr = NULL;
    if (success == EOF)
    {
        perror("Error closing the source file");
        goto cleanup;
    }
    success = fclose(encrypt_ptr);
    encrypt_ptr = NULL;
    if (success == EOF)
    {
        perror("Error closing the destination file");
        goto cleanup;
    }

    status = 0;
cleanup:
    EVP_CIPHER_CTX_free(ctx);
    if (plain_ptr != NULL)
    {
        fclose(plain_ptr);
        plain_ptr = NULL;
    }
    if (encrypt_ptr != NULL)
    {
        fclose(encrypt_ptr);
        encrypt_ptr = NULL;
    }

    return status;
}

int dumper(const char *file)
{
    unsigned char buffer[BUFFER_SIZE];
    size_t read_bytes;
    FILE *dump_ptr;
    dump_ptr = fopen(file, "rb");
    if (dump_ptr == NULL)
    {
        perror("Invalid filename or the file doesn't exist");
        return 1;
    }
    while ((read_bytes = fread(buffer, 1, BUFFER_SIZE, dump_ptr)) > 0)
    {
        int counter = 0;
        for (size_t i = 0; i < read_bytes; i++)
        {
            printf("%02x ", buffer[i]);
            counter++;
            if (counter == 16)
            {
                printf("\n");
                counter = 0;
            }
        }
        if (counter > 0)
        {
            printf("\n");
        }
    }
    if (ferror(dump_ptr))
    {
        perror("Error reading the file");
        fclose(dump_ptr);
        return 1;
    }
    if (fclose(dump_ptr) != 0)
    {
        perror("Error closing the file");
        return 1;
    }
    return 0;
}
int main(int argc, char *argv[])
{
    if (argc != 4)
    {
        printf("Usage: ./ccrypt -argument <source> <destination>\n");
        return 1;
    }

    if (strcmp(argv[1], "-e") == 0)
    {
        if (encrypt_file(argv[2], argv[3]) != 0)
        {
            fprintf(stderr, "Encryption Failed");
            return 1;
        }
    }

    printf("Source\n");
    dumper(argv[2]);
    printf("Destination\n");
    dumper(argv[3]);
    return 0;
}