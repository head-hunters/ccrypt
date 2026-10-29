#include "encrypt.h"
#include "decrypt.h"
#include "dumper.h"

int main(int argc, char *argv[])
{
    const char *arguments[] = {"-e", "-d", "-ev", "-dv", "-h"}; // Valid Arguments
    int num_args = sizeof(arguments) / sizeof(arguments[0]);

    int found = 0;

    // Checking if arg has been supplied and if it is a valid arg in the list
    if (argc < 2)
    {
        fprintf(stderr,
                "Error: No arguments supplied.\n"
                "Try 'ccrypt -h' for help.\n");
        return 1;
    }

    for (int i = 0; i < num_args; i++)
    {

        if (strcmp(argv[1], arguments[i]) == 0)
        {
            found = 1;
            break;
        }
    }

    if (found == 0)
    {
        fprintf(stderr,
                "Error: Invalid argument.\n"
                "Try 'ccrypt -h' for help.\n");
        return 1;
    }

    // Encryption
    if (strcmp(argv[1], "-e") == 0 || strcmp(argv[1], "-ev") == 0)
    {
        if (encrypt_file(argv[2], argv[3]) != 0)
        {
            return 1;
        }
        printf("\nInput: %s\nOutput: %s\n", argv[2], argv[3]);
        printf("Encryption Successful\n");

        // Verbose Output
        if (strcmp(argv[1], "-ev") == 0)
        {
            printf("\nSource\n");
            if (dumper(argv[2]) != 0)
            {
                return 1;
            }
            printf("\nDestination\n");
            if (dumper(argv[3]) != 0)
            {
                return 1;
            }
        }
    }

    // Decryption
    else if (strcmp(argv[1], "-d") == 0 || strcmp(argv[1], "-dv") == 0)
    {
        if (decrypt_file(argv[2], argv[3]) != 0)
        {
            return 1;
        }
        printf("\nInput: %s\nOutput: %s\n", argv[2], argv[3]);
        printf("Decryption Successful\n");

        // Verbose Output
        if (strcmp(argv[1], "-dv") == 0)
        {
            printf("\nSource\n");
            if (dumper(argv[2]) != 0)
            {
                return 1;
            }
            printf("\nDestination\n");
            if (dumper(argv[3]) != 0)
            {
                return 1;
            }
        }
    }

    // Help
    else if (strcmp(argv[1], "-h") == 0)
    {
        // Usage Manual
        printf(
            "\nUsage:\n"
            "  ccrypt <option> <source> <destination>\n"
            "\n"
            "Options:\n"
            "  -e    Encrypt a file\n"
            "  -d    Decrypt a file\n"
            "  -ev   Encrypt a file with verbose output\n"
            "  -dv   Decrypt a file with verbose output\n"
            "\n"
            "Arguments:\n"
            "  source       File to read (plaintext for encryption, ciphertext for decryption)\n"
            "  destination  File to write (ciphertext for encryption, plaintext for decryption)\n"
            "\n"
            "Examples:\n"
            "  ccrypt -e  plaintext.txt encrypted.bin\n"
            "  ccrypt -d  encrypted.bin decrypted.txt\n"
            "  ccrypt -ev plaintext.txt encrypted.bin\n"
            "  ccrypt -dv encrypted.bin decrypted.txt\n");
    }

    return 0;
}