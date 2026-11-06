#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>

#include "batch.h"

// Handling Ctrl+C termination -- To ensure temp files don't get left behind
volatile sig_atomic_t interrupted = 0;
static void handle_sigint(int signal)
{
    (void)signal;
    interrupted = 1;
}

int main(int argc, char *argv[])
{
    // Registering SIG_INT handler
    struct sigaction sa = {0};
    sa.sa_handler = handle_sigint;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;

    if (sigaction(SIGINT, &sa, NULL) == -1)
    {
        perror("sigaction");
        return 1;
    }

    const char *arguments[] = {"-e", "-d", "-ev", "-dv", "-h"}; // Valid Arguments
    size_t num_args = sizeof(arguments) / sizeof(arguments[0]);

    int found = 0;

    // Checking if arg has been supplied and if it is a valid arg in the list
    if (argc < 2)
    {
        fprintf(stderr,
                "Error: No arguments supplied.\n"
                "Try 'ccrypt -h' for help.\n");
        return 1;
    }

    for (size_t i = 0; i < num_args; i++)
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

    // Help
    if (strcmp(argv[1], "-h") == 0)
    {

        if (argc != 2)
        {
            fprintf(stderr, "Help option does not accept additional arguments\n");
            return 1;
        }

        // Usage Manual
        printf(
            "\nUsage:\n"
            "  ccrypt <option> <source> <destination>\n"
            "  ccrypt <option> <source1,source2,...> <destination1,destination2,...>\n"
            "\n"
            "Options:\n"
            "  -e    Encrypt file(s)\n"
            "  -d    Decrypt file(s)\n"
            "  -ev   Encrypt file(s) with verbose output\n"
            "  -dv   Decrypt file(s) with verbose output\n"
            "\n"
            "Arguments:\n"
            "  source       File(s) to read (plaintext for encryption, ciphertext for decryption)\n"
            "  destination  File(s) to write (ciphertext for encryption, plaintext for decryption)\n"
            "\n"
            "Batch Processing:\n"
            "  Multiple files can be specified using comma-separated lists.\n"
            "  Each source file is paired with its corresponding destination file by position.\n"
            "  The number of source and destination files must match.\n"
            "  Each file is processed independently and requires its own password.\n"
            "\n"
            "Examples:\n"
            "  ccrypt -e  plaintext.txt encrypted.bin\n"
            "  ccrypt -d  encrypted.bin decrypted.txt\n"
            "  ccrypt -ev plaintext.txt encrypted.bin\n"
            "  ccrypt -dv encrypted.bin decrypted.txt\n"
            "\n"
            "  ccrypt -e  file1.txt,file2.txt,file3.txt encrypted1.bin,encrypted2.bin,encrypted3.bin\n"
            "  ccrypt -d  encrypted1.bin,encrypted2.bin,encrypted3.bin decrypted1.txt,decrypted2.txt,decrypted3.txt\n"
            "  ccrypt -ev file1.txt,file2.txt encrypted1.bin,encrypted2.bin\n"
            "  ccrypt -dv encrypted1.bin,encrypted2.bin decrypted1.txt,decrypted2.txt\n");
    }

    // Encryption
    else if (strcmp(argv[1], "-e") == 0 || strcmp(argv[1], "-ev") == 0)
    {
        if (argc != 4)
        {
            fprintf(stderr, "Too many or insufficient arguments\n");
            return 1;
        }

        interrupted = 0; // resetting SIG_INT handler
        if (batch_processing(argv[2], argv[3], argv[1]) != 0)
        {
            return 1;
        }
    }

    // Decryption
    if (strcmp(argv[1], "-d") == 0 || strcmp(argv[1], "-dv") == 0)
    {

        if (argc != 4)
        {
            fprintf(stderr, "Too many or insufficient arguments\n");
            return 1;
        }

        interrupted = 0;
        if (batch_processing(argv[2], argv[3], argv[1]) != 0)
        {
            return 1;
        }
    }

    return 0;
}