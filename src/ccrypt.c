#include "encrypt.h"
#include "decrypt.h"
#include "dumper.h"

int main(int argc, char *argv[])
{
    const char *arguments[] = {"-e", "-d"};
    int num_args = sizeof(arguments) / sizeof(arguments[0]);

    if (argc != 4)
    {
        printf("Usage: ./ccrypt -argument <source> <destination>\n");
        return 1;
    }

    int found = 0;
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
        printf("Invalid Argument '%s'\n", argv[1]);
        printf("Usage: ./ccrypt -argument <source> <destination>\n");
        return 1;
    }

    // Encryption
    if (strcmp(argv[1], "-e") == 0)
    {
        if (encrypt_file(argv[2], argv[3]) != 0)
        {
            return 1;
        }
    }

    // Decryption
    if (strcmp(argv[1], "-d") == 0)
    {
        if (decrypt_file(argv[2], argv[3]) != 0)
        {
            return 1;
        }
    }

    printf("Source\n");
    dumper(argv[2]);
    printf("Destination\n");
    dumper(argv[3]);
    return 0;
}