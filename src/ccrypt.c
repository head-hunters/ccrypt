#include <stdio.h>
#include <string.h>

#define BUFFER_SIZE 4096

int copy_file(const char *source, const char *destination)
{

    if (strcmp(source, destination) == 0)
    {
        fprintf(stderr, "The source and destination file cannot be the same");
        return 1;
    }

    char buffer[BUFFER_SIZE];
    size_t read_bytes;
    FILE *plain_ptr;
    FILE *encrypt_ptr;

    plain_ptr = fopen(source, "rb");
    if (plain_ptr == NULL)
    {
        perror("Invalid source filename or the source file doesn't exist");
        return 1;
    }
    encrypt_ptr = fopen(destination, "wb");

    if (encrypt_ptr == NULL)
    {
        perror("Invalid destination filename or the destination file doesn't exist");
        fclose(plain_ptr);
        return 1;
    }
    while ((read_bytes = fread(buffer, 1, BUFFER_SIZE, plain_ptr)) > 0)
    {
        if (fwrite(buffer, 1, read_bytes, encrypt_ptr) != read_bytes)
        {
            perror("Error writing to destination file");
            fclose(plain_ptr);
            fclose(encrypt_ptr);
            return 1;
        }
    }

    if (ferror(plain_ptr))
    {
        perror("Error reading the source file");
        fclose(plain_ptr);
        fclose(encrypt_ptr);
        return 1;
    }

    if (fclose(plain_ptr) != 0)
    {
        perror("Error closing the source file");
        fclose(encrypt_ptr);
        return 1;
    }
    if (fclose(encrypt_ptr) != 0)
    {
        perror("Error closing the destination file");
        return 1;
    }
    return 0;
}

int main(int argc, char *argv[])
{
    if (argc != 3)
    {
        printf("Usage: ./ccrypt <source> <destination>\n");
        return 1;
    }

    return copy_file(argv[1], argv[2]);
}