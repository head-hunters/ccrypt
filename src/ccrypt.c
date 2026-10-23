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
    if (argc != 3)
    {
        printf("Usage: ./ccrypt <source> <destination>\n");
        return 1;
    }

    copy_file(argv[1], argv[2]);
    printf("Source\n");
    dumper(argv[1]);
    printf("Destination\n");
    dumper(argv[2]);
    return 0;
}