#include "dumper.h"
#include "constants.h"

#include <stdio.h>

int dumper(const char *file)
{
    unsigned char buffer[BUFFER_SIZE];
    size_t offset = 0;
    size_t read_bytes;
    FILE *dump_ptr;
    dump_ptr = fopen(file, "rb");
    if (dump_ptr == NULL)
    {
        perror("Invalid filename or the file doesn't exist");
        return 1;
    }
    printf("\n");
    while ((read_bytes = fread(buffer, 1, BUFFER_SIZE, dump_ptr)) > 0)
    {
        int counter = 0;
        for (size_t i = 0; i < read_bytes; i++)
        {

            if (counter == 0)
            {
                printf("%08zx  ", offset);
            }
            printf("%02x ", buffer[i]);
            offset++;
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