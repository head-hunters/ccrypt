#include "encrypt.h"
#include "decrypt.h"
#include "helpers.h"
#include "dumper.h"

#include <string.h>
#include <stdio.h>
#include <stdlib.h>

int batch_processing(const char *source, const char *destination, const char *option)
{

    int status = 0;
    int failed = 0;
    char **source_files = NULL;
    char **destination_files = NULL;
    char *source_copy = NULL;
    char *destination_copy = NULL;
    char *token = NULL;

    if (source == NULL || destination == NULL || option == NULL)
    {
        fprintf(stderr, "Invalid source/destination/option\n");
        return 1;
    }

    if (validate_args(source) == 1 || validate_args(destination) == 1)
    {
        fprintf(stderr, "Invalid source or destination file list\n");
        return 1;
    }

    // Check if the number of sources == number of destinations
    size_t source_count = 1;
    size_t destination_count = 1;

    for (size_t i = 0; source[i] != '\0'; i++)
    {
        if (source[i] == ',')
        {
            source_count++;
        }
    }

    for (size_t i = 0; destination[i] != '\0'; i++)
    {
        if (destination[i] == ',')
        {
            destination_count++;
        }
    }

    if (source_count != destination_count)
    {
        fprintf(stderr, "Number of source and destination files do not match\n");
        return 1;
    }

    // Tokenising string and storing the tokens in an array to individually process
    source_files = calloc(source_count, sizeof(char *));
    if (source_files == NULL)
    {
        fprintf(stderr, "Allocating memory to source array has failed\n");
        goto cleanup;
    }
    destination_files = calloc(destination_count, sizeof(char *));
    if (destination_files == NULL)
    {
        fprintf(stderr, "Allocating memory to destination array has failed\n");
        goto cleanup;
    }

    source_copy = strdup(source);
    if (source_copy == NULL)
    {
        fprintf(stderr, "Error creating a copy of source file list\n");
        goto cleanup;
    }
    destination_copy = strdup(destination);
    if (destination_copy == NULL)
    {
        fprintf(stderr, "Error creating a copy of the destination file list\n");
        goto cleanup;
    }

    token = strtok(source_copy, ",");
    if (token == NULL)
    {
        fprintf(stderr, "Error tokenising source array\n");
        goto cleanup;
    }
    for (size_t i = 0; i < source_count; i++)
    {
        if (token == NULL)
        {
            fprintf(stderr, "Error tokenising source array\n");
            goto cleanup;
        }
        source_files[i] = token;
        token = strtok(NULL, ",");
    }

    token = strtok(destination_copy, ",");
    if (token == NULL)
    {
        fprintf(stderr, "Error tokenising destination array\n");
        goto cleanup;
    }
    for (size_t i = 0; i < destination_count; i++)
    {
        if (token == NULL)
        {
            fprintf(stderr, "Error tokenising destination array\n");
            goto cleanup;
        }
        destination_files[i] = token;
        token = strtok(NULL, ",");
    }

    if (strcmp(option, "-e") == 0 || strcmp(option, "-ev") == 0)
    {
        for (size_t i = 0; i < source_count; i++)
        {
            printf("\nEncrypting File %zu of %zu\n", i + 1, source_count);
            printf("Input: %s\nOutput: %s\n", source_files[i], destination_files[i]);
            if (encrypt_file(source_files[i], destination_files[i]) != 0)
            {
                fprintf(stderr, "Error encrypting File %zu\n", i + 1);
                failed += 1;
                status = 1;
                continue;
            }

            if (strcmp(option, "-ev") == 0)
            {
                printf("\nSource\n");
                if (dumper(source_files[i]) != 0)
                {
                    fprintf(stderr, "Error printing source bytes of File %zu\n", i + 1);
                    status = 1;
                }
                printf("\nDestination\n");
                if (dumper(destination_files[i]) != 0)
                {
                    fprintf(stderr, "Error printing destination bytes of File %zu\n", i + 1);
                    status = 1;
                }
            }
        }
        printf("Encrypted %zu out of %zu Files\n", source_count - failed, source_count);
    }
    else if (strcmp(option, "-d") == 0 || strcmp(option, "-dv") == 0)
    {
        for (size_t i = 0; i < destination_count; i++)
        {
            printf("\nDecrypting File %zu of %zu\n", i + 1, destination_count);
            printf("Input: %s\nOutput: %s\n", source_files[i], destination_files[i]);
            if (decrypt_file(source_files[i], destination_files[i]) != 0)
            {
                fprintf(stderr, "Error decrypting File %zu\n", i + 1);
                failed += 1;
                status = 1;
                continue;
            }

            if (strcmp(option, "-dv") == 0)
            {
                printf("\nSource\n");
                if (dumper(source_files[i]) != 0)
                {
                    fprintf(stderr, "Error printing source bytes of File %zu\n", i + 1);
                    status = 1;
                }
                printf("\nDestination\n");
                if (dumper(destination_files[i]) != 0)
                {
                    fprintf(stderr, "Error printing destination bytes of File %zu\n", i + 1);
                    status = 1;
                }
            }
        }
        printf("Decrypted %zu out of %zu Files\n", destination_count - failed, destination_count);
    }

cleanup:
    free(source_files);
    free(destination_files);
    free(source_copy);
    free(destination_copy);
    return status;
}