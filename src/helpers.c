#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <termios.h>
#include "constants.h"

// This file contains helper functions and functionalities that are shared between encrypt.c and decrypt.c

// For accepting passwords from the user
int read_password(unsigned char *pwd, const char *prompt)
{
    int echo_disabled = 0; // to ensure terminal settings are only restored if echo was successfully disabled
    struct termios old_tty;
    int status = 1; // tracking if the function was successful

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

    printf("%s", prompt);
    fflush(stdout);

    if (fgets((char *)pwd, PWD_SIZE, stdin) == NULL)
    {
        fprintf(stderr, "Error Reading Password\n");

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
    return status;
}

// Validating source and destination file lists
int validate_args(const char *list)
{
    // Checking if the list is empty
    if (list == NULL || list[0] == '\0')
    {
        return 1;
    }
    // Checking for trailing commas
    if (list[0] == ',' || list[strlen(list) - 1] == ',')
    {
        return 1;
    }
    // Checking for consecutive commas
    for (size_t i = 0; list[i] != '\0'; i++)
    {
        if (list[i] == ',' && list[i + 1] == ',')
        {
            return 1;
        }
    }
    return 0;
}