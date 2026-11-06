#ifndef HELPERS_H
#define HELPERS_H

#include <signal.h>

extern volatile sig_atomic_t interrupted; // shared variable as encrypt/decrypt both need to access it

int read_password(unsigned char *pwd, const char *prompt);
int validate_args(const char *list);

#endif