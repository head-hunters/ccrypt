CC = gcc
CFLAGS = -Wall -Wextra -Wpedantic -std=c11 -D_POSIX_C_SOURCE=200809L -D_FILE_OFFSET_BITS=64 -Iinclude
LDLIBS = -largon2 -lcrypto
TARGET = build/ccrypt
SOURCE = src/main.c src/encrypt.c src/decrypt.c src/dumper.c src/helpers.c src/batch.c

all: $(TARGET)

$(TARGET): $(SOURCE)
	$(CC) $(CFLAGS) $(SOURCE) -o $(TARGET) $(LDLIBS)

clean:
	rm -f $(TARGET)

.PHONY: all clean