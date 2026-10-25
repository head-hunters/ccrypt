CC = gcc
CFLAGS = -Wall -Wextra -Wpedantic -std=c11
LDLIBS = -largon2 -lcrypto
TARGET = src/ccrypt
SOURCE = src/ccrypt.c

all: $(TARGET)

$(TARGET): $(SOURCE)
	$(CC) $(CFLAGS) $(SOURCE) -o $(TARGET) $(LDLIBS)

clean:
	rm -f $(TARGET)

.PHONY: all clean