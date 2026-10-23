CC = gcc
CFLAGS = -Wall -Wextra -Wpedantic -std=c11
TARGET = src/ccrypt
SOURCE = src/ccrypt.c

all: $(TARGET)

$(TARGET): $(SOURCE)
	$(CC) $(CFLAGS) $(SOURCE) -o $(TARGET)

clean:
	rm -f $(TARGET)

.PHONY: all clean