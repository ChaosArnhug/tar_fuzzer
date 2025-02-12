CC = gcc
CFLAGS = -Wall -Wextra -I./src
SRC = src/main.c src/utils.c src/statstable.c
OBJ = $(SRC:.c=.o)
TARGET = tar_fuzzer

all: $(TARGET)

$(TARGET): $(OBJ)
	$(CC) $(CFLAGS) -o $@ $^

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f $(OBJ) $(TARGET)

.PHONY: all clean