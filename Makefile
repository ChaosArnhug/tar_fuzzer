CC = gcc
CFLAGS = -Wall -Wextra -I./src
SRC = src/help.c src/main.c src/statstable.c
OBJ = $(SRC:.c=.o)

fuzzer: $(OBJ)
	$(CC) -o $@ $^

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f $(OBJ) fuzzer

.PHONY: clean