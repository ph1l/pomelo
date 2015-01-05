CC=gcc
CFLAGS=-Wall -g

SRC=pomelo.c
BIN=pomelo
LIBS=-lncurses -lpthread $(shell gpgme-config --thread=pthread --libs)

$(BIN):	Makefile $(SRC) list.h
	$(CC) $(CFLAGS) -o $@ $(SRC) $(LIBS)

.PHONY: clean
clean:
	rm -f $(BIN)
