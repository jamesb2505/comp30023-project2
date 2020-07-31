
CC     = gcc
CFLAGS = -Wall -Wpedantic -std=c99 -O2
CRACK  = crack
DH     = dh
OBJ    = main.o sha256.o
DEPS   = sha256.h

all: $(CRACK)

$(CRACK): $(OBJ) $(DEPS)
	$(CC) -o $@ $^ $(CFLAGS)

$(DH):
	$(CC) -o $@ $@.c $(CFLAGS)

%.o: %.c $(DEPS)
	$(CC) -c -o $@ $< $(CFLAGS)


.PHONY: clean cleanly all CLEAN

clean:
	rm -f $(OBJ)
CLEAN: clean
	rm -f $(CRACK) $(DH)
cleanly: all clean
