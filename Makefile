#makefile for traffic-debug

CC = gcc
CFLAGS = -Wall -Werror

all: traffic-debug

traffic-debug: traffic-debug.o
	$(CC) $(CFLAGS) -o traffic-debug traffic-debug.o -lpcap

traffic-debug.o: traffic-debug.c
	$(CC) $(CFLAGS) -c traffic-debug.c

clean:
	rm -f ~* *.o traffic-debug
