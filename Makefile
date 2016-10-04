#makefile for traffic-debug

CC = gcc
CFLAGS = -Wall -Werror

all: traffic-debug

traffic-debug: traffic-debug.o detect-stream.o
	$(CC) $(CFLAGS) -o traffic-debug traffic-debug.o detect-stream.o -lpcap

traffic-debug.o: traffic-debug.c detect-stream.h
	$(CC) $(CFLAGS) -c traffic-debug.c

detect-stream.o: detect-stream.c detect-stream.h
	$(CC) $(CFLAGS) -c detect-stream.c

clean:
	rm -f ~* *.o traffic-debug
