#makefile for traffic-debug

CC = gcc
CFLAGS = -Wall -Werror

all: pcap-test

pcap-test: pcap-test.o
	$(CC) $(CFLAGS) -o pcap-test pcap-test.o -lpcap

pcap-test.o: pcap-test.c
	$(CC) $(CFLAGS) -c pcap-test.c

clean:
	rm -f ~* *.o pcap-test
