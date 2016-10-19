#makefile for traffic_debug

CC = gcc
CFLAGS = -Wall -Werror -g

all: traffic_debug

traffic_debug: traffic_debug.o detect_init.o detect_stream.o callback_detect_stream.o callback_stream_analyze.o callback_stream_log.o
	$(CC) $(CFLAGS) -o traffic_debug detect_init.o traffic_debug.o detect_stream.o callback_detect_stream.o callback_stream_analyze.o callback_stream_log.o -lpcap

traffic_debug.o: traffic_debug.c traffic_debug.h callback_stream_log.h callback_stream_analyze.h callback_detect_stream.h detect_stream.h
	$(CC) $(CFLAGS) -c traffic_debug.c
	
callback_stream_log.o: callback_stream_log.c callback_stream_log.h
	$(CC) $(CFLAGS) -c callback_stream_log.c

callback_stream_analyze.o: callback_stream_analyze.c callback_stream_analyze.h
	$(CC) $(CFLAGS) -c callback_stream_analyze.c

callback_detect_stream.o: callback_detect_stream.c callback_detect_stream.h
	$(CC) $(CFLAGS) -c callback_detect_stream.c

detect_stream.o: detect_stream.c detect_stream.h
	$(CC) $(CFLAGS) -c detect_stream.c

detect_init.o: detect_init.c detect_init.h
	$(CC) $(CFLAGS) -c detect_init.c

clean:
	rm -f ~* *.o traffic_debug
