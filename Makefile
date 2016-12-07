#makefile for traffic_debug

CC = gcc
CFLAGS = -Wall -g -std=gnu99
LDFLAGS = -lpcap -lpthread # -lncurses

# List of sources
SOURCES = traffic_debug.c handle_init.c detect_stream.c callback_detect_stream.c callback_stream_analyze.c time_analysis.c callback_stream_log.c usertest.c
OBJECTS = $(SOURCES:.c=.o)

# Executable target
EXECUTABLE = traffic_debug

all: $(SOURCES) $(EXECUTABLE)

$(EXECUTABLE): $(OBJECTS)
	$(CC) $(CFLAGS) $(OBJECTS) -o $@ $(LDFLAGS)

traffic_debug.o: traffic_debug.c traffic_debug.h callback_stream_log.h callback_stream_analyze.h time_analysis.h callback_detect_stream.h detect_stream.h handle_init.h usertest.h global.h
	$(CC) $(CFLAGS) -c $<

usertest.o: usertest.c usertest.h
	$(CC) $(CFLAGS) -c $<

callback_stream_log.o: callback_stream_log.c callback_stream_log.h
	$(CC) $(CFLAGS) -c $<

callback_stream_analyze.o: callback_stream_analyze.c callback_stream_analyze.h time_analysis.h
	$(CC) $(CFLAGS) -c $<

time_analysis.o: time_analysis.c time_analysis.h
	$(CC) $(CFLAGS) -c $<

callback_detect_stream.o: callback_detect_stream.c callback_detect_stream.h
	$(CC) $(CFLAGS) -c $<

detect_stream.o: detect_stream.c detect_stream.h
	$(CC) $(CFLAGS) -c $<

handle_init.o: handle_init.c handle_init.h
	$(CC) $(CFLAGS) -c $<

clean:
	rm $(OBJECTS) $(EXECUTABLE)
