#makefile for traffic_debug

CC = gcc
CFLAGS = -std=gnu99
LDFLAGS = -lpcap -lpthread

SRCDIR = ./src
OBJDIR = ./obj

VPATH = src

# List of source
SOURCES = $(wildcard $(SRCDIR)/*.c)
OBJECTS = $(patsubst $(SRCDIR)/%.c,$(OBJDIR)/%.o,$(SOURCES))

# Executable target
EXECUTABLE = traffic_debug

all: $(SOURCES) $(EXECUTABLE)

$(EXECUTABLE): $(OBJECTS)
	$(CC) $(CFLAGS) $(OBJECTS) -o $@ $(LDFLAGS)

$(OBJDIR)/traffic_debug.o: traffic_debug.c traffic_debug.h callback_stream_log.h callback_stream_analyze.h time_analysis.h callback_detect_stream.h detect_stream.h handle_init.h usertest.h global.h 
	$(CC) $(CFLAGS) -c $< -o $@

$(OBJDIR)/usertest.o: usertest.c usertest.h
	$(CC) $(CFLAGS) -c $< -o $@

$(OBJDIR)/callback_stream_log.o: callback_stream_log.c callback_stream_log.h
	$(CC) $(CFLAGS) -c $< -o $@

$(OBJDIR)/callback_stream_analyze.o: callback_stream_analyze.c callback_stream_analyze.h time_analysis.h global.h
	$(CC) $(CFLAGS) -c $< -o $@

$(OBJDIR)/time_analysis.o: time_analysis.c time_analysis.h
	$(CC) $(CFLAGS) -c $< -o $@

$(OBJDIR)/callback_detect_stream.o: callback_detect_stream.c callback_detect_stream.h global.h
	$(CC) $(CFLAGS) -c $< -o $@

$(OBJDIR)/detect_stream.o: detect_stream.c detect_stream.h
	$(CC) $(CFLAGS) -c $< -o $@

$(OBJDIR)/handle_init.o: handle_init.c handle_init.h
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm $(OBJECTS) $(EXECUTABLE)
