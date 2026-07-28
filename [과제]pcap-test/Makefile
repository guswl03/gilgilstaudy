CC := gcc
CFLAGS := -Wall -Wextra -Wpedantic -std=gnu11
LDLIBS := -lpcap
TARGET := pcap-test
SOURCES := pcap-test.c
HEADERS := packet.h

.PHONY: all clean

all: $(TARGET)

$(TARGET): $(SOURCES) $(HEADERS)
	$(CC) $(CFLAGS) -o $@ $(SOURCES) $(LDLIBS)

clean:
	rm -f $(TARGET) *.o
