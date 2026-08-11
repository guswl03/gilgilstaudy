CXXFLAGS += -std=c++11 -Wall -Wextra
CPPFLAGS += -Iinclude
LDLIBS += -lpcap

TARGET := arp-spoof
OBJECTS := src/main.o src/arphdr.o src/arpspoofmanager.o src/ethhdr.o \
	src/ip.o src/mac.o src/netinfo.o

.PHONY: all clean

all: $(TARGET)

$(TARGET): $(OBJECTS)
	$(CXX) $(LDFLAGS) $^ $(LDLIBS) -o $@

src/main.o: src/main.cpp include/arpspoofmanager.h include/netinfo.h include/mac.h include/ip.h
src/arphdr.o: src/arphdr.cpp include/arphdr.h include/mac.h include/ip.h
src/arpspoofmanager.o: src/arpspoofmanager.cpp include/arpspoofmanager.h include/ethhdr.h include/arphdr.h include/mac.h include/ip.h
src/ethhdr.o: src/ethhdr.cpp include/ethhdr.h include/mac.h
src/ip.o: src/ip.cpp include/ip.h
src/mac.o: src/mac.cpp include/mac.h
src/netinfo.o: src/netinfo.cpp include/netinfo.h include/mac.h include/ip.h

clean:
	$(RM) $(TARGET) $(OBJECTS)
