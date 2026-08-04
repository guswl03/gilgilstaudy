CXXFLAGS += -std=c++11 -Wall -Wextra
LDLIBS += -lpcap

TARGET := send-arp
OBJECTS := main.o arphdr.o arpmanager.o ethhdr.o ip.o mac.o netinfo.o

.PHONY: all clean

all: $(TARGET)

$(TARGET): $(OBJECTS)
	$(CXX) $(LDFLAGS) $^ $(LDLIBS) -o $@

main.o: main.cpp arpmanager.h netinfo.h ethhdr.h arphdr.h mac.h ip.h
arphdr.o: arphdr.cpp arphdr.h mac.h ip.h
arpmanager.o: arpmanager.cpp arpmanager.h ethhdr.h arphdr.h mac.h ip.h
ethhdr.o: ethhdr.cpp ethhdr.h mac.h
ip.o: ip.cpp ip.h
mac.o: mac.cpp mac.h
netinfo.o: netinfo.cpp netinfo.h mac.h ip.h

clean:
	$(RM) $(TARGET) $(OBJECTS)
