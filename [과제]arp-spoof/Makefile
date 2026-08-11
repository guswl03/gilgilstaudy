CXXFLAGS += -std=c++11 -Wall -Wextra
CPPFLAGS += -Iinclude
LDLIBS += -lpcap

TARGET := arp-spoof
OBJECTS := src/main.o

.PHONY: all clean

all: $(TARGET)

$(TARGET): $(OBJECTS)
	$(CXX) $(LDFLAGS) $^ $(LDLIBS) -o $@

src/main.o: src/main.cpp

clean:
	$(RM) $(TARGET) $(OBJECTS)
