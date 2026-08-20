CXX ?= g++
CPPFLAGS ?= -Iinclude
CXXFLAGS ?= -std=c++17 -O2 -Wall -Wextra -Wpedantic
LDLIBS ?= -lpcap

TARGET := airodump

SOURCES := src/main.cpp src/packet_parser.cpp src/ap_table.cpp
OBJECTS := $(SOURCES:src/%.cpp=build/%.o)

.PHONY: all clean

all: $(TARGET)

$(TARGET): $(OBJECTS)
	$(CXX) $(CXXFLAGS) -o $@ $(OBJECTS) $(LDLIBS)

build/%.o: src/%.cpp
	@mkdir -p build
	$(CXX) $(CPPFLAGS) $(CXXFLAGS) -c $< -o $@

clean:
	rm -rf build $(TARGET)
