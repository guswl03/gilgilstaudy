TEMPLATE = app
CONFIG += console
CONFIG -= app_bundle
CONFIG -= qt

QMAKE_CFLAGS += -std=gnu11
LIBS += -lpcap

SOURCES += pcap-test.c
HEADERS += packet.h
