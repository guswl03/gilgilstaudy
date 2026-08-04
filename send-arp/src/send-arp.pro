TEMPLATE = app
CONFIG += console c++11
CONFIG -= app_bundle
CONFIG -= qt
LIBS += -lpcap
TARGET = send-arp

SOURCES += \
	arphdr.cpp \
	arpmanager.cpp \
	ethhdr.cpp \
	ip.cpp \
	mac.cpp \
	main.cpp \
	netinfo.cpp

HEADERS += \
	arphdr.h \
	arpmanager.h \
	ethhdr.h \
	ip.h \
	mac.h \
	netinfo.h
