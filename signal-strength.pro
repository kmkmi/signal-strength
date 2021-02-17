

QT += widgets

TEMPLATE = app
QMAKE_CXXFLAGS += -std=c++11

QT+=charts gui
CONFIG += console
CONFIG += c++11
#CONFIG -= app_bundle
#CONFIG -= qt
LIBS += -lpcap -lpthread

SOURCES += main.cpp


HEADERS += \
    main.h
