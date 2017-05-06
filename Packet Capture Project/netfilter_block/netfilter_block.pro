TEMPLATE = app
CONFIG += console c++11
CONFIG -= app_bundle
CONFIG -= qt
LIBS += -lnetfilter_queue
SOURCES += main.cpp \
    parse.cpp \
    printdata.cpp

HEADERS += \
    parse.h \
    printdata.h

