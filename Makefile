
CFILES=$(wildcard src/*.c)
OFILES=$(patsubst src/%.c,target/%.o,$(CFILES))

GLIB_INCLUDE=/usr/include/glib-2.0
WIRESHARK_INCLUDE=/usr/include/wireshark
GLIBCONFIG_INCLUDE=/usr/lib64/glib-2.0/include

WS_VERSION=$(shell wireshark --version | head -n 1 | egrep -o '[0-9.]+')
INSTALL=/usr/lib64/wireshark/plugins/$(WS_VERSION)

#OPT=-O2
CFLAGS=$(OPT) -g -std=gnu99 -fPIC -D_GNU_SOURCE -Wall -Wno-parentheses -Wno-unused-function -DWITH_TRACE -I$(WIRESHARK_INCLUDE) -I$(GLIB_INCLUDE) -I$(GLIBCONFIG_INCLUDE)
LDFLAGS=-shared -lwiretap

CP=cp
SUDO=sudo

TARGET=remoting.so

all: $(TARGET)

install: all
	$(SUDO) $(CP) $(TARGET) $(INSTALL)/$(TARGET)

clean:
	$(RM) $(TARGET) target/*.o target/*.c target/*.h

$(TARGET): $(OFILES)
	$(CC) $(LDFLAGS) -o $(TARGET) $(OFILES)

target/%.o: src/%.c Makefile
	$(CC) -c $(CFLAGS) $(CPPFLAGS) -Iinclude -Itarget $< -o $@

