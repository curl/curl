
TARGET = libjavacurl.so

OBJS = javacurl.o

CC = gcc
CFLAGS = -c
CPPFLAGS = -I/usr/j2se/include -I/usr/local/include -I/usr/j2se/include/solaris

# Linux might use -shared -Wl,-soname,libnative.so instead of -G
LDFLAGS = -G -lcurl -ldl -L/usr/local/ssl/lib -lssl -lcrypto

all: CurlGlue.h CurlGlue.class javacurl.o $(TARGET) test.class

test:
	java test

javacurl.o: javacurl.c CurlGlue.h
	$(CC) $(CPPFLAGS) $(CFLAGS) $<

CurlGlue.h: CurlGlue.java CurlGlue.class
	javah CurlGlue
	touch CurlGlue.h

test.class: CurlGlue.class javacurl.o
	javac test.java

CurlGlue.class: CurlGlue.java
	javac $<

$(TARGET): $(OBJS)
	$(CC) -o $(TARGET) $(LDFLAGS) $(OBJS)

clean:
	rm -f javacurl.o CurlGlue.h CurlGlue.class
