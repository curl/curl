#
# Build a little app for the Hiper project
# During dev at least, we use a static libcurl.
#

LDFLAGS = -lcrypt -lidn -lssl -lcrypto -ldl -lz -lresolv -L../ares/.libs -lcares
LIBCURL = -L../lib/.libs/ -lcurl
CFLAGS = -I../include -g -DHAVE_CURL_MULTI_SOCKET

all: hiper ulimiter

hiper: hiper.o $(LIBCURL)
	$(CC) -o $@ $< $(LIBCURL) $(LDFLAGS)

hiper.o: hiper.c
	$(CC) $(CFLAGS) -c $<

ulimiter: ulimiter.c
	$(CC) -o $@ $<

clean:
	rm hiper.o hiper

$(LIBCURL):
	(cd ../lib && make)
