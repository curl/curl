#
# Build a little app for the Hiper project
# During dev at least, we use a static libcurl.
#

LDFLAGS = -lcrypt -lidn -lssl -lcrypto -ldl -lz -lresolv -L../ares/.libs -lcares
LIBCURL = -L../lib/.libs/ -lcurl
CFLAGS = -I../include -g

all: shiper hiper ulimiter

hiper: hiper.o $(LIBCURL)
	$(CC) -o $@ $< $(LIBCURL) $(LDFLAGS)

hiper.o: hiper.c
	$(CC) $(CFLAGS) -c $<

shiper: shiper.o $(LIBCURL)
	$(CC) -o $@ $< $(LIBCURL) $(LDFLAGS)

shiper.o: shiper.c
	$(CC) $(CFLAGS) -c $<

ulimiter: ulimiter.c
	$(CC) -o $@ $<

clean:
	rm -f hiper.o hiper shiper shiper.o *~ ulimiter

$(LIBCURL):
	(cd ../lib && make)
