# General
Gisle Vanem made curl build fine on DOS (and MinGW) with djgpp, OpenSSL and his
Watt-32 stack.

Andre Seidelt builds cURL using DJGPP with Watt32 2.2dev.rel.11 and mbedTLS 2.28.1.

You might need to adjust the path variables to Watt32 and OpenSSL or mbedTLS in `common-openssl.dj` or `common-mbedtls.dj`

# OpenSSL
'make -f Makefile.dist djgpp' in the root curl dir should build it fine.
Or enter 'lib' and do a 'make -f Makefile.dj clean all' to first delete
'lib/curl_config.h' which is possibly from a previous incompatible Windows-build.

Note 1: djgpp 2.04 beta has a sscanf() bug so the URL parsing isn't
        done properly. Use djgpp 2.03 until they fix it.

Note 2: Compile Watt-32 (and OpenSSL) with the same version of djgpp.
        Otherwise things go wrong because things like FS-extensions and
        errnos have been changed between releases.

Note 3: Several 'USE_x' variables in 'common.dj' are on the 'USE_x ?= 0'
        form (conditional variable assignment). So one can build like this:
          c:\curl\lib> make -f makefile.dj USE_OPENSSL=1 USE_ZLIB=1 clean all

# mbedTLS
To build cURL using mbedTLS (>= mbedtls-2.28.1) instead of openssl specify `USE_MBEDTLS=1` instead of `USE_OPENSSL=1`.
E.g.:
```
make -C mbedtls-2.28.1  -f Makefile    lib
make -C curl-7.86.0/lib -f makefile.dj USE_MBEDTLS=1
```
An example configuration for mbedTLS can be found in `example_mbedtls_config.h`. This must either be placed in `mbedtls-2.28.1/include/mbedtls/config.h` or the path to it must be specified when calling GMake using `MBEDTLS_CONFIG_FILE`.

You need to provide an entropy source to mbedTLS for SSL/TLS to work. Below is an example that uses PIT timer 0 values and several runtime parameters to provide some entropy.

mbedTLS/cURL tried to find the trusted certificates in the file cacert.pem, you can fetch the current version using `curl --remote-name --time-cond cacert.pem https://curl.se/ca/cacert.pem`.

```
// add random n data to buffer b and icrement size counter p
#define CURL_ADD_RANDOM(n, p, b)                        \
    {                                                   \
        if (p + sizeof(n) < sizeof(b)) {                \
            memcpy(&b[p], (const void *)&n, sizeof(n)); \
            p += sizeof(n);                             \
        }                                               \
    }

int mbedtls_hardware_poll(void *data, unsigned char *output, size_t len, size_t *olen) {
    uint8_t rnd_buff[40];

    unsigned int pos = 0;
    rnd_buff[pos++] = inportb(0x40);  // PIT timer 0 at ports 40h-43h
    rnd_buff[pos++] = inportb(0x41);
    rnd_buff[pos++] = inportb(0x42);
    rnd_buff[pos++] = inportb(0x43);
    CURL_ADD_RANDOM(DOjS.sys_ticks, pos, rnd_buff);
    CURL_ADD_RANDOM(DOjS.current_frame_rate, pos, rnd_buff);
    CURL_ADD_RANDOM(DOjS.num_allocs, pos, rnd_buff);
    CURL_ADD_RANDOM(DOjS.last_mouse_x, pos, rnd_buff);
    CURL_ADD_RANDOM(DOjS.last_mouse_y, pos, rnd_buff);
    CURL_ADD_RANDOM(DOjS.last_mouse_b, pos, rnd_buff);

    // find smaller of the two
    *olen = pos < len ? pos : len;

    // copy to output buffer
    memcpy(output, rnd_buff, *olen);

    // always success
    return 0;
}
```
