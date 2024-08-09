---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Title: CURLSHOPT_DEBUGFUNCTION
Section: 3
Source: libcurl
See-also:
  - CURLINFO_CONN_ID (3)
  - CURLINFO_XFER_ID (3)
  - CURLSHOPT_DEBUGDATA (3)
  - CURLSHOPT_VERBOSE (3)
  - curl_global_trace (3)
Protocol:
  - All
Added-in: 8.10.0
---

# NAME

CURLSHOPT_DEBUGFUNCTION - debug callback

# SYNOPSIS

~~~c
#include <curl/curl.h>

typedef enum {
  CURLINFO_TEXT = 0,
  CURLINFO_HEADER_IN,    /* 1 */
  CURLINFO_HEADER_OUT,   /* 2 */
  CURLINFO_DATA_IN,      /* 3 */
  CURLINFO_DATA_OUT,     /* 4 */
  CURLINFO_SSL_DATA_IN,  /* 5 */
  CURLINFO_SSL_DATA_OUT, /* 6 */
  CURLINFO_END
} curl_infotype;

int debug_callback(CURLSH *share,
                   CURL *handle,
                   curl_infotype type,
                   char *data,
                   size_t size,
                   void *clientp);

CURLSHcode curl_share_setopt(CURLSH *share, CURLSHOPT_DEBUGFUNCTION,
                             debug_callback);
~~~

# DESCRIPTION

Pass a pointer to your callback function, which should match the prototype
shown above.

CURLSHOPT_DEBUGFUNCTION(3) adds a debug function used when
CURLSHOPT_VERBOSE(3) is in effect. This callback receives debug
information, as specified in the *type* argument. This function must
return 0. The *data* pointed to by the char * passed to this function is
not null-terminated, but is exactly of the *size* as told by the
*size* argument.

The *clientp* argument is the pointer set with CURLSHOPT_DEBUGDATA(3).

Available **curl_infotype** values:

## CURLINFO_TEXT

The data is informational text.

## CURLINFO_HEADER_IN

The data is header (or header-like) data received from the peer.

## CURLINFO_HEADER_OUT

The data is header (or header-like) data sent to the peer.

## CURLINFO_DATA_IN

The data is the unprocessed protocol data received from the peer. Even if the
data is encoded or compressed, it is not provided decoded nor decompressed
to this callback. If you need the data in decoded and decompressed form, use
CURLOPT_WRITEFUNCTION(3).

## CURLINFO_DATA_OUT

The data is protocol data sent to the peer.

## CURLINFO_SSL_DATA_OUT

The data is SSL/TLS (binary) data sent to the peer.

## CURLINFO_SSL_DATA_IN

The data is SSL/TLS (binary) data received from the peer.

##

WARNING: This callback may be called with the curl *handle* set to an internal
handle or no *handle* at all, e.g. a *NULL* value. A *NULL* handle may be used
to output debug information of type CURLINFO_TEXT for messages unrelated to
a specific transfer.

If you need to distinguish your curl *handle* from internal handles then set
CURLOPT_PRIVATE(3) on your handle.

# DEFAULT

NULL

# %PROTOCOLS%

# EXAMPLE

~~~c
static
void dump(const char *text,
          FILE *stream, unsigned char *ptr, size_t size)
{
  size_t i;
  size_t c;
  unsigned int width = 0x10;

  fprintf(stream, "%s, %10.10ld bytes (0x%8.8lx)\n",
          text, (long)size, (long)size);

  for(i = 0; i < size; i += width) {
    fprintf(stream, "%4.4lx: ", (long)i);

    /* show hex to the left */
    for(c = 0; c < width; c++) {
      if(i + c < size)
        fprintf(stream, "%02x ", ptr[i + c]);
      else
        fputs("   ", stream);
    }

    /* show data on the right */
    for(c = 0; (c < width) && (i + c < size); c++) {
      char x = (ptr[i + c] >= 0x20 && ptr[i + c] < 0x80) ? ptr[i + c] : '.';
      fputc(x, stream);
    }

    fputc('\n', stream); /* newline */
  }
}

static
int my_share_trace(CURLSH *share, CURL *handle, curl_infotype type,
                   char *data, size_t size,
                   void *clientp)
{
  const char *text;
  (void)share; /* prevent compiler warning */
  (void)handle; /* prevent compiler warning */
  (void)clientp;

  switch(type) {
  case CURLINFO_TEXT:
    fputs("== Info: ", stderr);
    fwrite(data, size, 1, stderr);
  default: /* in case a new one is introduced to shock us */
    return 0;

  case CURLINFO_HEADER_OUT:
    text = "=> Send header";
    break;
  case CURLINFO_DATA_OUT:
    text = "=> Send data";
    break;
  case CURLINFO_SSL_DATA_OUT:
    text = "=> Send SSL data";
    break;
  case CURLINFO_HEADER_IN:
    text = "<= Recv header";
    break;
  case CURLINFO_DATA_IN:
    text = "<= Recv data";
    break;
  case CURLINFO_SSL_DATA_IN:
    text = "<= Recv SSL data";
    break;
  }

  dump(text, stderr, (unsigned char *)data, size);
  return 0;
}

int main(void)
{
  struct priv mydata;
  CURLSH *share = curl_share_init();
  curl_share_setopt(share, CURLSHOPT_DEBUGFUNCTION, my_share_trace);
  curl_share_setopt(multi, CURLSHOPT_DEBUGDATA, &mydata);
}
~~~

# %AVAILABILITY%

# RETURN VALUE

Returns CURLSHE_OK
