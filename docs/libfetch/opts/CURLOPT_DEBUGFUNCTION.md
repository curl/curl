---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: fetch
Title: FETCHOPT_DEBUGFUNCTION
Section: 3
Source: libfetch
See-also:
  - FETCHINFO_CONN_ID (3)
  - FETCHINFO_XFER_ID (3)
  - FETCHOPT_DEBUGDATA (3)
  - FETCHOPT_VERBOSE (3)
  - fetch_global_trace (3)
Protocol:
  - All
Added-in: 7.9.6
---

# NAME

FETCHOPT_DEBUGFUNCTION - debug callback

# SYNOPSIS

~~~c
#include <fetch/fetch.h>

typedef enum {
  FETCHINFO_TEXT = 0,
  FETCHINFO_HEADER_IN,    /* 1 */
  FETCHINFO_HEADER_OUT,   /* 2 */
  FETCHINFO_DATA_IN,      /* 3 */
  FETCHINFO_DATA_OUT,     /* 4 */
  FETCHINFO_SSL_DATA_IN,  /* 5 */
  FETCHINFO_SSL_DATA_OUT, /* 6 */
  FETCHINFO_END
} fetch_infotype;

int debug_callback(FETCH *handle,
                   fetch_infotype type,
                   char *data,
                   size_t size,
                   void *clientp);

FETCHcode fetch_easy_setopt(FETCH *handle, FETCHOPT_DEBUGFUNCTION,
                          debug_callback);
~~~

# DESCRIPTION

Pass a pointer to your callback function, which should match the prototype
shown above.

FETCHOPT_DEBUGFUNCTION(3) replaces the standard debug function used when
FETCHOPT_VERBOSE(3) is in effect. This callback receives debug
information, as specified in the *type* argument. This function must
return 0. The *data* pointed to by the char * passed to this function is
not null-terminated, but is exactly of the *size* as told by the
*size* argument.

The *clientp* argument is the pointer set with FETCHOPT_DEBUGDATA(3).

Available **fetch_infotype** values:

## FETCHINFO_TEXT

The data is informational text.

## FETCHINFO_HEADER_IN

The data is header (or header-like) data received from the peer.

## FETCHINFO_HEADER_OUT

The data is header (or header-like) data sent to the peer.

## FETCHINFO_DATA_IN

The data is the unprocessed protocol data received from the peer. Even if the
data is encoded or compressed, it is not provided decoded nor decompressed
to this callback. If you need the data in decoded and decompressed form, use
FETCHOPT_WRITEFUNCTION(3).

## FETCHINFO_DATA_OUT

The data is protocol data sent to the peer.

## FETCHINFO_SSL_DATA_OUT

The data is SSL/TLS (binary) data sent to the peer.

## FETCHINFO_SSL_DATA_IN

The data is SSL/TLS (binary) data received from the peer.

##

WARNING: This callback may be called with the fetch *handle* set to an internal
handle. (Added in 8.4.0)

If you need to distinguish your fetch *handle* from internal handles then set
FETCHOPT_PRIVATE(3) on your handle.

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
int my_trace(FETCH *handle, fetch_infotype type,
             char *data, size_t size,
             void *clientp)
{
  const char *text;
  (void)handle; /* prevent compiler warning */
  (void)clientp;

  switch(type) {
  case FETCHINFO_TEXT:
    fputs("== Info: ", stderr);
    fwrite(data, size, 1, stderr);
  default: /* in case a new one is introduced to shock us */
    return 0;

  case FETCHINFO_HEADER_OUT:
    text = "=> Send header";
    break;
  case FETCHINFO_DATA_OUT:
    text = "=> Send data";
    break;
  case FETCHINFO_SSL_DATA_OUT:
    text = "=> Send SSL data";
    break;
  case FETCHINFO_HEADER_IN:
    text = "<= Recv header";
    break;
  case FETCHINFO_DATA_IN:
    text = "<= Recv data";
    break;
  case FETCHINFO_SSL_DATA_IN:
    text = "<= Recv SSL data";
    break;
  }

  dump(text, stderr, (unsigned char *)data, size);
  return 0;
}

int main(void)
{
  FETCH *fetch;
  FETCHcode res;

  fetch = fetch_easy_init();
  if(fetch) {
    fetch_easy_setopt(fetch, FETCHOPT_DEBUGFUNCTION, my_trace);

    /* the DEBUGFUNCTION has no effect until we enable VERBOSE */
    fetch_easy_setopt(fetch, FETCHOPT_VERBOSE, 1L);

    /* example.com is redirected, so we tell libfetch to follow redirection */
    fetch_easy_setopt(fetch, FETCHOPT_FOLLOWLOCATION, 1L);

    fetch_easy_setopt(fetch, FETCHOPT_URL, "https://example.com/");
    res = fetch_easy_perform(fetch);
    /* Check for errors */
    if(res != FETCHE_OK)
      fprintf(stderr, "fetch_easy_perform() failed: %s\n",
              fetch_easy_strerror(res));

    /* always cleanup */
    fetch_easy_cleanup(fetch);
  }
  return 0;
}
~~~

# %AVAILABILITY%

# RETURN VALUE

fetch_easy_setopt(3) returns a FETCHcode indicating success or error.

FETCHE_OK (0) means everything was OK, non-zero means an error occurred, see
libfetch-errors(3).
