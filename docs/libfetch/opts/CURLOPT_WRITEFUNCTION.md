---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: fetch
Title: FETCHOPT_WRITEFUNCTION
Section: 3
Source: libfetch
See-also:
  - FETCHOPT_HEADERFUNCTION (3)
  - FETCHOPT_READFUNCTION (3)
  - FETCHOPT_WRITEDATA (3)
Protocol:
  - All
Added-in: 7.1
---

# NAME

FETCHOPT_WRITEFUNCTION - callback for writing received data

# SYNOPSIS

~~~c
#include <fetch/fetch.h>

size_t write_callback(char *ptr, size_t size, size_t nmemb, void *userdata);

FETCHcode fetch_easy_setopt(FETCH *handle, FETCHOPT_WRITEFUNCTION, write_callback);
~~~

# DESCRIPTION

Pass a pointer to your callback function, which should match the prototype
shown above.

This callback function gets called by libfetch as soon as there is data
received that needs to be saved. For most transfers, this callback gets called
many times and each invoke delivers another chunk of data. *ptr* points to the
delivered data, and the size of that data is *nmemb*; *size* is always 1.

The data passed to this function is not null-terminated.

The callback function is passed as much data as possible in all invokes, but
you must not make any assumptions. It may be one byte, it may be
thousands. The maximum amount of body data that is passed to the write
callback is defined in the fetch.h header file: *FETCH_MAX_WRITE_SIZE* (the
usual default is 16K). If FETCHOPT_HEADER(3) is enabled, which makes header
data get passed to the write callback, you can get up to
*FETCH_MAX_HTTP_HEADER* bytes of header data passed into it. This usually means
100K.

This function may be called with zero bytes data if the transferred file is
empty.

Set the *userdata* argument with the FETCHOPT_WRITEDATA(3) option.

Your callback should return the number of bytes actually taken care of. If
that amount differs from the amount passed to your callback function, it
signals an error condition to the library. This causes the transfer to get
aborted and the libfetch function used returns *FETCHE_WRITE_ERROR*.

You can also abort the transfer by returning FETCH_WRITEFUNC_ERROR (added in
7.87.0), which makes *FETCHE_WRITE_ERROR* get returned.

If the callback function returns FETCH_WRITEFUNC_PAUSE it pauses this
transfer. See fetch_easy_pause(3) for further details.

Set this option to NULL to get the internal default function used instead of
your callback. The internal default function writes the data to the FILE *
given with FETCHOPT_WRITEDATA(3).

This option does not enable HSTS, you need to use FETCHOPT_HSTS_CTRL(3) to
do that.

# DEFAULT

fwrite(3)

# %PROTOCOLS%

# EXAMPLE

~~~c
#include <stdlib.h> /* for realloc */
#include <string.h> /* for memcpy */

struct memory {
  char *response;
  size_t size;
};

static size_t cb(char *data, size_t size, size_t nmemb, void *clientp)
{
  size_t realsize = size * nmemb;
  struct memory *mem = (struct memory *)clientp;

  char *ptr = realloc(mem->response, mem->size + realsize + 1);
  if(!ptr)
    return 0;  /* out of memory */

  mem->response = ptr;
  memcpy(&(mem->response[mem->size]), data, realsize);
  mem->size += realsize;
  mem->response[mem->size] = 0;

  return realsize;
}

int main(void)
{
  struct memory chunk = {0};
  FETCHcode res;
  FETCH *fetch = fetch_easy_init();
  if(fetch) {
    /* send all data to this function  */
    fetch_easy_setopt(fetch, FETCHOPT_WRITEFUNCTION, cb);

    /* we pass our 'chunk' struct to the callback function */
    fetch_easy_setopt(fetch, FETCHOPT_WRITEDATA, (void *)&chunk);

    /* send a request */
    res = fetch_easy_perform(fetch);

    /* remember to free the buffer */
    free(chunk.response);

    fetch_easy_cleanup(fetch);
  }
}
~~~

# HISTORY

Support for the FETCH_WRITEFUNC_PAUSE return code was added in version 7.18.0.

# %AVAILABILITY%

# RETURN VALUE

This returns FETCHE_OK.
