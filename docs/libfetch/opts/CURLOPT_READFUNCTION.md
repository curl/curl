---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: fetch
Title: FETCHOPT_READFUNCTION
Section: 3
Source: libfetch
See-also:
  - FETCHOPT_POST (3)
  - FETCHOPT_READDATA (3)
  - FETCHOPT_SEEKFUNCTION (3)
  - FETCHOPT_UPLOAD (3)
  - FETCHOPT_UPLOAD_BUFFERSIZE (3)
  - FETCHOPT_WRITEFUNCTION (3)
Protocol:
  - All
Added-in: 7.1
---

# NAME

FETCHOPT_READFUNCTION - read callback for data uploads

# SYNOPSIS

~~~c
#include <fetch/fetch.h>

size_t read_callback(char *buffer, size_t size, size_t nitems, void *userdata);

FETCHcode fetch_easy_setopt(FETCH *handle, FETCHOPT_READFUNCTION, read_callback);
~~~

# DESCRIPTION

Pass a pointer to your callback function, as the prototype shows above.

This callback function gets called by libfetch as soon as it needs to read data
in order to send it to the peer - like if you ask it to upload or post data to
the server. The data area pointed at by the pointer *buffer* should be
filled up with at most *size* multiplied with *nitems* number of bytes
by your function. *size* is always 1.

Set the *userdata* argument with the FETCHOPT_READDATA(3) option.

Your function must return the actual number of bytes that it stored in the
data area pointed at by the pointer *buffer*. Returning 0 signals
end-of-file to the library and causes it to stop the current transfer.

If you stop the current transfer by returning 0 "pre-maturely" (i.e before the
server expected it, like when you have said you would upload N bytes and you
upload less than N bytes), you may experience that the server "hangs" waiting
for the rest of the data that is not sent.

The read callback may return *FETCH_READFUNC_ABORT* to stop the current
operation immediately, resulting in a *FETCHE_ABORTED_BY_CALLBACK* error
code from the transfer.

The callback can return *FETCH_READFUNC_PAUSE* to cause reading from this
connection to pause. See fetch_easy_pause(3) for further details.

**Bugs**: when doing TFTP uploads, you must return the exact amount of data
that the callback wants, or it is considered the final packet by the server
end and the transfer ends there.

If you set this callback pointer to NULL, or do not set it at all, the default
internal read function is used. It is doing an fread() on the FILE * userdata
set with FETCHOPT_READDATA(3).

You can set the total size of the data you are sending by using
FETCHOPT_INFILESIZE_LARGE(3) or FETCHOPT_POSTFIELDSIZE_LARGE(3),
depending on the type of transfer. For some transfer types it may be required
and it allows for better error checking.

# DEFAULT

fread(3)

# %PROTOCOLS%

# EXAMPLE

~~~c
size_t read_callback(char *ptr, size_t size, size_t nmemb, void *userdata)
{
  FILE *readhere = (FILE *)userdata;
  fetch_off_t nread;

  /* copy as much data as possible into the 'ptr' buffer, but no more than
     'size' * 'nmemb' bytes. */
  size_t retcode = fread(ptr, size, nmemb, readhere);

  nread = (fetch_off_t)retcode;

  fprintf(stderr, "*** We read %" FETCH_FORMAT_FETCH_OFF_T
          " bytes from file\n", nread);
  return retcode;
}

int main(int argc, char **argv)
{
  FILE *file = fopen(argv[1], "rb");
  FETCHcode result;

  FETCH *fetch = fetch_easy_init();
  if(fetch) {
    /* set callback to use */
    fetch_easy_setopt(fetch, FETCHOPT_READFUNCTION, read_callback);

    /* pass in suitable argument to callback */
    fetch_easy_setopt(fetch, FETCHOPT_READDATA, (void *)file);

    result = fetch_easy_perform(fetch);
  }
}
~~~

# HISTORY

FETCH_READFUNC_PAUSE return code was added in 7.18.0 and FETCH_READFUNC_ABORT
was added in 7.12.1.

# %AVAILABILITY%

# RETURN VALUE

This returns FETCHE_OK.
