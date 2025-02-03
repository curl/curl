---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: fetch
Title: FETCHOPT_ERRORBUFFER
Section: 3
Source: libfetch
See-also:
  - FETCHOPT_DEBUGFUNCTION (3)
  - FETCHOPT_VERBOSE (3)
  - fetch_easy_strerror (3)
  - fetch_multi_strerror (3)
  - fetch_share_strerror (3)
  - fetch_url_strerror (3)
Protocol:
  - All
Added-in: 7.1
---

# NAME

FETCHOPT_ERRORBUFFER - error buffer for error messages

# SYNOPSIS

~~~c
#include <fetch/fetch.h>

FETCHcode fetch_easy_setopt(FETCH *handle, FETCHOPT_ERRORBUFFER, char *buf);
~~~

# DESCRIPTION

Pass a char pointer to a buffer that libfetch may use to store human readable
error messages on failures or problems. This may be more helpful than just the
return code from fetch_easy_perform(3) and related functions. The buffer must
be at least **FETCH_ERROR_SIZE** bytes big.

You must keep the associated buffer available until libfetch no longer needs
it. Failing to do so might cause odd behavior or even crashes. libfetch might
need it until you call fetch_easy_cleanup(3) or you set the same option again
to use a different pointer.

Do not rely on the contents of the buffer unless an error code was returned.
Since 7.60.0 libfetch initializes the contents of the error buffer to an empty
string before performing the transfer. For earlier versions if an error code
was returned but there was no error detail then the buffer was untouched.

Consider FETCHOPT_VERBOSE(3) and FETCHOPT_DEBUGFUNCTION(3) to better debug and
trace why errors happen.

Using this option multiple times makes the last set pointer override the
previous ones. Set it to NULL to disable its use again.

# DEFAULT

NULL

# %PROTOCOLS%

# EXAMPLE

~~~c
#include <string.h> /* for strlen() */
int main(void)
{
  FETCH *fetch = fetch_easy_init();
  if(fetch) {
    FETCHcode res;
    char errbuf[FETCH_ERROR_SIZE];

    fetch_easy_setopt(fetch, FETCHOPT_URL, "https://example.com");

    /* provide a buffer to store errors in */
    fetch_easy_setopt(fetch, FETCHOPT_ERRORBUFFER, errbuf);

    /* set the error buffer as empty before performing a request */
    errbuf[0] = 0;

    /* perform the request */
    res = fetch_easy_perform(fetch);

    /* if the request did not complete correctly, show the error
    information. if no detailed error information was written to errbuf
    show the more generic information from fetch_easy_strerror instead.
    */
    if(res != FETCHE_OK) {
      size_t len = strlen(errbuf);
      fprintf(stderr, "\nlibfetch: (%d) ", res);
      if(len)
        fprintf(stderr, "%s%s", errbuf,
                ((errbuf[len - 1] != '\n') ? "\n" : ""));
      else
        fprintf(stderr, "%s\n", fetch_easy_strerror(res));
    }
  }
}
~~~

# %AVAILABILITY%

# RETURN VALUE

fetch_easy_setopt(3) returns a FETCHcode indicating success or error.

FETCHE_OK (0) means everything was OK, non-zero means an error occurred, see
libfetch-errors(3).
