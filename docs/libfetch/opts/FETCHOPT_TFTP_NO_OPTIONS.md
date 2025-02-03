---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: fetch
Title: FETCHOPT_TFTP_NO_OPTIONS
Section: 3
Source: libfetch
See-also:
  - FETCHOPT_TFTP_BLKSIZE (3)
Protocol:
  - TFTP
Added-in: 7.48.0
---

# NAME

FETCHOPT_TFTP_NO_OPTIONS - send no TFTP options requests

# SYNOPSIS

~~~c
#include <fetch/fetch.h>

FETCHcode fetch_easy_setopt(FETCH *handle, FETCHOPT_TFTP_NO_OPTIONS, long onoff);
~~~

# DESCRIPTION

Set *onoff* to 1L to exclude all TFTP options defined in RFC 2347,
RFC 2348 and RFC 2349 from read and write requests.

This option improves interoperability with legacy servers that do not
acknowledge or properly implement TFTP options. When this option is used
FETCHOPT_TFTP_BLKSIZE(3) is ignored.

# DEFAULT

0

# %PROTOCOLS%

# EXAMPLE

~~~c
size_t write_callback(char *ptr, size_t size, size_t nmemb, void *fp)
{
  return fwrite(ptr, size, nmemb, (FILE *)fp);
}

int main(void)
{
  FETCH *fetch = fetch_easy_init();
  if(fetch) {
    FILE *fp = fopen("foo.bin", "wb");
    if(fp) {
      fetch_easy_setopt(fetch, FETCHOPT_WRITEDATA, (void *)fp);
      fetch_easy_setopt(fetch, FETCHOPT_WRITEFUNCTION, write_callback);

      fetch_easy_setopt(fetch, FETCHOPT_URL, "tftp://example.com/foo.bin");

      /* do not send TFTP options requests */
      fetch_easy_setopt(fetch, FETCHOPT_TFTP_NO_OPTIONS, 1L);

      /* Perform the request */
      fetch_easy_perform(fetch);

      fclose(fp);
    }
    fetch_easy_cleanup(fetch);
  }
}
~~~

# %AVAILABILITY%

# RETURN VALUE

fetch_easy_setopt(3) returns a FETCHcode indicating success or error.

FETCHE_OK (0) means everything was OK, non-zero means an error occurred, see
libfetch-errors(3).
