---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: fetch
Title: FETCHOPT_ALTSVC_CTRL
Section: 3
Source: libfetch
See-also:
  - FETCHOPT_ALTSVC (3)
  - FETCHOPT_CONNECT_TO (3)
  - FETCHOPT_RESOLVE (3)
Protocol:
  - HTTP
Added-in: 7.64.1
---

# NAME

FETCHOPT_ALTSVC_CTRL - control alt-svc behavior

# SYNOPSIS

~~~c
#include <fetch/fetch.h>

#define FETCHALTSVC_READONLYFILE (1<<2)
#define FETCHALTSVC_H1           (1<<3)
#define FETCHALTSVC_H2           (1<<4)
#define FETCHALTSVC_H3           (1<<5)

FETCHcode fetch_easy_setopt(FETCH *handle, FETCHOPT_ALTSVC_CTRL, long bitmask);
~~~

# DESCRIPTION

Populate the long *bitmask* with the correct set of features to instruct
libfetch how to handle Alt-Svc for the transfers using this handle.

libfetch only accepts Alt-Svc headers over a Secure Transport, meaning
HTTPS. It also only completes a request to an alternative origin if that
origin is properly hosted over HTTPS. These requirements are there to make
sure both the source and the destination are legitimate.

Alternative services are only used when setting up new connections. If there
exists an existing connection to the host in the connection pool, then that is
preferred.

If FETCHOPT_ALTSVC(3) is set, FETCHOPT_ALTSVC_CTRL(3) gets a default value
corresponding to FETCHALTSVC_H1 | FETCHALTSVC_H2 | FETCHALTSVC_H3 - the HTTP/2
and HTTP/3 bits are only set if libfetch was built with support for those
versions.

Setting any bit enables the alt-svc engine.

## FETCHALTSVC_READONLYFILE

Do not write the alt-svc cache back to the file specified with
FETCHOPT_ALTSVC(3) even if it gets updated. By default a file specified
with that option is read and written to as deemed necessary.

## FETCHALTSVC_H1

Accept alternative services offered over HTTP/1.1.

## FETCHALTSVC_H2

Accept alternative services offered over HTTP/2. This is only used if libfetch
was also built to actually support HTTP/2, otherwise this bit is ignored.

## FETCHALTSVC_H3

Accept alternative services offered over HTTP/3. This is only used if libfetch
was also built to actually support HTTP/3, otherwise this bit is ignored.

# DEFAULT

0 - Alt-Svc handling is disabled

# %PROTOCOLS%

# EXAMPLE

~~~c
int main(void)
{
  FETCH *fetch = fetch_easy_init();
  if(fetch) {
    fetch_easy_setopt(fetch, FETCHOPT_ALTSVC_CTRL, (long)FETCHALTSVC_H1);
    fetch_easy_setopt(fetch, FETCHOPT_ALTSVC, "altsvc-cache.txt");
    fetch_easy_perform(fetch);
  }
}
~~~

# %AVAILABILITY%

# RETURN VALUE

fetch_easy_setopt(3) returns a FETCHcode indicating success or error.

FETCHE_OK (0) means everything was OK, non-zero means an error occurred, see
libfetch-errors(3).
