---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: fetch
Title: FETCHOPT_FOLLOWLOCATION
Section: 3
Source: libfetch
See-also:
  - FETCHINFO_REDIRECT_COUNT (3)
  - FETCHINFO_REDIRECT_URL (3)
  - FETCHOPT_POSTREDIR (3)
  - FETCHOPT_PROTOCOLS_STR (3)
  - FETCHOPT_REDIR_PROTOCOLS_STR (3)
  - FETCHOPT_UNRESTRICTED_AUTH (3)
Protocol:
  - HTTP
Added-in: 7.1
---

# NAME

FETCHOPT_FOLLOWLOCATION - follow HTTP 3xx redirects

# SYNOPSIS

~~~c
#include <fetch/fetch.h>

FETCHcode fetch_easy_setopt(FETCH *handle, FETCHOPT_FOLLOWLOCATION, long enable);
~~~

# DESCRIPTION

A long parameter set to 1 tells the library to follow any Location: header
redirects that an HTTP server sends in a 30x response. The Location: header
can specify a relative or an absolute URL to follow.

libfetch issues another request for the new URL and follows subsequent new
`Location:` redirects all the way until no more such headers are returned or
the maximum limit is reached. FETCHOPT_MAXREDIRS(3) is used to limit the number
of redirects libfetch follows.

libfetch restricts what protocols it automatically follow redirects to. The
accepted target protocols are set with FETCHOPT_REDIR_PROTOCOLS_STR(3). By
default libfetch allows HTTP, HTTPS, FTP and FTPS on redirects.

When following a redirect, the specific 30x response code also dictates which
request method libfetch uses in the subsequent request: For 301, 302 and 303
responses libfetch switches method from POST to GET unless FETCHOPT_POSTREDIR(3)
instructs libfetch otherwise. All other redirect response codes make libfetch
use the same method again.

For users who think the existing location following is too naive, too simple
or just lacks features, it is easy to instead implement your own redirect
follow logic with the use of fetch_easy_getinfo(3)'s FETCHINFO_REDIRECT_URL(3)
option instead of using FETCHOPT_FOLLOWLOCATION(3).

By default, libfetch only sends `Authentication:` or explicitly set `Cookie:`
headers to the initial host given in the original URL, to avoid leaking
username + password to other sites. FETCHOPT_UNRESTRICTED_AUTH(3) is provided
to change that behavior.

Due to the way HTTP works, almost any header can be made to contain data a
client may not want to pass on to other servers than the initially intended
host and for all other headers than the two mentioned above, there is no
protection from this happening when libfetch is told to follow redirects.

# NOTE

Since libfetch changes method or not based on the specific HTTP response code,
setting FETCHOPT_CUSTOMREQUEST(3) while following redirects may change what
libfetch would otherwise do and if not that carefully may even make it
misbehave since FETCHOPT_CUSTOMREQUEST(3) overrides the method libfetch would
otherwise select internally.

# DEFAULT

0, disabled

# %PROTOCOLS%

# EXAMPLE

~~~c
int main(void)
{
  FETCH *fetch = fetch_easy_init();
  if(fetch) {
    fetch_easy_setopt(fetch, FETCHOPT_URL, "https://example.com");

    /* example.com is redirected, so we tell libfetch to follow redirection */
    fetch_easy_setopt(fetch, FETCHOPT_FOLLOWLOCATION, 1L);

    fetch_easy_perform(fetch);
  }
}
~~~

# %AVAILABILITY%

# RETURN VALUE

fetch_easy_setopt(3) returns a FETCHcode indicating success or error.

FETCHE_OK (0) means everything was OK, non-zero means an error occurred, see
libfetch-errors(3).
