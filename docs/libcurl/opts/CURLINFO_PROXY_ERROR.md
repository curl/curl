---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: fetch
Title: FETCHINFO_PROXY_ERROR
Section: 3
Source: libfetch
See-also:
  - FETCHINFO_RESPONSE_CODE (3)
  - fetch_easy_getinfo (3)
  - fetch_easy_setopt (3)
  - libfetch-errors (3)
Protocol:
  - All
Added-in: 7.73.0
---

# NAME

FETCHINFO_PROXY_ERROR - get the detailed (SOCKS) proxy error

# SYNOPSIS

~~~c
#include <fetch/fetch.h>

typedef enum {
  FETCHPX_OK,
  FETCHPX_BAD_ADDRESS_TYPE,
  FETCHPX_BAD_VERSION,
  FETCHPX_CLOSED,
  FETCHPX_GSSAPI,
  FETCHPX_GSSAPI_PERMSG,
  FETCHPX_GSSAPI_PROTECTION,
  FETCHPX_IDENTD,
  FETCHPX_IDENTD_DIFFER,
  FETCHPX_LONG_HOSTNAME,
  FETCHPX_LONG_PASSWD,
  FETCHPX_LONG_USER,
  FETCHPX_NO_AUTH,
  FETCHPX_RECV_ADDRESS,
  FETCHPX_RECV_AUTH,
  FETCHPX_RECV_CONNECT,
  FETCHPX_RECV_REQACK,
  FETCHPX_REPLY_ADDRESS_TYPE_NOT_SUPPORTED,
  FETCHPX_REPLY_COMMAND_NOT_SUPPORTED,
  FETCHPX_REPLY_CONNECTION_REFUSED,
  FETCHPX_REPLY_GENERAL_SERVER_FAILURE,
  FETCHPX_REPLY_HOST_UNREACHABLE,
  FETCHPX_REPLY_NETWORK_UNREACHABLE,
  FETCHPX_REPLY_NOT_ALLOWED,
  FETCHPX_REPLY_TTL_EXPIRED,
  FETCHPX_REPLY_UNASSIGNED,
  FETCHPX_REQUEST_FAILED,
  FETCHPX_RESOLVE_HOST,
  FETCHPX_SEND_AUTH,
  FETCHPX_SEND_CONNECT,
  FETCHPX_SEND_REQUEST,
  FETCHPX_UNKNOWN_FAIL,
  FETCHPX_UNKNOWN_MODE,
  FETCHPX_USER_REJECTED,
  FETCHPX_LAST /* never use */
} FETCHproxycode;

FETCHcode fetch_easy_getinfo(FETCH *handle, FETCHINFO_PROXY_ERROR, long *detail);
~~~

# DESCRIPTION

Pass a pointer to a long to receive a detailed error code when the most recent
transfer returned a **FETCHE_PROXY** error. That error code matches the
**FETCHproxycode** set.

The error code is zero (**FETCHPX_OK**) if no response code was available.

# %PROTOCOLS%

# EXAMPLE

~~~c
int main(void)
{
  FETCH *fetch = fetch_easy_init();
  if(fetch) {
    FETCHcode res;
    fetch_easy_setopt(fetch, FETCHOPT_URL, "https://example.com");

    fetch_easy_setopt(fetch, FETCHOPT_PROXY, "socks5://127.0.0.1");
    res = fetch_easy_perform(fetch);
    if(res == FETCHE_PROXY) {
      long proxycode;
      res = fetch_easy_getinfo(fetch, FETCHINFO_PROXY_ERROR, &proxycode);
      if(!res && proxycode)
        printf("The detailed proxy error: %ld\n", proxycode);
    }
    fetch_easy_cleanup(fetch);
  }
}
~~~

# %AVAILABILITY%

# RETURN VALUE

fetch_easy_getinfo(3) returns a FETCHcode indicating success or error.

FETCHE_OK (0) means everything was OK, non-zero means an error occurred, see
libfetch-errors(3).
