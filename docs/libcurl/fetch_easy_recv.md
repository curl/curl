---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: fetch
Title: fetch_easy_recv
Section: 3
Source: libfetch
See-also:
  - fetch_easy_getinfo (3)
  - fetch_easy_perform (3)
  - fetch_easy_send (3)
  - fetch_easy_setopt (3)
Protocol:
  - All
Added-in: 7.18.2
---

# NAME

fetch_easy_recv - receives raw data on an "easy" connection

# SYNOPSIS

~~~c
#include <fetch/fetch.h>

FETCHcode fetch_easy_recv(FETCH *fetch, void *buffer, size_t buflen, size_t *n);
~~~

# DESCRIPTION

This function receives raw data from the established connection. You may use
it together with fetch_easy_send(3) to implement custom protocols using
libfetch. This functionality can be particularly useful if you use proxies
and/or SSL encryption: libfetch takes care of proxy negotiation and connection
setup.

**buffer** is a pointer to your buffer memory that gets populated by the
received data. **buflen** is the maximum amount of data you can get in that
buffer. The variable **n** points to receives the number of received bytes.

To establish the connection, set FETCHOPT_CONNECT_ONLY(3) option before
calling fetch_easy_perform(3) or fetch_multi_perform(3). Note that
fetch_easy_recv(3) does not work on connections that were created without
this option.

The call returns **FETCHE_AGAIN** if there is no data to read - the socket is
used in non-blocking mode internally. When **FETCHE_AGAIN** is returned, use
your operating system facilities like *select(2)* to wait for data. The
socket may be obtained using fetch_easy_getinfo(3) with
FETCHINFO_ACTIVESOCKET(3).

Wait on the socket only if fetch_easy_recv(3) returns **FETCHE_AGAIN**.
The reason for this is libfetch or the SSL library may internally cache some
data, therefore you should call fetch_easy_recv(3) until all data is
read which would include any cached data.

Furthermore if you wait on the socket and it tells you there is data to read,
fetch_easy_recv(3) may return **FETCHE_AGAIN** if the only data that was
read was for internal SSL processing, and no other data is available.

# %PROTOCOLS%

# EXAMPLE

~~~c
int main(void)
{
  FETCH *fetch = fetch_easy_init();
  if(fetch) {
    FETCHcode res;
    fetch_easy_setopt(fetch, FETCHOPT_URL, "https://example.com");
    /* Do not do the transfer - only connect to host */
    fetch_easy_setopt(fetch, FETCHOPT_CONNECT_ONLY, 1L);
    res = fetch_easy_perform(fetch);

    if(res == FETCHE_OK) {
      char buf[256];
      size_t nread;
      long sockfd;

      /* Extract the socket from the fetch handle - we need it for waiting. */
      res = fetch_easy_getinfo(fetch, FETCHINFO_ACTIVESOCKET, &sockfd);

      /* read data */
      res = fetch_easy_recv(fetch, buf, sizeof(buf), &nread);
    }
  }
}
~~~

# %AVAILABILITY%

# RETURN VALUE

On success, returns **FETCHE_OK**, stores the received data into
**buffer**, and the number of bytes it actually read into ***n**.

On failure, returns the appropriate error code.

The function may return **FETCHE_AGAIN**. In this case, use your operating
system facilities to wait until data can be read, and retry.

Reading exactly 0 bytes indicates a closed connection.

If there is no socket available to use from the previous transfer, this
function returns **FETCHE_UNSUPPORTED_PROTOCOL**.
