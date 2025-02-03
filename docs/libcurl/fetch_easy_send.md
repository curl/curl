---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: fetch
Title: fetch_easy_send
Section: 3
Source: libfetch
See-also:
  - fetch_easy_getinfo (3)
  - fetch_easy_perform (3)
  - fetch_easy_recv (3)
  - fetch_easy_setopt (3)
Protocol:
  - All
Added-in: 7.18.2
---

# NAME

fetch_easy_send - sends raw data over an "easy" connection

# SYNOPSIS

~~~c
#include <fetch/fetch.h>

FETCHcode fetch_easy_send(FETCH *fetch, const void *buffer,
                        size_t buflen, size_t *n);
~~~

# DESCRIPTION

This function sends arbitrary data over the established connection. You may
use it together with fetch_easy_recv(3) to implement custom protocols
using libfetch. This functionality can be particularly useful if you use
proxies and/or SSL encryption: libfetch takes care of proxy negotiation and
connection setup.

**buffer** is a pointer to the data of length **buflen** that you want
sent. The variable **n** points to receives the number of sent bytes.

To establish the connection, set FETCHOPT_CONNECT_ONLY(3) option before
calling fetch_easy_perform(3) or fetch_multi_perform(3). Note that
fetch_easy_send(3) does not work on connections that were created without
this option.

The call returns **FETCHE_AGAIN** if it is not possible to send data right now
- the socket is used in non-blocking mode internally. When **FETCHE_AGAIN**
is returned, use your operating system facilities like *select(2)* to wait
until the socket is writable. The socket may be obtained using
fetch_easy_getinfo(3) with FETCHINFO_ACTIVESOCKET(3).

Furthermore if you wait on the socket and it tells you it is writable,
fetch_easy_send(3) may return **FETCHE_AGAIN** if the only data that was sent
was for internal SSL processing, and no other data could be sent.

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
      long sockfd;
      size_t sent;
      /* Extract the socket from the fetch handle - we need it for waiting. */
      res = fetch_easy_getinfo(fetch, FETCHINFO_ACTIVESOCKET, &sockfd);

      /* send data */
      res = fetch_easy_send(fetch, "hello", 5, &sent);
    }
  }
}
~~~

# %AVAILABILITY%

# RETURN VALUE

On success, returns **FETCHE_OK** and stores the number of bytes actually
sent into ***n**. Note that this may be less than the amount you wanted to
send.

On failure, returns the appropriate error code.

This function may return **FETCHE_AGAIN**. In this case, use your operating
system facilities to wait until the socket is writable, and retry.

If there is no socket available to use from the previous transfer, this
function returns **FETCHE_UNSUPPORTED_PROTOCOL**.
