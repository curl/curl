---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: fetch
Title: FETCHOPT_SOCKOPTDATA
Section: 3
Source: libfetch
See-also:
  - FETCHOPT_OPENSOCKETFUNCTION (3)
  - FETCHOPT_SOCKOPTFUNCTION (3)
Protocol:
  - All
Added-in: 7.16.0
---

# NAME

FETCHOPT_SOCKOPTDATA - pointer to pass to sockopt callback

# SYNOPSIS

~~~c
#include <fetch/fetch.h>

FETCHcode fetch_easy_setopt(FETCH *handle, FETCHOPT_SOCKOPTDATA, void *pointer);
~~~

# DESCRIPTION

Pass a *pointer* that is untouched by libfetch and passed as the first
argument in the sockopt callback set with FETCHOPT_SOCKOPTFUNCTION(3).

# DEFAULT

NULL

# %PROTOCOLS%

# EXAMPLE

~~~c
static int sockopt_callback(void *clientp, fetch_socket_t fetchfd,
                            fetchsocktype purpose)
{
  int val = *(int *)clientp;
  setsockopt((int)fetchfd, SOL_SOCKET, SO_RCVBUF,
             (const char *)&val, sizeof(val));
  return FETCH_SOCKOPT_OK;
}

int main(void)
{
  FETCH *fetch = fetch_easy_init();
  if(fetch) {
    FETCHcode res;
    int recvbuffersize = 256 * 1024;

    fetch_easy_setopt(fetch, FETCHOPT_URL, "https://example.com/");

    /* call this function to set options for the socket */
    fetch_easy_setopt(fetch, FETCHOPT_SOCKOPTFUNCTION, sockopt_callback);
    fetch_easy_setopt(fetch, FETCHOPT_SOCKOPTDATA, &recvbuffersize);

    res = fetch_easy_perform(fetch);

    fetch_easy_cleanup(fetch);
  }
}
~~~

# %AVAILABILITY%

# RETURN VALUE

Returns *FETCHE_OK* if the option is supported, and *FETCHE_UNKNOWN_OPTION* if not.
