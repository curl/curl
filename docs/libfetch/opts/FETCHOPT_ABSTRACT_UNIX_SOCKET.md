---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: fetch
Title: FETCHOPT_ABSTRACT_UNIX_SOCKET
Section: 3
Source: libfetch
See-also:
  - FETCHOPT_UNIX_SOCKET_PATH (3)
  - unix (7)
Protocol:
  - All
Added-in: 7.53.0
---

# NAME

FETCHOPT_ABSTRACT_UNIX_SOCKET - abstract Unix domain socket

# SYNOPSIS

~~~c
#include <fetch/fetch.h>

FETCHcode fetch_easy_setopt(FETCH *handle, FETCHOPT_ABSTRACT_UNIX_SOCKET,
                          char *path);
~~~

# DESCRIPTION

Enables the use of an abstract Unix domain socket instead of establishing a
TCP connection to a host. The parameter should be a char * to a
null-terminated string holding the path of the socket. The path is set to
*path* prefixed by a NULL byte. This is the convention for abstract
sockets, however it should be stressed that the path passed to this function
should not contain a leading NULL byte.

On non-supporting platforms, the abstract address is interpreted as an empty
string and fails gracefully, generating a runtime error.

This option shares the same semantics as FETCHOPT_UNIX_SOCKET_PATH(3) in
which documentation more details can be found. Internally, these two options
share the same storage and therefore only one of them can be set per handle.

# DEFAULT

NULL

# %PROTOCOLS%

# EXAMPLE

~~~c
int main(void)
{
  FETCH *fetch = fetch_easy_init();
  if(fetch) {
    fetch_easy_setopt(fetch, FETCHOPT_ABSTRACT_UNIX_SOCKET, "/tmp/foo.sock");
    fetch_easy_setopt(fetch, FETCHOPT_URL, "http://localhost/");

    /* Perform the request */
    fetch_easy_perform(fetch);
  }
}
~~~

# %AVAILABILITY%

# RETURN VALUE

fetch_easy_setopt(3) returns a FETCHcode indicating success or error.

FETCHE_OK (0) means everything was OK, non-zero means an error occurred, see
libfetch-errors(3).
