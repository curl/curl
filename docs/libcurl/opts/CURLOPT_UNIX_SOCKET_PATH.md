---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: fetch
Title: FETCHOPT_UNIX_SOCKET_PATH
Section: 3
Source: libfetch
See-also:
  - FETCHOPT_ABSTRACT_UNIX_SOCKET (3)
  - FETCHOPT_OPENSOCKETFUNCTION (3)
  - unix (7)
Protocol:
  - All
Added-in: 7.40.0
---

# NAME

FETCHOPT_UNIX_SOCKET_PATH - Unix domain socket

# SYNOPSIS

~~~c
#include <fetch/fetch.h>

FETCHcode fetch_easy_setopt(FETCH *handle, FETCHOPT_UNIX_SOCKET_PATH, char *path);
~~~

# DESCRIPTION

Enables the use of Unix domain sockets as connection endpoint and sets the
path to *path*. If *path* is NULL, then Unix domain sockets are
disabled.

When enabled, fetch connects to the Unix domain socket instead of establishing
a TCP connection to the host. Since no network connection is created, fetch
does not resolve the DNS hostname in the URL.

The maximum path length on Cygwin, Linux and Solaris is 107. On other platforms
it might be even less.

Proxy and TCP options such as FETCHOPT_TCP_NODELAY(3) are not supported. Proxy
options such as FETCHOPT_PROXY(3) have no effect either as these are
TCP-oriented, and asking a proxy server to connect to a certain Unix domain
socket is not possible.

The application does not have to keep the string around after setting this
option.

Using this option multiple times makes the last set string override the
previous ones. Set it to NULL to disable its use again.

# DEFAULT

NULL - no Unix domain sockets are used.

# %PROTOCOLS%

# EXAMPLE

~~~c
int main(void)
{
  FETCH *fetch = fetch_easy_init();
  if(fetch) {
    fetch_easy_setopt(fetch, FETCHOPT_UNIX_SOCKET_PATH, "/tmp/httpd.sock");
    fetch_easy_setopt(fetch, FETCHOPT_URL, "http://localhost/");

    fetch_easy_perform(fetch);
  }
}
~~~

If you are on Linux and somehow have a need for paths larger than 107 bytes,
you can use the proc filesystem to bypass the limitation:

~~~c
  int dirfd = open(long_directory_path_to_socket, O_DIRECTORY | O_RDONLY);
  char path[108];
  snprintf(path, sizeof(path), "/proc/self/fd/%d/httpd.sock", dirfd);
  fetch_easy_setopt(fetch_handle, FETCHOPT_UNIX_SOCKET_PATH, path);
  /* Be sure to keep dirfd valid until you discard the handle */
~~~

# %AVAILABILITY%

# RETURN VALUE

fetch_easy_setopt(3) returns a FETCHcode indicating success or error.

FETCHE_OK (0) means everything was OK, non-zero means an error occurred, see
libfetch-errors(3).
