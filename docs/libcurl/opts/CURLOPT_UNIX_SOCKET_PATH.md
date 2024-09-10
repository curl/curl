---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Title: CURLOPT_UNIX_SOCKET_PATH
Section: 3
Source: libcurl
See-also:
  - CURLOPT_ABSTRACT_UNIX_SOCKET (3)
  - CURLOPT_OPENSOCKETFUNCTION (3)
  - unix (7)
Protocol:
  - All
Added-in: 7.40.0
---

# NAME

CURLOPT_UNIX_SOCKET_PATH - Unix domain socket

# SYNOPSIS

~~~c
#include <curl/curl.h>

CURLcode curl_easy_setopt(CURL *handle, CURLOPT_UNIX_SOCKET_PATH, char *path);
~~~

# DESCRIPTION

Enables the use of Unix domain sockets as connection endpoint and sets the
path to *path*. If *path* is NULL, then Unix domain sockets are
disabled.

When enabled, curl connects to the Unix domain socket instead of establishing
a TCP connection to the host. Since no network connection is created, curl
does not resolve the DNS hostname in the URL.

The maximum path length on Cygwin, Linux and Solaris is 107. On other platforms
it might be even less.

Proxy and TCP options such as CURLOPT_TCP_NODELAY(3) are not supported. Proxy
options such as CURLOPT_PROXY(3) have no effect either as these are
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
  CURL *curl = curl_easy_init();
  if(curl) {
    curl_easy_setopt(curl, CURLOPT_UNIX_SOCKET_PATH, "/tmp/httpd.sock");
    curl_easy_setopt(curl, CURLOPT_URL, "http://localhost/");

    curl_easy_perform(curl);
  }
}
~~~

If you are on Linux and somehow have a need for paths larger than 107 bytes,
you can use the proc filesystem to bypass the limitation:

~~~c
  int dirfd = open(long_directory_path_to_socket, O_DIRECTORY | O_RDONLY);
  char path[108];
  snprintf(path, sizeof(path), "/proc/self/fd/%d/httpd.sock", dirfd);
  curl_easy_setopt(curl_handle, CURLOPT_UNIX_SOCKET_PATH, path);
  /* Be sure to keep dirfd valid until you discard the handle */
~~~

# %AVAILABILITY%

# RETURN VALUE

Returns CURLE_OK if the option is supported, and CURLE_UNKNOWN_OPTION if not.
