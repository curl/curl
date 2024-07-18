---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Title: CURLOPT_ABSTRACT_UNIX_SOCKET
Section: 3
Source: libcurl
See-also:
  - CURLOPT_UNIX_SOCKET_PATH (3)
  - unix (7)
Protocol:
  - All
Added-in: 7.53.0
---

# NAME

CURLOPT_ABSTRACT_UNIX_SOCKET - abstract Unix domain socket

# SYNOPSIS

~~~c
#include <curl/curl.h>

CURLcode curl_easy_setopt(CURL *handle, CURLOPT_ABSTRACT_UNIX_SOCKET,
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

This option shares the same semantics as CURLOPT_UNIX_SOCKET_PATH(3) in
which documentation more details can be found. Internally, these two options
share the same storage and therefore only one of them can be set per handle.

# DEFAULT

NULL

# %PROTOCOLS%

# EXAMPLE

~~~c
int main(void)
{
  CURL *curl = curl_easy_init();
  if(curl) {
    curl_easy_setopt(curl, CURLOPT_ABSTRACT_UNIX_SOCKET, "/tmp/foo.sock");
    curl_easy_setopt(curl, CURLOPT_URL, "http://localhost/");

    /* Perform the request */
    curl_easy_perform(curl);
  }
}
~~~

# %AVAILABILITY%

# RETURN VALUE

Returns CURLE_OK if the option is supported, and CURLE_UNKNOWN_OPTION if not.
