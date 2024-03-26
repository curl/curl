---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Title: CURLINFO_ACTIVESOCKET
Section: 3
Source: libcurl
See-also:
  - CURLINFO_LASTSOCKET (3)
  - CURLOPT_CONNECT_ONLY (3)
  - curl_easy_getinfo (3)
  - curl_easy_setopt (3)
Protocol:
  - All
---

# NAME

CURLINFO_ACTIVESOCKET - get the active socket

# SYNOPSIS

~~~c
#include <curl/curl.h>

CURLcode curl_easy_getinfo(CURL *handle, CURLINFO_ACTIVESOCKET,
                           curl_socket_t *socket);
~~~

# DESCRIPTION

Pass a pointer to a curl_socket_t to receive the most recently active socket
used for the transfer connection by this curl session. If the socket is no
longer valid, *CURL_SOCKET_BAD* is returned. When you are finished working
with the socket, you must call curl_easy_cleanup(3) as usual on the easy
handle and let libcurl close the socket and cleanup other resources associated
with the handle. This option returns the active socket only after the transfer
is complete, and is typically used in combination with
CURLOPT_CONNECT_ONLY(3), which skips the transfer phase.

CURLINFO_ACTIVESOCKET(3) was added as a replacement for
CURLINFO_LASTSOCKET(3) since that one is not working on all platforms.

# EXAMPLE

~~~c
int main(void)
{
  CURL *curl = curl_easy_init();
  if(curl) {
    CURLcode res;
    curl_socket_t sockfd;
    curl_easy_setopt(curl, CURLOPT_URL, "https://example.com");

    /* Do not do the transfer - only connect to host */
    curl_easy_setopt(curl, CURLOPT_CONNECT_ONLY, 1L);
    res = curl_easy_perform(curl);

    /* Extract the socket from the curl handle */
    res = curl_easy_getinfo(curl, CURLINFO_ACTIVESOCKET, &sockfd);

    if(res != CURLE_OK) {
      printf("Error: %s\n", curl_easy_strerror(res));
      return 1;
    }
  }
}
~~~

# AVAILABILITY

Added in 7.45.0

# RETURN VALUE

Returns CURLE_OK if the option is supported, and CURLE_UNKNOWN_OPTION if not.
