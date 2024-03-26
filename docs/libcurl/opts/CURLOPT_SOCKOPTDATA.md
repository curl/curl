---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Title: CURLOPT_SOCKOPTDATA
Section: 3
Source: libcurl
See-also:
  - CURLOPT_OPENSOCKETFUNCTION (3)
  - CURLOPT_SOCKOPTFUNCTION (3)
Protocol:
  - All
---

# NAME

CURLOPT_SOCKOPTDATA - pointer to pass to sockopt callback

# SYNOPSIS

~~~c
#include <curl/curl.h>

CURLcode curl_easy_setopt(CURL *handle, CURLOPT_SOCKOPTDATA, void *pointer);
~~~

# DESCRIPTION

Pass a *pointer* that is untouched by libcurl and passed as the first
argument in the sockopt callback set with CURLOPT_SOCKOPTFUNCTION(3).

# DEFAULT

The default value of this parameter is NULL.

# EXAMPLE

~~~c
static int sockopt_callback(void *clientp, curl_socket_t curlfd,
                            curlsocktype purpose)
{
  int val = *(int *)clientp;
  setsockopt((int)curlfd, SOL_SOCKET, SO_RCVBUF,
             (const char *)&val, sizeof(val));
  return CURL_SOCKOPT_OK;
}

int main(void)
{
  CURL *curl = curl_easy_init();
  if(curl) {
    CURLcode res;
    int recvbuffersize = 256 * 1024;

    curl_easy_setopt(curl, CURLOPT_URL, "https://example.com/");

    /* call this function to set options for the socket */
    curl_easy_setopt(curl, CURLOPT_SOCKOPTFUNCTION, sockopt_callback);
    curl_easy_setopt(curl, CURLOPT_SOCKOPTDATA, &recvbuffersize);

    res = curl_easy_perform(curl);

    curl_easy_cleanup(curl);
  }
}
~~~

# AVAILABILITY

Added in 7.16.0

# RETURN VALUE

Returns *CURLE_OK* if the option is supported, and *CURLE_UNKNOWN_OPTION* if not.
