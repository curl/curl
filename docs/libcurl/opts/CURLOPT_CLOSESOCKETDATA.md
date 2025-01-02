---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Title: CURLOPT_CLOSESOCKETDATA
Section: 3
Source: libcurl
See-also:
  - CURLOPT_CLOSESOCKETFUNCTION (3)
  - CURLOPT_OPENSOCKETFUNCTION (3)
Protocol:
  - All
Added-in: 7.21.7
---

# NAME

CURLOPT_CLOSESOCKETDATA - pointer passed to the socket close callback

# SYNOPSIS

~~~c
#include <curl/curl.h>

CURLcode curl_easy_setopt(CURL *handle, CURLOPT_CLOSESOCKETDATA,
                          void *pointer);
~~~

# DESCRIPTION

Pass a *pointer* that remains untouched by libcurl and passed as the first
argument in the closesocket callback set with
CURLOPT_CLOSESOCKETFUNCTION(3).

# DEFAULT

NULL

# %PROTOCOLS%

# EXAMPLE

~~~c
struct priv {
  void *custom;
};

static int closesocket(void *clientp, curl_socket_t item)
{
  struct priv *my = clientp;
  printf("our ptr: %p\n", my->custom);

  printf("libcurl wants to close %d now\n", (int)item);
  return 0;
}

int main(void)
{
  struct priv myown;
  CURL *curl = curl_easy_init();

  /* call this function to close sockets */
  curl_easy_setopt(curl, CURLOPT_CLOSESOCKETFUNCTION, closesocket);
  curl_easy_setopt(curl, CURLOPT_CLOSESOCKETDATA, &myown);

  curl_easy_perform(curl);
  curl_easy_cleanup(curl);
}
~~~

# %AVAILABILITY%

# RETURN VALUE

curl_easy_setopt(3) returns a CURLcode indicating success or error.

CURLE_OK (0) means everything was OK, non-zero means an error occurred, see
libcurl-errors(3).
