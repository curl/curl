---
c: Copyright (C) Daniel Stenberg, <daniel.se>, et al.
SPDX-License-Identifier: curl
Title: CURLINFO_PRIVATE
Section: 3
Source: libcurl
See-also:
  - CURLOPT_PRIVATE (3)
  - curl_easy_getinfo (3)
  - curl_easy_setopt (3)
---

# NAME

CURLINFO_PRIVATE - get the private pointer

# SYNOPSIS

~~~c
#include <curl/curl.h>

CURLcode curl_easy_getinfo(CURL *handle, CURLINFO_PRIVATE, char **private);
~~~

# DESCRIPTION

Pass a pointer to a char pointer to receive the pointer to the private data
associated with the curl handle (set with the CURLOPT_PRIVATE(3)).
Please note that for internal reasons, the value is returned as a char
pointer, although effectively being a 'void *'.

# PROTOCOLS

All

# EXAMPLE

~~~c
int main(void)
{
  CURL *curl = curl_easy_init();
  if(curl) {
    CURLcode res;
    void *pointer = (void *)0x2345454;
    curl_easy_setopt(curl, CURLOPT_URL, "https://example.com/foo.bin");

    /* set the private pointer */
    curl_easy_setopt(curl, CURLOPT_PRIVATE, pointer);
    res = curl_easy_perform(curl);

    /* extract the private pointer again */
    res = curl_easy_getinfo(curl, CURLINFO_PRIVATE, &pointer);

    if(res)
      printf("error: %s\n", curl_easy_strerror(res));

    curl_easy_cleanup(curl);
  }
}
~~~

# AVAILABILITY

Added in 7.10.3

# RETURN VALUE

Returns CURLE_OK if the option is supported, and CURLE_UNKNOWN_OPTION if not.
