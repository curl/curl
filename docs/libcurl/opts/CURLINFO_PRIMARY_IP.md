---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Title: CURLINFO_PRIMARY_IP
Section: 3
Source: libcurl
See-also:
  - CURLINFO_LOCAL_IP (3)
  - CURLINFO_LOCAL_PORT (3)
  - CURLINFO_PRIMARY_PORT (3)
  - curl_easy_getinfo (3)
  - curl_easy_setopt (3)
Protocol:
  - All
Added-in: 7.19.0
---

# NAME

CURLINFO_PRIMARY_IP - get IP address of last connection

# SYNOPSIS

~~~c
#include <curl/curl.h>

CURLcode curl_easy_getinfo(CURL *handle, CURLINFO_PRIMARY_IP, char **ip);
~~~

# DESCRIPTION

Pass a pointer to a char pointer to receive the pointer to a null-terminated
string holding the IP address of the most recent connection done with this
**curl** handle. This string may be IPv6 when that is enabled. Note that you
get a pointer to a memory area that is reused at next request so you need to
copy the string if you want to keep the information.

The **ip** pointer is NULL or points to private memory. You **must not** free
it. The memory gets freed automatically when you call curl_easy_cleanup(3) on
the corresponding curl handle.

# %PROTOCOLS%

# EXAMPLE

~~~c
int main(void)
{
  char *ip;
  CURLcode res;
  CURL *curl = curl_easy_init();

  curl_easy_setopt(curl, CURLOPT_URL, "https://example.com");

  /* Perform the transfer */
  res = curl_easy_perform(curl);
  /* Check for errors */
  if((res == CURLE_OK) &&
     !curl_easy_getinfo(curl, CURLINFO_PRIMARY_IP, &ip) && ip) {
    printf("IP: %s\n", ip);
  }

  /* always cleanup */
  curl_easy_cleanup(curl);
}
~~~

# %AVAILABILITY%

# RETURN VALUE

curl_easy_getinfo(3) returns a CURLcode indicating success or error.

CURLE_OK (0) means everything was OK, non-zero means an error occurred, see
libcurl-errors(3).
