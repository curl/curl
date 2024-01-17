---
c: Copyright (C) Daniel Stenberg, <daniel.se>, et al.
SPDX-License-Identifier: curl
Title: CURLINFO_LOCAL_IP
Section: 3
Source: libcurl
See-also:
  - CURLINFO_LOCAL_PORT (3)
  - CURLINFO_PRIMARY_IP (3)
  - curl_easy_getinfo (3)
  - curl_easy_setopt (3)
---

# NAME

CURLINFO_LOCAL_IP - get local IP address of last connection

# SYNOPSIS

~~~c
#include <curl/curl.h>

CURLcode curl_easy_getinfo(CURL *handle, CURLINFO_LOCAL_IP, char **ip);
~~~

# DESCRIPTION

Pass a pointer to a char pointer to receive the pointer to a null-terminated
string holding the IP address of the local end of most recent connection done
with this **curl** handle. This string may be IPv6 when that is
enabled. Note that you get a pointer to a memory area that is reused at next
request so you need to copy the string if you want to keep the information.

The **ip** pointer is NULL or points to private memory. You MUST NOT free -
it gets freed when you call curl_easy_cleanup(3) on the corresponding
CURL handle.

# PROTOCOLS

All

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
     !curl_easy_getinfo(curl, CURLINFO_LOCAL_IP, &ip) && ip) {
    printf("Local IP: %s\n", ip);
  }

  /* always cleanup */
  curl_easy_cleanup(curl);
}
~~~

# AVAILABILITY

Added in 7.21.0

# RETURN VALUE

Returns CURLE_OK if the option is supported, and CURLE_UNKNOWN_OPTION if not.
