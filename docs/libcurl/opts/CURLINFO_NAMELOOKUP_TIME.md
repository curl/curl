---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Title: CURLINFO_NAMELOOKUP_TIME
Section: 3
Source: libcurl
See-also:
  - CURLINFO_NAMELOOKUP_TIME_T (3)
  - curl_easy_getinfo (3)
  - curl_easy_setopt (3)
Protocol:
  - All
---

# NAME

CURLINFO_NAMELOOKUP_TIME - get the name lookup time

# SYNOPSIS

~~~c
#include <curl/curl.h>

CURLcode curl_easy_getinfo(CURL *handle, CURLINFO_NAMELOOKUP_TIME,
                           double *timep);
~~~

# DESCRIPTION

Pass a pointer to a double to receive the total time in seconds from the start
until the name resolving was completed.

When a redirect is followed, the time from each request is added together.

See also the TIMES overview in the curl_easy_getinfo(3) man page.

# EXAMPLE

~~~c
int main(void)
{
  CURL *curl = curl_easy_init();
  if(curl) {
    CURLcode res;
    double namelookup;
    curl_easy_setopt(curl, CURLOPT_URL, "https://example.com/");
    res = curl_easy_perform(curl);
    if(CURLE_OK == res) {
      res = curl_easy_getinfo(curl, CURLINFO_NAMELOOKUP_TIME, &namelookup);
      if(CURLE_OK == res) {
        printf("Time: %.1f", namelookup);
      }
    }
    /* always cleanup */
    curl_easy_cleanup(curl);
  }
}
~~~

# AVAILABILITY

Added in 7.4.1

# RETURN VALUE

Returns CURLE_OK if the option is supported, and CURLE_UNKNOWN_OPTION if not.
