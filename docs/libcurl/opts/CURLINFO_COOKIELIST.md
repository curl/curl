---
c: Copyright (C) Daniel Stenberg, <daniel.se>, et al.
SPDX-License-Identifier: curl
Title: CURLINFO_COOKIELIST
Section: 3
Source: libcurl
See-also:
  - CURLOPT_COOKIELIST (3)
  - curl_easy_getinfo (3)
  - curl_easy_setopt (3)
---

# NAME

CURLINFO_COOKIELIST - get all known cookies

# SYNOPSIS

~~~c
#include <curl/curl.h>

CURLcode curl_easy_getinfo(CURL *handle, CURLINFO_COOKIELIST,
                           struct curl_slist **cookies);
~~~

# DESCRIPTION

Pass a pointer to a 'struct curl_slist *' to receive a linked-list of all
cookies curl knows (expired ones, too). Do not forget to call
curl_slist_free_all(3) on the list after it has been used. If there are no
cookies (cookies for the handle have not been enabled or simply none have been
received) the 'struct curl_slist *' is made a NULL pointer.

Since 7.43.0 cookies that were imported in the Set-Cookie format without a
domain name are not exported by this option.

# PROTOCOLS

HTTP(S)

# EXAMPLE

~~~c
int main(void)
{
  CURL *curl = curl_easy_init();
  if(curl) {
    CURLcode res;
    curl_easy_setopt(curl, CURLOPT_URL, "https://example.com");

    /* enable the cookie engine */
    curl_easy_setopt(curl, CURLOPT_COOKIEFILE, "");

    res = curl_easy_perform(curl);

    if(!res) {
      /* extract all known cookies */
      struct curl_slist *cookies = NULL;
      res = curl_easy_getinfo(curl, CURLINFO_COOKIELIST, &cookies);
      if(!res && cookies) {
        /* a linked list of cookies in cookie file format */
        struct curl_slist *each = cookies;
        while(each) {
          printf("%s\n", each->data);
          each = each->next;
        }
        /* we must free these cookies when we are done */
        curl_slist_free_all(cookies);
      }
    }
    curl_easy_cleanup(curl);
  }
}
~~~

# AVAILABILITY

Added in 7.14.1

# RETURN VALUE

Returns CURLE_OK if the option is supported, and CURLE_UNKNOWN_OPTION if not.
