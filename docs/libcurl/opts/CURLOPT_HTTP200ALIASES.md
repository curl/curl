---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Title: CURLOPT_HTTP200ALIASES
Section: 3
Source: libcurl
Protocol:
  - HTTP
See-also:
  - CURLOPT_HTTP09_ALLOWED (3)
  - CURLOPT_HTTP_VERSION (3)
Added-in: 7.10.3
---

# NAME

CURLOPT_HTTP200ALIASES - alternative matches for HTTP 200 OK

# SYNOPSIS

~~~c
#include <curl/curl.h>

CURLcode curl_easy_setopt(CURL *handle, CURLOPT_HTTP200ALIASES,
                          struct curl_slist *aliases);
~~~

# DESCRIPTION

Pass a pointer to a linked list of *aliases* to be treated as valid HTTP 200
responses. Some servers respond with a custom header response line. For
example, SHOUTcast servers respond with "ICY 200 OK". Also some old Icecast
1.3.x servers respond like that for certain user agent headers or in absence
of such. By including this string in your list of aliases, the response gets
treated as a valid HTTP header line such as "HTTP/1.0 200 OK".

The linked list should be a fully valid list of struct curl_slist structs, and
be properly filled in. Use curl_slist_append(3) to create the list and
curl_slist_free_all(3) to clean up an entire list.

The alias itself is not parsed for any version strings. The protocol is
assumed to match HTTP 1.0 when an alias match.

# DEFAULT

NULL

# %PROTOCOLS%

# EXAMPLE

~~~c
int main(void)
{
  CURL *curl = curl_easy_init();
  if(curl) {
    struct curl_slist *list;
    curl_easy_setopt(curl, CURLOPT_URL, "https://example.com");

    list = curl_slist_append(NULL, "ICY 200 OK");
    list = curl_slist_append(list, "WEIRDO 99 FINE");

    curl_easy_setopt(curl, CURLOPT_HTTP200ALIASES, list);
    curl_easy_perform(curl);
    curl_slist_free_all(list); /* free the list again */
  }
}
~~~

# %AVAILABILITY%

# RETURN VALUE

Returns CURLE_OK if HTTP is supported, and CURLE_UNKNOWN_OPTION if not.
