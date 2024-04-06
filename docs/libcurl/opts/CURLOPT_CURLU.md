---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Title: CURLOPT_CURLU
Section: 3
Source: libcurl
See-also:
  - CURLOPT_URL (3)
  - curl_url (3)
  - curl_url_cleanup (3)
  - curl_url_dup (3)
  - curl_url_get (3)
  - curl_url_set (3)
  - curl_url_strerror (3)
Protocol:
  - All
---

# NAME

CURLOPT_CURLU - URL in URL handle format

# SYNOPSIS

~~~c
#include <curl/curl.h>

CURLcode curl_easy_setopt(CURL *handle, CURLOPT_CURLU, CURLU *pointer);
~~~

# DESCRIPTION

Pass in a pointer to the *URL* handle to work with. The parameter should be a
*CURLU pointer*. Setting CURLOPT_CURLU(3) explicitly overrides
CURLOPT_URL(3).

CURLOPT_URL(3) or CURLOPT_CURLU(3) **must** be set before a
transfer is started.

libcurl uses this handle and its contents read-only and does not change its
contents. An application can update the contents of the URL handle after a
transfer is done and if the same handle is used in a subsequent request the
updated contents is used.

# DEFAULT

The default value of this parameter is NULL.

# EXAMPLE

~~~c
int main(void)
{
  CURL *curl = curl_easy_init();
  CURLU *urlp = curl_url();
  if(curl) {
    CURLcode res;
    CURLUcode ret;
    ret = curl_url_set(urlp, CURLUPART_URL, "https://example.com", 0);

    curl_easy_setopt(curl, CURLOPT_CURLU, urlp);

    res = curl_easy_perform(curl);

    curl_url_cleanup(urlp);
    curl_easy_cleanup(curl);
  }
}
~~~

# AVAILABILITY

Added in 7.63.0.

# RETURN VALUE

Returns CURLE_OK if the option is supported, and CURLE_UNKNOWN_OPTION if not.
