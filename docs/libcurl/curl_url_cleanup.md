---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Title: curl_url_cleanup
Section: 3
Source: libcurl
See-also:
  - CURLOPT_CURLU (3)
  - curl_url (3)
  - curl_url_dup (3)
  - curl_url_get (3)
  - curl_url_set (3)
Protocol:
  - All
Added-in: 7.62.0
---

# NAME

curl_url_cleanup - free the URL handle

# SYNOPSIS

~~~c
#include <curl/curl.h>

void curl_url_cleanup(CURLU *handle);
~~~

# DESCRIPTION

Frees all the resources associated with the given *CURLU* handle.

Passing in a NULL pointer in *handle* makes this function return
immediately with no action.

Any use of the **handle** after this function has been called and have
returned, is illegal.

# %PROTOCOLS%

# EXAMPLE

~~~c
int main(void)
{
  CURLU *url = curl_url();
  curl_url_set(url, CURLUPART_URL, "https://example.com", 0);
  curl_url_cleanup(url);
}
~~~

# %AVAILABILITY%

# RETURN VALUE

none
