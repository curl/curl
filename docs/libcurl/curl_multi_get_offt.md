---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Title: curl_multi_get_offt
Section: 3
Source: libcurl
See-also:
  - curl_multi_add_handle (3)
  - curl_multi_remove_handle (3)
Protocol:
  - All
Added-in: 8.16.0
---

# NAME

curl_multi_get_offt - extract information from a multi handle

# SYNOPSIS

~~~c
#include <curl/curl.h>

CURLMcode curl_multi_get_offt(CURLM *multi_handle,
                              CURLMinfo_offt info,
                              curl_off_t *pvalue);
~~~

# DESCRIPTION

Get the *info* kept in the *multi* handle. If the *info* is not applicable,
this function returns CURLM_UNKNOWN_OPTION.

# OPTIONS

The following information can be extracted:

## CURLMINFO_XFERS_CURRENT

See CURLMINFO_XFERS_CURRENT(3).

## CURLMINFO_XFERS_RUNNING

See CURLMINFO_XFERS_RUNNING(3).

## CURLMINFO_XFERS_PENDING

See CURLMINFO_XFERS_PENDING(3).

## CURLMINFO_XFERS_DONE

See CURLMINFO_XFERS_DONE(3).

## CURLMINFO_XFERS_ADDED

See CURLMINFO_XFERS_ADDED(3).

# %PROTOCOLS%

# EXAMPLE

~~~c
int main(void)
{
  /* init a multi stack */
  CURLM *multi = curl_multi_init();
  CURL *curl = curl_easy_init();
  curl_off_t n;

  if(curl) {
    /* add the transfer */
    curl_multi_add_handle(multi, curl);

    curl_multi_get_offt(multi, CURLMINFO_XFERS_ADDED, &n);
    /* on successful add, n is 1 */
  }
}
~~~

# %AVAILABILITY%

# RETURN VALUE

This function returns a CURLMcode indicating success or error.

CURLM_OK (0) means everything was OK, non-zero means an error occurred,
see libcurl-errors(3).
