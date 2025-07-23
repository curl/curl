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

Get the *info* kept in the *multi* handle for `CURLMI_OFFT_*`.
If the *info* is not applicable, this function returns CURLM_UNKNOWN_OPTION.

# OPTIONS

The following information can be extracted:

## CURLMINFO_XFERS_CURRENT

The number of easy handles currently added to the multi. This does not
count handles removed. It does count internal handles that get
added for tasks (like resolving via DoH, for example).

For the total number of easy handles ever added to the multi, see
*CURLMINFO_XFERS_ADDED*.

## CURLMINFO_XFERS_RUNNING

The number of easy handles currently running, e.g. where the transfer
has started but not finished yet.

## CURLMINFO_XFERS_PENDING

The number of current easy handles waiting to start. An added transfer
might become pending for various reasons: a connection limit forces it
to wait, resolving DNS is not finished or it is not clear if an existing,
matching connection may allow multiplexing (HTTP/2 or HTTP/3).

## CURLMINFO_XFERS_DONE

The number of easy handles currently finished, but not yet processed
via curl_multi_info_read(3).

## CURLMINFO_XFERS_ADDED

The cumulative number of all easy handles added to the multi, ever.
This includes internal handles added for tasks (like resolving
via DoH, for example).

For the current number of easy handles managed by the multi, use
*CURLMINFO_XFERS_CURRENT*.

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
