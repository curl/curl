---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Title: CURLSHOPT_DEBUGDATA
Section: 3
Source: libcurl
See-also:
  - CURLSHOPT_DEBUGFUNCTION (3)
Protocol:
  - All
Added-in: 8.10.0
---

# NAME

CURLSHOPT_DEBUGDATA - pointer passed to the debug callback

# SYNOPSIS

~~~c
#include <curl/curl.h>

CURLSHcode curl_share_setopt(CURLSH *share, CURLSHOPT_DEBUGDATA, void *pointer);
~~~

# DESCRIPTION

Pass a *pointer* to whatever you want passed in to your
CURLSHOPT_DEBUGFUNCTION(3) in the last void * argument. This pointer is
not used by libcurl, it is only passed to the callback.

# DEFAULT

NULL

# %PROTOCOLS%

# EXAMPLE

~~~c
struct data {
  void *custom;
};

static int my_share_trace(CURLSH *share, CURL *handle, curl_infotype type,
                          char *data, size_t size,
                          void *clientp)
{
  struct data *mine = clientp;
  printf("our ptr: %p\n", mine->custom);

  /* output debug info */
}

int main(void)
{
  struct data my_tracedata;
  CURLSH *share = curl_share_init();
  curl_share_setopt(share, CURLSHOPT_VERBOSE, 1L);
  curl_share_setopt(share, CURLSHOPT_DEBUGFUNCTION, my_share_trace);
  curl_share_setopt(share, CURLSHOPT_DEBUGDATA, &my_tracedata);
}
~~~

# %AVAILABILITY%

# RETURN VALUE

Returns CURLM_OK
