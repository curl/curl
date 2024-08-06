---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Title: CURLMOPT_DEBUGDATA
Section: 3
Source: libcurl
See-also:
  - CURLMOPT_DEBUGFUNCTION (3)
Protocol:
  - All
Added-in: 8.10.0
---

# NAME

CURLMOPT_DEBUGDATA - pointer passed to the debug callback

# SYNOPSIS

~~~c
#include <curl/curl.h>

CURLMcode curl_multi_setopt(CURLM *handle, CURLMOPT_DEBUGDATA, void *pointer);
~~~

# DESCRIPTION

Pass a *pointer* to whatever you want passed in to your
CURLMOPT_DEBUGFUNCTION(3) in the last void * argument. This pointer is
not used by libcurl, it is only passed to the callback.

# DEFAULT

NULL

# %PROTOCOLS%

# EXAMPLE

~~~c
struct data {
  void *custom;
};

static int my_multi_trace(CURLM *multi, CURL *handle, curl_infotype type,
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
  CURLM *multi = curl_multi_init();
  curl_multi_setopt(multi, CURLMOPT_VERBOSE, 1L);
  curl_multi_setopt(curl, CURLOPT_DEBUGFUNCTION, my_multi_trace);
  curl_multi_setopt(curl, CURLOPT_DEBUGDATA, &my_tracedata);
}
~~~

# %AVAILABILITY%

# RETURN VALUE

Returns CURLM_OK
