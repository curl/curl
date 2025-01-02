---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Title: CURLOPT_XFERINFODATA
Section: 3
Source: libcurl
See-also:
  - CURLOPT_NOPROGRESS (3)
  - CURLOPT_VERBOSE (3)
  - CURLOPT_XFERINFOFUNCTION (3)
Protocol:
  - All
Added-in: 7.32.0
---

# NAME

CURLOPT_XFERINFODATA - pointer passed to the progress callback

# SYNOPSIS

~~~c
#include <curl/curl.h>

CURLcode curl_easy_setopt(CURL *handle, CURLOPT_XFERINFODATA, void *pointer);
~~~

# DESCRIPTION

Pass a *pointer* that is untouched by libcurl and passed as the first
argument in the progress callback set with CURLOPT_XFERINFOFUNCTION(3).

This is an alias for CURLOPT_PROGRESSDATA(3).

# DEFAULT

NULL

# %PROTOCOLS%

# EXAMPLE

~~~c
struct progress {
  char *private;
  size_t size;
};

static size_t progress_cb(void *clientp,
                          curl_off_t dltotal,
                          curl_off_t dlnow,
                          curl_off_t ultotal,
                          curl_off_t ulnow)
{
  struct progress *memory = clientp;
  printf("private ptr: %p\n", memory->private);
  /* use the values */

  return 0; /* all is good */
}

int main(void)
{
  CURL *curl = curl_easy_init();
  if(curl) {
    struct progress data;

    /* pass struct to callback  */
    curl_easy_setopt(curl, CURLOPT_XFERINFODATA, &data);
    curl_easy_setopt(curl, CURLOPT_XFERINFOFUNCTION, progress_cb);
  }
}
~~~

# %AVAILABILITY%

# RETURN VALUE

curl_easy_setopt(3) returns a CURLcode indicating success or error.

CURLE_OK (0) means everything was OK, non-zero means an error occurred, see
libcurl-errors(3).
