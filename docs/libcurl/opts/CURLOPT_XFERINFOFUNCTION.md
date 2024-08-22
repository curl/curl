---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Title: CURLOPT_XFERINFOFUNCTION
Section: 3
Source: libcurl
See-also:
  - CURLOPT_NOPROGRESS (3)
  - CURLOPT_XFERINFODATA (3)
Protocol:
  - All
Added-in: 7.32.0
---

# NAME

CURLOPT_XFERINFOFUNCTION - progress meter callback

# SYNOPSIS

~~~c
#include <curl/curl.h>

int progress_callback(void *clientp,
                      curl_off_t dltotal,
                      curl_off_t dlnow,
                      curl_off_t ultotal,
                      curl_off_t ulnow);

CURLcode curl_easy_setopt(CURL *handle, CURLOPT_XFERINFOFUNCTION,
                          progress_callback);
~~~

# DESCRIPTION

Pass a pointer to your callback function, which should match the prototype
shown above.

This function gets called by libcurl instead of its internal equivalent with a
frequent interval. While data is being transferred it gets called frequently,
and during slow periods like when nothing is being transferred it can slow
down to about one call per second.

*clientp* is the pointer set with CURLOPT_XFERINFODATA(3), it is not
used by libcurl but is only passed along from the application to the callback.

The callback gets told how much data libcurl is about to transfer and has
already transferred, in number of bytes. *dltotal* is the total number of
bytes libcurl expects to download in this transfer. *dlnow* is the number
of bytes downloaded so far. *ultotal* is the total number of bytes libcurl
expects to upload in this transfer. *ulnow* is the number of bytes
uploaded so far.

Unknown/unused argument values passed to the callback are set to zero (like if
you only download data, the upload size remains 0). Many times the callback is
called one or more times first, before it knows the data sizes so a program
must be made to handle that.

Return zero from the callback if everything is fine.

Return 1 from this callback to make libcurl abort the transfer and return
*CURLE_ABORTED_BY_CALLBACK*.

If your callback function returns CURL_PROGRESSFUNC_CONTINUE it makes libcurl
to continue executing the default progress function.

If you transfer data with the multi interface, this function is not called
during periods of idleness unless you call the appropriate libcurl function
that performs transfers.

CURLOPT_NOPROGRESS(3) must be set to 0 to make this function actually
get called.

# DEFAULT

NULL - use the internal progress meter. That is rarely wanted by users.

# %PROTOCOLS%

# EXAMPLE

~~~c
struct progress {
  char *private;
  size_t size;
};

static size_t progress_callback(void *clientp,
                                curl_off_t dltotal,
                                curl_off_t dlnow,
                                curl_off_t ultotal,
                                curl_off_t ulnow)
{
  struct progress *memory = clientp;
  printf("my ptr: %p\n", memory->private);

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

    /* enable progress callback getting called */
    curl_easy_setopt(curl, CURLOPT_NOPROGRESS, 0L);

    curl_easy_setopt(curl, CURLOPT_XFERINFOFUNCTION, progress_callback);
  }
}
~~~

# %AVAILABILITY%

# RETURN VALUE

Returns CURLE_OK.
