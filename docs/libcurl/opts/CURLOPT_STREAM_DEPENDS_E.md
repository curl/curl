---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Title: CURLOPT_STREAM_DEPENDS_E
Section: 3
Source: libcurl
See-also:
  - CURLMOPT_PIPELINING (3)
  - CURLOPT_HTTP_VERSION (3)
  - CURLOPT_STREAM_DEPENDS (3)
  - CURLOPT_STREAM_WEIGHT (3)
Protocol:
  - HTTP
---

# NAME

CURLOPT_STREAM_DEPENDS_E - stream this transfer depends on exclusively

# SYNOPSIS

~~~c
#include <curl/curl.h>

CURLcode curl_easy_setopt(CURL *handle, CURLOPT_STREAM_DEPENDS_E,
                          CURL *dephandle);
~~~

# DESCRIPTION

Pass a CURL pointer in *dephandle* to identify the stream within the same
connection that this stream is depending upon exclusively. That means it
depends on it and sets the Exclusive bit.

The spec says "Including a dependency expresses a preference to allocate
resources to the identified stream rather than to the dependent stream."

Setting a dependency with the exclusive flag for a reprioritized stream causes
all the dependencies of the new parent stream to become dependent on the
reprioritized stream.

This option can be set during transfer.

*dephandle* must not be the same as *handle*, that makes this function return
an error. It must be another easy handle, and it also needs to be a handle of
a transfer that is about to be sent over the same HTTP/2 connection for this
option to have an actual effect.

# DEFAULT

NULL

# EXAMPLE

~~~c
int main(void)
{
  CURL *curl = curl_easy_init();
  CURL *curl2 = curl_easy_init(); /* a second handle */
  if(curl) {
    curl_easy_setopt(curl, CURLOPT_URL, "https://example.com/one");

    /* the second depends on the first */
    curl_easy_setopt(curl2, CURLOPT_URL, "https://example.com/two");
    curl_easy_setopt(curl2, CURLOPT_STREAM_DEPENDS_E, curl);

    /* then add both to a multi handle and transfer them! */
  }
}
~~~

# AVAILABILITY

Added in 7.46.0

# RETURN VALUE

Returns CURLE_OK if the option is supported, and CURLE_UNKNOWN_OPTION if not.
