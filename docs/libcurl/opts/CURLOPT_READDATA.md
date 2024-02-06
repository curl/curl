---
c: Copyright (C) Daniel Stenberg, <daniel.se>, et al.
SPDX-License-Identifier: curl
Title: CURLOPT_READDATA
Section: 3
Source: libcurl
See-also:
  - CURLOPT_HEADERDATA (3)
  - CURLOPT_READFUNCTION (3)
  - CURLOPT_WRITEDATA (3)
  - CURLOPT_WRITEFUNCTION (3)
---

# NAME

CURLOPT_READDATA - pointer passed to the read callback

# SYNOPSIS

~~~c
#include <curl/curl.h>

CURLcode curl_easy_setopt(CURL *handle, CURLOPT_READDATA, void *pointer);
~~~

# DESCRIPTION

Data *pointer* to pass to the file read function. If you use the
CURLOPT_READFUNCTION(3) option, this is the pointer you get as input in
the fourth argument to the callback.

If you do not specify a read callback but instead rely on the default internal
read function, this data must be a valid readable FILE * (cast to 'void *').

If you are using libcurl as a DLL on Windows, you must use the
CURLOPT_READFUNCTION(3) callback if you set this option, otherwise you
might experience crashes.

# DEFAULT

By default, this is a FILE * to stdin.

# PROTOCOLS

This is used for all protocols when sending data.

# EXAMPLE

~~~c
struct MyData {
  void *custom;
};

int main(void)
{
  CURL *curl = curl_easy_init();
  struct MyData this;
  if(curl) {
    curl_easy_setopt(curl, CURLOPT_URL, "https://example.com");

    /* pass pointer that gets passed in to the
       CURLOPT_READFUNCTION callback */
    curl_easy_setopt(curl, CURLOPT_READDATA, &this);

    curl_easy_perform(curl);
  }
}
~~~

# AVAILABILITY

This option was once known by the older name CURLOPT_INFILE, the name
CURLOPT_READDATA(3) was introduced in 7.9.7.

# RETURN VALUE

This returns CURLE_OK.
