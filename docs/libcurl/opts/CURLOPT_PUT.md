---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Title: CURLOPT_PUT
Section: 3
Source: libcurl
See-also:
  - CURLOPT_HTTPGET (3)
  - CURLOPT_MIMEPOST (3)
  - CURLOPT_POSTFIELDS (3)
  - CURLOPT_UPLOAD (3)
Protocol:
  - HTTP
---

# NAME

CURLOPT_PUT - make an HTTP PUT request

# SYNOPSIS

~~~c
#include <curl/curl.h>

CURLcode curl_easy_setopt(CURL *handle, CURLOPT_PUT, long put);
~~~

# DESCRIPTION

A parameter set to 1 tells the library to use HTTP PUT to transfer data. The
data should be set with CURLOPT_READDATA(3) and
CURLOPT_INFILESIZE(3).

This option is **deprecated** since version 7.12.1. Use CURLOPT_UPLOAD(3).

# DEFAULT

0, disabled

# EXAMPLE

~~~c
static size_t read_cb(char *ptr, size_t size, size_t nmemb, void *userdata)
{
  FILE *src = userdata;
  /* copy as much data as possible into the 'ptr' buffer, but no more than
     'size' * 'nmemb' bytes */
  size_t retcode = fread(ptr, size, nmemb, src);

  return retcode;
}

int main(void)
{
  CURL *curl = curl_easy_init();
  if(curl) {
    FILE *src = fopen("local-file", "r");
    curl_off_t fsize; /* set this to the size of the input file */

    /* we want to use our own read function */
    curl_easy_setopt(curl, CURLOPT_READFUNCTION, read_cb);

    /* enable PUT */
    curl_easy_setopt(curl, CURLOPT_PUT, 1L);

    /* specify target */
    curl_easy_setopt(curl, CURLOPT_URL, "ftp://example.com/dir/to/newfile");

    /* now specify which pointer to pass to our callback */
    curl_easy_setopt(curl, CURLOPT_READDATA, src);

    /* Set the size of the file to upload */
    curl_easy_setopt(curl, CURLOPT_INFILESIZE_LARGE, (curl_off_t)fsize);

    /* Now run off and do what you have been told */
    curl_easy_perform(curl);
  }
}
~~~

# AVAILABILITY

Deprecated since 7.12.1. Do not use.

# RETURN VALUE

Returns CURLE_OK if HTTP is supported, and CURLE_UNKNOWN_OPTION if not.
