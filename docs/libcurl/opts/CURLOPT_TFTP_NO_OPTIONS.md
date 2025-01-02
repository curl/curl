---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Title: CURLOPT_TFTP_NO_OPTIONS
Section: 3
Source: libcurl
See-also:
  - CURLOPT_TFTP_BLKSIZE (3)
Protocol:
  - TFTP
Added-in: 7.48.0
---

# NAME

CURLOPT_TFTP_NO_OPTIONS - send no TFTP options requests

# SYNOPSIS

~~~c
#include <curl/curl.h>

CURLcode curl_easy_setopt(CURL *handle, CURLOPT_TFTP_NO_OPTIONS, long onoff);
~~~

# DESCRIPTION

Set *onoff* to 1L to exclude all TFTP options defined in RFC 2347,
RFC 2348 and RFC 2349 from read and write requests.

This option improves interoperability with legacy servers that do not
acknowledge or properly implement TFTP options. When this option is used
CURLOPT_TFTP_BLKSIZE(3) is ignored.

# DEFAULT

0

# %PROTOCOLS%

# EXAMPLE

~~~c
size_t write_callback(char *ptr, size_t size, size_t nmemb, void *fp)
{
  return fwrite(ptr, size, nmemb, (FILE *)fp);
}

int main(void)
{
  CURL *curl = curl_easy_init();
  if(curl) {
    FILE *fp = fopen("foo.bin", "wb");
    if(fp) {
      curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)fp);
      curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);

      curl_easy_setopt(curl, CURLOPT_URL, "tftp://example.com/foo.bin");

      /* do not send TFTP options requests */
      curl_easy_setopt(curl, CURLOPT_TFTP_NO_OPTIONS, 1L);

      /* Perform the request */
      curl_easy_perform(curl);

      fclose(fp);
    }
    curl_easy_cleanup(curl);
  }
}
~~~

# %AVAILABILITY%

# RETURN VALUE

curl_easy_setopt(3) returns a CURLcode indicating success or error.

CURLE_OK (0) means everything was OK, non-zero means an error occurred, see
libcurl-errors(3).
