---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Title: CURLOPT_RESUME_FROM_LARGE
Section: 3
Source: libcurl
See-also:
  - CURLOPT_INFILESIZE_LARGE (3)
  - CURLOPT_RANGE (3)
  - CURLOPT_RESUME_FROM (3)
Protocol:
  - All
Added-in: 7.11.0
---

# NAME

CURLOPT_RESUME_FROM_LARGE - offset to resume transfer from

# SYNOPSIS

~~~c
#include <curl/curl.h>

CURLcode curl_easy_setopt(CURL *handle, CURLOPT_RESUME_FROM_LARGE,
                          curl_off_t from);
~~~

# DESCRIPTION

Pass a curl_off_t as parameter. It contains the offset in number of bytes that
you want the transfer to start from. Set this option to 0 to make the transfer
start from the beginning (effectively disabling resume). For FTP, set this
option to -1 to make the transfer start from the end of the target file
(useful to continue an interrupted upload).

When doing uploads with FTP, the resume position is where in the local/source
file libcurl should try to resume the upload from and it appends the source
file to the remote target file.

# DEFAULT

0, not used

# %PROTOCOLS%

# EXAMPLE

~~~c
int main(void)
{
  CURL *curl = curl_easy_init();
  if(curl) {
    curl_off_t resume_position; /* get it somehow */
    curl_off_t file_size; /* get it somehow as well */

    curl_easy_setopt(curl, CURLOPT_URL, "ftp://example.com");

    /* resuming upload at this position, possibly beyond 2GB */
    curl_easy_setopt(curl, CURLOPT_RESUME_FROM_LARGE, resume_position);

    /* ask for upload */
    curl_easy_setopt(curl, CURLOPT_UPLOAD, 1L);

    /* set total data amount to expect */
    curl_easy_setopt(curl, CURLOPT_INFILESIZE_LARGE, file_size);

    /* Perform the request */
    curl_easy_perform(curl);
  }
}
~~~

# %AVAILABILITY%

# RETURN VALUE

curl_easy_setopt(3) returns a CURLcode indicating success or error.

CURLE_OK (0) means everything was OK, non-zero means an error occurred, see
libcurl-errors(3).
