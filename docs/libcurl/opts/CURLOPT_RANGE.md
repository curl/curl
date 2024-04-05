---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Title: CURLOPT_RANGE
Section: 3
Source: libcurl
See-also:
  - CURLOPT_LOW_SPEED_LIMIT (3)
  - CURLOPT_MAXFILESIZE_LARGE (3)
  - CURLOPT_MAX_RECV_SPEED_LARGE (3)
  - CURLOPT_RESUME_FROM (3)
Protocol:
  - HTTP
  - FTP
  - FILE
  - RTSP
  - SFTP
---

# NAME

CURLOPT_RANGE - byte range to request

# SYNOPSIS

~~~c
#include <curl/curl.h>

CURLcode curl_easy_setopt(CURL *handle, CURLOPT_RANGE, char *range);
~~~

# DESCRIPTION

Pass a char pointer as parameter, which should contain the specified range you
want to retrieve. It should be in the format "X-Y", where either X or Y may be
left out and X and Y are byte indexes.

HTTP transfers also support several intervals, separated with commas as in
*"X-Y,N-M"*. Using this kind of multiple intervals causes the HTTP server
to send the response document in pieces (using standard MIME separation
techniques). Unfortunately, the HTTP standard (RFC 7233 section 3.1) allows
servers to ignore range requests so even when you set CURLOPT_RANGE(3)
for a request, you may end up getting the full response sent back.

For RTSP, the formatting of a range should follow RFC 2326 Section 12.29. For
RTSP, byte ranges are **not** permitted. Instead, ranges should be given in
**npt**, **utc**, or **smpte** formats.

For HTTP PUT uploads this option should not be used, since it may conflict with
other options.

Pass a NULL to this option to disable the use of ranges.

The application does not have to keep the string around after setting this
option.

# DEFAULT

NULL

# EXAMPLE

~~~c
int main(void)
{
  CURL *curl = curl_easy_init();
  if(curl) {
    curl_easy_setopt(curl, CURLOPT_URL, "https://example.com");

    /* get the first 200 bytes */
    curl_easy_setopt(curl, CURLOPT_RANGE, "0-199");

    /* Perform the request */
    curl_easy_perform(curl);
  }
}
~~~

# AVAILABILITY

FILE since 7.18.0, RTSP since 7.20.0

# RETURN VALUE

Returns CURLE_OK on success or
CURLE_OUT_OF_MEMORY if there was insufficient heap space.
