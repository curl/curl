---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Title: CURLOPT_HEADERFUNCTION_EXTENDED
Section: 3
Source: libcurl
See-also:
  - CURLOPT_HEADERFUNCTION (3)
  - CURLOPT_HEADERDATA (3)
  - CURLOPT_WRITEFUNCTION (3)
  - curl_easy_header (3)
Protocol:
  - HTTP
  - FTP
  - POP3
  - IMAP
  - SMTP
Added-in: 8.21.0
---

# NAME

CURLOPT_HEADERFUNCTION_EXTENDED - callback that receives header data and origin

# SYNOPSIS

~~~c
#include <curl/curl.h>

size_t header_extended_callback(const char *buffer,
                                size_t nitems,
                                unsigned int origin,
                                void *userdata);

CURLcode curl_easy_setopt(CURL *handle, CURLOPT_HEADERFUNCTION_EXTENDED,
                          header_extended_callback);
~~~

# DESCRIPTION

Pass a pointer to your callback function, which should match the prototype
shown above.

This option works much like CURLOPT_HEADERFUNCTION(3). Additionally, the
callback gets information about the origin of the headers.

*buffer* points to the delivered data. The size of that data is *nitems*.
In contrast to CURLOPT_HEADERFUNCTION(3), there is no *size* parameter.

The provided header line is not null-terminated. Do not modify the passed in
buffer.

The header origin is passed to the callback function with the parameter
*origin*. The function may get headers from a CONNECT response
(CURLH_CONNECT), intermediate 1xx headers (CURLH_1XX), headers of the final
response (CURLH_HEADER), and trailers of the final response (CURLH_TRAILER).

Note that the CURLH_PSEUDO origin is not used here. See the
curl_easy_header(3) man page for more detailed descriptions of the origins.

The options CURLOPT_HEADERFUNCTION(3) and CURLOPT_HEADERFUNCTION_EXTENDED(3)
cannot be used at the same time. Setting one of these options automatically
clears the other option, so the headers are only passed to a single callback
function.

A more convenient way to get HTTP headers might be to use
curl_easy_header(3).

# DEFAULT

Nothing.

# %PROTOCOLS%

# EXAMPLE

~~~c
static size_t header_extended_callback(const char *buffer, size_t nitems,
                                       unsigned int origin, void *userdata)
{
  /* received header is 'nitems' bytes in 'buffer' NOT NULL-TERMINATED */
  /* 'userdata' is set with CURLOPT_HEADERDATA */
  return nitems;
}

int main(void)
{
  CURL *curl = curl_easy_init();
  if(curl) {
    CURLcode result;
    curl_easy_setopt(curl, CURLOPT_URL, "https://example.com");

    curl_easy_setopt(curl, CURLOPT_HEADERFUNCTION_EXTENDED,
                     header_extended_callback);

    result = curl_easy_perform(curl);

    curl_easy_cleanup(curl);
  }
}
~~~

# %AVAILABILITY%

# RETURN VALUE

curl_easy_setopt(3) returns a CURLcode indicating success or error.

CURLE_OK (0) means everything was OK, non-zero means an error occurred, see
libcurl-errors(3).
