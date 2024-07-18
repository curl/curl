---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Title: curl_mime_headers
Section: 3
Source: libcurl
See-also:
  - curl_mime_addpart (3)
  - curl_mime_name (3)
Protocol:
  - HTTP
  - IMAP
  - SMTP
Added-in: 7.56.0
---

# NAME

curl_mime_headers - set a mime part's custom headers

# SYNOPSIS

~~~c
#include <curl/curl.h>

CURLcode curl_mime_headers(curl_mimepart *part,
                           struct curl_slist *headers, int take_ownership);
~~~

# DESCRIPTION

curl_mime_headers(3) sets a mime part's custom headers.

*part* is the part's handle to assign the custom headers list to.

*headers* is the head of a list of custom headers; it may be set to NULL
to remove a previously attached custom header list.

*take_ownership*: when non-zero, causes the list to be freed upon
replacement or mime structure deletion; in this case the list must not be
freed explicitly.

Setting a part's custom headers list multiple times is valid: only the value
set by the last call is retained.

# %PROTOCOLS%

# EXAMPLE

~~~c
int main(void)
{
  struct curl_slist *headers = NULL;
  CURL *easy = curl_easy_init();
  curl_mime *mime;
  curl_mimepart *part;

  headers = curl_slist_append(headers, "Custom-Header: mooo");

  mime = curl_mime_init(easy);
  part = curl_mime_addpart(mime);

  /* use these headers in the part, takes ownership */
  curl_mime_headers(part, headers, 1);

  /* pass on this data */
  curl_mime_data(part, "12345679", CURL_ZERO_TERMINATED);

  /* set name */
  curl_mime_name(part, "numbers");

  /* Post and send it. */
  curl_easy_setopt(easy, CURLOPT_MIMEPOST, mime);
  curl_easy_setopt(easy, CURLOPT_URL, "https://example.com");
  curl_easy_perform(easy);
}
~~~

# %AVAILABILITY%

# RETURN VALUE

CURLE_OK or a CURL error code upon failure.
