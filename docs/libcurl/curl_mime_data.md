---
c: Copyright (C) Daniel Stenberg, <daniel.se>, et al.
SPDX-License-Identifier: curl
Title: curl_mime_data
Section: 3
Source: libcurl
See-also:
  - curl_mime_addpart (3)
  - curl_mime_data_cb (3)
  - curl_mime_name (3)
  - curl_mime_type (3)
---

# NAME

curl_mime_data - set a mime part's body data from memory

# SYNOPSIS

~~~c
#include <curl/curl.h>

CURLcode curl_mime_data(curl_mimepart *part, const char *data,
                        size_t datasize);
~~~

# DESCRIPTION

curl_mime_data(3) sets a mime part's body content from memory data.

*part* is the mime part to assign contents to, created with
curl_mime_addpart(3).

*data* points to the data that gets copied by this function. The storage
may safely be reused after the call.

*datasize* is the number of bytes *data* points to. It can be set to
*CURL_ZERO_TERMINATED* to indicate *data* is a null-terminated
character string.

Setting a part's contents multiple times is valid: only the value set by the
last call is retained. It is possible to unassign part's contents by setting
*data* to NULL.

Setting large data is memory consuming: one might consider using
curl_mime_data_cb(3) in such a case.

# EXAMPLE

~~~c
int main(void)
{
  curl_mime *mime;
  curl_mimepart *part;

  CURL *curl = curl_easy_init();
  if(curl) {
    /* create a mime handle */
    mime = curl_mime_init(curl);

    /* add a part */
    part = curl_mime_addpart(mime);

    /* add data to the part  */
    curl_mime_data(part, "raw contents to send", CURL_ZERO_TERMINATED);
  }
}
~~~

# AVAILABILITY

As long as at least one of HTTP, SMTP or IMAP is enabled. Added in 7.56.0.

# RETURN VALUE

CURLE_OK or a CURL error code upon failure.
