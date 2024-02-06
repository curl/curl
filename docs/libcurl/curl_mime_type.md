---
c: Copyright (C) Daniel Stenberg, <daniel.se>, et al.
SPDX-License-Identifier: curl
Title: curl_mime_type
Section: 3
Source: libcurl
See-also:
  - curl_mime_addpart (3)
  - curl_mime_data (3)
  - curl_mime_name (3)
---

# NAME

curl_mime_type - set a mime part's content type

# SYNOPSIS

~~~c
#include <curl/curl.h>

CURLcode curl_mime_type(curl_mimepart *part, const char *mimetype);
~~~

# DESCRIPTION

curl_mime_type(3) sets a mime part's content type.

*part* is the part's handle to assign the content type to.

*mimetype* points to the null-terminated file mime type string; it may be
set to NULL to remove a previously attached mime type.

The mime type string is copied into the part, thus the associated storage may
safely be released or reused after call. Setting a part's type multiple times
is valid: only the value set by the last call is retained.

In the absence of a mime type and if needed by the protocol specifications,
a default mime type is determined by the context:

- If set as a custom header, use this value.

- application/form-data for an HTTP form post.

- If a remote filename is set, the mime type is taken from the file name
extension, or application/octet-stream by default.

- For a multipart part, multipart/mixed.

- text/plain in other cases.

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

    /* get data from this file */
    curl_mime_filedata(part, "image.png");

    /* content-type for this part */
    curl_mime_type(part, "image/png");

    /* set name */
    curl_mime_name(part, "image");
}
}
~~~

# AVAILABILITY

As long as at least one of HTTP, SMTP or IMAP is enabled. Added in 7.56.0.

# RETURN VALUE

CURLE_OK or a CURL error code upon failure.
