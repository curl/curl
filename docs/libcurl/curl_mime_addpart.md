---
c: Copyright (C) Daniel Stenberg, <daniel.se>, et al.
SPDX-License-Identifier: curl
Title: curl_mime_addpart
Section: 3
Source: libcurl
See-also:
  - curl_mime_data (3)
  - curl_mime_data_cb (3)
  - curl_mime_encoder (3)
  - curl_mime_filedata (3)
  - curl_mime_filename (3)
  - curl_mime_headers (3)
  - curl_mime_init (3)
  - curl_mime_name (3)
  - curl_mime_subparts (3)
  - curl_mime_type (3)
---

# NAME

curl_mime_addpart - append a new empty part to a mime structure

# SYNOPSIS

~~~c
#include <curl/curl.h>

curl_mimepart *curl_mime_addpart(curl_mime *mime);
~~~

# DESCRIPTION

curl_mime_addpart(3) creates and appends a new empty part to the given
mime structure and returns a handle to it. The returned part handle can
subsequently be populated using functions from the mime API.

*mime* is the handle of the mime structure in which the new part must be
appended.

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

    /* continue and set name + data to the part */
    curl_mime_data(part, "This is the field data", CURL_ZERO_TERMINATED);
    curl_mime_name(part, "data");
  }
}
~~~

# AVAILABILITY

As long as at least one of HTTP, SMTP or IMAP is enabled. Added in 7.56.0.

# RETURN VALUE

A mime part structure handle, or NULL upon failure.
