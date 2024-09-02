---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Title: CURLOPT_MIME_OPTIONS
Section: 3
Source: libcurl
See-also:
  - CURLOPT_HTTPPOST (3)
  - CURLOPT_MIMEPOST (3)
Protocol:
  - HTTP
  - IMAP
  - SMTP
Added-in: 7.81.0
---

# NAME

CURLOPT_MIME_OPTIONS - set MIME option flags

# SYNOPSIS

~~~c
#include <curl/curl.h>

CURLcode curl_easy_setopt(CURL *handle, CURLOPT_MIME_OPTIONS, long options);
~~~

# DESCRIPTION

Pass a long that holds a bitmask of CURLMIMEOPT_* defines. Each bit is a
Boolean flag used while encoding a MIME tree or multipart form data.

Available bits are:

## CURLMIMEOPT_FORMESCAPE

Tells libcurl to escape multipart form field and filenames using the
backslash-escaping algorithm rather than percent-encoding (HTTP only).

Backslash-escaping consists in preceding backslashes and double quotes with
a backslash. Percent encoding maps all occurrences of double quote,
carriage return and line feed to %22, %0D and %0A respectively.

Before version 7.81.0, percent-encoding was never applied.

HTTP browsers used to do backslash-escaping in the past but have over time
transitioned to use percent-encoding. This option allows one to address
server-side applications that have not yet have been converted.

As an example, consider field or filename *strangename"kind*. When the
containing multipart form is sent, this is normally transmitted as
*strangename%22kind*. When this option is set, it is sent as
*strangename"kind*.

# DEFAULT

0, meaning disabled.

# %PROTOCOLS%

# EXAMPLE

~~~c
int main(void)
{
  CURL *curl = curl_easy_init();
  curl_mime *form = NULL;

  if(curl) {
    curl_easy_setopt(curl, CURLOPT_URL, "https://example.com");
    curl_easy_setopt(curl, CURLOPT_MIME_OPTIONS, CURLMIMEOPT_FORMESCAPE);

    form = curl_mime_init(curl);
    if(form) {
      curl_mimepart *part = curl_mime_addpart(form);

      if(part) {
        curl_mime_filedata(part, "strange\\file\\name");
        curl_mime_name(part, "strange\"field\"name");
        curl_easy_setopt(curl, CURLOPT_MIMEPOST, form);

        /* Perform the request */
        curl_easy_perform(curl);
      }
    }

    curl_easy_cleanup(curl);
    curl_mime_free(form);
  }
}
~~~

# %AVAILABILITY%

# RETURN VALUE

Returns CURLE_OK
