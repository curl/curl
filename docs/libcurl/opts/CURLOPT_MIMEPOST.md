---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Title: CURLOPT_MIMEPOST
Section: 3
Source: libcurl
See-also:
  - CURLOPT_HTTPPOST (3)
  - CURLOPT_POSTFIELDS (3)
  - CURLOPT_PUT (3)
  - curl_mime_init (3)
Protocol:
  - HTTP
  - SMTP
  - IMAP
Added-in: 7.56.0
---

# NAME

CURLOPT_MIMEPOST - send data from mime structure

# SYNOPSIS

~~~c
#include <curl/curl.h>

curl_mime *mime;

CURLcode curl_easy_setopt(CURL *handle, CURLOPT_MIMEPOST, mime);
~~~

# DESCRIPTION

Pass a mime handle previously obtained from curl_mime_init(3).

This setting is supported by the HTTP protocol to post forms and by the
SMTP and IMAP protocols to provide the email data to send/upload.

This option is the preferred way of posting an HTTP form, replacing and
extending the CURLOPT_HTTPPOST(3) option.

When setting CURLOPT_MIMEPOST(3) to NULL, libcurl resets the request
type for HTTP to the default to disable the POST. Typically that would mean it
is reset to GET. Instead you should set a desired request method explicitly.

# %PROTOCOLS%

# EXAMPLE

~~~c
int main(void)
{
  CURL *curl = curl_easy_init();
  if(curl) {
    curl_mime *multipart = curl_mime_init(curl);
    if(multipart) {
      curl_mimepart *part = curl_mime_addpart(multipart);
      curl_mime_name(part, "name");
      curl_mime_data(part, "daniel", CURL_ZERO_TERMINATED);
      part = curl_mime_addpart(multipart);
      curl_mime_name(part, "project");
      curl_mime_data(part, "curl", CURL_ZERO_TERMINATED);
      part = curl_mime_addpart(multipart);
      curl_mime_name(part, "logotype-image");
      curl_mime_filedata(part, "curl.png");

      /* Set the form info */
      curl_easy_setopt(curl, CURLOPT_MIMEPOST, multipart);

      curl_easy_perform(curl); /* post away! */
      curl_mime_free(multipart); /* free the post data */
    }
  }
}
~~~

# %AVAILABILITY%

# RETURN VALUE

This returns CURLE_OK.
