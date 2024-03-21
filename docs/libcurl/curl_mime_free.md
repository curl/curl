---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Title: curl_mime_free
Section: 3
Source: libcurl
See-also:
  - curl_free (3)
  - curl_mime_init (3)
Protocol:
  - HTTP
  - IMAP
  - SMTP
---

# NAME

curl_mime_free - free a previously built mime structure

# SYNOPSIS

~~~c
#include <curl/curl.h>

void curl_mime_free(curl_mime *mime);
~~~

# DESCRIPTION

curl_mime_free(3) is used to clean up data previously built/appended
with curl_mime_addpart(3) and other mime-handling functions. This must
be called when the data has been used, which typically means after
curl_easy_perform(3) has been called.

The handle to free is the one you passed to the CURLOPT_MIMEPOST(3)
option: attached sub part mime structures must not be explicitly freed as they
are by the top structure freeing.

**mime** is the handle as returned from a previous call to
curl_mime_init(3) and may be NULL.

Passing in a NULL pointer in *mime* makes this function return immediately
with no action.

# EXAMPLE

~~~c
int main(void)
{
  CURL *curl = curl_easy_init();
  if(curl) {
    /* Build the mime message. */
    curl_mime *mime = curl_mime_init(curl);

    /* send off the transfer */

    /* Free multipart message. */
    curl_mime_free(mime);
  }
}
~~~

# AVAILABILITY

As long as at least one of HTTP, SMTP or IMAP is enabled. Added in 7.56.0.

# RETURN VALUE

None
