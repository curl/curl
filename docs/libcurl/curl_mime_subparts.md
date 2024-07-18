---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Title: curl_mime_subparts
Section: 3
Source: libcurl
See-also:
  - curl_mime_addpart (3)
  - curl_mime_init (3)
Protocol:
  - HTTP
  - IMAP
  - SMTP
Added-in: 7.56.0
---

# NAME

curl_mime_subparts - set sub-parts of a multipart mime part

# SYNOPSIS

~~~c
#include <curl/curl.h>

CURLcode curl_mime_subparts(curl_mimepart *part, curl_mime *subparts);
~~~

# DESCRIPTION

curl_mime_subparts(3) sets a multipart mime part's content from a mime
structure.

*part* is a handle to the multipart part.

*subparts* is a mime structure handle holding the sub-parts. After
curl_mime_subparts(3) succeeds, the mime structure handle belongs to the
multipart part and must not be freed explicitly. It may however be updated by
subsequent calls to mime API functions.

Setting a part's contents multiple times is valid: only the value set by the
last call is retained. It is possible to unassign previous part's contents by
setting *subparts* to NULL.

# %PROTOCOLS%

# EXAMPLE

~~~c

static char *inline_html = "<title>example</title>";
static char *inline_text = "once upon the time";

int main(void)
{
  CURL *curl = curl_easy_init();
  if(curl) {
    struct curl_slist *slist;

    /* The inline part is an alternative proposing the html and the text
       versions of the email. */
    curl_mime *alt = curl_mime_init(curl);
    curl_mimepart *part;

    /* HTML message. */
    part = curl_mime_addpart(alt);
    curl_mime_data(part, inline_html, CURL_ZERO_TERMINATED);
    curl_mime_type(part, "text/html");

    /* Text message. */
    part = curl_mime_addpart(alt);
    curl_mime_data(part, inline_text, CURL_ZERO_TERMINATED);

    /* Create the inline part. */
    part = curl_mime_addpart(alt);
    curl_mime_subparts(part, alt);
    curl_mime_type(part, "multipart/alternative");
    slist = curl_slist_append(NULL, "Content-Disposition: inline");
    curl_mime_headers(part, slist, 1);
  }
}
~~~

# %AVAILABILITY%

# RETURN VALUE

CURLE_OK or a CURL error code upon failure.
