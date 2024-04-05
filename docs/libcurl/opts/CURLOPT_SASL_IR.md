---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Title: CURLOPT_SASL_IR
Section: 3
Source: libcurl
See-also:
  - CURLOPT_MAIL_AUTH (3)
  - CURLOPT_MAIL_FROM (3)
  - CURLOPT_SASL_AUTHZID (3)
Protocol:
  - SMTP
  - IMAP
---

# NAME

CURLOPT_SASL_IR - send initial response in first packet

# SYNOPSIS

~~~c
#include <curl/curl.h>

CURLcode curl_easy_setopt(CURL *handle, CURLOPT_SASL_IR, long enable);
~~~

# DESCRIPTION

Pass a long. If the value is 1, curl sends the initial response to the server
in the first authentication packet in order to reduce the number of ping pong
requests. Only applicable to the following supporting SASL authentication
mechanisms:

* Login
* Plain
* GSSAPI
* NTLM
* OAuth 2.0

Note: Whilst IMAP supports this option there is no need to explicitly set it,
as libcurl can determine the feature itself when the server supports the
SASL-IR CAPABILITY.

# DEFAULT

0

# EXAMPLE

~~~c
int main(void)
{
  CURL *curl = curl_easy_init();
  if(curl) {
    CURLcode res;
    curl_easy_setopt(curl, CURLOPT_URL, "smtp://example.com/");
    curl_easy_setopt(curl, CURLOPT_SASL_IR, 1L);
    res = curl_easy_perform(curl);
    curl_easy_cleanup(curl);
  }
}
~~~

# AVAILABILITY

Added in 7.31.0

# RETURN VALUE

Returns CURLE_OK if the option is supported, and CURLE_UNKNOWN_OPTION if not.
