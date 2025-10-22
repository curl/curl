---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Title: CURLOPT_AWS_SIGV4_MODE
Section: 3
Source: libcurl
See-also:
  - CURLOPT_AWS_SIGV4 (3)
  - CURLOPT_AWS_SIGV4_ALGORITHM (3)
  - CURLOPT_AWS_SIGV4_SIGNEDHEADERS (3)
Protocol:
  - HTTP
Added-in: 8.17.0
---

# NAME

CURLOPT_AWS_SIGV4_MODE - AWS SigV4 signing mode

# SYNOPSIS

~~~c
#include <curl/curl.h>

CURLcode curl_easy_setopt(CURL *handle, CURLOPT_AWS_SIGV4_MODE, char *mode);
~~~

# DESCRIPTION

Pass a pointer to a null-terminated string that specifies the AWS SigV4 signing mode.

The mode determines how the signature is applied to the request:

- **"header"** - Add signature to HTTP headers (default)
- **"querystring"** - Add signature to URL query parameters

When using **"querystring"** mode, the signature and related parameters are added as query parameters to the URL instead of HTTP headers. This is useful for creating pre-signed URLs or when HTTP headers cannot be modified.

The application does not have to keep the string around after setting this option.

# DEFAULT

"header"

# %PROTOCOLS%

# EXAMPLE

~~~c
int main(void)
{
  CURL *curl = curl_easy_init();
  if(curl) {
    curl_easy_setopt(curl, CURLOPT_URL, "https://s3.amazonaws.com/bucket/object");
    curl_easy_setopt(curl, CURLOPT_AWS_SIGV4, "aws:amz:us-east-1:s3");
    curl_easy_setopt(curl, CURLOPT_AWS_SIGV4_MODE, "querystring");
    curl_easy_setopt(curl, CURLOPT_USERPWD, "ACCESS_KEY:SECRET_KEY");
    curl_easy_perform(curl);
  }
}
~~~

# %AVAILABILITY%

# RETURN VALUE

Returns CURLE_OK if the option is supported, CURLE_UNKNOWN_OPTION if not, or CURLE_OUT_OF_MEMORY if there was insufficient heap space.
