---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Title: CURLOPT_AWS_SIGV4_SIGNEDHEADERS
Section: 3
Source: libcurl
See-also:
  - CURLOPT_AWS_SIGV4 (3)
  - CURLOPT_AWS_SIGV4_ALGORITHM (3)
  - CURLOPT_AWS_SIGV4_MODE (3)
Protocol:
  - HTTP
Added-in: 8.17.0
---

# NAME

CURLOPT_AWS_SIGV4_SIGNEDHEADERS - AWS SigV4 signed headers list

# SYNOPSIS

~~~c
#include <curl/curl.h>

CURLcode curl_easy_setopt(CURL *handle, CURLOPT_AWS_SIGV4_SIGNEDHEADERS, char *headers);
~~~

# DESCRIPTION

Pass a pointer to a null-terminated string that specifies which HTTP headers should be included in the AWS SigV4 signature calculation.

The headers string should be a semicolon-separated list of header names in lowercase. Only the specified headers will be included in the signature calculation.

If this option is not set, libcurl automatically determines which headers to sign based on the request and AWS service requirements. Common headers that are typically signed include:

- **host** - Always required
- **content-type** - For requests with a body
- **x-amz-date** - AWS timestamp header
- **x-amz-content-sha256** - Content checksum header

The application does not have to keep the string around after setting this option.

# DEFAULT

NULL (automatic header selection)

# %PROTOCOLS%

# EXAMPLE

~~~c
int main(void)
{
  CURL *curl = curl_easy_init();
  if(curl) {
    curl_easy_setopt(curl, CURLOPT_URL, "https://s3.amazonaws.com/bucket/object");
    curl_easy_setopt(curl, CURLOPT_AWS_SIGV4, "aws:amz:us-east-1:s3");
    curl_easy_setopt(curl, CURLOPT_AWS_SIGV4_SIGNEDHEADERS, "host;x-amz-date;x-amz-content-sha256");
    curl_easy_setopt(curl, CURLOPT_USERPWD, "ACCESS_KEY:SECRET_KEY");
    curl_easy_perform(curl);
  }
}
~~~

# %AVAILABILITY%

# RETURN VALUE

Returns CURLE_OK if the option is supported, CURLE_UNKNOWN_OPTION if not, or CURLE_OUT_OF_MEMORY if there was insufficient heap space.
