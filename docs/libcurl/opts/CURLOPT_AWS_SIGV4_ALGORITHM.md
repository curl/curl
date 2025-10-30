---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Title: CURLOPT_AWS_SIGV4_ALGORITHM
Section: 3
Source: libcurl
See-also:
  - CURLOPT_AWS_SIGV4 (3)
  - CURLOPT_AWS_SIGV4_MODE (3)
  - CURLOPT_AWS_SIGV4_SIGNEDHEADERS (3)
Protocol:
  - HTTP
Added-in: 8.17.0
---

# NAME

CURLOPT_AWS_SIGV4_ALGORITHM - AWS SigV4 algorithm

# SYNOPSIS

~~~c
#include <curl/curl.h>

CURLcode curl_easy_setopt(CURL *handle, CURLOPT_AWS_SIGV4_ALGORITHM, char *algorithm);
~~~

# DESCRIPTION

Pass a pointer to a null-terminated string that specifies the AWS SigV4 algorithm to use for signing requests.

The algorithm string determines the cryptographic algorithm used in the signature calculation. Common values include:

- **"ECDSA-P256-SHA256"** - for AWS SigV4A with ECDSA P-256 curve
- **"HMAC-SHA256"** - for standard AWS SigV4 (default)

If this option is not set, libcurl defaults to **"HMAC-SHA256"** for standard SigV4 signing.

The application does not have to keep the string around after setting this option.

# DEFAULT

"HMAC-SHA256"

# %PROTOCOLS%

# EXAMPLE

~~~c
int main(void)
{
  CURL *curl = curl_easy_init();
  if(curl) {
    curl_easy_setopt(curl, CURLOPT_URL, "https://s3.amazonaws.com/bucket/object");
    curl_easy_setopt(curl, CURLOPT_AWS_SIGV4, "aws:amz:us-east-1:s3");
    curl_easy_setopt(curl, CURLOPT_AWS_SIGV4_ALGORITHM, "ECDSA-P256-SHA256");
    curl_easy_setopt(curl, CURLOPT_USERPWD, "ACCESS_KEY:SECRET_KEY");
    curl_easy_perform(curl);
  }
}
~~~

# %AVAILABILITY%

# RETURN VALUE

Returns CURLE_OK if the option is supported, CURLE_UNKNOWN_OPTION if not, or CURLE_OUT_OF_MEMORY if there was insufficient heap space.
