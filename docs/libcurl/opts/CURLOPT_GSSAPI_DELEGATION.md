---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Title: CURLOPT_GSSAPI_DELEGATION
Section: 3
Source: libcurl
Protocol:
  - HTTP
See-also:
  - CURLOPT_HTTPAUTH (3)
  - CURLOPT_PROXYAUTH (3)
Added-in: 7.22.0
---

# NAME

CURLOPT_GSSAPI_DELEGATION - allowed GSS-API delegation

# SYNOPSIS

~~~c
#include <curl/curl.h>

CURLcode curl_easy_setopt(CURL *handle, CURLOPT_GSSAPI_DELEGATION, long level);
~~~

# DESCRIPTION

Set the long parameter *level* to **CURLGSSAPI_DELEGATION_FLAG** to allow
unconditional GSSAPI credential delegation. The delegation is disabled by
default since 7.21.7. Set the parameter to
**CURLGSSAPI_DELEGATION_POLICY_FLAG** to delegate only if the OK-AS-DELEGATE
flag is set in the service ticket in case this feature is supported by the
GSS-API implementation and the definition of *GSS_C_DELEG_POLICY_FLAG* was
available at compile-time.

# DEFAULT

CURLGSSAPI_DELEGATION_NONE

# %PROTOCOLS%

# EXAMPLE

~~~c
int main(void)
{
  CURL *curl = curl_easy_init();
  if(curl) {
    CURLcode ret;
    curl_easy_setopt(curl, CURLOPT_URL, "https://example.com/");
    /* delegate if okayed by policy */
    curl_easy_setopt(curl, CURLOPT_GSSAPI_DELEGATION,
                     (long)CURLGSSAPI_DELEGATION_POLICY_FLAG);
    ret = curl_easy_perform(curl);
  }
}
~~~

# %AVAILABILITY%

# RETURN VALUE

curl_easy_setopt(3) returns a CURLcode indicating success or error.

CURLE_OK (0) means everything was OK, non-zero means an error occurred, see
libcurl-errors(3).
