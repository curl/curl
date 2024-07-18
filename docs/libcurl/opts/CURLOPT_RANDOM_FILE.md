---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Title: CURLOPT_RANDOM_FILE
Section: 3
Source: libcurl
See-also:
  - CURLOPT_EGDSOCKET (3)
Protocol:
  - TLS
TLS-backend:
  - OpenSSL
Added-in: 7.7
---

# NAME

CURLOPT_RANDOM_FILE - file to read random data from

# SYNOPSIS

~~~c
#include <curl/curl.h>

CURLcode curl_easy_setopt(CURL *handle, CURLOPT_RANDOM_FILE, char *path);
~~~

# DESCRIPTION

Deprecated option. It serves no purpose anymore.

# DEFAULT

NULL, not used

# DEPRECATED

Deprecated since 7.84.0.

# %AVAILABILITY%

# RETURN VALUE

Returns CURLE_OK.
