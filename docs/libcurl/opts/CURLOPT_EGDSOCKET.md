---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Title: CURLOPT_EGDSOCKET
Section: 3
Source: libcurl
See-also:
  - CURLOPT_RANDOM_FILE (3)
Protocol:
  - TLS
TLS-backend:
  - OpenSSL
Added-in: 7.7
---

# NAME

CURLOPT_EGDSOCKET - EGD socket path

# SYNOPSIS

~~~c
#include <curl/curl.h>

CURLcode curl_easy_setopt(CURL *handle, CURLOPT_EGDSOCKET, char *path);
~~~

# DESCRIPTION

Deprecated option. It serves no purpose anymore.

# DEFAULT

NULL

# DEPRECATED

This option was deprecated in 7.84.0.

# %AVAILABILITY%

# RETURN VALUE

Returns CURLE_OK.
