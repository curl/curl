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

# AVAILABILITY

This option was deprecated in 7.84.0.

# RETURN VALUE

Returns CURLE_OK.
