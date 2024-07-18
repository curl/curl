---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Title: CURLSHOPT_UNSHARE
Section: 3
Source: libcurl
See-also:
  - CURLSHOPT_SHARE (3)
  - curl_share_cleanup (3)
  - curl_share_init (3)
  - curl_share_setopt (3)
Protocol:
  - All
Added-in: 7.10.3
---

# NAME

CURLSHOPT_UNSHARE - remove data to share

# SYNOPSIS

~~~c
#include <curl/curl.h>

CURLSHcode curl_share_setopt(CURLSH *share, CURLSHOPT_UNSHARE, long type);
~~~

# DESCRIPTION

The *type* parameter specifies what specific data that should no longer be
shared and kept in the share object that was created with
curl_share_init(3). In other words, stop sharing that data in this
shared object. The given *type* must be one of the values described
below. You can set CURLSHOPT_UNSHARE(3) multiple times with different
data arguments to remove multiple types from the shared object. Add data to
share again with CURLSHOPT_SHARE(3).

## CURL_LOCK_DATA_COOKIE

Cookie data is no longer shared across the easy handles using this shared
object.

## CURL_LOCK_DATA_DNS

Cached DNS hosts are no longer shared across the easy handles using this
shared object.

## CURL_LOCK_DATA_SSL_SESSION

SSL session IDs are no longer shared across the easy handles using this shared
object.

## CURL_LOCK_DATA_CONNECT

The connection cache is no longer shared.

## CURL_LOCK_DATA_PSL

The Public Suffix List is no longer shared.

# %PROTOCOLS%

# EXAMPLE

~~~c
int main(void)
{
  CURLSHcode sh;
  CURLSH *share = curl_share_init();
  sh = curl_share_setopt(share, CURLSHOPT_UNSHARE, CURL_LOCK_DATA_COOKIE);
  if(sh)
    printf("Error: %s\n", curl_share_strerror(sh));
}
~~~

# %AVAILABILITY%

# RETURN VALUE

CURLSHE_OK (zero) means that the option was set properly, non-zero means an
error occurred. See libcurl-errors(3) for the full list with
descriptions.
