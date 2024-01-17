---
c: Copyright (C) Daniel Stenberg, <daniel.se>, et al.
SPDX-License-Identifier: curl
Title: curl_share_setopt
Section: 3
Source: libcurl
See-also:
  - curl_share_cleanup (3)
  - curl_share_init (3)
---

# NAME

curl_share_setopt - Set options for a shared object

# SYNOPSIS

~~~c
#include <curl/curl.h>

CURLSHcode curl_share_setopt(CURLSH *share, CURLSHoption option, parameter);
~~~

# DESCRIPTION

Set the *option* to *parameter* for the given *share*.

# OPTIONS

## CURLSHOPT_LOCKFUNC

See CURLSHOPT_LOCKFUNC(3).

## CURLSHOPT_UNLOCKFUNC

See CURLSHOPT_UNLOCKFUNC(3).

## CURLSHOPT_SHARE

See CURLSHOPT_SHARE(3).

## CURLSHOPT_UNSHARE

See CURLSHOPT_UNSHARE(3).

## CURLSHOPT_USERDATA

See CURLSHOPT_USERDATA(3).

# EXAMPLE

~~~c
int main(void)
{
  CURLSHcode sh;
  CURLSH *share = curl_share_init();
  sh = curl_share_setopt(share, CURLSHOPT_SHARE, CURL_LOCK_DATA_CONNECT);
  if(sh)
    printf("Error: %s\n", curl_share_strerror(sh));
}
~~~

# AVAILABILITY

Added in 7.10

# RETURN VALUE

CURLSHE_OK (zero) means that the option was set properly, non-zero means an
error occurred as *<curl/curl.h>* defines. See the libcurl-errors(3)
man page for the full list with descriptions.
