---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Title: CURLSHOPT_USERDATA
Section: 3
Source: libcurl
See-also:
  - CURLSHOPT_LOCKFUNC (3)
  - curl_share_cleanup (3)
  - curl_share_init (3)
  - curl_share_setopt (3)
Protocol:
  - All
Added-in: 7.10.3
---

# NAME

CURLSHOPT_USERDATA - pointer passed to the lock and unlock mutex callbacks

# SYNOPSIS

~~~c
#include <curl/curl.h>

CURLSHcode curl_share_setopt(CURLSH *share, CURLSHOPT_USERDATA, void *clientp);
~~~

# DESCRIPTION

The *clientp* parameter is held verbatim by libcurl and is passed on as
the *clientp* argument to the callbacks set with
CURLSHOPT_LOCKFUNC(3) and CURLSHOPT_UNLOCKFUNC(3).

# %PROTOCOLS%

# EXAMPLE

~~~c
struct secrets {
  void *custom;
};

int main(void)
{
  CURLSHcode sh;
  struct secrets private_stuff;
  CURLSH *share = curl_share_init();
  sh = curl_share_setopt(share, CURLSHOPT_USERDATA, &private_stuff);
  if(sh)
    printf("Error: %s\n", curl_share_strerror(sh));
}
~~~

# %AVAILABILITY%

# RETURN VALUE

CURLSHE_OK (zero) means that the option was set properly, non-zero means an
error occurred. See libcurl-errors(3) for the full list with
descriptions.
