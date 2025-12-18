---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Title: curl_share_init
Section: 3
Source: libcurl
See-also:
  - curl_share_cleanup (3)
  - curl_share_setopt (3)
Protocol:
  - All
Added-in: 7.10
---

# NAME

curl_share_init - create a share object

# SYNOPSIS

~~~c
#include <curl/curl.h>

CURLSH *curl_share_init();
~~~

# DESCRIPTION

This function returns a pointer to a *CURLSH* handle to be used as input
to all the other share-functions, sometimes referred to as a share handle in
some places in the documentation. This init call MUST have a corresponding
call to curl_share_cleanup(3) when all operations using the share are
complete.

This *share handle* is what you pass to curl using the
CURLOPT_SHARE(3) option with curl_easy_setopt(3), to make that
specific curl handle use the data in this share.

# %PROTOCOLS%

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

# %AVAILABILITY%

# RETURN VALUE

If this function returns NULL, something went wrong (out of memory, etc.)
and therefore the share object was not created.
