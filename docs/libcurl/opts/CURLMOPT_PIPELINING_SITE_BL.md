---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Title: CURLMOPT_PIPELINING_SITE_BL
Section: 3
Source: libcurl
See-also:
  - CURLMOPT_PIPELINING (3)
  - CURLMOPT_PIPELINING_SERVER_BL (3)
Protocol:
  - HTTP
Added-in: 7.30.0
---

# NAME

CURLMOPT_PIPELINING_SITE_BL - pipelining host block list

# SYNOPSIS

~~~c
#include <curl/curl.h>

CURLMcode curl_multi_setopt(CURLM *handle, CURLMOPT_PIPELINING_SITE_BL,
                            char **hosts);
~~~

# DESCRIPTION

No function since pipelining was removed in 7.62.0.

Pass a **hosts** array of char *, ending with a NULL entry. This is a list
of sites that are blocked from pipelining, i.e sites that are known to not
support HTTP pipelining. The array is copied by libcurl.

Pass a NULL pointer to clear the block list.

# DEFAULT

NULL, which means that there is no block list.

# %PROTOCOLS%

# EXAMPLE

~~~c
static char *site_block_list[] =
{
  "www.haxx.se",
  "www.example.com:1234",
  NULL
};

int main(void)
{
  CURLM *m = curl_multi_init();
  curl_multi_setopt(m, CURLMOPT_PIPELINING_SITE_BL, site_block_list);
}
~~~

# %AVAILABILITY%

# RETURN VALUE

curl_multi_setopt(3) returns a CURLMcode indicating success or error.

CURLM_OK (0) means everything was OK, non-zero means an error occurred, see
libcurl-errors(3).
