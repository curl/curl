---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Title: CURLMOPT_PIPELINING_SERVER_BL
Section: 3
Source: libcurl
See-also:
  - CURLMOPT_PIPELINING (3)
  - CURLMOPT_PIPELINING_SITE_BL (3)
Protocol:
  - HTTP
Added-in: 7.30.0
---

# NAME

CURLMOPT_PIPELINING_SERVER_BL - pipelining server block list

# SYNOPSIS

~~~c
#include <curl/curl.h>

CURLMcode curl_multi_setopt(CURLM *handle, CURLMOPT_PIPELINING_SERVER_BL,
                            char **servers);
~~~

# DESCRIPTION

No function since pipelining was removed in 7.62.0.

Pass a **servers** array of char *, ending with a NULL entry. This is a list
of server types prefixes (in the Server: HTTP header) that are blocked from
pipelining, i.e server types that are known to not support HTTP
pipelining. The array is copied by libcurl.

Note that the comparison matches if the Server: header begins with the string
in the block list, i.e "Server: Ninja 1.2.3" and "Server: Ninja 1.4.0" can
both be blocked by having "Ninja" in the list.

Pass a NULL pointer to clear the block list.

# DEFAULT

NULL, which means that there is no block list.

# %PROTOCOLS%

# EXAMPLE

~~~c
static char *server_block_list[] =
{
  "Microsoft-IIS/6.0",
  "nginx/0.8.54",
  NULL
};
int main(void)
{
  CURLM *m = curl_multi_init();
  curl_multi_setopt(m, CURLMOPT_PIPELINING_SERVER_BL, server_block_list);
}
~~~

# %AVAILABILITY%

# RETURN VALUE

Returns CURLM_OK if the option is supported, and CURLM_UNKNOWN_OPTION if not.
