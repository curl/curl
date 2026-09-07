---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Title: CURLMOPT_REMOVE_CONNECTION
Section: 3
Source: libcurl
See-also:
  - CURLOPT_FRESH_CONNECT (3)
  - CURLOPT_FORBID_REUSE (3)
  - CURLOPT_NETWORK_CHANGED (3)
Protocol:
  - All
Added-in: 8.23.0
---

# NAME

CURLMOPT_REMOVE_CONNECTION - drain and close connection

# SYNOPSIS

~~~c
#include <curl/curl.h>

CURLMcode curl_multi_setopt(CURLM *handle, CURLMOPT_REMOVE_CONNECTION,
                            curl_off_t connid);
~~~

# DESCRIPTION

Pass a curl_off_t to request libcurl prevent further use of a given connection.

This option can prevent the reuse of a connection, allowing drain of a single
connection and further requests to ensure a new connection, in the case where
the application decides a connection is no longer valid and needs to be closed.

This can be used along with CURLINFO_CONN_ID to prevent further reuse of the
last connection used by an easy handle in the multi.

This option can be set at any time and repeatedly.

# %PROTOCOLS%

# EXAMPLE

~~~c
int main(void)
{
  CURLM *m = curl_multi_init();
  CURL *c = curl_easy_init();
  
  curl_multi_add_handle(m, c);
  /* do transfers on the multi handle */
  /* do not reuse existing connections */
  
  /* after c has finished. we want to prevent reusing that connection */
  curl_off_t id = -1;
  curl_easy_getinfo(e, CURLINFO_CONN_ID, &id);
  if (id >= 0) {
    curl_multi_setopt(m, CURLMOPT_REMOVE_CONNECTION, id);
  }
  
}
~~~

# %AVAILABILITY%

# RETURN VALUE

curl_multi_setopt(3) returns a CURLMcode indicating success or error.

CURLM_OK (0) means the connection was found and closed, non-zero means
an error occurred, see libcurl-errors(3).
