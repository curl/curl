---
c: Copyright (C) Daniel Stenberg, <daniel.se>, et al.
SPDX-License-Identifier: curl
Title: CURLOPT_EGDSOCKET
Section: 3
Source: libcurl
See-also:
  - CURLOPT_RANDOM_FILE (3)
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

Pass a char pointer to the null-terminated path name to the Entropy Gathering
Daemon socket. It is used to seed the random engine for TLS.

The application does not have to keep the string around after setting this
option.

# DEFAULT

NULL

# PROTOCOLS

All TLS based protocols: HTTPS, FTPS, IMAPS, POP3S, SMTPS etc.

# EXAMPLE

~~~c
int main(void)
{
  CURL *curl = curl_easy_init();
  if(curl) {
    CURLcode res;
    curl_easy_setopt(curl, CURLOPT_URL, "https://example.com/");
    curl_easy_setopt(curl, CURLOPT_EGDSOCKET, "/var/egd.socket");
    res = curl_easy_perform(curl);
    curl_easy_cleanup(curl);
  }
}
~~~

# AVAILABILITY

If built with TLS enabled. Only the OpenSSL backend uses this, and only with
OpenSSL versions before 1.1.0.

This option was deprecated in 7.84.0.

# RETURN VALUE

Returns CURLE_OK if TLS is supported, CURLE_UNKNOWN_OPTION if not, or
CURLE_OUT_OF_MEMORY if there was insufficient heap space.
