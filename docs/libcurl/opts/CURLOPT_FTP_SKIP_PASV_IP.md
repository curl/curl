---
c: Copyright (C) Daniel Stenberg, <daniel.se>, et al.
SPDX-License-Identifier: curl
Title: CURLOPT_FTP_SKIP_PASV_IP
Section: 3
Source: libcurl
See-also:
  - CURLOPT_FTPPORT (3)
  - CURLOPT_FTP_USE_EPRT (3)
---

# NAME

CURLOPT_FTP_SKIP_PASV_IP - ignore the IP address in the PASV response

# SYNOPSIS

~~~c
#include <curl/curl.h>

CURLcode curl_easy_setopt(CURL *handle, CURLOPT_FTP_SKIP_PASV_IP, long skip);
~~~

# DESCRIPTION

Pass a long. If *skip* is set to 1, it instructs libcurl to not use the IP
address the server suggests in its 227-response to libcurl's PASV command when
libcurl connects the data connection. Instead libcurl reuses the same IP
address it already uses for the control connection. It still uses the port
number from the 227-response.

This option allows libcurl to work around broken server installations or funny
network setups that due to NATs, firewalls or incompetence report the wrong IP
address. Setting this option also reduces the risk for various sorts of client
abuse by malicious servers.

This option has no effect if PORT, EPRT or EPSV is used instead of PASV.

# DEFAULT

1 since 7.74.0, was 0 before then.

# PROTOCOLS

FTP

# EXAMPLE

~~~c
int main(void)
{
  CURL *curl = curl_easy_init();
  if(curl) {
    CURLcode res;
    curl_easy_setopt(curl, CURLOPT_URL, "ftp://example.com/file.txt");

    /* please ignore the IP in the PASV response */
    curl_easy_setopt(curl, CURLOPT_FTP_SKIP_PASV_IP, 1L);
    res = curl_easy_perform(curl);

    curl_easy_cleanup(curl);
  }
}
~~~

# AVAILABILITY

Added in 7.14.2

# RETURN VALUE

Returns CURLE_OK if the option is supported, and CURLE_UNKNOWN_OPTION if not.
