---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Title: CURLOPT_PROTOCOLS
Section: 3
Source: libcurl
See-also:
  - CURLOPT_DEFAULT_PROTOCOL (3)
  - CURLOPT_REDIR_PROTOCOLS (3)
  - CURLOPT_URL (3)
Protocol:
  - All
Added-in: 7.19.4
---

# NAME

CURLOPT_PROTOCOLS - allowed protocols

# SYNOPSIS

~~~c
#include <curl/curl.h>

CURLcode curl_easy_setopt(CURL *handle, CURLOPT_PROTOCOLS, long bitmask);
~~~

# DESCRIPTION

This option is deprecated. We strongly recommend using
CURLOPT_PROTOCOLS_STR(3) instead because this option cannot control all
available protocols!

Pass a long that holds a bitmask of CURLPROTO_* defines. If used, this bitmask
limits what protocols libcurl may use in the transfer. This allows you to have
a libcurl built to support a wide range of protocols but still limit specific
transfers to only be allowed to use a subset of them. By default libcurl
accepts all protocols it supports (*CURLPROTO_ALL*). See also
CURLOPT_REDIR_PROTOCOLS(3).

These are the available protocol defines:
~~~c
CURLPROTO_DICT
CURLPROTO_FILE
CURLPROTO_FTP
CURLPROTO_FTPS
CURLPROTO_GOPHER
CURLPROTO_HTTP
CURLPROTO_HTTPS
CURLPROTO_IMAP
CURLPROTO_IMAPS
CURLPROTO_LDAP
CURLPROTO_LDAPS
CURLPROTO_POP3
CURLPROTO_POP3S
CURLPROTO_RTMP
CURLPROTO_RTMPE
CURLPROTO_RTMPS
CURLPROTO_RTMPT
CURLPROTO_RTMPTE
CURLPROTO_RTMPTS
CURLPROTO_RTSP
CURLPROTO_SCP
CURLPROTO_SFTP
CURLPROTO_SMB
CURLPROTO_SMBS
CURLPROTO_SMTP
CURLPROTO_SMTPS
CURLPROTO_TELNET
CURLPROTO_TFTP
~~~

# DEFAULT

All protocols built-in.

# %PROTOCOLS%

# EXAMPLE

~~~c
int main(int argc, char **argv)
{
  CURL *curl = curl_easy_init();
  if(curl) {
    /* pass in the URL from an external source */
    curl_easy_setopt(curl, CURLOPT_URL, argv[1]);

    /* only allow HTTP, TFTP and SFTP */
    curl_easy_setopt(curl, CURLOPT_PROTOCOLS,
                     CURLPROTO_HTTP | CURLPROTO_TFTP | CURLPROTO_SFTP);

    /* Perform the request */
    curl_easy_perform(curl);
  }
}
~~~

# DEPRECATED

Deprecated since 7.85.0.

# %AVAILABILITY%

# RETURN VALUE

Returns CURLE_OK if the option is supported, and CURLE_UNKNOWN_OPTION if not.
