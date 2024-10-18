---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Title: CURLOPT_REDIR_PROTOCOLS
Section: 3
Source: libcurl
See-also:
  - CURLINFO_SCHEME (3)
  - CURLOPT_DEFAULT_PROTOCOL (3)
  - CURLOPT_PROTOCOLS (3)
  - CURLOPT_REDIR_PROTOCOLS_STR (3)
Protocol:
  - HTTP
Added-in: 7.19.4
---

# NAME

CURLOPT_REDIR_PROTOCOLS - protocols allowed to redirect to

# SYNOPSIS

~~~c
#include <curl/curl.h>

CURLcode curl_easy_setopt(CURL *handle, CURLOPT_REDIR_PROTOCOLS, long bitmask);
~~~

# DESCRIPTION

This option is deprecated. We strongly recommend using
CURLOPT_REDIR_PROTOCOLS_STR(3) instead because this option cannot
control all available protocols.

Pass a long that holds a bitmask of CURLPROTO_* defines. If used, this bitmask
limits what protocols libcurl may use in a transfer that it follows to in a
redirect when CURLOPT_FOLLOWLOCATION(3) is enabled. This allows you to
limit specific transfers to only be allowed to use a subset of protocols in
redirections.

Protocols denied by CURLOPT_PROTOCOLS(3) are not overridden by this
option.

By default libcurl allows HTTP, HTTPS, FTP and FTPS on redirect (7.65.2).
*CURLPROTO_ALL* enables all protocols on redirect, including those
otherwise disabled for security.

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

HTTP, HTTPS, FTP and FTPS (Added in 7.65.2).

Older versions defaulted to all protocols except FILE, SCP and since 7.40.0
SMB and SMBS.

# %PROTOCOLS%

# EXAMPLE

~~~c
int main(int argc, char **argv)
{
  CURL *curl = curl_easy_init();
  if(curl) {
    /* pass in the URL from an external source */
    curl_easy_setopt(curl, CURLOPT_URL, argv[1]);

    /* only allow redirects to HTTP and HTTPS URLs */
    curl_easy_setopt(curl, CURLOPT_REDIR_PROTOCOLS,
                     CURLPROTO_HTTP | CURLPROTO_HTTPS);

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
