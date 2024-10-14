---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Title: CURLINFO_PROTOCOL
Section: 3
Source: libcurl
See-also:
  - CURLINFO_RESPONSE_CODE (3)
  - curl_easy_getinfo (3)
  - curl_easy_setopt (3)
Protocol:
  - All
Added-in: 7.52.0
---

# NAME

CURLINFO_PROTOCOL - get the protocol used in the connection

# SYNOPSIS

~~~c
#include <curl/curl.h>

CURLcode curl_easy_getinfo(CURL *handle, CURLINFO_PROTOCOL, long *p);
~~~

# DESCRIPTION

This option is deprecated. We strongly recommend using
CURLINFO_SCHEME(3) instead, because this option cannot return all
possible protocols.

Pass a pointer to a long to receive the version used in the last http
connection. The returned value is set to one of the CURLPROTO_* values:

~~~c
CURLPROTO_DICT, CURLPROTO_FILE, CURLPROTO_FTP, CURLPROTO_FTPS,
CURLPROTO_GOPHER, CURLPROTO_HTTP, CURLPROTO_HTTPS, CURLPROTO_IMAP,
CURLPROTO_IMAPS, CURLPROTO_LDAP, CURLPROTO_LDAPS, CURLPROTO_POP3,
CURLPROTO_POP3S, CURLPROTO_RTMP, CURLPROTO_RTMPE, CURLPROTO_RTMPS,
CURLPROTO_RTMPT, CURLPROTO_RTMPTE, CURLPROTO_RTMPTS, CURLPROTO_RTSP,
CURLPROTO_SCP, CURLPROTO_SFTP, CURLPROTO_SMB, CURLPROTO_SMBS, CURLPROTO_SMTP,
CURLPROTO_SMTPS, CURLPROTO_TELNET, CURLPROTO_TFTP, CURLPROTO_MQTT
~~~

# %PROTOCOLS%

# EXAMPLE

~~~c
int main(void)
{
  CURL *curl = curl_easy_init();
  if(curl) {
    CURLcode res;
    curl_easy_setopt(curl, CURLOPT_URL, "https://example.com");
    res = curl_easy_perform(curl);
    if(res == CURLE_OK) {
      long protocol;
      curl_easy_getinfo(curl, CURLINFO_PROTOCOL, &protocol);
    }
    curl_easy_cleanup(curl);
  }
}
~~~

# DEPRECATED

Deprecated since 7.85.0.

# %AVAILABILITY%

# RETURN VALUE

Returns CURLE_OK if the option is supported, and CURLE_UNKNOWN_OPTION if not.
