---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: fetch
Title: FETCHINFO_PROTOCOL
Section: 3
Source: libfetch
See-also:
  - FETCHINFO_RESPONSE_CODE (3)
  - fetch_easy_getinfo (3)
  - fetch_easy_setopt (3)
Protocol:
  - All
Added-in: 7.52.0
---

# NAME

FETCHINFO_PROTOCOL - get the protocol used in the connection

# SYNOPSIS

~~~c
#include <fetch/fetch.h>

FETCHcode fetch_easy_getinfo(FETCH *handle, FETCHINFO_PROTOCOL, long *p);
~~~

# DESCRIPTION

This option is deprecated. We strongly recommend using
FETCHINFO_SCHEME(3) instead, because this option cannot return all
possible protocols.

Pass a pointer to a long to receive the version used in the last http
connection. The returned value is set to one of the FETCHPROTO_* values:

~~~c
FETCHPROTO_DICT, FETCHPROTO_FILE, FETCHPROTO_FTP, FETCHPROTO_FTPS,
FETCHPROTO_GOPHER, FETCHPROTO_HTTP, FETCHPROTO_HTTPS, FETCHPROTO_IMAP,
FETCHPROTO_IMAPS, FETCHPROTO_LDAP, FETCHPROTO_LDAPS, FETCHPROTO_POP3,
FETCHPROTO_POP3S, FETCHPROTO_RTMP, FETCHPROTO_RTMPE, FETCHPROTO_RTMPS,
FETCHPROTO_RTMPT, FETCHPROTO_RTMPTE, FETCHPROTO_RTMPTS, FETCHPROTO_RTSP,
FETCHPROTO_SCP, FETCHPROTO_SFTP, FETCHPROTO_SMB, FETCHPROTO_SMBS, FETCHPROTO_SMTP,
FETCHPROTO_SMTPS, FETCHPROTO_TELNET, FETCHPROTO_TFTP, FETCHPROTO_MQTT
~~~

# %PROTOCOLS%

# EXAMPLE

~~~c
int main(void)
{
  FETCH *fetch = fetch_easy_init();
  if(fetch) {
    FETCHcode res;
    fetch_easy_setopt(fetch, FETCHOPT_URL, "https://example.com");
    res = fetch_easy_perform(fetch);
    if(res == FETCHE_OK) {
      long protocol;
      fetch_easy_getinfo(fetch, FETCHINFO_PROTOCOL, &protocol);
    }
    fetch_easy_cleanup(fetch);
  }
}
~~~

# DEPRECATED

Deprecated since 7.85.0.

# %AVAILABILITY%

# RETURN VALUE

fetch_easy_getinfo(3) returns a FETCHcode indicating success or error.

FETCHE_OK (0) means everything was OK, non-zero means an error occurred, see
libfetch-errors(3).
