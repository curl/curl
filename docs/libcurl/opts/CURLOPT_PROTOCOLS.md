---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: fetch
Title: FETCHOPT_PROTOCOLS
Section: 3
Source: libfetch
See-also:
  - FETCHOPT_DEFAULT_PROTOCOL (3)
  - FETCHOPT_REDIR_PROTOCOLS (3)
  - FETCHOPT_URL (3)
Protocol:
  - All
Added-in: 7.19.4
---

# NAME

FETCHOPT_PROTOCOLS - allowed protocols

# SYNOPSIS

~~~c
#include <fetch/fetch.h>

FETCHcode fetch_easy_setopt(FETCH *handle, FETCHOPT_PROTOCOLS, long bitmask);
~~~

# DESCRIPTION

This option is deprecated. We strongly recommend using
FETCHOPT_PROTOCOLS_STR(3) instead because this option cannot control all
available protocols.

Pass a long that holds a bitmask of FETCHPROTO_* defines. If used, this bitmask
limits what protocols libfetch may use in the transfer. This allows you to have
a libfetch built to support a wide range of protocols but still limit specific
transfers to only be allowed to use a subset of them. By default libfetch
accepts all protocols it supports (*FETCHPROTO_ALL*). See also
FETCHOPT_REDIR_PROTOCOLS(3).

These are the available protocol defines:
~~~c
FETCHPROTO_DICT
FETCHPROTO_FILE
FETCHPROTO_FTP
FETCHPROTO_FTPS
FETCHPROTO_GOPHER
FETCHPROTO_HTTP
FETCHPROTO_HTTPS
FETCHPROTO_IMAP
FETCHPROTO_IMAPS
FETCHPROTO_LDAP
FETCHPROTO_LDAPS
FETCHPROTO_POP3
FETCHPROTO_POP3S
FETCHPROTO_RTMP
FETCHPROTO_RTMPE
FETCHPROTO_RTMPS
FETCHPROTO_RTMPT
FETCHPROTO_RTMPTE
FETCHPROTO_RTMPTS
FETCHPROTO_RTSP
FETCHPROTO_SCP
FETCHPROTO_SFTP
FETCHPROTO_SMB
FETCHPROTO_SMBS
FETCHPROTO_SMTP
FETCHPROTO_SMTPS
FETCHPROTO_TELNET
FETCHPROTO_TFTP
~~~

# DEFAULT

All protocols built-in.

# %PROTOCOLS%

# EXAMPLE

~~~c
int main(int argc, char **argv)
{
  FETCH *fetch = fetch_easy_init();
  if(fetch) {
    /* pass in the URL from an external source */
    fetch_easy_setopt(fetch, FETCHOPT_URL, argv[1]);

    /* only allow HTTP, TFTP and SFTP */
    fetch_easy_setopt(fetch, FETCHOPT_PROTOCOLS,
                     FETCHPROTO_HTTP | FETCHPROTO_TFTP | FETCHPROTO_SFTP);

    /* Perform the request */
    fetch_easy_perform(fetch);
  }
}
~~~

# DEPRECATED

Deprecated since 7.85.0.

# %AVAILABILITY%

# RETURN VALUE

fetch_easy_setopt(3) returns a FETCHcode indicating success or error.

FETCHE_OK (0) means everything was OK, non-zero means an error occurred, see
libfetch-errors(3).
