---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: fetch
Title: FETCHOPT_REDIR_PROTOCOLS
Section: 3
Source: libfetch
See-also:
  - FETCHINFO_SCHEME (3)
  - FETCHOPT_DEFAULT_PROTOCOL (3)
  - FETCHOPT_PROTOCOLS (3)
  - FETCHOPT_REDIR_PROTOCOLS_STR (3)
Protocol:
  - HTTP
Added-in: 7.19.4
---

# NAME

FETCHOPT_REDIR_PROTOCOLS - protocols allowed to redirect to

# SYNOPSIS

~~~c
#include <fetch/fetch.h>

FETCHcode fetch_easy_setopt(FETCH *handle, FETCHOPT_REDIR_PROTOCOLS, long bitmask);
~~~

# DESCRIPTION

This option is deprecated. We strongly recommend using
FETCHOPT_REDIR_PROTOCOLS_STR(3) instead because this option cannot
control all available protocols.

Pass a long that holds a bitmask of FETCHPROTO_* defines. If used, this bitmask
limits what protocols libfetch may use in a transfer that it follows to in a
redirect when FETCHOPT_FOLLOWLOCATION(3) is enabled. This allows you to
limit specific transfers to only be allowed to use a subset of protocols in
redirections.

Protocols denied by FETCHOPT_PROTOCOLS(3) are not overridden by this
option.

By default libfetch allows HTTP, HTTPS, FTP and FTPS on redirect (7.65.2).
*FETCHPROTO_ALL* enables all protocols on redirect, including those
otherwise disabled for security.

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

HTTP, HTTPS, FTP and FTPS (Added in 7.65.2).

Older versions defaulted to all protocols except FILE, SCP and since 7.40.0
SMB and SMBS.

# %PROTOCOLS%

# EXAMPLE

~~~c
int main(int argc, char **argv)
{
  FETCH *fetch = fetch_easy_init();
  if(fetch) {
    /* pass in the URL from an external source */
    fetch_easy_setopt(fetch, FETCHOPT_URL, argv[1]);

    /* only allow redirects to HTTP and HTTPS URLs */
    fetch_easy_setopt(fetch, FETCHOPT_REDIR_PROTOCOLS,
                     FETCHPROTO_HTTP | FETCHPROTO_HTTPS);

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
