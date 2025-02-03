---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: fetch
Title: FETCHOPT_REDIR_PROTOCOLS_STR
Section: 3
Source: libfetch
See-also:
  - FETCHINFO_SCHEME (3)
  - FETCHOPT_DEFAULT_PROTOCOL (3)
  - FETCHOPT_PROTOCOLS (3)
  - FETCHOPT_PROTOCOLS_STR (3)
  - FETCHOPT_REDIR_PROTOCOLS (3)
Protocol:
  - HTTP
Added-in: 7.85.0
---

# NAME

FETCHOPT_REDIR_PROTOCOLS_STR - protocols allowed to redirect to

# SYNOPSIS

~~~c
#include <fetch/fetch.h>

FETCHcode fetch_easy_setopt(FETCH *handle, FETCHOPT_REDIR_PROTOCOLS_STR,
                          char *spec);
~~~

# DESCRIPTION

Pass a pointer to a string that holds a comma-separated list of case
insensitive protocol names (URL schemes). That list limits what protocols
libfetch may use in a transfer that it follows to in a redirect when
FETCHOPT_FOLLOWLOCATION(3) is enabled. This option allows applications to limit
specific transfers to only be allowed to use a subset of protocols in
redirections.

Protocols denied by FETCHOPT_PROTOCOLS_STR(3) are not overridden by this
option.

By default libfetch allows HTTP, HTTPS, FTP and FTPS on redirects (since
7.65.2).

These are the available protocols:

DICT, FILE, FTP, FTPS, GOPHER, GOPHERS, HTTP, HTTPS, IMAP, IMAPS, LDAP, LDAPS,
MQTT, POP3, POP3S, RTMP, RTMPE, RTMPS, RTMPT, RTMPTE, RTMPTS, RTSP, SCP, SFTP,
SMB, SMBS, SMTP, SMTPS, TELNET, TFTP, WS, WSS

You can set "ALL" as a short-cut to enable all protocols. Note that by setting
all, you may enable protocols that were not supported the day you write this
but are introduced in a future libfetch version.

If trying to set a non-existing protocol or if no matching protocol at all is
set, it returns error.

Using this option multiple times makes the last set string override the
previous ones. Set it to NULL to restore to internal default.

The application does not have to keep the string around after setting this
option.

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
    fetch_easy_setopt(fetch, FETCHOPT_REDIR_PROTOCOLS_STR, "http,https");

    /* Perform the request */
    fetch_easy_perform(fetch);
  }
}
~~~

# %AVAILABILITY%

# RETURN VALUE

Returns FETCHE_UNKNOWN_OPTION if the option is not implemented,
FETCHE_UNSUPPORTED_PROTOCOL if a listed protocol is not supported or disabled,
FETCHE_BAD_FUNCTION_ARGUMENT if no protocol is listed else FETCHE_OK.
