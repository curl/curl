---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: fetch
Title: FETCHOPT_PROTOCOLS_STR
Section: 3
Source: libfetch
See-also:
  - FETCHINFO_SCHEME (3)
  - FETCHOPT_DEFAULT_PROTOCOL (3)
  - FETCHOPT_REDIR_PROTOCOLS_STR (3)
  - FETCHOPT_URL (3)
  - fetch_version_info (3)
Protocol:
  - All
Added-in: 7.85.0
---

# NAME

FETCHOPT_PROTOCOLS_STR - allowed protocols

# SYNOPSIS

~~~c
#include <fetch/fetch.h>

FETCHcode fetch_easy_setopt(FETCH *handle, FETCHOPT_PROTOCOLS_STR, char *spec);
~~~

# DESCRIPTION

Pass a pointer to a string that holds a comma-separated list of case
insensitive protocol names (URL schemes) to allow in the transfer. This
option allows applications to use libfetch built to support a wide range of
protocols but still limit specific transfers to only be allowed to use a
subset of them. By default, libfetch accepts all protocols it was built with
support for. See also FETCHOPT_REDIR_PROTOCOLS_STR(3).

If trying to set a non-existing protocol or if no matching protocol at all is
set, it returns error.

These are the available protocols:

DICT, FILE, FTP, FTPS, GOPHER, GOPHERS, HTTP, HTTPS, IMAP, IMAPS, LDAP, LDAPS,
MQTT, POP3, POP3S, RTMP, RTMPE, RTMPS, RTMPT, RTMPTE, RTMPTS, RTSP, SCP, SFTP,
SMB, SMBS, SMTP, SMTPS, TELNET, TFTP, WS, WSS

You can set "ALL" as a short-cut to enable all protocols. Note that by setting
all, you may enable protocols that were not supported the day you write this
but are introduced in a future libfetch version.

fetch_version_info(3) can be used to get a list of all supported protocols in
the current libfetch. FETCHINFO_SCHEME(3) is the recommended way to figure out
the protocol used in a previous transfer.

Using this option multiple times makes the last set string override the
previous ones. Set it to NULL to restore to the internal default.

# DEFAULT

All protocols built-in

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
    fetch_easy_setopt(fetch, FETCHOPT_PROTOCOLS_STR, "http,tftp,sftp");

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
