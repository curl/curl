---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: fetch
Title: FETCHOPT_DEFAULT_PROTOCOL
Section: 3
Source: libfetch
See-also:
  - FETCHINFO_PROTOCOL (3)
  - FETCHINFO_SCHEME (3)
  - FETCHOPT_URL (3)
Protocol:
  - All
Added-in: 7.45.0
---

# NAME

FETCHOPT_DEFAULT_PROTOCOL - default protocol to use if the URL is missing a
scheme name

# SYNOPSIS

~~~c
#include <fetch/fetch.h>

FETCHcode fetch_easy_setopt(FETCH *handle, FETCHOPT_DEFAULT_PROTOCOL,
                          char *protocol);
~~~

# DESCRIPTION

This option tells libfetch to use *protocol* if the URL is missing a scheme
name.

Use one of these protocol (scheme) names:

dict, file, ftp, ftps, gopher, http, https, imap, imaps, ldap, ldaps, pop3,
pop3s, rtsp, scp, sftp, smb, smbs, smtp, smtps, telnet, tftp

An unknown or unsupported protocol causes error *FETCHE_UNSUPPORTED_PROTOCOL*
when libfetch parses a URL without a scheme. Parsing happens when
fetch_easy_perform(3) or fetch_multi_perform(3) is called. The protocol set
supported by libfetch vary depending on how it was built. Use
fetch_version_info(3) if you need a list of protocol names supported by the
build of libfetch that you are using.

This option does not change the default proxy protocol (http).

Without this option libfetch would make a guess based on the host, see
FETCHOPT_URL(3) for details.

The application does not have to keep the string around after setting this
option.

Using this option multiple times makes the last set string override the
previous ones. Set it to NULL to disable its use again.

# DEFAULT

NULL (make a guess based on the host)

# %PROTOCOLS%

# EXAMPLE

~~~c
int main(void)
{
  FETCH *fetch = fetch_easy_init();
  if(fetch) {
    /* set a URL without a scheme */
    fetch_easy_setopt(fetch, FETCHOPT_URL, "example.com");

    /* set the default protocol (scheme) for schemeless URLs */
    fetch_easy_setopt(fetch, FETCHOPT_DEFAULT_PROTOCOL, "https");

    /* Perform the request */
    fetch_easy_perform(fetch);
  }
}
~~~

# %AVAILABILITY%

# RETURN VALUE

FETCHE_OK if the option is supported.

FETCHE_OUT_OF_MEMORY if there was insufficient heap space.

FETCHE_UNKNOWN_OPTION if the option is not supported.
