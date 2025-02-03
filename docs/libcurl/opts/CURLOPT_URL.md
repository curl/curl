---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: fetch
Title: FETCHOPT_URL
Section: 3
Source: libfetch
See-also:
  - FETCHINFO_REDIRECT_URL (3)
  - FETCHOPT_FETCHU (3)
  - FETCHOPT_FORBID_REUSE (3)
  - FETCHOPT_FRESH_CONNECT (3)
  - FETCHOPT_PATH_AS_IS (3)
  - FETCHOPT_PROTOCOLS_STR (3)
  - fetch_easy_perform (3)
  - fetch_url_get (3)
  - fetch_url_set (3)
Protocol:
  - All
Added-in: 7.1
---

# NAME

FETCHOPT_URL - URL for this transfer

# SYNOPSIS

~~~c
#include <fetch/fetch.h>

FETCHcode fetch_easy_setopt(FETCH *handle, FETCHOPT_URL, char *URL);
~~~

# DESCRIPTION

Pass in a pointer to the *URL* to work with. The parameter should be a
char * to a null-terminated string which must be URL-encoded in the following
format:

scheme://host:port/path

For a greater explanation of the format please see RFC 3986.

libfetch does not validate the syntax or use the URL until the transfer is
started. Even if you set a crazy value here, fetch_easy_setopt(3) might
still return *FETCHE_OK*.

If the given URL is missing a scheme name (such as "http://" or "ftp://" etc)
then libfetch guesses based on the host. If the outermost subdomain name
matches DICT, FTP, IMAP, LDAP, POP3 or SMTP then that protocol gets used,
otherwise HTTP is used. Since 7.45.0 guessing can be disabled by setting a
default protocol, see FETCHOPT_DEFAULT_PROTOCOL(3) for details.

Should the protocol, either as specified by the URL scheme or deduced by
libfetch from the hostname, not be supported by libfetch then
*FETCHE_UNSUPPORTED_PROTOCOL* is returned from either the fetch_easy_perform(3)
or fetch_multi_perform(3) functions when you call them. Use
fetch_version_info(3) for detailed information of which protocols are supported
by the build of libfetch you are using.

FETCHOPT_PROTOCOLS_STR(3) can be used to limit what protocols libfetch may
use for this transfer, independent of what libfetch has been compiled to
support. That may be useful if you accept the URL from an external source and
want to limit the accessibility.

The FETCHOPT_URL(3) string is ignored if FETCHOPT_FETCHU(3) is set.

Either FETCHOPT_URL(3) or FETCHOPT_FETCHU(3) must be set before a
transfer is started.

The application does not have to keep the string around after setting this
option.

Using this option multiple times makes the last set string override the
previous ones. Set it to NULL to disable its use again. Note however that
libfetch needs a URL set to be able to performed a transfer.

The parser used for handling the URL set with FETCHOPT_URL(3) is the same
that fetch_url_set(3) uses.

# ENCODING

The string pointed to in the FETCHOPT_URL(3) argument is generally
expected to be a sequence of characters using an ASCII compatible encoding.

If libfetch is built with IDN support, the server name part of the URL can use
an "international name" by using the current encoding (according to locale) or
UTF-8 (when WinIDN is used; or a Windows Unicode build using libidn2).

If libfetch is built without IDN support, the server name is used exactly as
specified when passed to the name resolver functions.

# DEFAULT

NULL. If this option is not set, no transfer can be performed.

# SECURITY CONCERNS

Applications may at times find it convenient to allow users to specify URLs
for various purposes and that string would then end up fed to this option.

Getting a URL from an external untrusted party brings several security
concerns:

If you have an application that runs as or in a server application, getting an
unfiltered URL can easily trick your application to access a local resource
instead of a remote. Protecting yourself against localhost accesses is hard
when accepting user provided URLs.

Such custom URLs can also access other ports than you planned as port numbers
are part of the regular URL format. The combination of a local host and a
custom port number can allow external users to play tricks with your local
services.

Accepting external URLs may also use other protocols than http:// or other
common ones. Restrict what accept with FETCHOPT_PROTOCOLS_STR(3).

User provided URLs can also be made to point to sites that redirect further on
(possibly to other protocols too). Consider your
FETCHOPT_FOLLOWLOCATION(3) and FETCHOPT_REDIR_PROTOCOLS_STR(3) settings.

# %PROTOCOLS%

# EXAMPLE

~~~c
int main(void)
{
  FETCH *fetch = fetch_easy_init();
  if(fetch) {
    fetch_easy_setopt(fetch, FETCHOPT_URL, "https://example.com");

    fetch_easy_perform(fetch);
  }
}
~~~

# %AVAILABILITY%

# RETURN VALUE

fetch_easy_setopt(3) returns a FETCHcode indicating success or error.

FETCHE_OK (0) means everything was OK, non-zero means an error occurred, see
libfetch-errors(3).

Note that fetch_easy_setopt(3) does not parse the given string so given a bad
URL, it is not detected until fetch_easy_perform(3) or similar is called.
