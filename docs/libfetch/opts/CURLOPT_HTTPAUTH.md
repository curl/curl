---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: fetch
Title: FETCHOPT_HTTPAUTH
Section: 3
Source: libfetch
Protocol:
  - HTTP
See-also:
  - FETCHOPT_PASSWORD (3)
  - FETCHOPT_PROXYAUTH (3)
  - FETCHOPT_USERNAME (3)
Added-in: 7.10.6
---

# NAME

FETCHOPT_HTTPAUTH - HTTP server authentication methods to try

# SYNOPSIS

~~~c
#include <fetch/fetch.h>

FETCHcode fetch_easy_setopt(FETCH *handle, FETCHOPT_HTTPAUTH, long bitmask);
~~~

# DESCRIPTION

Pass a long as parameter, which is set to a bitmask, to tell libfetch which
authentication method(s) you want it to use speaking to the remote server.

The available bits are listed below. If more than one bit is set, libfetch
first queries the host to see which authentication methods it supports and
then picks the best one you allow it to use. For some methods, this induces an
extra network round-trip. Set the actual name and password with the
FETCHOPT_USERPWD(3) option or with the FETCHOPT_USERNAME(3) and the
FETCHOPT_PASSWORD(3) options.

For authentication with a proxy, see FETCHOPT_PROXYAUTH(3).

## FETCHAUTH_BASIC

HTTP Basic authentication. This is the default choice, and the only method
that is in wide-spread use and supported virtually everywhere. This sends
the username and password over the network in plain text, easily captured by
others.

## FETCHAUTH_DIGEST

HTTP Digest authentication. Digest authentication is defined in RFC 2617 and
is a more secure way to do authentication over public networks than the
regular old-fashioned Basic method.

## FETCHAUTH_DIGEST_IE

HTTP Digest authentication with an IE flavor. Digest authentication is defined
in RFC 2617 and is a more secure way to do authentication over public networks
than the regular old-fashioned Basic method. The IE flavor is simply that
libfetch uses a special "quirk" that IE is known to have used before version 7
and that some servers require the client to use.

## FETCHAUTH_BEARER

HTTP Bearer token authentication, used primarily in OAuth 2.0 protocol.

You can set the Bearer token to use with FETCHOPT_XOAUTH2_BEARER(3).

## FETCHAUTH_NEGOTIATE

HTTP Negotiate (SPNEGO) authentication. Negotiate authentication is defined
in RFC 4559 and is the most secure way to perform authentication over HTTP.

You need to build libfetch with a suitable GSS-API library or SSPI on Windows
for this to work.

## FETCHAUTH_NTLM

HTTP NTLM authentication. A proprietary protocol invented and used by
Microsoft. It uses a challenge-response and hash concept similar to Digest, to
prevent the password from being eavesdropped.

You need to build libfetch with either OpenSSL or GnuTLS support for this
option to work, or build libfetch on Windows with SSPI support.

## FETCHAUTH_NTLM_WB

Support for this is removed since libfetch 8.8.0.

NTLM delegating to winbind helper. Authentication is performed by a separate
binary application that is executed when needed. The name of the application
is specified at compile time but is typically **/usr/bin/ntlm_auth**.

Note that libfetch forks when necessary to run the winbind application and kill
it when complete, calling **waitpid()** to await its exit when done. On POSIX
operating systems, killing the process causes a SIGCHLD signal to be raised
(regardless of whether FETCHOPT_NOSIGNAL(3) is set), which must be handled
intelligently by the application. In particular, the application must not
unconditionally call wait() in its SIGCHLD signal handler to avoid being
subject to a race condition. This behavior is subject to change in future
versions of libfetch.

## FETCHAUTH_ANY

This is a convenience macro that sets all bits and thus makes libfetch pick any
it finds suitable. libfetch automatically selects the one it finds most secure.

## FETCHAUTH_ANYSAFE

This is a convenience macro that sets all bits except Basic and thus makes
libfetch pick any it finds suitable. libfetch automatically selects the one it
finds most secure.

## FETCHAUTH_ONLY

This is a meta symbol. OR this value together with a single specific auth
value to force libfetch to probe for unrestricted auth and if not, only that
single auth algorithm is acceptable.

## FETCHAUTH_AWS_SIGV4

provides AWS V4 signature authentication on HTTPS header
see FETCHOPT_AWS_SIGV4(3).

# DEFAULT

FETCHAUTH_BASIC

# %PROTOCOLS%

# EXAMPLE

~~~c
int main(void)
{
  FETCH *fetch = fetch_easy_init();
  if(fetch) {
    FETCHcode ret;
    fetch_easy_setopt(fetch, FETCHOPT_URL, "https://example.com/");
    /* allow whatever auth the server speaks */
    fetch_easy_setopt(fetch, FETCHOPT_HTTPAUTH, (long)FETCHAUTH_ANY);
    fetch_easy_setopt(fetch, FETCHOPT_USERPWD, "james:bond");
    ret = fetch_easy_perform(fetch);
  }
}
~~~

# HISTORY

FETCHAUTH_DIGEST_IE was added in 7.19.3

FETCHAUTH_ONLY was added in 7.21.3

FETCHAUTH_NTLM_WB was added in 7.22.0

FETCHAUTH_BEARER was added in 7.61.0

FETCHAUTH_AWS_SIGV4 was added in 7.74.0

# %AVAILABILITY%

# RETURN VALUE

fetch_easy_setopt(3) returns a FETCHcode indicating success or error.

FETCHE_OK (0) means everything was OK, non-zero means an error occurred, see
libfetch-errors(3).
