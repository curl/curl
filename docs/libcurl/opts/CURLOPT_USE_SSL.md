---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: fetch
Title: FETCHOPT_USE_SSL
Section: 3
Source: libfetch
See-also:
  - FETCHOPT_PROXY_SSLVERSION (3)
  - FETCHOPT_SSLVERSION (3)
  - FETCHOPT_SSL_OPTIONS (3)
Protocol:
  - FTP
  - SMTP
  - POP3
  - IMAP
Added-in: 7.17.0
---

# NAME

FETCHOPT_USE_SSL - request using SSL / TLS for the transfer

# SYNOPSIS

~~~c
#include <fetch/fetch.h>

FETCHcode fetch_easy_setopt(FETCH *handle, FETCHOPT_USE_SSL, long level);
~~~

# DESCRIPTION

Pass a long using one of the values from below, to make libfetch use your
desired *level* of SSL for the transfer.

These are all protocols that start out plain text and get "upgraded" to SSL
using the STARTTLS command.

This is for enabling SSL/TLS when you use FTP, SMTP, POP3, IMAP etc.

## FETCHUSESSL_NONE

do not attempt to use SSL.

## FETCHUSESSL_TRY

Try using SSL, proceed as normal otherwise. Note that server may close the
connection if the negotiation does not succeed.

## FETCHUSESSL_CONTROL

Require SSL for the control connection or fail with *FETCHE_USE_SSL_FAILED*.

## FETCHUSESSL_ALL

Require SSL for all communication or fail with *FETCHE_USE_SSL_FAILED*.

# DEFAULT

FETCHUSESSL_NONE

# %PROTOCOLS%

# EXAMPLE

~~~c
int main(void)
{
  FETCH *fetch = fetch_easy_init();
  if(fetch) {
    fetch_easy_setopt(fetch, FETCHOPT_URL, "ftp://example.com/dir/file.ext");

    /* require use of SSL for this, or fail */
    fetch_easy_setopt(fetch, FETCHOPT_USE_SSL, (long)FETCHUSESSL_ALL);

    /* Perform the request */
    fetch_easy_perform(fetch);
  }
}
~~~

# HISTORY

This option was known as FETCHOPT_FTP_SSL up to 7.16.4, and the constants were
known as FETCHFTPSSL_* Handled by LDAP since 7.81.0. Fully supported by the
OpenLDAP backend only.

# %AVAILABILITY%

# RETURN VALUE

fetch_easy_setopt(3) returns a FETCHcode indicating success or error.

FETCHE_OK (0) means everything was OK, non-zero means an error occurred, see
libfetch-errors(3).
