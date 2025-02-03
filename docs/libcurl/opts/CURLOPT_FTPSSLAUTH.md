---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: fetch
Title: FETCHOPT_FTPSSLAUTH
Section: 3
Source: libfetch
Protocol:
  - FTP
See-also:
  - FETCHOPT_FTP_SSL_CCC (3)
  - FETCHOPT_USE_SSL (3)
Added-in: 7.12.2
---

# NAME

FETCHOPT_FTPSSLAUTH - order in which to attempt TLS vs SSL

# SYNOPSIS

~~~c
#include <fetch/fetch.h>

FETCHcode fetch_easy_setopt(FETCH *handle, FETCHOPT_FTPSSLAUTH, long order);
~~~

# DESCRIPTION

Pass a long using one of the values from below, to alter how libfetch issues
"AUTH TLS" or "AUTH SSL" when FTP over SSL is activated. This is only
interesting if FETCHOPT_USE_SSL(3) is also set.

Possible *order* values:

## FETCHFTPAUTH_DEFAULT

Allow libfetch to decide.

## FETCHFTPAUTH_SSL

Try "AUTH SSL" first, and only if that fails try "AUTH TLS".

## FETCHFTPAUTH_TLS

Try "AUTH TLS" first, and only if that fails try "AUTH SSL".

# DEFAULT

FETCHFTPAUTH_DEFAULT

# %PROTOCOLS%

# EXAMPLE

~~~c
int main(void)
{
  FETCH *fetch = fetch_easy_init();
  if(fetch) {
    FETCHcode res;
    fetch_easy_setopt(fetch, FETCHOPT_URL, "ftp://example.com/file.txt");
    fetch_easy_setopt(fetch, FETCHOPT_USE_SSL, FETCHUSESSL_TRY);
    /* funny server, ask for SSL before TLS */
    fetch_easy_setopt(fetch, FETCHOPT_FTPSSLAUTH, (long)FETCHFTPAUTH_SSL);
    res = fetch_easy_perform(fetch);
    fetch_easy_cleanup(fetch);
  }
}
~~~

# %AVAILABILITY%

# RETURN VALUE

fetch_easy_setopt(3) returns a FETCHcode indicating success or error.

FETCHE_OK (0) means everything was OK, non-zero means an error occurred, see
libfetch-errors(3).
