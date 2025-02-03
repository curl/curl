---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: fetch
Title: FETCHOPT_FTP_SSL_CCC
Section: 3
Source: libfetch
Protocol:
  - FTP
See-also:
  - FETCHOPT_FTPSSLAUTH (3)
  - FETCHOPT_PROTOCOLS_STR (3)
  - FETCHOPT_USE_SSL (3)
Added-in: 7.16.1
---

# NAME

FETCHOPT_FTP_SSL_CCC - switch off SSL again with FTP after auth

# SYNOPSIS

~~~c
#include <fetch/fetch.h>

FETCHcode fetch_easy_setopt(FETCH *handle, FETCHOPT_FTP_SSL_CCC,
                          long how);
~~~

# DESCRIPTION

If enabled, this option makes libfetch use CCC (Clear Command Channel). It
shuts down the SSL/TLS layer after authenticating. The rest of the control
channel communication remains unencrypted. This allows NAT routers to follow
the FTP transaction. Pass a long using one of the values below

## FETCHFTPSSL_CCC_NONE

do not attempt to use CCC.

## FETCHFTPSSL_CCC_PASSIVE

Do not initiate the shutdown, but wait for the server to do it. Do not send a
reply.

## FETCHFTPSSL_CCC_ACTIVE

Initiate the shutdown and wait for a reply.

# DEFAULT

FETCHFTPSSL_CCC_NONE

# %PROTOCOLS%

# EXAMPLE

~~~c
int main(void)
{
  FETCH *fetch = fetch_easy_init();
  if(fetch) {
    FETCHcode res;
    fetch_easy_setopt(fetch, FETCHOPT_URL, "ftp://example.com/file.txt");
    fetch_easy_setopt(fetch, FETCHOPT_USE_SSL, FETCHUSESSL_CONTROL);
    /* go back to clear-text FTP after authenticating */
    fetch_easy_setopt(fetch, FETCHOPT_FTP_SSL_CCC, (long)FETCHFTPSSL_CCC_ACTIVE);
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
