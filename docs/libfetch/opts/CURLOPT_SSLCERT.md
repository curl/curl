---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: fetch
Title: FETCHOPT_SSLCERT
Section: 3
Source: libfetch
See-also:
  - FETCHOPT_KEYPASSWD (3)
  - FETCHOPT_SSLCERTTYPE (3)
  - FETCHOPT_SSLKEY (3)
Protocol:
  - TLS
TLS-backend:
  - OpenSSL
  - GnuTLS
  - mbedTLS
  - Schannel
  - Secure Transport
  - wolfSSL
Added-in: 7.1
---

# NAME

FETCHOPT_SSLCERT - SSL client certificate

# SYNOPSIS

~~~c
#include <fetch/fetch.h>

FETCHcode fetch_easy_setopt(FETCH *handle, FETCHOPT_SSLCERT, char *cert);
~~~

# DESCRIPTION

Pass a pointer to a null-terminated string as parameter. The string should be
the filename of your client certificate. The default format is `P12` on Secure
Transport and `PEM` on other engines, and can be changed with
FETCHOPT_SSLCERTTYPE(3).

With Secure Transport, this can also be the nickname of the certificate you
wish to authenticate with as it is named in the security database. If you want
to use a file from the current directory, please precede it with `./` prefix,
in order to avoid confusion with a nickname.

(Schannel only) Client certificates can be specified by a path expression to a
certificate store. (You can import *PFX* to a store first). You can use
"\<store location\>\\\<store name\>\\\<thumbprint\>" to refer to a certificate
in the system certificates store, for example,
**"CurrentUser\\MY\\934a7ac6f8a5d5"**. The thumbprint is usually a SHA-1 hex
string which you can see in certificate details. Following store locations are
supported: **CurrentUser**, **LocalMachine**, **CurrentService**,
**Services**, **CurrentUserGroupPolicy**, **LocalMachineGroupPolicy**,
**LocalMachineEnterprise**. Schannel also support P12 certificate file, with
the string `P12` specified with FETCHOPT_SSLCERTTYPE(3).

When using a client certificate, you most likely also need to provide a
private key with FETCHOPT_SSLKEY(3).

The application does not have to keep the string around after setting this
option.

Using this option multiple times makes the last set string override the
previous ones. Set it to NULL to disable its use again.

# DEFAULT

NULL

# %PROTOCOLS%

# EXAMPLE

~~~c
int main(void)
{
  FETCH *fetch = fetch_easy_init();
  if(fetch) {
    FETCHcode res;
    fetch_easy_setopt(fetch, FETCHOPT_URL, "https://example.com/");
    fetch_easy_setopt(fetch, FETCHOPT_SSLCERT, "client.pem");
    fetch_easy_setopt(fetch, FETCHOPT_SSLKEY, "key.pem");
    fetch_easy_setopt(fetch, FETCHOPT_KEYPASSWD, "s3cret");
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
