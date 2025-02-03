---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: fetch
Title: FETCHOPT_CERTINFO
Section: 3
Source: libfetch
See-also:
  - FETCHINFO_CAINFO (3)
  - FETCHINFO_CAPATH (3)
  - FETCHINFO_CERTINFO (3)
  - FETCHOPT_CAINFO (3)
  - FETCHOPT_SSL_VERIFYPEER (3)
Protocol:
  - TLS
TLS-backend:
  - OpenSSL
  - GnuTLS
  - Schannel
  - Secure Transport
Added-in: 7.19.1
---

# NAME

FETCHOPT_CERTINFO - request SSL certificate information

# SYNOPSIS

~~~c
#include <fetch/fetch.h>

FETCHcode fetch_easy_setopt(FETCH *handle, FETCHOPT_CERTINFO, long certinfo);
~~~

# DESCRIPTION

Pass a long set to 1 to enable libfetch's certificate chain info gatherer. With
this enabled, libfetch extracts lots of information and data about the
certificates in the certificate chain used in the SSL connection. This data
may then be retrieved after a transfer using fetch_easy_getinfo(3) and
its option FETCHINFO_CERTINFO(3).

# DEFAULT

0

# %PROTOCOLS%

# EXAMPLE

~~~c
int main(void)
{
  FETCH *fetch = fetch_easy_init();
  if(fetch) {
    FETCHcode res;
    fetch_easy_setopt(fetch, FETCHOPT_URL, "https://www.example.com/");

    /* connect to any HTTPS site, trusted or not */
    fetch_easy_setopt(fetch, FETCHOPT_SSL_VERIFYPEER, 0L);
    fetch_easy_setopt(fetch, FETCHOPT_SSL_VERIFYHOST, 0L);

    fetch_easy_setopt(fetch, FETCHOPT_CERTINFO, 1L);

    res = fetch_easy_perform(fetch);

    if(!res) {
      struct fetch_certinfo *ci;
      res = fetch_easy_getinfo(fetch, FETCHINFO_CERTINFO, &ci);

      if(!res) {
        int i;
        printf("%d certs!\n", ci->num_of_certs);

        for(i = 0; i < ci->num_of_certs; i++) {
          struct fetch_slist *slist;

          for(slist = ci->certinfo[i]; slist; slist = slist->next)
            printf("%s\n", slist->data);
        }
      }
    }
    fetch_easy_cleanup(fetch);
  }
}
~~~

# HISTORY

Schannel support added in 7.50.0. Secure Transport support added in 7.79.0.
mbedTLS support added in 8.9.0.

# %AVAILABILITY%

# RETURN VALUE

fetch_easy_setopt(3) returns a FETCHcode indicating success or error.

FETCHE_OK (0) means everything was OK, non-zero means an error occurred, see
libfetch-errors(3).
