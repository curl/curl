---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: fetch
Title: FETCHINFO_CERTINFO
Section: 3
Source: libfetch
See-also:
  - FETCHINFO_CAPATH (3)
  - fetch_easy_getinfo (3)
  - fetch_easy_setopt (3)
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

FETCHINFO_CERTINFO - get the TLS certificate chain

# SYNOPSIS

~~~c
#include <fetch/fetch.h>

FETCHcode fetch_easy_getinfo(FETCH *handle, FETCHINFO_CERTINFO,
                           struct fetch_certinfo **chainp);
~~~

# DESCRIPTION

Pass a pointer to a *struct fetch_certinfo ** and it is set to point to a
struct that holds info about the server's certificate chain, assuming you had
FETCHOPT_CERTINFO(3) enabled when the request was made.

~~~c
struct fetch_certinfo {
  int num_of_certs;
  struct fetch_slist **certinfo;
};
~~~

The *certinfo* struct member is an array of linked lists of certificate
information. The *num_of_certs* struct member is the number of certificates
which is the number of elements in the array. Each certificate's list has
items with textual information in the format "name:content" such as
"Subject:Foo", "Issuer:Bar", etc. The items in each list varies depending on
the SSL backend and the certificate.

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
      int i;
      struct fetch_certinfo *ci;
      res = fetch_easy_getinfo(fetch, FETCHINFO_CERTINFO, &ci);

      if(!res) {
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

See also the *certinfo.c* example.

# HISTORY

GnuTLS support added in 7.42.0. Schannel support added in 7.50.0. Secure
Transport support added in 7.79.0. mbedTLS support added in 8.9.0.

# %AVAILABILITY%

# RETURN VALUE

fetch_easy_getinfo(3) returns a FETCHcode indicating success or error.

FETCHE_OK (0) means everything was OK, non-zero means an error occurred, see
libfetch-errors(3).
