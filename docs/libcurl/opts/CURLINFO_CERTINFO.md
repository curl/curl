---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Title: CURLINFO_CERTINFO
Section: 3
Source: libcurl
See-also:
  - CURLINFO_CAPATH (3)
  - curl_easy_getinfo (3)
  - curl_easy_setopt (3)
Protocol:
  - TLS
TLS-backend:
  - OpenSSL
  - GnuTLS
  - Schannel
  - Secure Transport
  - rustls
Added-in: 7.19.1
---

# NAME

CURLINFO_CERTINFO - get the TLS certificate chain

# SYNOPSIS

~~~c
#include <curl/curl.h>

CURLcode curl_easy_getinfo(CURL *handle, CURLINFO_CERTINFO,
                           struct curl_certinfo **chainp);
~~~

# DESCRIPTION

Pass a pointer to a *struct curl_certinfo ** and it is set to point to a
struct that holds info about the server's certificate chain, assuming you had
CURLOPT_CERTINFO(3) enabled when the request was made.

~~~c
struct curl_certinfo {
  int num_of_certs;
  struct curl_slist **certinfo;
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
  CURL *curl = curl_easy_init();
  if(curl) {
    CURLcode res;
    curl_easy_setopt(curl, CURLOPT_URL, "https://www.example.com/");

    /* connect to any HTTPS site, trusted or not */
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);

    curl_easy_setopt(curl, CURLOPT_CERTINFO, 1L);

    res = curl_easy_perform(curl);

    if(!res) {
      int i;
      struct curl_certinfo *ci;
      res = curl_easy_getinfo(curl, CURLINFO_CERTINFO, &ci);

      if(!res) {
        printf("%d certs!\n", ci->num_of_certs);

        for(i = 0; i < ci->num_of_certs; i++) {
          struct curl_slist *slist;

          for(slist = ci->certinfo[i]; slist; slist = slist->next)
            printf("%s\n", slist->data);
        }
      }
    }
    curl_easy_cleanup(curl);
  }
}
~~~

See also the *certinfo.c* example.

# HISTORY

GnuTLS support added in 7.42.0. Schannel support added in 7.50.0. Secure
Transport support added in 7.79.0. mbedTLS support added in 8.9.0.

# %AVAILABILITY%

# RETURN VALUE

curl_easy_getinfo(3) returns a CURLcode indicating success or error.

CURLE_OK (0) means everything was OK, non-zero means an error occurred, see
libcurl-errors(3).
