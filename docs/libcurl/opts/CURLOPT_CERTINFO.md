---
c: Copyright (C) Daniel Stenberg, <daniel.se>, et al.
SPDX-License-Identifier: curl
Title: CURLOPT_CERTINFO
Section: 3
Source: libcurl
See-also:
  - CURLINFO_CAINFO (3)
  - CURLINFO_CAPATH (3)
  - CURLINFO_CERTINFO (3)
  - CURLOPT_CAINFO (3)
  - CURLOPT_SSL_VERIFYPEER (3)
---

# NAME

CURLOPT_CERTINFO - request SSL certificate information

# SYNOPSIS

~~~c
#include <curl/curl.h>

CURLcode curl_easy_setopt(CURL *handle, CURLOPT_CERTINFO, long certinfo);
~~~

# DESCRIPTION

Pass a long set to 1 to enable libcurl's certificate chain info gatherer. With
this enabled, libcurl extracts lots of information and data about the
certificates in the certificate chain used in the SSL connection. This data
may then be retrieved after a transfer using curl_easy_getinfo(3) and
its option CURLINFO_CERTINFO(3).

# DEFAULT

0

# PROTOCOLS

All TLS-based

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
      struct curl_certinfo *ci;
      res = curl_easy_getinfo(curl, CURLINFO_CERTINFO, &ci);

      if(!res) {
        int i;
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

# AVAILABILITY

This option is supported by the OpenSSL, GnuTLS, Schannel and Secure
Transport backends. Schannel support added in 7.50.0. Secure Transport support
added in 7.79.0.

# RETURN VALUE

Returns CURLE_OK if the option is supported, and CURLE_UNKNOWN_OPTION if not.
