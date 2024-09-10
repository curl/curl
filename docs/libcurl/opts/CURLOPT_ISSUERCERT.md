---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Title: CURLOPT_ISSUERCERT
Section: 3
Source: libcurl
See-also:
  - CURLOPT_CRLFILE (3)
  - CURLOPT_SSL_VERIFYHOST (3)
  - CURLOPT_SSL_VERIFYPEER (3)
Protocol:
  - TLS
TLS-backend:
  - OpenSSL
  - GnuTLS
Added-in: 7.19.0
---

# NAME

CURLOPT_ISSUERCERT - issuer SSL certificate filename

# SYNOPSIS

~~~c
#include <curl/curl.h>

CURLcode curl_easy_setopt(CURL *handle, CURLOPT_ISSUERCERT, char *file);
~~~

# DESCRIPTION

Pass a char pointer to a null-terminated string naming a *file* holding a CA
certificate in PEM format. If the option is set, an additional check against
the peer certificate is performed to verify the issuer is indeed the one
associated with the certificate provided by the option. This additional check
is useful in multi-level PKI where one needs to enforce that the peer
certificate is from a specific branch of the tree.

This option makes sense only when used in combination with the
CURLOPT_SSL_VERIFYPEER(3) option. Otherwise, the result of the check is
not considered as failure.

A specific error code (CURLE_SSL_ISSUER_ERROR) is defined with the option,
which is returned if the setup of the SSL/TLS session has failed due to a
mismatch with the issuer of peer certificate (CURLOPT_SSL_VERIFYPEER(3)
has to be set too for the check to fail). (Added in 7.19.0)

Using this option multiple times makes the last set string override the
previous ones. Set it to NULL to disable its use again.

The application does not have to keep the string around after setting this
option.

# DEFAULT

NULL

# %PROTOCOLS%

# EXAMPLE

~~~c
int main(void)
{
  CURL *curl = curl_easy_init();
  if(curl) {
    CURLcode res;
    curl_easy_setopt(curl, CURLOPT_URL, "https://example.com/");
    curl_easy_setopt(curl, CURLOPT_ISSUERCERT, "/etc/certs/cacert.pem");
    res = curl_easy_perform(curl);
    curl_easy_cleanup(curl);
  }
}
~~~

# %AVAILABILITY%

# RETURN VALUE

Returns CURLE_OK if the option is supported, CURLE_UNKNOWN_OPTION if not, or
CURLE_OUT_OF_MEMORY if there was insufficient heap space.
