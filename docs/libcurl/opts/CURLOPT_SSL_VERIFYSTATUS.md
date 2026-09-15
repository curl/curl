---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Title: CURLOPT_SSL_VERIFYSTATUS
Section: 3
Source: libcurl
See-also:
  - CURLOPT_CAINFO (3)
  - CURLOPT_SSL_VERIFYHOST (3)
  - CURLOPT_SSL_VERIFYPEER (3)
Protocol:
  - TLS
TLS-backend:
  - OpenSSL
  - GnuTLS
Added-in: 7.41.0
---

# NAME

CURLOPT_SSL_VERIFYSTATUS - verify the certificate's status

# SYNOPSIS

~~~c
#include <curl/curl.h>

CURLcode curl_easy_setopt(CURL *handle, CURLOPT_SSL_VERIFYSTATUS, long verify);
~~~

# DESCRIPTION

Pass a long as parameter set to 1 to enable or 0 to disable.

This option determines whether libcurl verifies the status of the server cert
using the "Certificate Status Request" TLS extension (aka. OCSP stapling).

Note that if this option is enabled but the server does not support the TLS
extension, the verification fails.

This option has no effect on LDAP connections when libcurl uses the legacy LDAP
backend. That backend manages TLS independently of curl's TLS layer, and
neither the OpenLDAP nor the WinLDAP native TLS APIs offer an OCSP-stapling
verification facility, so no equivalent check occurs when this option is
enabled for ldaps:// transfers. When libcurl is built with USE_OPENLDAP, the
OpenLDAP backend routes TLS through curl's layer and this option is honored.

# DEFAULT

0

# %PROTOCOLS%

# EXAMPLE

~~~c
int main(void)
{
  CURL *curl = curl_easy_init();
  if(curl) {
    CURLcode result;
    curl_easy_setopt(curl, CURLOPT_URL, "https://example.com/");
    /* ask for OCSP stapling */
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYSTATUS, 1L);
    result = curl_easy_perform(curl);
    curl_easy_cleanup(curl);
  }
}
~~~

# %AVAILABILITY%

# RETURN VALUE

curl_easy_setopt(3) returns a CURLcode indicating success or error.

CURLE_OK (0) means everything was OK, non-zero means an error occurred, see
libcurl-errors(3).
