---
c: Copyright (C) Daniel Stenberg, <daniel.se>, et al.
SPDX-License-Identifier: curl
Title: CURLOPT_PROXY_PINNEDPUBLICKEY
Section: 3
Source: libcurl
See-also:
  - CURLOPT_PINNEDPUBLICKEY (3)
  - CURLOPT_PROXY_CAINFO (3)
  - CURLOPT_PROXY_CAPATH (3)
  - CURLOPT_PROXY_SSL_VERIFYHOST (3)
  - CURLOPT_PROXY_SSL_VERIFYPEER (3)
---

# NAME

CURLOPT_PROXY_PINNEDPUBLICKEY - pinned public key for https proxy

# SYNOPSIS

~~~c
#include <curl/curl.h>

CURLcode curl_easy_setopt(CURL *handle, CURLOPT_PROXY_PINNEDPUBLICKEY,
                          char *pinnedpubkey);
~~~

# DESCRIPTION

Pass a pointer to a null-terminated string as parameter. The string can be the
filename of your pinned public key. The file format expected is "PEM" or
"DER". The string can also be any number of base64 encoded sha256 hashes
preceded by "sha256//" and separated by ";"

When negotiating a TLS or SSL connection, the https proxy sends a certificate
indicating its identity. A public key is extracted from this certificate and
if it does not exactly match the public key provided to this option, libcurl
aborts the connection before sending or receiving any data.

On mismatch, *CURLE_SSL_PINNEDPUBKEYNOTMATCH* is returned.

The application does not have to keep the string around after setting this
option.

# DEFAULT

NULL

# PROTOCOLS

All TLS based protocols: HTTPS, FTPS, IMAPS, POP3S, SMTPS etc.

# EXAMPLE

~~~c
int main(void)
{
  CURL *curl = curl_easy_init();
  if(curl) {
    curl_easy_setopt(curl, CURLOPT_URL, "https://example.com");
    curl_easy_setopt(curl, CURLOPT_PROXY, "https://proxy:443");
    curl_easy_setopt(curl, CURLOPT_PROXY_PINNEDPUBLICKEY,
                     "sha256//YhKJKSzoTt2b5FP18fvpHo7fJYqQCjA"
                     "a3HWY3tvRMwE=;sha256//t62CeU2tQiqkexU74"
                     "Gxa2eg7fRbEgoChTociMee9wno=");

    /* Perform the request */
    curl_easy_perform(curl);
  }
}
~~~

# PUBLIC KEY EXTRACTION

If you do not have the https proxy server's public key file you can extract it
from the https proxy server's certificate.
~~~c
# retrieve the server's certificate if you do not already have it
#
# be sure to examine the certificate to see if it is what you expected
#
# Windows-specific:
# - Use NUL instead of /dev/null.
# - OpenSSL may wait for input instead of disconnecting. Hit enter.
# - If you do not have sed, then just copy the certificate into a file:
#   Lines from -----BEGIN CERTIFICATE----- to -----END CERTIFICATE-----.
#
openssl s_client -servername www.example.com -connect www.example.com:443 \
  < /dev/null | sed -n "/-----BEGIN/,/-----END/p" > www.example.com.pem

# extract public key in pem format from certificate
openssl x509 -in www.example.com.pem -pubkey -noout > www.example.com.pubkey.pem

# convert public key from pem to der
openssl asn1parse -noout -inform pem -in www.example.com.pubkey.pem \
  -out www.example.com.pubkey.der

# sha256 hash and base64 encode der to string for use
openssl dgst -sha256 -binary www.example.com.pubkey.der | openssl base64
~~~
The public key in PEM format contains a header, base64 data and a
footer:
~~~c
-----BEGIN PUBLIC KEY-----
[BASE 64 DATA]
-----END PUBLIC KEY-----
~~~

# AVAILABILITY

PEM/DER support:

 7.52.0: GnuTLS, OpenSSL, mbedTLS, wolfSSL

sha256 support:

 7.52.0: GnuTLS, OpenSSL, mbedTLS, wolfSSL

Other SSL backends not supported.

# RETURN VALUE

Returns CURLE_OK if TLS enabled, CURLE_UNKNOWN_OPTION if not, or
CURLE_OUT_OF_MEMORY if there was insufficient heap space.
