---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Title: CURLOPT_PROXY_CAINFO
Section: 3
Source: libcurl
See-also:
  - CURLOPT_CAINFO (3)
  - CURLOPT_CAINFO_BLOB (3)
  - CURLOPT_CAPATH (3)
  - CURLOPT_PROXY_CAINFO_BLOB (3)
  - CURLOPT_PROXY_CAPATH (3)
  - CURLOPT_PROXY_SSL_VERIFYHOST (3)
  - CURLOPT_PROXY_SSL_VERIFYPEER (3)
  - CURLOPT_SSL_VERIFYHOST (3)
  - CURLOPT_SSL_VERIFYPEER (3)
Protocol:
  - TLS
TLS-backend:
  - All
Added-in: 7.52.0
---

# NAME

CURLOPT_PROXY_CAINFO - path to proxy Certificate Authority (CA) bundle

# SYNOPSIS

~~~c
#include <curl/curl.h>

CURLcode curl_easy_setopt(CURL *handle, CURLOPT_PROXY_CAINFO, char *path);
~~~

# DESCRIPTION

This option is for connecting to an HTTPS proxy, not an HTTPS server.

Pass a char pointer to a null-terminated string naming a file holding one or
more certificates to verify the HTTPS proxy with.

If CURLOPT_PROXY_SSL_VERIFYPEER(3) is zero and you avoid verifying the
server's certificate, CURLOPT_PROXY_CAINFO(3) need not even indicate an
accessible file.

This option is by default set to the system path where libcurl's CA
certificate bundle is assumed to be stored, as established at build time.

(iOS and macOS only) If curl is built against Secure Transport, then this
option is supported for backward compatibility with other SSL engines, but it
should not be set. If the option is not set, then curl uses the certificates
in the system and user Keychain to verify the peer, which is the preferred
method of verifying the peer's certificate chain.

The application does not have to keep the string around after setting this
option.

Using this option multiple times makes the last set string override the
previous ones. Set it to NULL to disable its use again and switches back to
internal default.

The default value for this can be figured out with CURLINFO_CAINFO(3).

# DEFAULT

Built-in system specific

# %PROTOCOLS%

# EXAMPLE

~~~c
int main(void)
{
  CURL *curl = curl_easy_init();
  if(curl) {
    CURLcode res;
    curl_easy_setopt(curl, CURLOPT_URL, "https://example.com/");
    /* using an HTTPS proxy */
    curl_easy_setopt(curl, CURLOPT_PROXY, "https://localhost:443");
    curl_easy_setopt(curl, CURLOPT_PROXY_CAINFO, "/etc/certs/cabundle.pem");
    res = curl_easy_perform(curl);
    curl_easy_cleanup(curl);
  }
}
~~~

# NOTES

For TLS backends that do not support certificate files, the
CURLOPT_PROXY_CAINFO(3) option is ignored. Refer to
https://curl.se/docs/ssl-compared.html

# %AVAILABILITY%

# RETURN VALUE

curl_easy_setopt(3) returns a CURLcode indicating success or error.

CURLE_OK (0) means everything was OK, non-zero means an error occurred, see
libcurl-errors(3).
