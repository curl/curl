---
c: Copyright (C) Daniel Stenberg, <daniel.se>, et al.
SPDX-License-Identifier: curl
Title: CURLOPT_CAINFO
Section: 3
Source: libcurl
See-also:
  - CURLINFO_CAINFO (3)
  - CURLOPT_CAINFO_BLOB (3)
  - CURLOPT_CAPATH (3)
  - CURLOPT_CA_CACHE_TIMEOUT (3)
  - CURLOPT_SSL_VERIFYHOST (3)
  - CURLOPT_SSL_VERIFYPEER (3)
---

# NAME

CURLOPT_CAINFO - path to Certificate Authority (CA) bundle

# SYNOPSIS

~~~c
#include <curl/curl.h>

CURLcode curl_easy_setopt(CURL *handle, CURLOPT_CAINFO, char *path);
~~~

# DESCRIPTION

Pass a char pointer to a null-terminated string naming a file holding one or
more certificates to verify the peer with.

If CURLOPT_SSL_VERIFYPEER(3) is zero and you avoid verifying the
server's certificate, CURLOPT_CAINFO(3) need not even indicate an
accessible file.

This option is by default set to the system path where libcurl's CA
certificate bundle is assumed to be stored, as established at build time.

(iOS and macOS) When curl uses Secure Transport this option is supported. If
the option is not set, then curl uses the certificates in the system and user
Keychain to verify the peer.

(Schannel) This option is supported for Schannel in Windows 7 or later but we
recommend not using it until Windows 8 since it works better starting then.
If the option is not set, then curl uses the certificates in the Windows'
store of root certificates (the default for Schannel).

The application does not have to keep the string around after setting this
option.

The default value for this can be figured out with CURLINFO_CAINFO(3).

# DEFAULT

Built-in system specific. When curl is built with Secure Transport or
Schannel, this option is not set by default.

# PROTOCOLS

All TLS based protocols: HTTPS, FTPS, IMAPS, POP3S, SMTPS etc.

# EXAMPLE

~~~c
int main(void)
{
  CURL *curl = curl_easy_init();
  if(curl) {
    curl_easy_setopt(curl, CURLOPT_URL, "https://example.com/");
    curl_easy_setopt(curl, CURLOPT_CAINFO, "/etc/certs/cabundle.pem");
    curl_easy_perform(curl);
    curl_easy_cleanup(curl);
  }
}
~~~

# AVAILABILITY

For the SSL engines that do not support certificate files the
CURLOPT_CAINFO(3) option is ignored. Schannel support added in libcurl
7.60.

# RETURN VALUE

Returns CURLE_OK if the option is supported, CURLE_UNKNOWN_OPTION if not, or
CURLE_OUT_OF_MEMORY if there was insufficient heap space.
