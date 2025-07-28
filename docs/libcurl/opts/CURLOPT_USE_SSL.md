---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Title: CURLOPT_USE_SSL
Section: 3
Source: libcurl
See-also:
  - CURLOPT_PROXY_SSLVERSION (3)
  - CURLOPT_SSLVERSION (3)
  - CURLOPT_SSL_OPTIONS (3)
Protocol:
  - FTP
  - SMTP
  - POP3
  - IMAP
Added-in: 7.17.0
---

# NAME

CURLOPT_USE_SSL - request using SSL / TLS for the transfer

# SYNOPSIS

~~~c
#include <curl/curl.h>

CURLcode curl_easy_setopt(CURL *handle, CURLOPT_USE_SSL, long level);
~~~

# DESCRIPTION

Pass a long using one of the values from below, to make libcurl use your
desired *level* of SSL for the transfer.

These are all protocols that start out plain text and get "upgraded" to SSL
using the STARTTLS command.

This is for enabling SSL/TLS when you use FTP, SMTP, POP3, IMAP etc.

## CURLUSESSL_NONE

do not attempt to use SSL.

## CURLUSESSL_TRY

Try using SSL, proceed as normal otherwise. Note that server may close the
connection if the negotiation does not succeed.

## CURLUSESSL_CONTROL

Require SSL for the control connection or fail with *CURLE_USE_SSL_FAILED*.

## CURLUSESSL_ALL

Require SSL for all communication or fail with *CURLE_USE_SSL_FAILED*.

# DEFAULT

CURLUSESSL_NONE

# %PROTOCOLS%

# EXAMPLE

~~~c
int main(void)
{
  CURL *curl = curl_easy_init();
  if(curl) {
    curl_easy_setopt(curl, CURLOPT_URL, "ftp://example.com/dir/file.ext");

    /* require use of SSL for this, or fail */
    curl_easy_setopt(curl, CURLOPT_USE_SSL, (long)CURLUSESSL_ALL);

    /* Perform the request */
    curl_easy_perform(curl);
  }
}
~~~

# HISTORY

This option was known as CURLOPT_FTP_SSL up to 7.16.4. Supported by LDAP since
7.81.0. Fully supported by the OpenLDAP backend only.

# %AVAILABILITY%

# RETURN VALUE

curl_easy_setopt(3) returns a CURLcode indicating success or error.

CURLE_OK (0) means everything was OK, non-zero means an error occurred, see
libcurl-errors(3).
