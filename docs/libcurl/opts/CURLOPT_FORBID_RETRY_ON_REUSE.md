---
c: Copyright (C) 2025 Hewlett Packard Enterprise Development LP
SPDX-License-Identifier: curl
Title: CURLOPT_FORBID_RETRY_ON_REUSE
Section: 3
Source: libcurl
See-also:
  - CURLOPT_FRESH_CONNECT (3)
  - CURLOPT_FORBID_REUSE (3)
Protocol:
  - All
Added-in: 8.16.0
---

# NAME

CURLOPT_FORBID_RETRY_ON_REUSE - prevent retry in case of reused connection is reset

# SYNOPSIS

~~~c
#include <curl/curl.h>

CURLcode curl_easy_setopt(CURL *handle, CURLOPT_FORBID_RETRY_ON_REUSE,
                          long forbid_retry);
~~~

# DESCRIPTION

Pass a long. Set *forbid_retry* to 1 to prevent libcurl from resubmitting a
transfer on a new connection when the previous reused connection was reset.
Instead, the reset is returned to the caller as a `CURLE_RECV_ERROR`.

This option only affects retry decision if the connection used to perform
the request (and from which CURL received a TCP reset) is reused.

Normally, libcurl considers connection resets on reused connections as a
transient timing issue. The reset event is only visible to curl at the time
libcurl attempts to issue transfer on that connection. As a result,
sometimes libcurl may issue more than 1 identical transfers in a row on
different connections with a single `curl_easy_perform()` call. Caller is
not informed about any previous transfer attempts that may or may not have
arrived at the server before the reset happened.

This can break transactional application-level protocols if the protocol
state machine considers connection state changes as part of state
transition edges, or the protocol involves non-idempotent requests with
side effects.

Before introduction of this option, the only way to avoid unobservable
retries was to set CURLOPT_FORBID_REUSE(3) to 1. However, without
connection reuse and keepalive, the application pays significant
overhead from the TCP and TLS handshake for every transfer. This option
decouples implicit retry behavior from connection reuse, allowing the
application to benefit from connection reuse without risking unobservable
retries.

Set to 0 to have libcurl transparently retry the transfer on a new
connection if the reused connection was reset (default behavior).

# DEFAULT

0

# %PROTOCOLS%

# EXAMPLE

~~~c
#include <unistd.h>

int main(void)
{
  CURL *curl = curl_easy_init();
  if(curl) {
    curl_easy_setopt(curl, CURLOPT_URL, "https://example.com/");
    curl_easy_setopt(curl, CURLOPT_FORBID_RETRY_ON_REUSE, 1L);

    /*
     * This request will establish a connection and retained it for reuse
     * after the transfer is done.
     */
    curl_easy_perform(curl);

    /* Wait long enough for the server to drop connection. */
    sleep(60);

    /*
     * curl will fail this request from the reset instead of
     * transmitting the same transfer again over a new connection.
     */
    curl_easy_perform(curl);

    curl_easy_cleanup(curl);
  }
}
~~~

# %AVAILABILITY%

# RETURN VALUE

curl_easy_setopt(3) returns a CURLcode indicating success or error.

CURLE_OK (0) means everything was OK, non-zero means an error occurred, see
libcurl-errors(3).
