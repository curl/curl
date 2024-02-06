---
c: Copyright (C) Daniel Stenberg, <daniel.se>, et al.
SPDX-License-Identifier: curl
Title: curl_easy_upkeep
Section: 3
Source: libcurl
See-also:
  - CURLOPT_TCP_KEEPALIVE (3)
  - CURLOPT_TCP_KEEPIDLE (3)
---

# NAME

curl_easy_upkeep - Perform any connection upkeep checks.

# SYNOPSIS

~~~c
#include <curl/curl.h>

CURLcode curl_easy_upkeep(CURL *handle);
~~~

# DESCRIPTION

Some protocols have "connection upkeep" mechanisms. These mechanisms usually
send some traffic on existing connections in order to keep them alive; this
can prevent connections from being closed due to overzealous firewalls, for
example.

Currently the only protocol with a connection upkeep mechanism is HTTP/2: when
the connection upkeep interval is exceeded and curl_easy_upkeep(3)
is called, an HTTP/2 PING frame is sent on the connection.

This function must be explicitly called in order to perform the upkeep work.
The connection upkeep interval is set with
CURLOPT_UPKEEP_INTERVAL_MS(3).

# EXAMPLE

~~~c
int main(void)
{
  CURL *curl = curl_easy_init();
  if(curl) {
    /* Make a connection to an HTTP/2 server. */
    curl_easy_setopt(curl, CURLOPT_URL, "https://example.com");

    /* Set the interval to 30000ms / 30s */
    curl_easy_setopt(curl, CURLOPT_UPKEEP_INTERVAL_MS, 30000L);

    curl_easy_perform(curl);

    /* Perform more work here. */

    /* While the connection is being held open, curl_easy_upkeep() can be
       called. If curl_easy_upkeep() is called and the time since the last
       upkeep exceeds the interval, then an HTTP/2 PING is sent. */
    curl_easy_upkeep(curl);

    /* Perform more work here. */

    /* always cleanup */
    curl_easy_cleanup(curl);
  }
}
~~~

# AVAILABILITY

Added in 7.62.0.

# RETURN VALUE

On success, returns **CURLE_OK**.

On failure, returns the appropriate error code.
