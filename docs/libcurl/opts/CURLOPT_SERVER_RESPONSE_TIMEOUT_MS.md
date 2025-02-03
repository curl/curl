---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: fetch
Title: FETCHOPT_SERVER_RESPONSE_TIMEOUT_MS
Section: 3
Source: libfetch
See-also:
  - FETCHOPT_CONNECTTIMEOUT (3)
  - FETCHOPT_LOW_SPEED_LIMIT (3)
  - FETCHOPT_TIMEOUT (3)
Protocol:
  - FTP
  - IMAP
  - POP3
  - SMTP
  - SFTP
  - SCP
Added-in: 8.6.0
---

# NAME

FETCHOPT_SERVER_RESPONSE_TIMEOUT_MS - time allowed to wait for server response

# SYNOPSIS

~~~c
#include <fetch/fetch.h>

FETCHcode fetch_easy_setopt(FETCH *handle, FETCHOPT_SERVER_RESPONSE_TIMEOUT_MS,
                          long timeout);
~~~

# DESCRIPTION

Pass a long. Causes libfetch to set a *timeout* period (in milliseconds) on the
amount of time that the server is allowed to take in order to send a response
message for a command before the session is considered dead. While libfetch is
waiting for a response, this value overrides FETCHOPT_TIMEOUT(3). It is
recommended that if used in conjunction with FETCHOPT_TIMEOUT(3), you set
FETCHOPT_SERVER_RESPONSE_TIMEOUT_MS(3) to a value smaller than
FETCHOPT_TIMEOUT(3).

The maximum accepted value is 2147483648.

This is the millisecond version of FETCHOPT_SERVER_RESPONSE_TIMEOUT(3).

# DEFAULT

None

# %PROTOCOLS%

# EXAMPLE

~~~c
int main(void)
{
  FETCH *fetch = fetch_easy_init();
  if(fetch) {
    FETCHcode res;
    fetch_easy_setopt(fetch, FETCHOPT_URL, "ftp://example.com/slow.txt");
    /* wait no more than 237 milliseconds */
    fetch_easy_setopt(fetch, FETCHOPT_SERVER_RESPONSE_TIMEOUT_MS, 237L);
    res = fetch_easy_perform(fetch);

    fetch_easy_cleanup(fetch);
  }
}
~~~

# %AVAILABILITY%

# RETURN VALUE

fetch_easy_setopt(3) returns a FETCHcode indicating success or error.

FETCHE_OK (0) means everything was OK, non-zero means an error occurred, see
libfetch-errors(3).
