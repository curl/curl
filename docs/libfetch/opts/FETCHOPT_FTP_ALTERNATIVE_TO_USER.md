---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: fetch
Title: FETCHOPT_FTP_ALTERNATIVE_TO_USER
Section: 3
Source: libfetch
Protocol:
  - FTP
See-also:
  - FETCHOPT_FTP_ACCOUNT (3)
  - FETCHOPT_FTP_SKIP_PASV_IP (3)
  - FETCHOPT_SERVER_RESPONSE_TIMEOUT (3)
  - FETCHOPT_USERNAME (3)
Added-in: 7.15.5
---

# NAME

FETCHOPT_FTP_ALTERNATIVE_TO_USER - command to use instead of USER with FTP

# SYNOPSIS

~~~c
#include <fetch/fetch.h>

FETCHcode fetch_easy_setopt(FETCH *handle, FETCHOPT_FTP_ALTERNATIVE_TO_USER,
                          char *cmd);
~~~

# DESCRIPTION

Pass a char pointer as parameter, pointing to a string which is used to
authenticate if the usual FTP "USER user" and "PASS password" negotiation
fails. This is currently only known to be required when connecting to
Tumbleweed's Secure Transport FTPS server using client certificates for
authentication.

The application does not have to keep the string around after setting this
option.

# DEFAULT

NULL

# %PROTOCOLS%

# EXAMPLE

~~~c
int main(void)
{
  FETCH *fetch = fetch_easy_init();
  if(fetch) {
    FETCHcode res;
    fetch_easy_setopt(fetch, FETCHOPT_URL, "ftp://example.com/foo.bin");
    fetch_easy_setopt(fetch, FETCHOPT_FTP_ALTERNATIVE_TO_USER, "two users");
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
