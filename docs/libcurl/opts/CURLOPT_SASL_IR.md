---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: fetch
Title: FETCHOPT_SASL_IR
Section: 3
Source: libfetch
See-also:
  - FETCHOPT_MAIL_AUTH (3)
  - FETCHOPT_MAIL_FROM (3)
  - FETCHOPT_SASL_AUTHZID (3)
Protocol:
  - SMTP
  - IMAP
Added-in: 7.31.0
---

# NAME

FETCHOPT_SASL_IR - send initial response in first packet

# SYNOPSIS

~~~c
#include <fetch/fetch.h>

FETCHcode fetch_easy_setopt(FETCH *handle, FETCHOPT_SASL_IR, long enable);
~~~

# DESCRIPTION

Pass a long. If the value is 1, fetch sends the initial response to the server
in the first authentication packet in order to reduce the number of ping pong
requests. Only applicable to the following supporting SASL authentication
mechanisms:

* Login
* Plain
* GSSAPI
* NTLM
* OAuth 2.0

Note: Whilst IMAP supports this option there is no need to explicitly set it,
as libfetch can determine the feature itself when the server supports the
SASL-IR CAPABILITY.

# DEFAULT

0

# %PROTOCOLS%

# EXAMPLE

~~~c
int main(void)
{
  FETCH *fetch = fetch_easy_init();
  if(fetch) {
    FETCHcode res;
    fetch_easy_setopt(fetch, FETCHOPT_URL, "smtp://example.com/");
    fetch_easy_setopt(fetch, FETCHOPT_SASL_IR, 1L);
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
