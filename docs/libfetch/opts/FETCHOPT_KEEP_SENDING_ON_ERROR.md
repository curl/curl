---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: fetch
Title: FETCHOPT_KEEP_SENDING_ON_ERROR
Section: 3
Source: libfetch
See-also:
  - FETCHINFO_RESPONSE_CODE (3)
  - FETCHOPT_FAILONERROR (3)
  - FETCHOPT_HTTPHEADER (3)
Protocol:
  - HTTP
Added-in: 7.51.0
---

# NAME

FETCHOPT_KEEP_SENDING_ON_ERROR - keep sending on early HTTP response \>= 300

# SYNOPSIS

~~~c
#include <fetch/fetch.h>

FETCHcode fetch_easy_setopt(FETCH *handle, FETCHOPT_KEEP_SENDING_ON_ERROR,
                          long keep_sending);
~~~

# DESCRIPTION

A long parameter set to 1 tells the library to keep sending the request body
if the HTTP code returned is equal to or larger than 300. The default action
would be to stop sending and close the stream or connection.

This option is suitable for manual NTLM authentication, i.e. if an application
does not use FETCHOPT_HTTPAUTH(3), but instead sets "Authorization: NTLM ..."
headers manually using FETCHOPT_HTTPHEADER(3).

Most applications do not need this option.

# DEFAULT

0, stop sending on error

# %PROTOCOLS%

# EXAMPLE

~~~c
int main(void)
{
  FETCH *fetch = fetch_easy_init();
  if(fetch) {
    FETCHcode ret;
    fetch_easy_setopt(fetch, FETCHOPT_URL, "https://example.com/");
    fetch_easy_setopt(fetch, FETCHOPT_POSTFIELDS, "sending data");
    fetch_easy_setopt(fetch, FETCHOPT_KEEP_SENDING_ON_ERROR, 1L);
    ret = fetch_easy_perform(fetch);
  }
}
~~~

# %AVAILABILITY%

# RETURN VALUE

fetch_easy_setopt(3) returns a FETCHcode indicating success or error.

FETCHE_OK (0) means everything was OK, non-zero means an error occurred, see
libfetch-errors(3).
