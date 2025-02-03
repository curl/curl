---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: fetch
Title: FETCHOPT_RTSP_CLIENT_CSEQ
Section: 3
Source: libfetch
See-also:
  - FETCHINFO_RTSP_CLIENT_CSEQ (3)
  - FETCHINFO_RTSP_SERVER_CSEQ (3)
  - FETCHOPT_RTSP_REQUEST (3)
  - FETCHOPT_RTSP_SERVER_CSEQ (3)
Protocol:
  - RTSP
Added-in: 7.20.0
---

# NAME

FETCHOPT_RTSP_CLIENT_CSEQ - RTSP client CSEQ number

# SYNOPSIS

~~~c
#include <fetch/fetch.h>

FETCHcode fetch_easy_setopt(FETCH *handle, FETCHOPT_RTSP_CLIENT_CSEQ, long cseq);
~~~

# DESCRIPTION

Pass a long to set the CSEQ number to issue for the next RTSP request. Useful
if the application is resuming a previously broken connection. The CSEQ
increments from this new number henceforth.

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
    fetch_easy_setopt(fetch, FETCHOPT_URL, "rtsp://example.com/");
    fetch_easy_setopt(fetch, FETCHOPT_RTSP_CLIENT_CSEQ, 1234L);
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
