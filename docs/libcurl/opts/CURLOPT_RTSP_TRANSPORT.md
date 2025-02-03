---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: fetch
Title: FETCHOPT_RTSP_TRANSPORT
Section: 3
Source: libfetch
See-also:
  - FETCHOPT_RTSP_REQUEST (3)
  - FETCHOPT_RTSP_SESSION_ID (3)
Protocol:
  - RTSP
Added-in: 7.20.0
---

# NAME

FETCHOPT_RTSP_TRANSPORT - RTSP Transport: header

# SYNOPSIS

~~~c
#include <fetch/fetch.h>

FETCHcode fetch_easy_setopt(FETCH *handle, FETCHOPT_RTSP_TRANSPORT,
                          char *transport);
~~~

# DESCRIPTION

Pass a char pointer to tell libfetch what to pass for the Transport: header for
this RTSP session. This is mainly a convenience method to avoid needing to set
a custom Transport: header for every SETUP request. The application must set a
Transport: header before issuing a SETUP request.

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
    fetch_easy_setopt(fetch, FETCHOPT_URL, "rtsp://example.com/");
    fetch_easy_setopt(fetch, FETCHOPT_RTSP_REQUEST, FETCH_RTSPREQ_SETUP);
    fetch_easy_setopt(fetch, FETCHOPT_RTSP_TRANSPORT,
                     "RTP/AVP;unicast;client_port=4588-4589");
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
