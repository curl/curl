---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: fetch
Title: FETCHOPT_STREAM_WEIGHT
Section: 3
Source: libfetch
See-also:
  - FETCHMOPT_PIPELINING (3)
  - FETCHOPT_PIPEWAIT (3)
  - FETCHOPT_STREAM_DEPENDS (3)
  - FETCHOPT_STREAM_DEPENDS_E (3)
Protocol:
  - HTTP
Added-in: 7.46.0
---

# NAME

FETCHOPT_STREAM_WEIGHT - numerical stream weight

# SYNOPSIS

~~~c
#include <fetch/fetch.h>

FETCHcode fetch_easy_setopt(FETCH *handle, FETCHOPT_STREAM_WEIGHT, long weight);
~~~

# DESCRIPTION

Set the long *weight* to a number between 1 and 256.

When using HTTP/2, this option sets the individual weight for this particular
stream used by the easy *handle*. Setting and using weights only makes
sense and is only usable when doing multiple streams over the same
connections, which thus implies that you use FETCHMOPT_PIPELINING(3).

This option can be set during transfer and causes the updated weight info get
sent to the server the next time an HTTP/2 frame is sent to the server.

See section 5.3 of RFC 7540 for protocol details.

Streams with the same parent should be allocated resources proportionally
based on their weight. If you have two streams going, stream A with weight 16
and stream B with weight 32, stream B gets two thirds (32/48) of the available
bandwidth (assuming the server can send off the data equally for both
streams).

# DEFAULT

16

# %PROTOCOLS%

# EXAMPLE

~~~c
int main(void)
{
  FETCH *fetch = fetch_easy_init();
  FETCH *fetch2 = fetch_easy_init(); /* a second handle */
  if(fetch) {
    fetch_easy_setopt(fetch, FETCHOPT_URL, "https://example.com/one");
    fetch_easy_setopt(fetch, FETCHOPT_STREAM_WEIGHT, 10L);

    /* the second has twice the weight */
    fetch_easy_setopt(fetch2, FETCHOPT_URL, "https://example.com/two");
    fetch_easy_setopt(fetch2, FETCHOPT_STREAM_WEIGHT, 20L);

    /* then add both to a multi handle and transfer them */
  }
}
~~~

# %AVAILABILITY%

# RETURN VALUE

fetch_easy_setopt(3) returns a FETCHcode indicating success or error.

FETCHE_OK (0) means everything was OK, non-zero means an error occurred, see
libfetch-errors(3).
