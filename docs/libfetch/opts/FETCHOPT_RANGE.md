---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: fetch
Title: FETCHOPT_RANGE
Section: 3
Source: libfetch
See-also:
  - FETCHOPT_LOW_SPEED_LIMIT (3)
  - FETCHOPT_MAXFILESIZE_LARGE (3)
  - FETCHOPT_MAX_RECV_SPEED_LARGE (3)
  - FETCHOPT_RESUME_FROM (3)
Protocol:
  - HTTP
  - FTP
  - FILE
  - RTSP
  - SFTP
Added-in: 7.1
---

# NAME

FETCHOPT_RANGE - byte range to request

# SYNOPSIS

~~~c
#include <fetch/fetch.h>

FETCHcode fetch_easy_setopt(FETCH *handle, FETCHOPT_RANGE, char *range);
~~~

# DESCRIPTION

Pass a char pointer as parameter, which should contain the specified range you
want to retrieve. It should be in the format "X-Y", where either X or Y may be
left out and X and Y are byte indexes.

HTTP transfers also support several intervals, separated with commas as in
*"X-Y,N-M"*. Using this kind of multiple intervals causes the HTTP server
to send the response document in pieces (using standard MIME separation
techniques). Unfortunately, the HTTP standard (RFC 7233 section 3.1) allows
servers to ignore range requests so even when you set FETCHOPT_RANGE(3)
for a request, you may end up getting the full response sent back.

For RTSP, the formatting of a range should follow RFC 2326 Section 12.29. For
RTSP, byte ranges are **not** permitted. Instead, ranges should be given in
**npt**, **utc**, or **smpte** formats.

For HTTP PUT uploads this option should not be used, since it may conflict with
other options.

Using this option multiple times makes the last set string override the
previous ones. Set it to NULL to disable its use again.

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
    fetch_easy_setopt(fetch, FETCHOPT_URL, "https://example.com");

    /* get the first 200 bytes */
    fetch_easy_setopt(fetch, FETCHOPT_RANGE, "0-199");

    /* Perform the request */
    fetch_easy_perform(fetch);
  }
}
~~~

# HISTORY

FILE since 7.18.0, RTSP since 7.20.0

# %AVAILABILITY%

# RETURN VALUE

fetch_easy_setopt(3) returns a FETCHcode indicating success or error.

FETCHE_OK (0) means everything was OK, non-zero means an error occurred, see
libfetch-errors(3).
