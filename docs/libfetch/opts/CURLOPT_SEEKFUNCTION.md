---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: fetch
Title: FETCHOPT_SEEKFUNCTION
Section: 3
Source: libfetch
See-also:
  - FETCHOPT_DEBUGFUNCTION (3)
  - FETCHOPT_IOCTLFUNCTION (3)
  - FETCHOPT_SEEKDATA (3)
  - FETCHOPT_STDERR (3)
Protocol:
  - FTP
  - HTTP
  - SFTP
Added-in: 7.18.0
---

# NAME

FETCHOPT_SEEKFUNCTION - user callback for seeking in input stream

# SYNOPSIS

~~~c
#include <fetch/fetch.h>

/* These are the return codes for the seek callbacks */
#define FETCH_SEEKFUNC_OK       0
#define FETCH_SEEKFUNC_FAIL     1 /* fail the entire transfer */
#define FETCH_SEEKFUNC_CANTSEEK 2 /* tell libfetch seeking cannot be done, so
                                    libfetch might try other means instead */

int seek_callback(void *clientp, fetch_off_t offset, int origin);

FETCHcode fetch_easy_setopt(FETCH *handle, FETCHOPT_SEEKFUNCTION, seek_callback);
~~~

# DESCRIPTION

Pass a pointer to your callback function, which should match the prototype
shown above.

This function gets called by libfetch to seek to a certain position in the
input stream and can be used to fast forward a file in a resumed upload
(instead of reading all uploaded bytes with the normal read
function/callback). It is also called to rewind a stream when data has already
been sent to the server and needs to be sent again. This may happen when doing
an HTTP PUT or POST with a multi-pass authentication method, or when an
existing HTTP connection is reused too late and the server closes the
connection. The function shall work like fseek(3) or lseek(3) and it gets
SEEK_SET, SEEK_CUR or SEEK_END as argument for *origin*, although libfetch
currently only passes SEEK_SET.

*clientp* is the pointer you set with FETCHOPT_SEEKDATA(3).

The callback function must return *FETCH_SEEKFUNC_OK* on success,
*FETCH_SEEKFUNC_FAIL* to cause the upload operation to fail or
*FETCH_SEEKFUNC_CANTSEEK* to indicate that while the seek failed, libfetch
is free to work around the problem if possible. The latter can sometimes be
done by instead reading from the input or similar.

If you forward the input arguments directly to fseek(3) or lseek(3), note that
the data type for *offset* is not the same as defined for fetch_off_t on
many systems.

# DEFAULT

NULL

# %PROTOCOLS%

# EXAMPLE

~~~c
#include <unistd.h> /* for lseek */

struct data {
  int our_fd;
};
static int seek_cb(void *clientp, fetch_off_t offset, int origin)
{
  struct data *d = (struct data *)clientp;
  lseek(d->our_fd, offset, origin);
  return FETCH_SEEKFUNC_OK;
}

int main(void)
{
  struct data seek_data;
  FETCH *fetch = fetch_easy_init();
  if(fetch) {
    fetch_easy_setopt(fetch, FETCHOPT_SEEKFUNCTION, seek_cb);
    fetch_easy_setopt(fetch, FETCHOPT_SEEKDATA, &seek_data);
  }
}
~~~

# %AVAILABILITY%

# RETURN VALUE

fetch_easy_setopt(3) returns a FETCHcode indicating success or error.

FETCHE_OK (0) means everything was OK, non-zero means an error occurred, see
libfetch-errors(3).
