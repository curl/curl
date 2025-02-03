---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: fetch
Title: FETCHOPT_IOCTLFUNCTION
Section: 3
Source: libfetch
Protocol:
  - All
See-also:
  - FETCHOPT_IOCTLDATA (3)
  - FETCHOPT_SEEKFUNCTION (3)
Added-in: 7.12.3
---

# NAME

FETCHOPT_IOCTLFUNCTION - callback for I/O operations

# SYNOPSIS

~~~c
#include <fetch/fetch.h>

typedef enum {
  FETCHIOE_OK,            /* I/O operation successful */
  FETCHIOE_UNKNOWNCMD,    /* command was unknown to callback */
  FETCHIOE_FAILRESTART,   /* failed to restart the read */
  FETCHIOE_LAST           /* never use */
} fetchioerr;

typedef enum  {
  FETCHIOCMD_NOP,         /* no operation */
  FETCHIOCMD_RESTARTREAD, /* restart the read stream from start */
  FETCHIOCMD_LAST         /* never use */
} fetchiocmd;

fetchioerr ioctl_callback(FETCH *handle, int cmd, void *clientp);

FETCHcode fetch_easy_setopt(FETCH *handle, FETCHOPT_IOCTLFUNCTION, ioctl_callback);
~~~

# DESCRIPTION

Pass a pointer to your callback function, which should match the prototype
shown above.

This callback function gets called by libfetch when something special
I/O-related needs to be done that the library cannot do by itself. For now,
rewinding the read data stream is the only action it can request. The
rewinding of the read data stream may be necessary when doing an HTTP PUT or
POST with a multi-pass authentication method.

The callback MUST return *FETCHIOE_UNKNOWNCMD* if the input *cmd* is
not *FETCHIOCMD_RESTARTREAD*.

The *clientp* argument to the callback is set with the
FETCHOPT_IOCTLDATA(3) option.

**This option is deprecated**. Do not use it. Use FETCHOPT_SEEKFUNCTION(3)
instead to provide seeking. If FETCHOPT_SEEKFUNCTION(3) is set, this
parameter is ignored when seeking.

# DEFAULT

NULL

# %PROTOCOLS%

# EXAMPLE

~~~c
#include <unistd.h> /* for lseek */

struct data {
  int fd; /* our file descriptor */
};

static fetchioerr ioctl_callback(FETCH *handle, int cmd, void *clientp)
{
  struct data *io = (struct data *)clientp;
  if(cmd == FETCHIOCMD_RESTARTREAD) {
    lseek(io->fd, 0, SEEK_SET);
    return FETCHIOE_OK;
  }
  return FETCHIOE_UNKNOWNCMD;
}
int main(void)
{
  struct data ioctl_data;
  FETCH *fetch = fetch_easy_init();
  if(fetch) {
    fetch_easy_setopt(fetch, FETCHOPT_IOCTLFUNCTION, ioctl_callback);
    fetch_easy_setopt(fetch, FETCHOPT_IOCTLDATA, &ioctl_data);
  }
}
~~~

# DEPRECATED

Deprecated since 7.18.0.

# %AVAILABILITY%

# RETURN VALUE

fetch_easy_setopt(3) returns a FETCHcode indicating success or error.

FETCHE_OK (0) means everything was OK, non-zero means an error occurred, see
libfetch-errors(3).
