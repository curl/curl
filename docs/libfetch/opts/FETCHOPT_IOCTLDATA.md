---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: fetch
Title: FETCHOPT_IOCTLDATA
Section: 3
Source: libfetch
See-also:
  - FETCHOPT_IOCTLFUNCTION (3)
  - FETCHOPT_SEEKFUNCTION (3)
Protocol:
  - All
Added-in: 7.12.3
---

# NAME

FETCHOPT_IOCTLDATA - pointer passed to I/O callback

# SYNOPSIS

~~~c
#include <fetch/fetch.h>

FETCHcode fetch_easy_setopt(FETCH *handle, FETCHOPT_IOCTLDATA, void *pointer);
~~~

# DESCRIPTION

Pass the *pointer* that is untouched by libfetch and passed as the 3rd
argument in the ioctl callback set with FETCHOPT_IOCTLFUNCTION(3).

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
