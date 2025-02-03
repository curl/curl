---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: fetch
Title: FETCHOPT_SEEKDATA
Section: 3
Source: libfetch
See-also:
  - FETCHOPT_DEBUGFUNCTION (3)
  - FETCHOPT_IOCTLFUNCTION (3)
  - FETCHOPT_SEEKFUNCTION (3)
  - FETCHOPT_STDERR (3)
Protocol:
  - FTP
  - HTTP
  - SFTP
Added-in: 7.18.0
---

# NAME

FETCHOPT_SEEKDATA - pointer passed to the seek callback

# SYNOPSIS

~~~c
#include <fetch/fetch.h>

FETCHcode fetch_easy_setopt(FETCH *handle, FETCHOPT_SEEKDATA, void *pointer);
~~~

# DESCRIPTION

Data *pointer* to pass to the seek callback function. If you use the
FETCHOPT_SEEKFUNCTION(3) option, this is the pointer you get as input.

# DEFAULT

If you do not set this, NULL is passed to the callback.

# %PROTOCOLS%

# EXAMPLE

~~~c
#include <unistd.h> /* for lseek() */

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
