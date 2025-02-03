---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: fetch
Title: FETCHOPT_SSH_HOSTKEYDATA
Section: 3
Source: libfetch
See-also:
  - FETCHOPT_SSH_HOSTKEYFUNCTION (3)
Protocol:
  - SFTP
  - SCP
Added-in: 7.84.0
---

# NAME

FETCHOPT_SSH_HOSTKEYDATA - pointer to pass to the SSH host key callback

# SYNOPSIS

~~~c
#include <fetch/fetch.h>

FETCHcode fetch_easy_setopt(FETCH *handle, FETCHOPT_SSH_HOSTKEYDATA, void *pointer);
~~~

# DESCRIPTION

Pass a void * as parameter. This *pointer* is passed along untouched to
the callback set with FETCHOPT_SSH_HOSTKEYFUNCTION(3).

# DEFAULT

NULL

# %PROTOCOLS%

# EXAMPLE

~~~c
struct mine {
  void *custom;
};

static int hostkeycb(void *clientp,   /* FETCHOPT_SSH_HOSTKEYDATA */
                     int keytype,     /* FETCHKHTYPE */
                     const char *key, /* host key to check */
                     size_t keylen)   /* length of the key */
{
  /* 'clientp' points to the callback_data struct */
  /* investigate the situation and return the correct value */
  return FETCHKHMATCH_OK;
}

int main(void)
{
  FETCH *fetch = fetch_easy_init();
  if(fetch) {
    struct mine callback_data;
    fetch_easy_setopt(fetch, FETCHOPT_URL, "sftp://example.com/thisfile.txt");
    fetch_easy_setopt(fetch, FETCHOPT_SSH_HOSTKEYFUNCTION, hostkeycb);
    fetch_easy_setopt(fetch, FETCHOPT_SSH_HOSTKEYDATA, &callback_data);

    fetch_easy_perform(fetch);
  }
}
~~~

# NOTES

Works only with the libssh2 backend.

# %AVAILABILITY%

# RETURN VALUE

fetch_easy_setopt(3) returns a FETCHcode indicating success or error.

FETCHE_OK (0) means everything was OK, non-zero means an error occurred, see
libfetch-errors(3).
