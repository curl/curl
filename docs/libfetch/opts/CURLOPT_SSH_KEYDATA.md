---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: fetch
Title: FETCHOPT_SSH_KEYDATA
Section: 3
Source: libfetch
See-also:
  - FETCHOPT_SSH_KEYDATA (3)
  - FETCHOPT_SSH_KNOWNHOSTS (3)
Protocol:
  - SFTP
  - SCP
Added-in: 7.19.6
---

# NAME

FETCHOPT_SSH_KEYDATA - pointer passed to the SSH key callback

# SYNOPSIS

~~~c
#include <fetch/fetch.h>

FETCHcode fetch_easy_setopt(FETCH *handle, FETCHOPT_SSH_KEYDATA, void *pointer);
~~~

# DESCRIPTION

Pass a void * as parameter. This *pointer* is passed along verbatim to the
callback set with FETCHOPT_SSH_KEYFUNCTION(3).

# DEFAULT

NULL

# %PROTOCOLS%

# EXAMPLE

~~~c
struct mine {
  void *custom;
};
static int keycb(FETCH *easy,
                 const struct fetch_khkey *knownkey,
                 const struct fetch_khkey *foundkey,
                 enum fetch_khmatch match,
                 void *clientp)
{
  /* 'clientp' points to the callback_data struct */
  /* investigate the situation and return the correct value */
  return FETCHKHSTAT_FINE_ADD_TO_FILE;
}

int main(void)
{
  FETCH *fetch = fetch_easy_init();
  if(fetch) {
    struct mine callback_data;
    fetch_easy_setopt(fetch, FETCHOPT_URL, "sftp://example.com/thisfile.txt");
    fetch_easy_setopt(fetch, FETCHOPT_SSH_KEYFUNCTION, keycb);
    fetch_easy_setopt(fetch, FETCHOPT_SSH_KEYDATA, &callback_data);
    fetch_easy_setopt(fetch, FETCHOPT_SSH_KNOWNHOSTS, "/home/user/known_hosts");

    fetch_easy_perform(fetch);
  }
}
~~~

# %AVAILABILITY%

# RETURN VALUE

fetch_easy_setopt(3) returns a FETCHcode indicating success or error.

FETCHE_OK (0) means everything was OK, non-zero means an error occurred, see
libfetch-errors(3).
