---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: fetch
Title: FETCHOPT_SSH_HOST_PUBLIC_KEY_MD5
Section: 3
Source: libfetch
See-also:
  - FETCHOPT_SSH_AUTH_TYPES (3)
  - FETCHOPT_SSH_HOST_PUBLIC_KEY_SHA256 (3)
  - FETCHOPT_SSH_KNOWNHOSTS (3)
  - FETCHOPT_SSH_PUBLIC_KEYFILE (3)
Protocol:
  - SFTP
  - SCP
Added-in: 7.17.1
---

# NAME

FETCHOPT_SSH_HOST_PUBLIC_KEY_MD5 - MD5 checksum of SSH server public key

# SYNOPSIS

~~~c
#include <fetch/fetch.h>

FETCHcode fetch_easy_setopt(FETCH *handle, FETCHOPT_SSH_HOST_PUBLIC_KEY_MD5,
                          char *md5);
~~~

# DESCRIPTION

Pass a char pointer pointing to a string containing 32 hexadecimal digits. The
string should be the 128 bit MD5 checksum of the remote host's public key, and
libfetch aborts the connection to the host unless the MD5 checksum match.

MD5 is a weak algorithm. We strongly recommend using
FETCHOPT_SSH_HOST_PUBLIC_KEY_SHA256(3) instead.

The application does not have to keep the string around after setting this
option.

Using this option multiple times makes the last set string override the
previous ones. Set it to NULL to disable its use again.

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
    fetch_easy_setopt(fetch, FETCHOPT_URL, "sftp://example.com/file");
    fetch_easy_setopt(fetch, FETCHOPT_SSH_HOST_PUBLIC_KEY_MD5,
                     "afe17cd62a0f3b61f1ab9cb22ba269a7");
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
