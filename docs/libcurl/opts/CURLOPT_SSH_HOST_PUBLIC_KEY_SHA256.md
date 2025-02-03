---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: fetch
Title: FETCHOPT_SSH_HOST_PUBLIC_KEY_SHA256
Section: 3
Source: libfetch
See-also:
  - FETCHOPT_SSH_AUTH_TYPES (3)
  - FETCHOPT_SSH_HOST_PUBLIC_KEY_MD5 (3)
  - FETCHOPT_SSH_PUBLIC_KEYFILE (3)
Protocol:
  - SFTP
  - SCP
Added-in: 7.80.0
---

# NAME

FETCHOPT_SSH_HOST_PUBLIC_KEY_SHA256 - SHA256 hash of SSH server public key

# SYNOPSIS

~~~c
#include <fetch/fetch.h>

FETCHcode fetch_easy_setopt(FETCH *handle, FETCHOPT_SSH_HOST_PUBLIC_KEY_SHA256,
                          char *sha256);
~~~

# DESCRIPTION

Pass a char pointer pointing to a string containing a Base64-encoded SHA256
hash of the remote host's public key. The transfer fails if the given hash
does not match the hash the remote host provides.

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
    fetch_easy_setopt(fetch, FETCHOPT_SSH_HOST_PUBLIC_KEY_SHA256,
                     "NDVkMTQxMGQ1ODdmMjQ3MjczYjAyOTY5MmRkMjVmNDQ=");
    res = fetch_easy_perform(fetch);
    fetch_easy_cleanup(fetch);
  }
}
~~~

# NOTES

Requires the libssh2 backend.

# %AVAILABILITY%

# RETURN VALUE

fetch_easy_setopt(3) returns a FETCHcode indicating success or error.

FETCHE_OK (0) means everything was OK, non-zero means an error occurred, see
libfetch-errors(3).
