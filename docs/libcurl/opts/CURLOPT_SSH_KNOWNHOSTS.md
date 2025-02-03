---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: fetch
Title: FETCHOPT_SSH_KNOWNHOSTS
Section: 3
Source: libfetch
See-also:
  - FETCHOPT_SSH_AUTH_TYPES (3)
  - FETCHOPT_SSH_HOST_PUBLIC_KEY_MD5 (3)
Protocol:
  - SFTP
  - SCP
Added-in: 7.19.6
---

# NAME

FETCHOPT_SSH_KNOWNHOSTS - filename holding the SSH known hosts

# SYNOPSIS

~~~c
#include <fetch/fetch.h>

FETCHcode fetch_easy_setopt(FETCH *handle, FETCHOPT_SSH_KNOWNHOSTS, char *fname);
~~~

# DESCRIPTION

Pass a pointer to a null-terminated string holding the filename of the
known_host file to use. The known_hosts file should use the OpenSSH file
format as supported by libssh2. If this file is specified, libfetch only
accepts connections with hosts that are known and present in that file, with a
matching public key. Use FETCHOPT_SSH_KEYFUNCTION(3) to alter the default
behavior on host and key matches and mismatches.

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
    fetch_easy_setopt(fetch, FETCHOPT_SSH_KNOWNHOSTS,
                     "/home/clarkkent/.ssh/known_hosts");
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
