---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: fetch
Title: FETCHOPT_SSH_AUTH_TYPES
Section: 3
Source: libfetch
See-also:
  - FETCHOPT_SSH_HOST_PUBLIC_KEY_MD5 (3)
  - FETCHOPT_SSH_HOST_PUBLIC_KEY_SHA256 (3)
  - FETCHOPT_SSH_PUBLIC_KEYFILE (3)
Protocol:
  - SFTP
  - SCP
Added-in: 7.16.1
---

# NAME

FETCHOPT_SSH_AUTH_TYPES - auth types for SFTP and SCP

# SYNOPSIS

~~~c
#include <fetch/fetch.h>

FETCHcode fetch_easy_setopt(FETCH *handle, FETCHOPT_SSH_AUTH_TYPES, long bitmask);
~~~

# DESCRIPTION

Pass a long set to a bitmask consisting of one or more of
FETCHSSH_AUTH_PUBLICKEY, FETCHSSH_AUTH_PASSWORD, FETCHSSH_AUTH_HOST,
FETCHSSH_AUTH_KEYBOARD and FETCHSSH_AUTH_AGENT.

Set *FETCHSSH_AUTH_ANY* to let libfetch pick a suitable one. Currently
FETCHSSH_AUTH_HOST has no effect. If FETCHSSH_AUTH_AGENT is used, libfetch
attempts to connect to ssh-agent or pageant and let the agent attempt the
authentication.

# DEFAULT

FETCHSSH_AUTH_ANY (all available)

# %PROTOCOLS%

# EXAMPLE

~~~c
int main(void)
{
  FETCH *fetch = fetch_easy_init();
  if(fetch) {
    FETCHcode res;
    fetch_easy_setopt(fetch, FETCHOPT_URL, "sftp://example.com/file");
    fetch_easy_setopt(fetch, FETCHOPT_SSH_AUTH_TYPES,
                     FETCHSSH_AUTH_PUBLICKEY | FETCHSSH_AUTH_KEYBOARD);
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
