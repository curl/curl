---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: fetch
Title: FETCHOPT_SSH_PUBLIC_KEYFILE
Section: 3
Source: libfetch
See-also:
  - FETCHOPT_SSH_AUTH_TYPES (3)
  - FETCHOPT_SSH_PRIVATE_KEYFILE (3)
Protocol:
  - SFTP
  - SCP
Added-in: 7.16.1
---

# NAME

FETCHOPT_SSH_PUBLIC_KEYFILE - public key file for SSH auth

# SYNOPSIS

~~~c
#include <fetch/fetch.h>

FETCHcode fetch_easy_setopt(FETCH *handle, FETCHOPT_SSH_PUBLIC_KEYFILE,
                          char *filename);
~~~

# DESCRIPTION

Pass a char pointer pointing to a *filename* for your public key. If not used,
libfetch defaults to **$HOME/.ssh/id_dsa.pub** if the HOME environment variable
is set, and just "id_dsa.pub" in the current directory if HOME is not set.

If NULL (or an empty string) is passed to this option, libfetch passes no
public key to the SSH library, which then rather derives it from the private
key. If the SSH library cannot derive the public key from the private one and
no public one is provided, the transfer fails.

The application does not have to keep the string around after setting this
option.

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
    fetch_easy_setopt(fetch, FETCHOPT_SSH_PUBLIC_KEYFILE,
                     "/home/clarkkent/.ssh/id_rsa.pub");
    res = fetch_easy_perform(fetch);
    fetch_easy_cleanup(fetch);
  }
}
~~~

# HISTORY

The "" trick was added in 7.26.0

# %AVAILABILITY%

# RETURN VALUE

fetch_easy_setopt(3) returns a FETCHcode indicating success or error.

FETCHE_OK (0) means everything was OK, non-zero means an error occurred, see
libfetch-errors(3).
