---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: fetch
Title: FETCHOPT_NEW_FILE_PERMS
Section: 3
Source: libfetch
See-also:
  - FETCHOPT_NEW_DIRECTORY_PERMS (3)
  - FETCHOPT_UPLOAD (3)
Protocol:
  - SFTP
  - SCP
  - FILE
Added-in: 7.16.4
---

# NAME

FETCHOPT_NEW_FILE_PERMS - permissions for remotely created files

# SYNOPSIS

~~~c
#include <fetch/fetch.h>

FETCHcode fetch_easy_setopt(FETCH *handle, FETCHOPT_NEW_FILE_PERMS,
                          long mode);
~~~

# DESCRIPTION

Pass a long as a parameter, containing the value of the permissions that are
set on newly created files on the remote server. The default value is *0644*.
The only protocols that can use this are *sftp://*, *scp://*, and *file://*.

# DEFAULT

0644

# %PROTOCOLS%

# EXAMPLE

~~~c
int main(void)
{
  FETCH *fetch = fetch_easy_init();
  if(fetch) {
    FETCHcode ret;
    fetch_easy_setopt(fetch, FETCHOPT_URL, "sftp://upload.example.com/file.txt");
    fetch_easy_setopt(fetch, FETCHOPT_NEW_FILE_PERMS, 0664L);
    ret = fetch_easy_perform(fetch);
  }
}
~~~

# %AVAILABILITY%

# RETURN VALUE

fetch_easy_setopt(3) returns a FETCHcode indicating success or error.

FETCHE_OK (0) means everything was OK, non-zero means an error occurred, see
libfetch-errors(3).
