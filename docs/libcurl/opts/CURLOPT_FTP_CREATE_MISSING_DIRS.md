---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: fetch
Title: FETCHOPT_FTP_CREATE_MISSING_DIRS
Section: 3
Source: libfetch
Protocol:
  - FTP
See-also:
  - FETCHOPT_FTP_FILEMETHOD (3)
  - FETCHOPT_FTP_USE_EPSV (3)
Added-in: 7.10.7
---

# NAME

FETCHOPT_FTP_CREATE_MISSING_DIRS - create missing directories for FTP and SFTP

# SYNOPSIS

~~~c
#include <fetch/fetch.h>

typedef enum {
  FETCHFTP_CREATE_DIR_NONE,
  FETCHFTP_CREATE_DIR,
  FETCHFTP_CREATE_DIR_RETRY
} fetch_ftpcreatedir;

FETCHcode fetch_easy_setopt(FETCH *handle, FETCHOPT_FTP_CREATE_MISSING_DIRS,
                          long create);
~~~

# DESCRIPTION

Pass a long telling libfetch to *create* the dir. If the value is
*FETCHFTP_CREATE_DIR* (1), libfetch may create any remote directory that it
fails to "move" into.

For FTP requests, that means a CWD command fails. CWD being the command that
changes working directory.

For SFTP requests, libfetch may create the remote directory if it cannot obtain
a handle to the target-location. The creation fails if a file of the same name
as the directory to create already exists or lack of permissions prevents
creation.

Setting *create* to *FETCHFTP_CREATE_DIR_RETRY* (2), tells libfetch to
retry the CWD command again if the subsequent **MKD** command fails. This is
especially useful if you are doing many simultaneous connections against the
same server and they all have this option enabled, as then CWD may first fail
but then another connection does **MKD** before this connection and thus
**MKD** fails but trying CWD works.

# DEFAULT

FETCHFTP_CREATE_DIR_NONE (0)

# %PROTOCOLS%

# EXAMPLE

~~~c
int main(void)
{
  FETCH *fetch = fetch_easy_init();
  if(fetch) {
    FETCHcode res;
    fetch_easy_setopt(fetch, FETCHOPT_URL,
                     "ftp://example.com/non-existing/new.txt");
    fetch_easy_setopt(fetch, FETCHOPT_FTP_CREATE_MISSING_DIRS,
                     (long)FETCHFTP_CREATE_DIR_RETRY);

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
