---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: fetch
Title: FETCHOPT_FTP_FILEMETHOD
Section: 3
Source: libfetch
Protocol:
  - FTP
See-also:
  - FETCHOPT_DIRLISTONLY (3)
  - FETCHOPT_FTP_SKIP_PASV_IP (3)
Added-in: 7.15.1
---

# NAME

FETCHOPT_FTP_FILEMETHOD - select directory traversing method for FTP

# SYNOPSIS

~~~c
#include <fetch/fetch.h>

FETCHcode fetch_easy_setopt(FETCH *handle, FETCHOPT_FTP_FILEMETHOD,
                          long method);
~~~

# DESCRIPTION

Pass a long telling libfetch which *method* to use to reach a file on a
FTP(S) server.

This option exists because some server implementations are not compliant to
what the standards say should work.

The argument should be one of the following alternatives:

## FETCHFTPMETHOD_MULTICWD

libfetch does a single CWD operation for each path part in the given URL. For
deep hierarchies this means many commands. This is how RFC 1738 says it should
be done. This is the default but the slowest behavior.

## FETCHFTPMETHOD_NOCWD

libfetch makes no CWD at all. libfetch does SIZE, RETR, STOR etc and gives a
full path to the server for all these commands. This is the fastest behavior
since it skips having to change directories.

## FETCHFTPMETHOD_SINGLECWD

libfetch does one CWD with the full target directory and then operates on the
file &"normally" (like in the multicwd case). This is somewhat more standards
compliant than 'nocwd' but without the full penalty of 'multicwd'.

# DEFAULT

FETCHFTPMETHOD_MULTICWD

# %PROTOCOLS%

# EXAMPLE

~~~c
int main(void)
{
  FETCH *fetch = fetch_easy_init();
  if(fetch) {
    FETCHcode res;
    fetch_easy_setopt(fetch, FETCHOPT_URL, "ftp://example.com/1/2/3/4/new.txt");
    fetch_easy_setopt(fetch, FETCHOPT_FTP_FILEMETHOD,
                     (long)FETCHFTPMETHOD_SINGLECWD);

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
