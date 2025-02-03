---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: fetch
Title: FETCHOPT_DIRLISTONLY
Section: 3
Source: libfetch
See-also:
  - FETCHOPT_CUSTOMREQUEST (3)
  - FETCHOPT_WILDCARDMATCH (3)
Protocol:
  - FTP
  - SFTP
  - POP3
Added-in: 7.17.0
---

# NAME

FETCHOPT_DIRLISTONLY - ask for names only in a directory listing

# SYNOPSIS

~~~c
#include <fetch/fetch.h>

FETCHcode fetch_easy_setopt(FETCH *handle, FETCHOPT_DIRLISTONLY, long listonly);
~~~

# DESCRIPTION

For FTP and SFTP based URLs a parameter set to 1 tells the library to list the
names of files in a directory, rather than performing a full directory listing
that would normally include file sizes, dates etc.

For POP3 a parameter of 1 tells the library to list the email message or
messages on the POP3 server. This can be used to change the default behavior
of libfetch, when combined with a URL that contains a message ID, to perform a
"scan listing" which can then be used to determine the size of an email.

For FILE, this option has no effect yet as directories are always listed in
this mode.

Note: For FTP this causes a NLST command to be sent to the FTP server. Beware
that some FTP servers list only files in their response to NLST; they might
not include subdirectories and symbolic links.

Setting this option to 1 also implies a directory listing even if the URL
does not end with a slash, which otherwise is necessary.

Do not use this option if you also use FETCHOPT_WILDCARDMATCH(3) as it
effectively breaks that feature.

# DEFAULT

0, disabled

# %PROTOCOLS%

# EXAMPLE

~~~c
int main(void)
{
  FETCH *fetch = fetch_easy_init();
  if(fetch) {
    FETCHcode res;
    fetch_easy_setopt(fetch, FETCHOPT_URL, "ftp://example.com/dir/");

    /* list only */
    fetch_easy_setopt(fetch, FETCHOPT_DIRLISTONLY, 1L);

    res = fetch_easy_perform(fetch);

    fetch_easy_cleanup(fetch);
  }
}
~~~

# HISTORY

This option was known as FETCHOPT_FTPLISTONLY up to 7.16.4. POP3 is supported
since 7.21.5.

# %AVAILABILITY%

# RETURN VALUE

fetch_easy_setopt(3) returns a FETCHcode indicating success or error.

FETCHE_OK (0) means everything was OK, non-zero means an error occurred, see
libfetch-errors(3).
