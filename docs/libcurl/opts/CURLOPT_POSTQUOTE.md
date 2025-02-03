---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: fetch
Title: FETCHOPT_POSTQUOTE
Section: 3
Source: libfetch
See-also:
  - FETCHOPT_PREQUOTE (3)
  - FETCHOPT_QUOTE (3)
Protocol:
  - FTP
  - SFTP
Added-in: 7.1
---

# NAME

FETCHOPT_POSTQUOTE - (S)FTP commands to run after the transfer

# SYNOPSIS

~~~c
#include <fetch/fetch.h>

FETCHcode fetch_easy_setopt(FETCH *handle, FETCHOPT_POSTQUOTE,
                          struct fetch_slist *cmds);
~~~

# DESCRIPTION

Pass a pointer to a linked list of FTP or SFTP commands to pass to the server
after your FTP transfer request. The commands are only issued if no error
occur. The linked list should be a fully valid list of struct fetch_slist
structs properly filled in as described for FETCHOPT_QUOTE(3).

Using this option multiple times makes the last set list override the previous
ones. Set it to NULL to disable its use again.

libfetch does not copy the list, it needs to be kept around until after the
transfer has completed.

# DEFAULT

NULL

# %PROTOCOLS%

# EXAMPLE

~~~c
int main(void)
{
  struct fetch_slist *cmdlist = NULL;
  cmdlist = fetch_slist_append(cmdlist, "RNFR source-name");
  cmdlist = fetch_slist_append(cmdlist, "RNTO new-name");

  FETCH *fetch = fetch_easy_init();
  if(fetch) {
    FETCHcode res;
    fetch_easy_setopt(fetch, FETCHOPT_URL, "ftp://example.com/foo.bin");

    /* pass in the FTP commands to run after the transfer */
    fetch_easy_setopt(fetch, FETCHOPT_POSTQUOTE, cmdlist);

    res = fetch_easy_perform(fetch);

    fetch_easy_cleanup(fetch);
  }
  fetch_slist_free_all(cmdlist);
}
~~~

# %AVAILABILITY%

# RETURN VALUE

fetch_easy_setopt(3) returns a FETCHcode indicating success or error.

FETCHE_OK (0) means everything was OK, non-zero means an error occurred, see
libfetch-errors(3).
