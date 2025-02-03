---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: fetch
Title: FETCHOPT_PREQUOTE
Section: 3
Source: libfetch
See-also:
  - FETCHOPT_POSTQUOTE (3)
  - FETCHOPT_QUOTE (3)
Protocol:
  - FTP
Added-in: 7.9.5
---

# NAME

FETCHOPT_PREQUOTE - commands to run before an FTP transfer

# SYNOPSIS

~~~c
#include <fetch/fetch.h>

FETCHcode fetch_easy_setopt(FETCH *handle, FETCHOPT_PREQUOTE,
                          struct fetch_slist *cmds);
~~~

# DESCRIPTION

Pass a pointer to a linked list of FTP commands to pass to the server after
the transfer type is set. The linked list should be a fully valid list of
struct fetch_slist structs properly filled in as described for
FETCHOPT_QUOTE(3).

Using this option multiple times makes the last set string override the
previous ones. Set it to NULL to disable its use again.

libfetch does not copy the list, it needs to be kept around until after the
transfer has completed.

These commands are not performed when a directory listing is performed, only
for file transfers.

While FETCHOPT_QUOTE(3) and FETCHOPT_POSTQUOTE(3) work for SFTP,
this option does not.

# DEFAULT

NULL

# %PROTOCOLS%

# EXAMPLE

~~~c
int main(void)
{
  struct fetch_slist *cmdlist = NULL;
  cmdlist = fetch_slist_append(cmdlist, "SYST");

  FETCH *fetch = fetch_easy_init();
  if(fetch) {
    FETCHcode res;
    fetch_easy_setopt(fetch, FETCHOPT_URL, "ftp://example.com/foo.bin");

    /* pass in the FTP commands to run */
    fetch_easy_setopt(fetch, FETCHOPT_PREQUOTE, cmdlist);

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
