---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: fetch
Title: fetch_easy_cleanup
Section: 3
Source: libfetch
See-also:
  - fetch_easy_duphandle (3)
  - fetch_easy_init (3)
  - fetch_easy_reset (3)
  - fetch_multi_cleanup (3)
  - fetch_multi_remove_handle (3)
Protocol:
  - All
Added-in: 7.1
---

# NAME

fetch_easy_cleanup - free an easy handle

# SYNOPSIS

~~~c
#include <fetch/fetch.h>

void fetch_easy_cleanup(FETCH *handle);
~~~

# DESCRIPTION

This function is the opposite of fetch_easy_init(3). It closes down and frees
all resources previously associated with this easy handle.

This call closes all connections this handle has used and possibly has kept
open until now unless the easy handle was attached to a multi handle while
doing the transfers. Do not call this function if you intend to transfer more
files, reusing handles is a key to good performance with libfetch.

Occasionally you may get your progress callback or header callback called from
within fetch_easy_cleanup(3) (if previously set for the handle using
fetch_easy_setopt(3)). Like if libfetch decides to shut down the connection and
the protocol is of a kind that requires a command/response sequence before
disconnect. Examples of such protocols are FTP, POP3 and IMAP.

Any use of the easy **handle** after this function has been called and have
returned, is illegal.

To close an easy handle that has been used with the multi interface, make sure
to first call fetch_multi_remove_handle(3) to remove it from the multi handle
before it is closed.

Passing in a NULL pointer in *handle* makes this function return immediately
with no action.

# %PROTOCOLS%

# EXAMPLE

~~~c
int main(void)
{
  FETCH *fetch = fetch_easy_init();
  if(fetch) {
    FETCHcode res;
    fetch_easy_setopt(fetch, FETCHOPT_URL, "https://example.com");
    res = fetch_easy_perform(fetch);
    if(res)
      printf("error: %s\n", fetch_easy_strerror(res));
    fetch_easy_cleanup(fetch);
  }
}
~~~

# %AVAILABILITY%

# RETURN VALUE

None
