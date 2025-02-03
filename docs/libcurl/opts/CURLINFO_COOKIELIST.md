---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: fetch
Title: FETCHINFO_COOKIELIST
Section: 3
Source: libfetch
See-also:
  - FETCHOPT_COOKIELIST (3)
  - fetch_easy_getinfo (3)
  - fetch_easy_setopt (3)
Protocol:
  - HTTP
Added-in: 7.14.1
---

# NAME

FETCHINFO_COOKIELIST - get all known cookies

# SYNOPSIS

~~~c
#include <fetch/fetch.h>

FETCHcode fetch_easy_getinfo(FETCH *handle, FETCHINFO_COOKIELIST,
                           struct fetch_slist **cookies);
~~~

# DESCRIPTION

Pass a pointer to a 'struct fetch_slist *' to receive a linked-list of all
cookies fetch knows (expired ones, too). Do not forget to call
fetch_slist_free_all(3) on the list after it has been used. If there are no
cookies (cookies for the handle have not been enabled or simply none have been
received) the 'struct fetch_slist *' is made a NULL pointer.

Since 7.43.0 cookies that were imported in the Set-Cookie format without a
domain name are not exported by this option.

# %PROTOCOLS%

# EXAMPLE

~~~c
int main(void)
{
  FETCH *fetch = fetch_easy_init();
  if(fetch) {
    FETCHcode res;
    fetch_easy_setopt(fetch, FETCHOPT_URL, "https://example.com");

    /* enable the cookie engine */
    fetch_easy_setopt(fetch, FETCHOPT_COOKIEFILE, "");

    res = fetch_easy_perform(fetch);

    if(!res) {
      /* extract all known cookies */
      struct fetch_slist *cookies = NULL;
      res = fetch_easy_getinfo(fetch, FETCHINFO_COOKIELIST, &cookies);
      if(!res && cookies) {
        /* a linked list of cookies in cookie file format */
        struct fetch_slist *each = cookies;
        while(each) {
          printf("%s\n", each->data);
          each = each->next;
        }
        /* we must free these cookies when we are done */
        fetch_slist_free_all(cookies);
      }
    }
    fetch_easy_cleanup(fetch);
  }
}
~~~

# %AVAILABILITY%

# RETURN VALUE

fetch_easy_getinfo(3) returns a FETCHcode indicating success or error.

FETCHE_OK (0) means everything was OK, non-zero means an error occurred, see
libfetch-errors(3).
