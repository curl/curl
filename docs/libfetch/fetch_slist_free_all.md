---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: fetch
Title: fetch_slist_free_all
Section: 3
Source: libfetch
See-also:
  - fetch_slist_append (3)
Protocol:
  - All
Added-in: 7.1
---

# NAME

fetch_slist_free_all - free an entire fetch_slist list

# SYNOPSIS

~~~c
#include <fetch/fetch.h>

void fetch_slist_free_all(struct fetch_slist *list);
~~~

# DESCRIPTION

fetch_slist_free_all() removes all traces of a previously built fetch_slist
linked list.

Passing in a NULL pointer in *list* makes this function return immediately
with no action.

Any use of the **list** after this function has been called and have returned,
is illegal.

# %PROTOCOLS%

# EXAMPLE

~~~c
int main(void)
{
  FETCH *handle;
  struct fetch_slist *slist = NULL;

  slist = fetch_slist_append(slist, "X-libfetch: coolness");

  if(!slist)
    return -1;

  fetch_easy_setopt(handle, FETCHOPT_HTTPHEADER, slist);

  fetch_easy_perform(handle);

  fetch_slist_free_all(slist); /* free the list again */
}
~~~

# %AVAILABILITY%

# RETURN VALUE

Nothing.
