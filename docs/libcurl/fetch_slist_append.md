---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: fetch
Title: fetch_slist_append
Section: 3
Source: libfetch
See-also:
  - fetch_slist_free_all (3)
Protocol:
  - All
Added-in: 7.1
---

# NAME

fetch_slist_append - add a string to an slist

# SYNOPSIS

~~~c
#include <fetch/fetch.h>

struct fetch_slist *fetch_slist_append(struct fetch_slist *list,
                                     const char *string);
~~~

# DESCRIPTION

fetch_slist_append(3) appends a string to a linked list of strings. The
existing **list** should be passed as the first argument and the new list is
returned from this function. Pass in NULL in the **list** argument to create
a new list. The specified **string** has been appended when this function
returns. fetch_slist_append(3) copies the string.

The list should be freed again (after usage) with
fetch_slist_free_all(3).

# %PROTOCOLS%

# EXAMPLE

~~~c
int main(void)
{
  FETCH *handle;
  struct fetch_slist *slist = NULL;
  struct fetch_slist *temp = NULL;

  slist = fetch_slist_append(slist, "pragma:");

  if(!slist)
    return -1;

  temp = fetch_slist_append(slist, "Accept:");

  if(!temp) {
    fetch_slist_free_all(slist);
    return -1;
  }

  slist = temp;

  fetch_easy_setopt(handle, FETCHOPT_HTTPHEADER, slist);

  fetch_easy_perform(handle);

  fetch_slist_free_all(slist); /* free the list again */
}
~~~

# %AVAILABILITY%

# RETURN VALUE

A null pointer is returned if anything went wrong, otherwise the new list
pointer is returned. To avoid overwriting an existing non-empty list on
failure, the new list should be returned to a temporary variable which can
be tested for NULL before updating the original list pointer.
