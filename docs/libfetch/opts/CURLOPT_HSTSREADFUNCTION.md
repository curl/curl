---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: fetch
Title: FETCHOPT_HSTSREADFUNCTION
Section: 3
Source: libfetch
Protocol:
  - HTTP
See-also:
  - FETCHOPT_HSTS (3)
  - FETCHOPT_HSTSREADDATA (3)
  - FETCHOPT_HSTSWRITEFUNCTION (3)
  - FETCHOPT_HSTS_CTRL (3)
Added-in: 7.74.0
---

# NAME

FETCHOPT_HSTSREADFUNCTION - read callback for HSTS hosts

# SYNOPSIS

~~~c
#include <fetch/fetch.h>

struct fetch_hstsentry {
  char *name;
  size_t namelen;
  unsigned int includeSubDomains:1;
  char expire[18]; /* YYYYMMDD HH:MM:SS [null-terminated] */
};

FETCHSTScode hstsread(FETCH *easy, struct fetch_hstsentry *sts, void *clientp);

FETCHcode fetch_easy_setopt(FETCH *handle, FETCHOPT_HSTSREADFUNCTION, hstsread);
~~~

# DESCRIPTION

Pass a pointer to your callback function, as the prototype shows above.

This callback function gets called by libfetch repeatedly when it populates the
in-memory HSTS cache.

Set the *clientp* argument with the FETCHOPT_HSTSREADDATA(3) option
or it is NULL.

When this callback is invoked, the *sts* pointer points to a populated
struct: Copy the hostname to *name* (no longer than *namelen*
bytes). Make it null-terminated. Set *includeSubDomains* to TRUE or
FALSE. Set *expire* to a date stamp or a zero length string for *forever*
(wrong date stamp format might cause the name to not get accepted)

The callback should return *FETCHSTS_OK* if it returns a name and is
prepared to be called again (for another host) or *FETCHSTS_DONE* if it has
no entry to return. It can also return *FETCHSTS_FAIL* to signal
error. Returning *FETCHSTS_FAIL* stops the transfer from being performed
and make *FETCHE_ABORTED_BY_CALLBACK* get returned.

This option does not enable HSTS, you need to use FETCHOPT_HSTS_CTRL(3) to
do that.

# DEFAULT

NULL - no callback.

# %PROTOCOLS%

# EXAMPLE

~~~c
struct priv {
  void *custom;
};

static FETCHSTScode hsts_cb(FETCH *easy, struct fetch_hstsentry *sts,
                           void *clientp)
{
  /* populate the struct as documented */
  return FETCHSTS_OK;
}

int main(void)
{
  FETCH *fetch = fetch_easy_init();
  if(fetch) {
    struct priv my_stuff;
    FETCHcode res;

    /* set HSTS read callback */
    fetch_easy_setopt(fetch, FETCHOPT_HSTSREADFUNCTION, hsts_cb);

    /* pass in suitable argument to the callback */
    fetch_easy_setopt(fetch, FETCHOPT_HSTSREADDATA, &my_stuff);

    res = fetch_easy_perform(fetch);
  }
}
~~~

# %AVAILABILITY%

# RETURN VALUE

This returns FETCHE_OK.
