---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: fetch
Title: FETCHOPT_HSTSWRITEFUNCTION
Section: 3
Source: libfetch
Protocol:
  - HTTP
See-also:
  - FETCHOPT_HSTS (3)
  - FETCHOPT_HSTSWRITEDATA (3)
  - FETCHOPT_HSTSWRITEFUNCTION (3)
  - FETCHOPT_HSTS_CTRL (3)
Added-in: 7.74.0
---

# NAME

FETCHOPT_HSTSWRITEFUNCTION - write callback for HSTS hosts

# SYNOPSIS

~~~c
#include <fetch/fetch.h>

struct fetch_hstsentry {
  char *name;
  size_t namelen;
  unsigned int includeSubDomains:1;
  char expire[18]; /* YYYYMMDD HH:MM:SS [null-terminated] */
};

struct fetch_index {
  size_t index; /* the provided entry's "index" or count */
  size_t total; /* total number of entries to save */
};

FETCHSTScode hstswrite(FETCH *easy, struct fetch_hstsentry *sts,
                      struct fetch_index *count, void *clientp);

FETCHcode fetch_easy_setopt(FETCH *handle, FETCHOPT_HSTSWRITEFUNCTION, hstswrite);
~~~

# DESCRIPTION

Pass a pointer to your callback function, as the prototype shows above.

This callback function gets called by libfetch repeatedly to allow the
application to store the in-memory HSTS cache when libfetch is about to discard
it.

Set the *clientp* argument with the FETCHOPT_HSTSWRITEDATA(3) option
or it is NULL.
When the callback is invoked, the *sts* pointer points to a populated
struct: Read the hostname to 'name' (it is *namelen* bytes long and null
terminated. The *includeSubDomains* field is non-zero if the entry matches
subdomains. The *expire* string is a date stamp null-terminated string
using the syntax YYYYMMDD HH:MM:SS.

The callback should return *FETCHSTS_OK* if it succeeded and is prepared to
be called again (for another host) or *FETCHSTS_DONE* if there is nothing
more to do. It can also return *FETCHSTS_FAIL* to signal error.

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

static FETCHSTScode hswr_cb(FETCH *easy, struct fetch_hstsentry *sts,
                           struct fetch_index *count, void *clientp)
{
  /* save the passed in HSTS data somewhere */
  return FETCHSTS_OK;
}

int main(void)
{
  FETCH *fetch = fetch_easy_init();
  if(fetch) {
    struct priv my_stuff;
    FETCHcode res;

    /* set HSTS read callback */
    fetch_easy_setopt(fetch, FETCHOPT_HSTSWRITEFUNCTION, hswr_cb);

    /* pass in suitable argument to the callback */
    fetch_easy_setopt(fetch, FETCHOPT_HSTSWRITEDATA, &my_stuff);

    res = fetch_easy_perform(fetch);
  }
}
~~~

# %AVAILABILITY%

# RETURN VALUE

This returns FETCHE_OK.
