---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: fetch
Title: FETCHOPT_PROGRESSFUNCTION
Section: 3
Source: libfetch
See-also:
  - FETCHOPT_NOPROGRESS (3)
  - FETCHOPT_VERBOSE (3)
  - FETCHOPT_XFERINFOFUNCTION (3)
Protocol:
  - All
Added-in: 7.1
---

# NAME

FETCHOPT_PROGRESSFUNCTION - progress meter callback

# SYNOPSIS

~~~c
#include <fetch/fetch.h>

int progress_callback(void *clientp,
                      double dltotal,
                      double dlnow,
                      double ultotal,
                      double ulnow);

FETCHcode fetch_easy_setopt(FETCH *handle, FETCHOPT_PROGRESSFUNCTION,
                          progress_callback);
~~~

# DESCRIPTION

Pass a pointer to your callback function, which should match the prototype
shown above.

This option is deprecated and we encourage users to use the
newer FETCHOPT_XFERINFOFUNCTION(3) instead, if you can.

This function gets called by libfetch instead of its internal equivalent with a
frequent interval. While data is being transferred it is invoked frequently,
and during slow periods like when nothing is being transferred it can slow
down to about one call per second.

*clientp* is the pointer set with FETCHOPT_PROGRESSDATA(3), it is not
used by libfetch but is only passed along from the application to the callback.

The callback gets told how much data libfetch is about to transfer and has
transferred, in number of bytes. *dltotal* is the total number of bytes
libfetch expects to download in this transfer. *dlnow* is the number of
bytes downloaded so far. *ultotal* is the total number of bytes libfetch
expects to upload in this transfer. *ulnow* is the number of bytes
uploaded so far.

Unknown/unused argument values passed to the callback are be set to zero (like
if you only download data, the upload size remains 0). Many times the callback
is called one or more times first, before it knows the data sizes so a program
must be made to handle that.

Return zero from the callback if everything is fine.

If your callback function returns FETCH_PROGRESSFUNC_CONTINUE it causes libfetch
to continue executing the default progress function.

Return 1 from this callback to make libfetch abort the transfer and return
*FETCHE_ABORTED_BY_CALLBACK*.

If you transfer data with the multi interface, this function is not called
during periods of idleness unless you call the appropriate libfetch function
that performs transfers.

FETCHOPT_NOPROGRESS(3) must be set to 0 to make this function actually
get called.

# DEFAULT

NULL. libfetch has an internal progress meter. That is rarely wanted by users.

# %PROTOCOLS%

# EXAMPLE

~~~c
struct progress {
  char *private;
  size_t size;
};

static size_t progress_callback(void *clientp,
                                double dltotal,
                                double dlnow,
                                double ultotal,
                                double ulnow)
{
  struct progress *memory = clientp;
  printf("private: %p\n", memory->private);

  /* use the values */

  return 0; /* all is good */
}

int main(void)
{
  struct progress data;

  FETCH *fetch = fetch_easy_init();
  if(fetch) {
    /* pass struct to callback  */
    fetch_easy_setopt(fetch, FETCHOPT_PROGRESSDATA, &data);
    fetch_easy_setopt(fetch, FETCHOPT_PROGRESSFUNCTION, progress_callback);

    fetch_easy_perform(fetch);
  }
}
~~~

# DEPRECATED

Deprecated since 7.32.0.

# %AVAILABILITY%

# RETURN VALUE

fetch_easy_setopt(3) returns a FETCHcode indicating success or error.

FETCHE_OK (0) means everything was OK, non-zero means an error occurred, see
libfetch-errors(3).
