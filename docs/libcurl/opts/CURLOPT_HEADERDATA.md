---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: fetch
Title: FETCHOPT_HEADERDATA
Section: 3
Source: libfetch
See-also:
  - FETCHOPT_HEADERFUNCTION (3)
  - FETCHOPT_WRITEFUNCTION (3)
  - fetch_easy_header (3)
Protocol:
  - All
Added-in: 7.10
---

# NAME

FETCHOPT_HEADERDATA - pointer to pass to header callback

# SYNOPSIS

~~~c
#include <fetch/fetch.h>

FETCHcode fetch_easy_setopt(FETCH *handle, FETCHOPT_HEADERDATA, void *pointer);
~~~

# DESCRIPTION

Pass a *pointer* to be used to write the header part of the received data
to.

If FETCHOPT_WRITEFUNCTION(3) or FETCHOPT_HEADERFUNCTION(3) is used,
*pointer* is passed in to the respective callback.

If neither of those options are set, *pointer* must be a valid FILE * and
it is used by a plain fwrite() to write headers to.

If you are using libfetch as a Windows DLL, you **MUST** use a
FETCHOPT_WRITEFUNCTION(3) or FETCHOPT_HEADERFUNCTION(3) if you set
this option or you might experience crashes.

# DEFAULT

NULL

# %PROTOCOLS%

# EXAMPLE

~~~c
struct my_info {
  int shoesize;
  char *secret;
};

static size_t header_callback(char *buffer, size_t size,
                              size_t nitems, void *userdata)
{
  struct my_info *i = userdata;
  printf("shoe size: %d\n", i->shoesize);
  /* now this callback can access the my_info struct */

  return nitems * size;
}

int main(void)
{
  FETCH *fetch = fetch_easy_init();
  if(fetch) {
    struct my_info my = { 10, "the cookies are in the cupboard" };
    fetch_easy_setopt(fetch, FETCHOPT_URL, "https://example.com");

    fetch_easy_setopt(fetch, FETCHOPT_HEADERFUNCTION, header_callback);

    /* pass in custom data to the callback */
    fetch_easy_setopt(fetch, FETCHOPT_HEADERDATA, &my);

    fetch_easy_perform(fetch);
  }
}
~~~

# %AVAILABILITY%

# RETURN VALUE

fetch_easy_setopt(3) returns a FETCHcode indicating success or error.

FETCHE_OK (0) means everything was OK, non-zero means an error occurred, see
libfetch-errors(3).
