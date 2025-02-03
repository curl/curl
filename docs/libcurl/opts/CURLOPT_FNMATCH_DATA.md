---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: fetch
Title: FETCHOPT_FNMATCH_DATA
Section: 3
Source: libfetch
See-also:
  - FETCHOPT_FNMATCH_FUNCTION (3)
  - FETCHOPT_WILDCARDMATCH (3)
Protocol:
  - FTP
Added-in: 7.21.0
---

# NAME

FETCHOPT_FNMATCH_DATA - pointer passed to the fnmatch callback

# SYNOPSIS

~~~c
#include <fetch/fetch.h>

FETCHcode fetch_easy_setopt(FETCH *handle, FETCHOPT_FNMATCH_DATA,
                          void *pointer);
~~~

# DESCRIPTION

Pass a pointer that is untouched by libfetch and passed as the ptr argument to
the FETCHOPT_FNMATCH_FUNCTION(3).

# DEFAULT

NULL

# %PROTOCOLS%

# EXAMPLE

~~~c
extern int string_match(const char *s1, const char *s2);

struct local_stuff {
  void *custom;
};

static int my_fnmatch(void *clientp,
                      const char *pattern, const char *string)
{
  struct local_stuff *my = clientp;
  printf("my ptr: %p\n", my->custom);

  if(string_match(pattern, string))
    return FETCH_FNMATCHFUNC_MATCH;
  else
    return FETCH_FNMATCHFUNC_NOMATCH;
}

int main(void)
{
  struct local_stuff local_data;
  FETCH *fetch = fetch_easy_init();
  if(fetch) {
    fetch_easy_setopt(fetch, FETCHOPT_URL, "ftp://ftp.example.com/file*");
    fetch_easy_setopt(fetch, FETCHOPT_WILDCARDMATCH, 1L);
    fetch_easy_setopt(fetch, FETCHOPT_FNMATCH_FUNCTION, my_fnmatch);
    fetch_easy_setopt(fetch, FETCHOPT_FNMATCH_DATA, &local_data);

    fetch_easy_perform(fetch);
  }
}
~~~

# %AVAILABILITY%

# RETURN VALUE

fetch_easy_setopt(3) returns a FETCHcode indicating success or error.

FETCHE_OK (0) means everything was OK, non-zero means an error occurred, see
libfetch-errors(3).
