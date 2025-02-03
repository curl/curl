---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: fetch
Title: fetch_easy_option_next
Section: 3
Source: libfetch
See-also:
  - fetch_easy_option_by_id (3)
  - fetch_easy_option_by_name (3)
  - fetch_easy_setopt (3)
Protocol:
  - All
Added-in: 7.73.0
---

# NAME

fetch_easy_option_next - iterate over easy setopt options

# SYNOPSIS

~~~c
#include <fetch/fetch.h>

const struct fetch_easyoption *
fetch_easy_option_next(const struct fetch_easyoption *prev);
~~~

# DESCRIPTION

This function returns a pointer to the first or the next *fetch_easyoption*
struct, providing an ability to iterate over all known options for
fetch_easy_setopt(3) in this instance of libfetch.

Pass a **NULL** argument as **prev** to get the first option returned, or
pass in the current option to get the next one returned. If there is no more
option to return, fetch_easy_option_next(3) returns NULL.

The options returned by this functions are the ones known to this libfetch and
information about what argument type they want.

If the **FETCHOT_FLAG_ALIAS** bit is set in the flags field, it means the
name is provided for backwards compatibility as an alias.

# struct

~~~c
typedef enum {
  FETCHOT_LONG,    /* long (a range of values) */
  FETCHOT_VALUES,  /*      (a defined set or bitmask) */
  FETCHOT_OFF_T,   /* fetch_off_t (a range of values) */
  FETCHOT_OBJECT,  /* pointer (void *) */
  FETCHOT_STRING,  /*         (char * to null-terminated buffer) */
  FETCHOT_SLIST,   /*         (struct fetch_slist *) */
  FETCHOT_CBPTR,   /*         (void * passed as-is to a callback) */
  FETCHOT_BLOB,    /* blob (struct fetch_blob *) */
  FETCHOT_FUNCTION /* function pointer */
} fetch_easytype;

/* The FETCHOPTTYPE_* id ranges can still be used to figure out what type/size
   to use for fetch_easy_setopt() for the given id */
struct fetch_easyoption {
  const char *name;
  FETCHoption id;
  fetch_easytype type;
  unsigned int flags;
};
~~~

# %PROTOCOLS%

# EXAMPLE

~~~c
int main(void)
{
  /* iterate over all available options */
  const struct fetch_easyoption *opt;
  opt = fetch_easy_option_next(NULL);
  while(opt) {
    printf("Name: %s\n", opt->name);
    opt = fetch_easy_option_next(opt);
  }
}
~~~

# %AVAILABILITY%

# RETURN VALUE

A pointer to the *fetch_easyoption* struct for the next option or NULL if
no more options.
