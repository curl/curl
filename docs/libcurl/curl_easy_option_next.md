---
c: Copyright (C) Daniel Stenberg, <daniel.se>, et al.
SPDX-License-Identifier: curl
Title: curl_easy_option_next
Section: 3
Source: libcurl
See-also:
  - curl_easy_option_by_id (3)
  - curl_easy_option_by_name (3)
  - curl_easy_setopt (3)
---

# NAME

curl_easy_option_next - iterate over easy setopt options

# SYNOPSIS

~~~c
#include <curl/curl.h>

const struct curl_easyoption *
curl_easy_option_next(const struct curl_easyoption *prev);
~~~

# DESCRIPTION

This function returns a pointer to the first or the next *curl_easyoption*
struct, providing an ability to iterate over all known options for
curl_easy_setopt(3) in this instance of libcurl.

Pass a **NULL** argument as **prev** to get the first option returned, or
pass in the current option to get the next one returned. If there is no more
option to return, curl_easy_option_next(3) returns NULL.

The options returned by this functions are the ones known to this libcurl and
information about what argument type they want.

If the **CURLOT_FLAG_ALIAS** bit is set in the flags field, it means the
name is provided for backwards compatibility as an alias.

# struct

~~~c
typedef enum {
  CURLOT_LONG,    /* long (a range of values) */
  CURLOT_VALUES,  /*      (a defined set or bitmask) */
  CURLOT_OFF_T,   /* curl_off_t (a range of values) */
  CURLOT_OBJECT,  /* pointer (void *) */
  CURLOT_STRING,  /*         (char * to null-terminated buffer) */
  CURLOT_SLIST,   /*         (struct curl_slist *) */
  CURLOT_CBPTR,   /*         (void * passed as-is to a callback) */
  CURLOT_BLOB,    /* blob (struct curl_blob *) */
  CURLOT_FUNCTION /* function pointer */
} curl_easytype;

/* The CURLOPTTYPE_* id ranges can still be used to figure out what type/size
   to use for curl_easy_setopt() for the given id */
struct curl_easyoption {
  const char *name;
  CURLoption id;
  curl_easytype type;
  unsigned int flags;
};
~~~

# EXAMPLE

~~~c
int main(void)
{
  /* iterate over all available options */
  const struct curl_easyoption *opt;
  opt = curl_easy_option_next(NULL);
  while(opt) {
    printf("Name: %s\n", opt->name);
    opt = curl_easy_option_next(opt);
  }
}
~~~

# AVAILABILITY

This function was added in libcurl 7.73.0

# RETURN VALUE

A pointer to the *curl_easyoption* struct for the next option or NULL if
no more options.
