---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: fetch
Title: fetch_formget
Section: 3
Source: libfetch
See-also:
  - fetch_formadd (3)
  - fetch_mime_init (3)
Protocol:
  - HTTP
Added-in: 7.15.5
---

# NAME

fetch_formget - serialize a multipart form POST chain

# SYNOPSIS

~~~c
#include <fetch/fetch.h>

int fetch_formget(struct fetch_httppost * form, void *userp,
                 fetch_formget_callback append);
~~~

# DESCRIPTION

The form API (including this function) is deprecated since libfetch 7.56.0.

fetch_formget() serializes data previously built with fetch_formadd(3). It
accepts a void pointer as second argument named *userp* which is passed as the
first argument to the fetch_formget_callback function.

~~~c
 typedef size_t (*fetch_formget_callback)(void *userp, const char *buf,
                                         size_t len);"
~~~

The fetch_formget_callback is invoked for each part of the HTTP POST chain. The
character buffer passed to the callback must not be freed. The callback should
return the buffer length passed to it on success.

If the **FETCHFORM_STREAM** option is used in the formpost, it prevents
fetch_formget(3) from working until you have performed the actual HTTP request.
This, because first then does libfetch known which actual read callback to use.

# %PROTOCOLS%

# EXAMPLE

~~~c
size_t print_httppost_callback(void *arg, const char *buf, size_t len)
{
  fwrite(buf, len, 1, stdout);
  (*(size_t *) arg) += len;
  return len;
}

size_t print_httppost(struct fetch_httppost *post)
{
  size_t total_size = 0;
  if(fetch_formget(post, &total_size, print_httppost_callback)) {
    return (size_t) -1;
  }
  return total_size;
}
~~~

# %AVAILABILITY%

# RETURN VALUE

0 means everything was OK, non-zero means an error occurred
