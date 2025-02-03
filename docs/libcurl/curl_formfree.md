---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: fetch
Title: fetch_formfree
Section: 3
Source: libfetch
See-also:
  - fetch_formadd (3)
  - fetch_mime_free (3)
  - fetch_mime_init (3)
Protocol:
  - HTTP
Added-in: 7.1
---

# NAME

fetch_formfree - free a previously build multipart form post chain

# SYNOPSIS

~~~c
#include <fetch/fetch.h>

void fetch_formfree(struct fetch_httppost *form);
~~~

# DESCRIPTION

This function is deprecated. Do not use. See fetch_mime_init(3) instead.

fetch_formfree() is used to clean up data previously built/appended with
fetch_formadd(3). This must be called when the data has been used, which
typically means after fetch_easy_perform(3) has been called.

The pointer to free is the same pointer you passed to the
FETCHOPT_HTTPPOST(3) option, which is the *firstitem* pointer from
the fetch_formadd(3) invoke(s).

**form** is the pointer as returned from a previous call to
fetch_formadd(3) and may be NULL.

Passing in a NULL pointer in *form* makes this function return immediately
with no action.

# %PROTOCOLS%

# EXAMPLE

~~~c
int main(void)
{
  FETCH *fetch = fetch_easy_init();
  if(fetch) {
    struct fetch_httppost *formpost;
    struct fetch_httppost *lastptr;

    /* Fill in a file upload field */
    fetch_formadd(&formpost,
                 &lastptr,
                 FETCHFORM_COPYNAME, "file",
                 FETCHFORM_FILE, "nice-image.jpg",
                 FETCHFORM_END);

    fetch_easy_setopt(fetch, FETCHOPT_HTTPPOST, formpost);

    fetch_easy_perform(fetch);

    /* then cleanup the formpost chain */
    fetch_formfree(formpost);
  }
}
~~~

# DEPRECATED

Deprecated in 7.56.0.

# %AVAILABILITY%

# RETURN VALUE

None
