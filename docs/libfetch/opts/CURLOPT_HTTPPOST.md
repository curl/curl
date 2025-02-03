---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: fetch
Title: FETCHOPT_HTTPPOST
Section: 3
Source: libfetch
Protocol:
  - HTTP
See-also:
  - FETCHOPT_MIMEPOST (3)
  - FETCHOPT_POST (3)
  - FETCHOPT_POSTFIELDS (3)
  - fetch_formadd (3)
  - fetch_formfree (3)
  - fetch_mime_init (3)
Added-in: 7.1
---

# NAME

FETCHOPT_HTTPPOST - multipart formpost content

# SYNOPSIS

~~~c
#include <fetch/fetch.h>

FETCHcode fetch_easy_setopt(FETCH *handle, FETCHOPT_HTTPPOST,
                          struct fetch_httppost *formpost);
~~~

# DESCRIPTION

**This option is deprecated.** Use FETCHOPT_MIMEPOST(3) instead.

Tells libfetch you want a **multipart/formdata** HTTP POST to be made and you
instruct what data to pass on to the server in the *formpost* argument.
Pass a pointer to a linked list of *fetch_httppost* structs as parameter.
The easiest way to create such a list, is to use fetch_formadd(3) as
documented. The data in this list must remain intact as long as the fetch
transfer is alive and is using it.

Using POST with HTTP 1.1 implies the use of a "Expect: 100-continue" header.
You can disable this header with FETCHOPT_HTTPHEADER(3).

When setting FETCHOPT_HTTPPOST(3), libfetch automatically sets
FETCHOPT_NOBODY(3) to 0.

# DEFAULT

NULL

# %PROTOCOLS%

# EXAMPLE

~~~c
int main(void)
{
  struct fetch_httppost *formpost;
  struct fetch_httppost *lastptr;

  /* Fill in the file upload field. This makes libfetch load data from
     the given file name when fetch_easy_perform() is called. */
  fetch_formadd(&formpost,
               &lastptr,
               FETCHFORM_COPYNAME, "sendfile",
               FETCHFORM_FILE, "postit2.c",
               FETCHFORM_END);

  /* Fill in the filename field */
  fetch_formadd(&formpost,
               &lastptr,
               FETCHFORM_COPYNAME, "filename",
               FETCHFORM_COPYCONTENTS, "postit2.c",
               FETCHFORM_END);

  /* Fill in the submit field too, even if this is rarely needed */
  fetch_formadd(&formpost,
               &lastptr,
               FETCHFORM_COPYNAME, "submit",
               FETCHFORM_COPYCONTENTS, "send",
               FETCHFORM_END);

  FETCH *fetch = fetch_easy_init();
  if(fetch) {
    fetch_easy_setopt(fetch, FETCHOPT_HTTPPOST, formpost);
    fetch_easy_perform(fetch);
    fetch_easy_cleanup(fetch);
  }
  fetch_formfree(formpost);
}
~~~

# DEPRECATED

Deprecated in 7.56.0.

# %AVAILABILITY%

# RETURN VALUE

fetch_easy_setopt(3) returns a FETCHcode indicating success or error.

FETCHE_OK (0) means everything was OK, non-zero means an error occurred, see
libfetch-errors(3).
