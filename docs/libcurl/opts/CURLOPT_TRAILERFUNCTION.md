---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: fetch
Title: FETCHOPT_TRAILERFUNCTION
Section: 3
Source: libfetch
See-also:
  - FETCHOPT_TRAILERDATA (3)
  - FETCHOPT_WRITEFUNCTION (3)
Protocol:
  - HTTP
Added-in: 7.64.0
---

# NAME

FETCHOPT_TRAILERFUNCTION - callback for sending trailing headers

# SYNOPSIS

~~~c
#include <fetch.h>

int fetch_trailer_callback(struct fetch_slist ** list, void *userdata);

FETCHcode fetch_easy_setopt(FETCH *handle, FETCHOPT_TRAILERFUNCTION,
                          fetch_trailer_callback *func);
~~~

# DESCRIPTION

Pass a pointer to a callback function.

This callback function is called once right before sending the final CR LF in
an HTTP chunked transfer to fill a list of trailing headers to be sent before
finishing the HTTP transfer.

You can set the userdata argument with the FETCHOPT_TRAILERDATA(3)
option.

The trailing headers included in the linked list must not be CRLF-terminated,
because libfetch adds the appropriate line termination characters after each
header item.

If you use fetch_slist_append(3) to add trailing headers to the *fetch_slist*
then libfetch duplicates the strings, and frees the *fetch_slist* once the
trailers have been sent.

If one of the trailing header fields is not formatted correctly it is ignored
and an info message is emitted.

The return value can either be **FETCH_TRAILERFUNC_OK** or
**FETCH_TRAILERFUNC_ABORT** which would respectively instruct libfetch to
either continue with sending the trailers or to abort the request.

If you set this option to NULL, then the transfer proceeds as usual
without any interruptions.

# DEFAULT

NULL

# %PROTOCOLS%

# EXAMPLE
~~~c
static int trailer_cb(struct fetch_slist **tr, void *data)
{
  /* libfetch frees the list */
  *tr = fetch_slist_append(*tr, "My-super-awesome-trailer: trailer-stuff");
  return FETCH_TRAILERFUNC_OK;
}

int main(void)
{
  FETCH *fetch = fetch_easy_init();
  if(fetch) {
    FETCHcode res;

    /* Set the URL of the request */
    fetch_easy_setopt(fetch, FETCHOPT_URL, "https://example.com/");
    /* Now set it as a put */
    fetch_easy_setopt(fetch, FETCHOPT_UPLOAD, 1L);

    /* Assuming we have a function that returns the data to be pushed
       Let that function be read_cb */
    fetch_easy_setopt(fetch, FETCHOPT_READFUNCTION, trailer_cb);

    struct fetch_slist *headers = NULL;
    headers = fetch_slist_append(headers, "Trailer: My-super-awesome-trailer");
    res = fetch_easy_setopt(fetch, FETCHOPT_HTTPHEADER, headers);

    /* Set the trailers filling callback */
    fetch_easy_setopt(fetch, FETCHOPT_TRAILERFUNCTION, trailer_cb);

    /* Perform the transfer */
    res = fetch_easy_perform(fetch);

    fetch_easy_cleanup(fetch);

    fetch_slist_free_all(headers);
  }
}
~~~

# %AVAILABILITY%

# RETURN VALUE

fetch_easy_setopt(3) returns a FETCHcode indicating success or error.

FETCHE_OK (0) means everything was OK, non-zero means an error occurred, see
libfetch-errors(3).
