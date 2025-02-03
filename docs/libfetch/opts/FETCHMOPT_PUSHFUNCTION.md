---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: fetch
Title: FETCHMOPT_PUSHFUNCTION
Section: 3
Source: libfetch
See-also:
  - FETCHMOPT_PIPELINING (3)
  - FETCHMOPT_PUSHDATA (3)
  - FETCHOPT_PIPEWAIT (3)
  - RFC 7540
Protocol:
  - HTTP
Added-in: 7.44.0
---

# NAME

FETCHMOPT_PUSHFUNCTION - callback that approves or denies server pushes

# SYNOPSIS

~~~c
#include <fetch/fetch.h>

int fetch_push_callback(FETCH *parent,
                       FETCH *easy,
                       size_t num_headers,
                       struct fetch_pushheaders *headers,
                       void *clientp);

FETCHMcode fetch_multi_setopt(FETCHM *handle, FETCHMOPT_PUSHFUNCTION,
                            fetch_push_callback func);
~~~

# DESCRIPTION

This callback gets called when a new HTTP/2 stream is being pushed by the
server (using the PUSH_PROMISE frame). If no push callback is set, all offered
pushes are denied automatically.

# CALLBACK DESCRIPTION

The callback gets its arguments like this:

*parent* is the handle of the stream on which this push arrives. The new
handle has been duplicated from the parent, meaning that it has gotten all its
options inherited. It is then up to the application to alter any options if
desired.

*easy* is a newly created handle that represents this upcoming transfer.

*num_headers* is the number of name+value pairs that was received and can
be accessed

*headers* is a handle used to access push headers using the accessor
functions described below. This only accesses and provides the PUSH_PROMISE
headers, the normal response headers are provided in the header callback as
usual.

*clientp* is the pointer set with FETCHMOPT_PUSHDATA(3)

If the callback returns FETCH_PUSH_OK, the new easy handle is added to the
multi handle, the callback must not do that by itself.

The callback can access PUSH_PROMISE headers with two accessor
functions. These functions can only be used from within this callback and they
can only access the PUSH_PROMISE headers: fetch_pushheader_byname(3) and
fetch_pushheader_bynum(3). The normal response headers are passed to the
header callback for pushed streams just as for normal streams.

The header fields can also be accessed with fetch_easy_header(3),
introduced in later libfetch versions.

# CALLBACK RETURN VALUE

## FETCH_PUSH_OK (0)

The application has accepted the stream and it can now start receiving data,
the ownership of the fetch handle has been taken over by the application.

## FETCH_PUSH_DENY (1)

The callback denies the stream and no data reaches the application, the easy
handle is destroyed by libfetch.

## FETCH_PUSH_ERROROUT (2)

Returning this code rejects the pushed stream and returns an error back on the
parent stream making it get closed with an error. (Added in 7.72.0)

## *

All other return codes are reserved for future use.

# DEFAULT

NULL, no callback

# %PROTOCOLS%

# EXAMPLE

~~~c
#include <string.h>

/* only allow pushes for filenames starting with "push-" */
int push_callback(FETCH *parent,
                  FETCH *easy,
                  size_t num_headers,
                  struct fetch_pushheaders *headers,
                  void *clientp)
{
  char *headp;
  int *transfers = (int *)clientp;
  FILE *out;
  headp = fetch_pushheader_byname(headers, ":path");
  if(headp && !strncmp(headp, "/push-", 6)) {
    fprintf(stderr, "The PATH is %s\n", headp);

    /* save the push here */
    out = fopen("pushed-stream", "wb");

    /* write to this file */
    fetch_easy_setopt(easy, FETCHOPT_WRITEDATA, out);

    (*transfers)++; /* one more */

    return FETCH_PUSH_OK;
  }
  return FETCH_PUSH_DENY;
}

int main(void)
{
  int counter;
  FETCHM *multi = fetch_multi_init();
  fetch_multi_setopt(multi, FETCHMOPT_PUSHFUNCTION, push_callback);
  fetch_multi_setopt(multi, FETCHMOPT_PUSHDATA, &counter);
}
~~~

# %AVAILABILITY%

# RETURN VALUE

fetch_multi_setopt(3) returns a FETCHMcode indicating success or error.

FETCHM_OK (0) means everything was OK, non-zero means an error occurred, see
libfetch-errors(3).
