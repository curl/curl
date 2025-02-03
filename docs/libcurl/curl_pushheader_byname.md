---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: fetch
Title: fetch_pushheader_byname
Section: 3
Source: libfetch
See-also:
  - FETCHMOPT_PUSHFUNCTION (3)
  - fetch_pushheader_bynum (3)
Protocol:
  - HTTP
Added-in: 7.44.0
---

# NAME

fetch_pushheader_byname - get a push header by name

# SYNOPSIS

~~~c
#include <fetch/fetch.h>

char *fetch_pushheader_byname(struct fetch_pushheaders *h, const char *name);
~~~

# DESCRIPTION

This is a function that is only functional within a
FETCHMOPT_PUSHFUNCTION(3) callback. It makes no sense to try to use it
elsewhere and it has no function then.

It returns the value for the given header field name (or NULL) for the
incoming server push request. This is a shortcut so that the application does
not have to loop through all headers to find the one it is interested in. The
data this function points to is freed when this callback returns. If more than
one header field use the same name, this returns only the first one.

# %PROTOCOLS%

# EXAMPLE

~~~c
#include <string.h> /* for strncmp */

static int push_cb(FETCH *parent,
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
  fetch_multi_setopt(multi, FETCHMOPT_PUSHFUNCTION, push_cb);
  fetch_multi_setopt(multi, FETCHMOPT_PUSHDATA, &counter);
}
~~~

# %AVAILABILITY%

# RETURN VALUE

Returns a pointer to the header field content or NULL.
