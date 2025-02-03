---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: fetch
Title: FETCHMOPT_PUSHDATA
Section: 3
Source: libfetch
See-also:
  - FETCHMOPT_PIPELINING (3)
  - FETCHMOPT_PUSHFUNCTION (3)
  - FETCHOPT_PIPEWAIT (3)
  - RFC 7540
Protocol:
  - HTTP
Added-in: 7.44.0
---

# NAME

FETCHMOPT_PUSHDATA - pointer to pass to push callback

# SYNOPSIS

~~~c
#include <fetch/fetch.h>

FETCHMcode fetch_multi_setopt(FETCHM *handle, FETCHMOPT_PUSHDATA, void *pointer);
~~~

# DESCRIPTION

Set a *pointer* to pass as the last argument to the
FETCHMOPT_PUSHFUNCTION(3) callback. The pointer is not touched or used by
libfetch itself, only passed on to the callback function.

# DEFAULT

NULL

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
