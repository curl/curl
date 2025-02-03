---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: fetch
Title: fetch_pushheader_bynum
Section: 3
Source: libfetch
See-also:
  - FETCHMOPT_PUSHFUNCTION (3)
  - fetch_pushheader_byname (3)
Protocol:
  - HTTP
Added-in: 7.44.0
---

# NAME

fetch_pushheader_bynum - get a push header by index

# SYNOPSIS

~~~c
#include <fetch/fetch.h>

char *fetch_pushheader_bynum(struct fetch_pushheaders *h, size_t num);
~~~

# DESCRIPTION

This is a function that is only functional within a
FETCHMOPT_PUSHFUNCTION(3) callback. It makes no sense to try to use it
elsewhere and it has no function then.

It returns the value for the header field at the given index **num**, for
the incoming server push request or NULL. The data pointed to is freed by
libfetch when this callback returns. The returned pointer points to a
"name:value" string that gets freed when this callback returns.

# %PROTOCOLS%

# EXAMPLE

~~~c
/* output all the incoming push request headers */
static int push_cb(FETCH *parent,
                   FETCH *easy,
                   size_t num_headers,
                   struct fetch_pushheaders *headers,
                   void *clientp)
{
  int i = 0;
  char *field;
  do {
     field = fetch_pushheader_bynum(headers, i);
     if(field)
       fprintf(stderr, "Push header: %s\n", field);
     i++;
  } while(field);
  return FETCH_PUSH_OK; /* permission granted */
}

int main(void)
{
  FETCHM *multi = fetch_multi_init();
  fetch_multi_setopt(multi, FETCHMOPT_PUSHFUNCTION, push_cb);
}
~~~

# %AVAILABILITY%

# RETURN VALUE

Returns a pointer to the header field content or NULL.
