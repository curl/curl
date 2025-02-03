---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: fetch
Title: FETCHOPT_PREREQDATA
Section: 3
Source: libfetch
See-also:
  - FETCHINFO_PRIMARY_IP (3)
  - FETCHINFO_PRIMARY_PORT (3)
  - FETCHOPT_PREREQFUNCTION (3)
Protocol:
  - All
Added-in: 7.80.0
---

# NAME

FETCHOPT_PREREQDATA - pointer passed to the pre-request callback

# SYNOPSIS

~~~c
#include <fetch/fetch.h>

FETCHcode fetch_easy_setopt(FETCH *handle, FETCHOPT_PREREQDATA, void *pointer);
~~~

# DESCRIPTION

Pass a *pointer* that is untouched by libfetch and passed as the first
argument in the pre-request callback set with FETCHOPT_PREREQFUNCTION(3).

# DEFAULT

NULL

# %PROTOCOLS%

# EXAMPLE

~~~c
struct priv {
  void *custom;
};

static int prereq_callback(void *clientp,
                           char *conn_primary_ip,
                           char *conn_local_ip,
                           int conn_primary_port,
                           int conn_local_port)
{
  printf("Connection made to %s:%d\n", conn_primary_ip, conn_primary_port);
  return FETCH_PREREQFUNC_OK;
}

int main(void)
{
  struct priv prereq_data;
  FETCH *fetch = fetch_easy_init();
  if(fetch) {
    fetch_easy_setopt(fetch, FETCHOPT_PREREQFUNCTION, prereq_callback);
    fetch_easy_setopt(fetch, FETCHOPT_PREREQDATA, &prereq_data);
    fetch_easy_perform(fetch);
  }
}
~~~

# %AVAILABILITY%

# RETURN VALUE

fetch_easy_setopt(3) returns a FETCHcode indicating success or error.

FETCHE_OK (0) means everything was OK, non-zero means an error occurred, see
libfetch-errors(3).
