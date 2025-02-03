---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: fetch
Title: FETCHOPT_GSSAPI_DELEGATION
Section: 3
Source: libfetch
Protocol:
  - HTTP
See-also:
  - FETCHOPT_HTTPAUTH (3)
  - FETCHOPT_PROXYAUTH (3)
Added-in: 7.22.0
---

# NAME

FETCHOPT_GSSAPI_DELEGATION - allowed GSS-API delegation

# SYNOPSIS

~~~c
#include <fetch/fetch.h>

FETCHcode fetch_easy_setopt(FETCH *handle, FETCHOPT_GSSAPI_DELEGATION, long level);
~~~

# DESCRIPTION

Set the long parameter *level* to **FETCHGSSAPI_DELEGATION_FLAG** to allow
unconditional GSSAPI credential delegation. The delegation is disabled by
default since 7.21.7. Set the parameter to
**FETCHGSSAPI_DELEGATION_POLICY_FLAG** to delegate only if the OK-AS-DELEGATE
flag is set in the service ticket in case this feature is supported by the
GSS-API implementation and the definition of *GSS_C_DELEG_POLICY_FLAG* was
available at compile-time.

# DEFAULT

FETCHGSSAPI_DELEGATION_NONE

# %PROTOCOLS%

# EXAMPLE

~~~c
int main(void)
{
  FETCH *fetch = fetch_easy_init();
  if(fetch) {
    FETCHcode ret;
    fetch_easy_setopt(fetch, FETCHOPT_URL, "https://example.com/");
    /* delegate if okayed by policy */
    fetch_easy_setopt(fetch, FETCHOPT_GSSAPI_DELEGATION,
                     (long)FETCHGSSAPI_DELEGATION_POLICY_FLAG);
    ret = fetch_easy_perform(fetch);
  }
}
~~~

# %AVAILABILITY%

# RETURN VALUE

fetch_easy_setopt(3) returns a FETCHcode indicating success or error.

FETCHE_OK (0) means everything was OK, non-zero means an error occurred, see
libfetch-errors(3).
