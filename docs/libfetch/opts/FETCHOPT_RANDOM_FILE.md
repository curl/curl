---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: fetch
Title: FETCHOPT_RANDOM_FILE
Section: 3
Source: libfetch
See-also:
  - FETCHOPT_EGDSOCKET (3)
Protocol:
  - TLS
TLS-backend:
  - OpenSSL
Added-in: 7.7
---

# NAME

FETCHOPT_RANDOM_FILE - file to read random data from

# SYNOPSIS

~~~c
#include <fetch/fetch.h>

FETCHcode fetch_easy_setopt(FETCH *handle, FETCHOPT_RANDOM_FILE, char *path);
~~~

# DESCRIPTION

Deprecated option. It serves no purpose anymore.

# DEFAULT

NULL, not used

# DEPRECATED

Deprecated since 7.84.0.

# %AVAILABILITY%

# RETURN VALUE

fetch_easy_setopt(3) returns a FETCHcode indicating success or error.

FETCHE_OK (0) means everything was OK, non-zero means an error occurred, see
libfetch-errors(3).
