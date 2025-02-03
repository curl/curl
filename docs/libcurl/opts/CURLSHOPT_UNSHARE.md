---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: fetch
Title: FETCHSHOPT_UNSHARE
Section: 3
Source: libfetch
See-also:
  - FETCHSHOPT_SHARE (3)
  - fetch_share_cleanup (3)
  - fetch_share_init (3)
  - fetch_share_setopt (3)
Protocol:
  - All
Added-in: 7.10.3
---

# NAME

FETCHSHOPT_UNSHARE - remove data to share

# SYNOPSIS

~~~c
#include <fetch/fetch.h>

FETCHSHcode fetch_share_setopt(FETCHSH *share, FETCHSHOPT_UNSHARE, long type);
~~~

# DESCRIPTION

The *type* parameter specifies what specific data that should no longer be
shared and kept in the share object that was created with
fetch_share_init(3). In other words, stop sharing that data in this
shared object. The given *type* must be one of the values described
below. You can set FETCHSHOPT_UNSHARE(3) multiple times with different
data arguments to remove multiple types from the shared object. Add data to
share again with FETCHSHOPT_SHARE(3).

## FETCH_LOCK_DATA_COOKIE

Cookie data is no longer shared across the easy handles using this shared
object.

## FETCH_LOCK_DATA_DNS

Cached DNS hosts are no longer shared across the easy handles using this
shared object.

## FETCH_LOCK_DATA_SSL_SESSION

SSL session IDs are no longer shared across the easy handles using this shared
object.

## FETCH_LOCK_DATA_CONNECT

The connection cache is no longer shared.

## FETCH_LOCK_DATA_PSL

The Public Suffix List is no longer shared.

# %PROTOCOLS%

# EXAMPLE

~~~c
int main(void)
{
  FETCHSHcode sh;
  FETCHSH *share = fetch_share_init();
  sh = fetch_share_setopt(share, FETCHSHOPT_UNSHARE, FETCH_LOCK_DATA_COOKIE);
  if(sh)
    printf("Error: %s\n", fetch_share_strerror(sh));
}
~~~

# %AVAILABILITY%

# RETURN VALUE

FETCHSHE_OK (zero) means that the option was set properly, non-zero means an
error occurred. See libfetch-errors(3) for the full list with
descriptions.
