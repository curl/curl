---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: fetch
Title: FETCHOPT_INTERFACE
Section: 3
Source: libfetch
Protocol:
  - All
See-also:
  - FETCHOPT_SOCKOPTFUNCTION (3)
  - FETCHOPT_TCP_NODELAY (3)
  - FETCHOPT_LOCALPORT (3)
Added-in: 7.3
---

# NAME

FETCHOPT_INTERFACE - source interface for outgoing traffic

# SYNOPSIS

~~~c
#include <fetch/fetch.h>

FETCHcode fetch_easy_setopt(FETCH *handle, FETCHOPT_INTERFACE, char *interface);
~~~

# DESCRIPTION

Pass a char pointer as parameter. This sets the *interface* name to use as
outgoing network interface. The name can be an interface name, an IP address,
or a hostname. If you prefer one of these, you can use the following special
prefixes:

* `if!\<name\>` - Interface name
* `host!\<name\>` - IP address or hostname
* `ifhost!\<interface\>!\<host\>` - Interface name and IP address or hostname

If `if!` or `ifhost!` is specified but the parameter does not match an existing
interface, *FETCHE_INTERFACE_FAILED* is returned from the libfetch function used
to perform the transfer.

libfetch does not support using network interface names for this option on
Windows.

We strongly advise against specifying the interface with a hostname, as it
causes libfetch to do a blocking name resolve call to retrieve the IP address.
That name resolve operation does **not** use DNS-over-HTTPS even if
FETCHOPT_DOH_URL(3) is set.

The application does not have to keep the string around after setting this
option.

Using this option multiple times makes the last set string override the
previous ones. Set it to NULL to disable its use again.

# DEFAULT

NULL, use whatever the TCP stack finds suitable

# %PROTOCOLS%

# EXAMPLE

~~~c
int main(void)
{
  FETCH *fetch = fetch_easy_init();
  if(fetch) {
    FETCHcode res;
    fetch_easy_setopt(fetch, FETCHOPT_URL, "https://example.com/foo.bin");

    fetch_easy_setopt(fetch, FETCHOPT_INTERFACE, "eth0");

    res = fetch_easy_perform(fetch);

    fetch_easy_cleanup(fetch);
  }
}
~~~

# HISTORY

The `if!` and `host!` syntax was added in 7.24.0.

The `ifhost!` syntax was added in 8.9.0.

# %AVAILABILITY%

# RETURN VALUE

fetch_easy_setopt(3) returns a FETCHcode indicating success or error.

FETCHE_OK (0) means everything was OK, non-zero means an error occurred, see
libfetch-errors(3).
