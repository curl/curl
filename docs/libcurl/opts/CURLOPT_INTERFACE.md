---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Title: CURLOPT_INTERFACE
Section: 3
Source: libcurl
Protocol:
  - All
See-also:
  - CURLOPT_SOCKOPTFUNCTION (3)
  - CURLOPT_TCP_NODELAY (3)
  - CURLOPT_LOCALPORT (3)
Added-in: 7.3
---

# NAME

CURLOPT_INTERFACE - source interface for outgoing traffic

# SYNOPSIS

~~~c
#include <curl/curl.h>

CURLcode curl_easy_setopt(CURL *handle, CURLOPT_INTERFACE, char *interface);
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
interface, *CURLE_INTERFACE_FAILED* is returned from the libcurl function used
to perform the transfer.

libcurl does not support using network interface names for this option on
Windows.

We strongly advise against specifying the interface with a hostname, as it
causes libcurl to do a blocking name resolve call to retrieve the IP address.
That name resolve operation does **not** use DNS-over-HTTPS even if
CURLOPT_DOH_URL(3) is set.

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
  CURL *curl = curl_easy_init();
  if(curl) {
    CURLcode res;
    curl_easy_setopt(curl, CURLOPT_URL, "https://example.com/foo.bin");

    curl_easy_setopt(curl, CURLOPT_INTERFACE, "eth0");

    res = curl_easy_perform(curl);

    curl_easy_cleanup(curl);
  }
}
~~~

# HISTORY

The `if!` and `host!` syntax was added in 7.24.0.

The `ifhost!` syntax was added in 8.9.0.

# %AVAILABILITY%

# RETURN VALUE

curl_easy_setopt(3) returns a CURLcode indicating success or error.

CURLE_OK (0) means everything was OK, non-zero means an error occurred, see
libcurl-errors(3).
