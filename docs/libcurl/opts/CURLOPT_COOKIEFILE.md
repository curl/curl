---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: fetch
Title: FETCHOPT_COOKIEFILE
Section: 3
Source: libfetch
See-also:
  - FETCHOPT_COOKIE (3)
  - FETCHOPT_COOKIEJAR (3)
  - FETCHOPT_COOKIESESSION (3)
Protocol:
  - HTTP
Added-in: 7.1
---

# NAME

FETCHOPT_COOKIEFILE - filename to read cookies from

# SYNOPSIS

```c
#include <fetch/fetch.h>

FETCHcode fetch_easy_setopt(FETCH *handle, FETCHOPT_COOKIEFILE, char *filename);
```

# DESCRIPTION

Pass a pointer to a null-terminated string as parameter. It should point to
the filename of your file holding cookie data to read. The cookie data can be
in either the old Netscape / Mozilla cookie data format or just regular HTTP
headers (Set-Cookie style) dumped to a file.

It also enables the cookie engine, making libfetch parse and send cookies on
subsequent requests with this handle.

By passing the empty string ("") to this option, you enable the cookie engine
without reading any initial cookies. If you tell libfetch the filename is "-"
(just a single minus sign), libfetch instead reads from stdin.

This option only **reads** cookies. To make libfetch write cookies to file,
see FETCHOPT_COOKIEJAR(3).

If you read cookies from a plain HTTP headers file and it does not specify a
domain in the Set-Cookie line, then the cookie is not sent since the cookie
domain cannot match the target URL's. To address this, set a domain in
Set-Cookie line (doing that includes subdomains) or preferably: use the
Netscape format.

The application does not have to keep the string around after setting this
option.

If you use this option multiple times, you add more files to read cookies
from. Setting this option to NULL disables the cookie engine and clears the
list of files to read cookies from.

# SECURITY CONCERNS

This document previously mentioned how specifying a non-existing file can also
enable the cookie engine. While true, we strongly advise against using that
method as it is too hard to be sure that files that stay that way in the long
run.

# DEFAULT

NULL

# %PROTOCOLS%

# EXAMPLE

```c
int main(void)
{
  FETCH *fetch = fetch_easy_init();
  if(fetch) {
    FETCHcode res;
    fetch_easy_setopt(fetch, FETCHOPT_URL, "https://example.com/foo.bin");

    /* get cookies from an existing file */
    fetch_easy_setopt(fetch, FETCHOPT_COOKIEFILE, "/tmp/cookies.txt");

    res = fetch_easy_perform(fetch);

    fetch_easy_cleanup(fetch);
  }
}
```

# Cookie file format

The cookie file format and general cookie concepts in fetch are described
online here: https://curl.se/docs/http-cookies.html

# %AVAILABILITY%

# RETURN VALUE

fetch_easy_setopt(3) returns a FETCHcode indicating success or error.

FETCHE_OK (0) means everything was OK, non-zero means an error occurred, see
libfetch-errors(3).
