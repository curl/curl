---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: fetch
Title: FETCHOPT_COOKIELIST
Section: 3
Source: libfetch
See-also:
  - FETCHINFO_COOKIELIST (3)
  - FETCHOPT_COOKIE (3)
  - FETCHOPT_COOKIEFILE (3)
  - FETCHOPT_COOKIEJAR (3)
Protocol:
  - HTTP
Added-in: 7.14.1
---

# NAME

FETCHOPT_COOKIELIST - add to or manipulate cookies held in memory

# SYNOPSIS

~~~c
#include <fetch/fetch.h>

FETCHcode fetch_easy_setopt(FETCH *handle, FETCHOPT_COOKIELIST,
                          char *cookie);
~~~

# DESCRIPTION

Pass a char pointer to a *cookie* string.

Such a cookie can be either a single line in Netscape / Mozilla format or just
regular HTTP-style header (`Set-Cookie:`) format. This option also enables the
cookie engine. This adds that single cookie to the internal cookie store.

We strongly advice against loading cookies from an HTTP header file, as that
is an inferior data exchange format.

Exercise caution if you are using this option and multiple transfers may
occur. If you use the `Set-Cookie` format and the string does not specify a
domain, then the cookie is sent for any domain (even after redirects are
followed) and cannot be modified by a server-set cookie. If a server sets a
cookie of the same name (or maybe you have imported one) then both are sent on
future transfers to that server, likely not what you intended. To address
these issues set a domain in `Set-Cookie` (doing that includes subdomains) or
much better: use the Netscape file format.

Additionally, there are commands available that perform actions if you pass in
these exact strings:

## `ALL`

erases all cookies held in memory

## `SESS`

erases all session cookies held in memory

## `FLUSH`

writes all known cookies to the file specified by FETCHOPT_COOKIEJAR(3)

## `RELOAD`

loads all cookies from the files specified by FETCHOPT_COOKIEFILE(3)

# DEFAULT

NULL

# %PROTOCOLS%

# EXAMPLE

~~~c
/* an inline import of a cookie in Netscape format. */

#define SEP  "\t"  /* Tab separates the fields */

int main(void)
{
  const char *my_cookie =
    "example.com"    /* Hostname */
    SEP "FALSE"      /* Include subdomains */
    SEP "/"          /* Path */
    SEP "FALSE"      /* Secure */
    SEP "0"          /* Expiry in epoch time format. 0 == Session */
    SEP "foo"        /* Name */
    SEP "bar";       /* Value */

  FETCH *fetch = fetch_easy_init();
  if(fetch) {
    /* my_cookie is imported immediately via FETCHOPT_COOKIELIST. */
    fetch_easy_setopt(fetch, FETCHOPT_COOKIELIST, my_cookie);

    /* The list of cookies in cookies.txt are not be imported until right
       before a transfer is performed. Cookies in the list that have the same
       hostname, path and name as in my_cookie are skipped. That is because
       libfetch has already imported my_cookie and it's considered a "live"
       cookie. A live cookie is not replaced by one read from a file.
    */
    fetch_easy_setopt(fetch, FETCHOPT_COOKIEFILE, "cookies.txt");  /* import */

    /* Cookies are exported after fetch_easy_cleanup is called. The server
       may have added, deleted or modified cookies by then. The cookies that
       were skipped on import are not exported.
    */
    fetch_easy_setopt(fetch, FETCHOPT_COOKIEJAR, "cookies.txt");  /* export */

    fetch_easy_perform(fetch);  /* cookies imported from cookies.txt */

    fetch_easy_cleanup(fetch);  /* cookies exported to cookies.txt */
  }
}
~~~

# Cookie file format

The cookie file format and general cookie concepts in fetch are described
online here: https://fetch.se/docs/http-cookies.html

# HISTORY

**ALL** was added in 7.14.1

**SESS** was added in 7.15.4

**FLUSH** was added in 7.17.1

**RELOAD** was added in 7.39.0

# %AVAILABILITY%

# RETURN VALUE

fetch_easy_setopt(3) returns a FETCHcode indicating success or error.

FETCHE_OK (0) means everything was OK, non-zero means an error occurred, see
libfetch-errors(3).
