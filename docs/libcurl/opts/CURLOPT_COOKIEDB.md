---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Title: CURLOPT_COOKIEDB
Section: 3
Source: libcurl
See-also:
  - CURLOPT_COOKIEFILE (3)
  - CURLOPT_COOKIEJAR (3)
  - CURLOPT_COOKIELIST (3)
  - CURLOPT_COOKIESESSION (3)
  - CURLOPT_COOKIESITE (3)
Protocol:
  - HTTP
Added-in: 8.24.0
---

# NAME

CURLOPT_COOKIEDB - SQLite database to keep cookies in

# SYNOPSIS

~~~c
#include <curl/curl.h>

CURLcode curl_easy_setopt(CURL *handle, CURLOPT_COOKIEDB, char *filename);
~~~

# DESCRIPTION

Pass a *filename* as a null-terminated string. libcurl uses the SQLite
database in that file as its cookie store: the cookies in it are loaded when
a transfer starts, and every cookie received from a server is written to it
right away. The file is created, with the needed table, if it does not exist.

Setting this option enables the cookie engine, like CURLOPT_COOKIEFILE(3)
does. Cookies read from files given with CURLOPT_COOKIEFILE(3), and cookies
added with CURLOPT_COOKIELIST(3) before the first transfer, are written to
the database. A cookie jar file set with CURLOPT_COOKIEJAR(3) is still
written when the handle is closed, and CURLINFO_COOKIELIST(3) works as
usual.

Since the cookies are written through as they arrive and the database is
checked for changes made by others before cookies are sent, several easy
handles, several share objects and even several processes can use the same
database and see each other's cookies. That makes it a fit for applications
with many concurrent transfers, like a browser with one process per tab,
which otherwise need to rewrite a whole cookie jar file for every cookie
received.

The `SameSite` and `Partitioned` attributes of cookies, used with
CURLOPT_COOKIESITE(3), are stored in the database too.

CURLOPT_COOKIELIST(3) with "ALL" or "SESS" removes the cookies from the
database as well. With CURLOPT_COOKIESESSION(3) set, session cookies in the
database are discarded when it is opened.

A database that cannot be opened or used is reported in the verbose log and
the transfer continues without it, like with a cookie file that cannot be
read.

This option requires libcurl to be built with SQLite support, otherwise it
returns CURLE_NOT_BUILT_IN. The "SQLite" feature in curl_version_info(3)
tells whether it is available.

The application does not keep the string around after setting this option.

# DEFAULT

NULL

# %PROTOCOLS%

# EXAMPLE

~~~c
int main(void)
{
  CURL *curl = curl_easy_init();
  if(curl) {
    CURLcode result;
    curl_easy_setopt(curl, CURLOPT_URL, "https://example.com/foo.bin");

    /* keep the cookies in this database */
    curl_easy_setopt(curl, CURLOPT_COOKIEDB, "/tmp/cookies.db");

    result = curl_easy_perform(curl);

    curl_easy_cleanup(curl);
  }
}
~~~

# %AVAILABILITY%

# RETURN VALUE

curl_easy_setopt(3) returns a CURLcode indicating success or error.

CURLE_OK (0) means everything was OK, non-zero means an error occurred, see
libcurl-errors(3).
