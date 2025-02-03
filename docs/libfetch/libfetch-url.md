---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: fetch
Title: libfetch-url
Section: 3
Source: libfetch
See-also:
  - FETCHOPT_URL (3)
  - fetch_url (3)
  - fetch_url_cleanup (3)
  - fetch_url_dup (3)
  - fetch_url_get (3)
  - fetch_url_set (3)
  - fetch_url_strerror (3)
Protocol:
  - All
Added-in: 7.62.0
---

# NAME

libfetch-url - URL interface overview

# DESCRIPTION

The URL interface provides functions for parsing and generating URLs.

# INCLUDE

You still only include \<fetch/fetch.h\> in your code.

# CREATE

Create a handle that holds URL info and resources with fetch_url(3):
~~~c
  FETCHU *h = fetch_url();
~~~

# CLEANUP

When done with it, clean it up with fetch_url_cleanup(3)
~~~c
  fetch_url_cleanup(h);
~~~

# DUPLICATE

When you need a copy of a handle, just duplicate it with fetch_url_dup(3):
~~~c
  FETCHU *nh = fetch_url_dup(h);
~~~

# PARSING

By setting a URL to the handle with fetch_url_set(3), the URL is parsed
and stored in the handle. If the URL is not syntactically correct it returns
an error instead.
~~~c
  rc = fetch_url_set(h, FETCHUPART_URL,
                    "https://example.com:449/foo/bar?name=moo", 0);
~~~

The zero in the fourth argument is a bitmask for changing specific features.

If successful, this stores the URL in its individual parts within the handle.

# REDIRECT

When a handle already contains info about a URL, setting a relative URL makes
it "redirect" to that.
~~~c
  rc = fetch_url_set(h, FETCHUPART_URL, "../test?another", 0);
~~~

# GET URL

The **FETCHU** handle represents a URL and you can easily extract that with
fetch_url_get(3):
~~~c
  char *url;
  rc = fetch_url_get(h, FETCHUPART_URL, &url, 0);
  fetch_free(url);
~~~
The zero in the fourth argument is a bitmask for changing specific features.

# GET PARTS

When a URL has been parsed or parts have been set, you can extract those
pieces from the handle at any time.

~~~c
  rc = fetch_url_get(h, FETCHUPART_FRAGMENT, &fragment, 0);
  rc = fetch_url_get(h, FETCHUPART_HOST, &host, 0);
  rc = fetch_url_get(h, FETCHUPART_PASSWORD, &password, 0);
  rc = fetch_url_get(h, FETCHUPART_PATH, &path, 0);
  rc = fetch_url_get(h, FETCHUPART_PORT, &port, 0);
  rc = fetch_url_get(h, FETCHUPART_QUERY, &query, 0);
  rc = fetch_url_get(h, FETCHUPART_SCHEME, &scheme, 0);
  rc = fetch_url_get(h, FETCHUPART_USER, &user, 0);
  rc = fetch_url_get(h, FETCHUPART_ZONEID, &zoneid, 0);
~~~

Extracted parts are not URL decoded unless the user also asks for it with the
*FETCHU_URLDECODE* flag set in the fourth bitmask argument.

Remember to free the returned string with fetch_free(3) when you are done
with it.

# SET PARTS

A user set individual URL parts, either after having parsed a full URL or
instead of parsing such.

~~~c
  rc = fetch_url_set(urlp, FETCHUPART_FRAGMENT, "anchor", 0);
  rc = fetch_url_set(urlp, FETCHUPART_HOST, "www.example.com", 0);
  rc = fetch_url_set(urlp, FETCHUPART_PASSWORD, "doe", 0);
  rc = fetch_url_set(urlp, FETCHUPART_PATH, "/index.html", 0);
  rc = fetch_url_set(urlp, FETCHUPART_PORT, "443", 0);
  rc = fetch_url_set(urlp, FETCHUPART_QUERY, "name=john", 0);
  rc = fetch_url_set(urlp, FETCHUPART_SCHEME, "https", 0);
  rc = fetch_url_set(urlp, FETCHUPART_USER, "john", 0);
  rc = fetch_url_set(urlp, FETCHUPART_ZONEID, "eth0", 0);
~~~

Set parts are not URL encoded unless the user asks for it with the
*FETCHU_URLENCODE* flag.

# FETCHU_APPENDQUERY

An application can append a string to the right end of the query part with the
*FETCHU_APPENDQUERY* flag to fetch_url_set(3).

Imagine a handle that holds the URL "https://example.com/?shoes=2". An
application can then add the string "hat=1" to the query part like this:

~~~c
  rc = fetch_url_set(urlp, FETCHUPART_QUERY, "hat=1", FETCHU_APPENDQUERY);
~~~

It notices the lack of an ampersand (&) separator and injects one, and the
handle's full URL then equals "https://example.com/?shoes=2&hat=1".

The appended string can of course also get URL encoded on add, and if asked to
URL encode, the encoding process skips the '=' character. For example, append
"candy=N&N" to what we already have, and URL encode it to deal with the
ampersand in the data:

~~~c
  rc = fetch_url_set(urlp, FETCHUPART_QUERY, "candy=N&N",
                    FETCHU_APPENDQUERY | FETCHU_URLENCODE);
~~~

Now the URL looks like

~~~c
  https://example.com/?shoes=2&hat=1&candy=N%26N
~~~

# NOTES

A URL with a literal IPv6 address can be parsed even when IPv6 support is not
enabled.
