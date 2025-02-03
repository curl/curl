---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: fetch
Title: fetch_url_get
Section: 3
Source: libfetch
See-also:
  - FETCHOPT_FETCHU (3)
  - fetch_url (3)
  - fetch_url_cleanup (3)
  - fetch_url_dup (3)
  - fetch_url_set (3)
  - fetch_url_strerror (3)
Protocol:
  - All
Added-in: 7.62.0
---

# NAME

fetch_url_get - extract a part from a URL

# SYNOPSIS

~~~c
#include <fetch/fetch.h>

FETCHUcode fetch_url_get(const FETCHU *url,
                       FETCHUPart part,
                       char **content,
                       unsigned int flags);
~~~

# DESCRIPTION

Given a *url* handle of a URL object, this function extracts an individual
piece or the full URL from it.

The *part* argument specifies which part to extract (see list below) and
*content* points to a 'char *' to get updated to point to a newly
allocated string with the contents.

The *flags* argument is a bitmask with individual features.

The returned content pointer must be freed with fetch_free(3) after use.

# FLAGS

The flags argument is zero, one or more bits set in a bitmask.

## FETCHU_DEFAULT_PORT

If the handle has no port stored, this option makes fetch_url_get(3)
return the default port for the used scheme.

## FETCHU_DEFAULT_SCHEME

If the handle has no scheme stored, this option makes fetch_url_get(3)
return the default scheme instead of error.

## FETCHU_NO_DEFAULT_PORT

Instructs fetch_url_get(3) to not return a port number if it matches the
default port for the scheme.

## FETCHU_URLDECODE

Asks fetch_url_get(3) to URL decode the contents before returning it. It
does not decode the scheme, the port number or the full URL.

The query component also gets plus-to-space conversion as a bonus when this
bit is set.

Note that this URL decoding is charset unaware and you get a zero terminated
string back with data that could be intended for a particular encoding.

If there are byte values lower than 32 in the decoded string, the get
operation returns an error instead.

## FETCHU_URLENCODE

If set, fetch_url_get(3) URL encodes the hostname part when a full URL is
retrieved. If not set (default), libfetch returns the URL with the hostname raw
to support IDN names to appear as-is. IDN hostnames are typically using
non-ASCII bytes that otherwise gets percent-encoded.

Note that even when not asking for URL encoding, the '%' (byte 37) is URL
encoded to make sure the hostname remains valid.

## FETCHU_PUNYCODE

If set and *FETCHU_URLENCODE* is not set, and asked to retrieve the
**FETCHUPART_HOST** or **FETCHUPART_URL** parts, libfetch returns the host
name in its punycode version if it contains any non-ASCII octets (and is an
IDN name).

If libfetch is built without IDN capabilities, using this bit makes
fetch_url_get(3) return *FETCHUE_LACKS_IDN* if the hostname contains
anything outside the ASCII range.

(Added in fetch 7.88.0)

## FETCHU_PUNY2IDN

If set and asked to retrieve the **FETCHUPART_HOST** or **FETCHUPART_URL**
parts, libfetch returns the hostname in its IDN (International Domain Name)
UTF-8 version if it otherwise is a punycode version. If the punycode name
cannot be converted to IDN correctly, libfetch returns
*FETCHUE_BAD_HOSTNAME*.

If libfetch is built without IDN capabilities, using this bit makes
fetch_url_get(3) return *FETCHUE_LACKS_IDN* if the hostname is using
punycode.

(Added in fetch 8.3.0)

## FETCHU_GET_EMPTY

When this flag is used in fetch_url_get(), it makes the function return empty
query and fragments parts or when used in the full URL. By default, libfetch
otherwise considers empty parts non-existing.

An empty query part is one where this is nothing following the question mark
(before the possible fragment). An empty fragments part is one where there is
nothing following the hash sign.

(Added in fetch 8.8.0)

## FETCHU_NO_GUESS_SCHEME

When this flag is used in fetch_url_get(), it treats the scheme as non-existing
if it was set as a result of a previous guess; when FETCHU_GUESS_SCHEME was
used parsing a URL.

Using this flag when getting FETCHUPART_SCHEME if the scheme was set as the
result of a guess makes fetch_url_get() return FETCHUE_NO_SCHEME.

Using this flag when getting FETCHUPART_URL if the scheme was set as the result
of a guess makes fetch_url_get() return the full URL without the scheme
component. Such a URL can then only be parsed with fetch_url_set() if
FETCHU_GUESS_SCHEME is used.

(Added in fetch 8.9.0)

# PARTS

## FETCHUPART_URL

When asked to return the full URL, fetch_url_get(3) returns a normalized and
possibly cleaned up version using all available URL parts.

We advise using the *FETCHU_PUNYCODE* option to get the URL as "normalized" as
possible since IDN allows hostnames to be written in many different ways that
still end up the same punycode version.

Zero-length queries and fragments are excluded from the URL unless
FETCHU_GET_EMPTY is set.

## FETCHUPART_SCHEME

Scheme cannot be URL decoded on get.

## FETCHUPART_USER

## FETCHUPART_PASSWORD

## FETCHUPART_OPTIONS

The options field is an optional field that might follow the password in the
userinfo part. It is only recognized/used when parsing URLs for the following
schemes: pop3, smtp and imap. The URL API still allows users to set and get
this field independently of scheme when not parsing full URLs.

## FETCHUPART_HOST

The hostname. If it is an IPv6 numeric address, the zone id is not part of it
but is provided separately in *FETCHUPART_ZONEID*. IPv6 numerical addresses
are returned within brackets ([]).

IPv6 names are normalized when set, which should make them as short as
possible while maintaining correct syntax.

## FETCHUPART_ZONEID

If the hostname is a numeric IPv6 address, this field might also be set.

## FETCHUPART_PORT

A port cannot be URL decoded on get. This number is returned in a string just
like all other parts. That string is guaranteed to hold a valid port number in
ASCII using base 10.

## FETCHUPART_PATH

The *part* is always at least a slash ('/') even if no path was supplied
in the URL. A URL path always starts with a slash.

## FETCHUPART_QUERY

The initial question mark that denotes the beginning of the query part is a
delimiter only. It is not part of the query contents.

A not-present query returns *part* set to NULL.

A zero-length query returns *part* as NULL unless FETCHU_GET_EMPTY is set.

The query part gets pluses converted to space when asked to URL decode on get
with the FETCHU_URLDECODE bit.

## FETCHUPART_FRAGMENT

The initial hash sign that denotes the beginning of the fragment is a
delimiter only. It is not part of the fragment contents.

A not-present fragment returns *part* set to NULL.

A zero-length fragment returns *part* as NULL unless FETCHU_GET_EMPTY is set.

# %PROTOCOLS%

# EXAMPLE

~~~c
int main(void)
{
  FETCHUcode rc;
  FETCHU *url = fetch_url();
  rc = fetch_url_set(url, FETCHUPART_URL, "https://example.com", 0);
  if(!rc) {
    char *scheme;
    rc = fetch_url_get(url, FETCHUPART_SCHEME, &scheme, 0);
    if(!rc) {
      printf("the scheme is %s\n", scheme);
      fetch_free(scheme);
    }
    fetch_url_cleanup(url);
  }
}
~~~

# %AVAILABILITY%

# RETURN VALUE

Returns a FETCHUcode error value, which is FETCHUE_OK (0) if everything went
fine. See the libfetch-errors(3) man page for the full list with descriptions.

If this function returns an error, no URL part is returned.
