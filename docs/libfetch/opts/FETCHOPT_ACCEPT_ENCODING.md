---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: fetch
Title: FETCHOPT_ACCEPT_ENCODING
Section: 3
Source: libfetch
See-also:
  - FETCHOPT_HTTPHEADER (3)
  - FETCHOPT_HTTP_CONTENT_DECODING (3)
  - FETCHOPT_TRANSFER_ENCODING (3)
Protocol:
  - HTTP
Added-in: 7.21.6
---

# NAME

FETCHOPT_ACCEPT_ENCODING - automatic decompression of HTTP downloads

# SYNOPSIS

~~~c
#include <fetch/fetch.h>

FETCHcode fetch_easy_setopt(FETCH *handle, FETCHOPT_ACCEPT_ENCODING, char *enc);
~~~

# DESCRIPTION

Pass a char pointer argument specifying what encoding you would like.

Sets the contents of the Accept-Encoding: header sent in an HTTP request, and
enables decoding of a response when a Content-Encoding: header is received.

libfetch potentially supports several different compressed encodings depending
on what support that has been built-in.

To aid applications not having to bother about what specific algorithms this
particular libfetch build supports, libfetch allows a zero-length string to be
set ("") to ask for an Accept-Encoding: header to be used that contains all
built-in supported encodings.

Alternatively, you can specify exactly the encoding or list of encodings you
want in the response. The following encodings are supported: *identity*,
meaning non-compressed, *deflate* which requests the server to compress its
response using the zlib algorithm, *gzip* which requests the gzip algorithm,
(since fetch 7.57.0) *br* which is brotli and (since fetch 7.72.0) *zstd* which
is zstd. Provide them in the string as a comma-separated list of accepted
encodings, like: **"br, gzip, deflate"**.

Set FETCHOPT_ACCEPT_ENCODING(3) to NULL to explicitly disable it, which makes
libfetch not send an Accept-Encoding: header and not decompress received
contents automatically.

You can also opt to just include the Accept-Encoding: header in your request
with FETCHOPT_HTTPHEADER(3) but then there is no automatic decompressing when
receiving data.

This is a request, not an order; the server may or may not do it. This option
must be set (to any non-NULL value) or else any unsolicited encoding done by
the server is ignored.

Servers might respond with Content-Encoding even without getting a
Accept-Encoding: in the request. Servers might respond with a different
Content-Encoding than what was asked for in the request.

The Content-Length: servers send for a compressed response is supposed to
indicate the length of the compressed content so when auto decoding is enabled
it may not match the sum of bytes reported by the write callbacks (although,
sending the length of the non-compressed content is a common server mistake).

The application does not have to keep the string around after setting this
option.

Using this option multiple times makes the last set string override the
previous ones.

# HISTORY

This option was called FETCHOPT_ENCODING before 7.21.6

# NOTES

The specific libfetch you are using must have been built with zlib to be able to
decompress gzip and deflate responses, with the brotli library to
decompress brotli responses and with the zstd library to decompress zstd
responses.

# DEFAULT

NULL

# %PROTOCOLS%

# EXAMPLE

~~~c
int main(void)
{
  FETCH *fetch = fetch_easy_init();
  if(fetch) {
    fetch_easy_setopt(fetch, FETCHOPT_URL, "https://example.com");

    /* enable all supported built-in compressions */
    fetch_easy_setopt(fetch, FETCHOPT_ACCEPT_ENCODING, "");

    /* Perform the request */
    fetch_easy_perform(fetch);
  }
}
~~~

# %AVAILABILITY%

# RETURN VALUE

fetch_easy_setopt(3) returns a FETCHcode indicating success or error.

FETCHE_OK (0) means everything was OK, non-zero means an error occurred, see
libfetch-errors(3).
