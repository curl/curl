---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: fetch
Title: FETCHOPT_HEADERFUNCTION
Section: 3
Source: libfetch
See-also:
  - FETCHOPT_HEADERDATA (3)
  - FETCHOPT_WRITEFUNCTION (3)
  - fetch_easy_header (3)
Protocol:
  - HTTP
  - FTP
  - POP3
  - IMAP
  - SMTP
Added-in: 7.7.2
---

# NAME

FETCHOPT_HEADERFUNCTION - callback that receives header data

# SYNOPSIS

~~~c
#include <fetch/fetch.h>

size_t header_callback(char *buffer,
                       size_t size,
                       size_t nitems,
                       void *userdata);

FETCHcode fetch_easy_setopt(FETCH *handle, FETCHOPT_HEADERFUNCTION,
                          header_callback);
~~~

# DESCRIPTION

Pass a pointer to your callback function, which should match the prototype
shown above.

This callback function gets invoked by libfetch as soon as it has received
header data. The header callback is called once for each header and only
complete header lines are passed on to the callback. Parsing headers is easy
to do using this callback. *buffer* points to the delivered data, and the size
of that data is *nitems*; *size* is always 1. The provided header line is not
null-terminated. Do not modify the passed in buffer.

The pointer named *userdata* is the one you set with the FETCHOPT_HEADERDATA(3)
option.

Your callback should return the number of bytes actually taken care of. If
that amount differs from the amount passed to your callback function, it
signals an error condition to the library. This causes the transfer to get
aborted and the libfetch function used returns *FETCHE_WRITE_ERROR*.

You can also abort the transfer by returning FETCH_WRITEFUNC_ERROR. (7.87.0)

A complete HTTP header that is passed to this function can be up to
*FETCH_MAX_HTTP_HEADER* (100K) bytes and includes the final line terminator.

If this option is not set, or if it is set to NULL, but
FETCHOPT_HEADERDATA(3) is set to anything but NULL, the function used to
accept response data is used instead. That is the function specified with
FETCHOPT_WRITEFUNCTION(3), or if it is not specified or NULL - the
default, stream-writing function.

It is important to note that the callback is invoked for the headers of all
responses received after initiating a request and not just the final
response. This includes all responses which occur during authentication
negotiation. If you need to operate on only the headers from the final
response, you need to collect headers in the callback yourself and use HTTP
status lines, for example, to delimit response boundaries.

For an HTTP transfer, the status line and the blank line preceding the response
body are both included as headers and passed to this function.

When a server sends a chunked encoded transfer, it may contain a trailer. That
trailer is identical to an HTTP header and if such a trailer is received it is
passed to the application using this callback as well. There are several ways
to detect it being a trailer and not an ordinary header: 1) it comes after the
response-body. 2) it comes after the final header line (CR LF) 3) a Trailer:
header among the regular response-headers mention what header(s) to expect in
the trailer.

For non-HTTP protocols like FTP, POP3, IMAP and SMTP this function gets called
with the server responses to the commands that libfetch sends.

A more convenient way to get HTTP headers might be to use
fetch_easy_header(3).

# LIMITATIONS

libfetch does not unfold HTTP "folded headers" (deprecated since RFC 7230). A
folded header is a header that continues on a subsequent line and starts with
a whitespace. Such folds are passed to the header callback as separate ones,
although strictly they are just continuations of the previous lines.

# DEFAULT

Nothing.

# %PROTOCOLS%

# EXAMPLE

~~~c
static size_t header_callback(char *buffer, size_t size,
                              size_t nitems, void *userdata)
{
  /* received header is nitems * size long in 'buffer' NOT ZERO TERMINATED */
  /* 'userdata' is set with FETCHOPT_HEADERDATA */
  return nitems * size;
}

int main(void)
{
  FETCH *fetch = fetch_easy_init();
  if(fetch) {
    fetch_easy_setopt(fetch, FETCHOPT_URL, "https://example.com");

    fetch_easy_setopt(fetch, FETCHOPT_HEADERFUNCTION, header_callback);

    fetch_easy_perform(fetch);
  }
}
~~~

# %AVAILABILITY%

# RETURN VALUE

fetch_easy_setopt(3) returns a FETCHcode indicating success or error.

FETCHE_OK (0) means everything was OK, non-zero means an error occurred, see
libfetch-errors(3).
