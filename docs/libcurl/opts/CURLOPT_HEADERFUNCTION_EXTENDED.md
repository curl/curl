---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Title: CURLOPT_HEADERFUNCTION_EXTENDED
Section: 3
Source: libcurl
See-also:
  - CURLOPT_HEADERDATA (3)
  - CURLOPT_HEADERFUNCTION (3)
  - CURLOPT_WRITEFUNCTION (3)
  - curl_easy_header (3)
Protocol:
  - HTTP
  - FTP
  - POP3
  - IMAP
  - SMTP
Added-in: 8.17.0
---

# NAME

CURLOPT_HEADERFUNCTION_EXTENDED - callback that receives header data with origin information

# SYNOPSIS

~~~c
#include <curl/curl.h>
#include <curl/header.h>

size_t header_callback_ex(char *buffer,
                           size_t size,
                           size_t nitems,
                           unsigned int origin,
                           void *userdata);

CURLcode curl_easy_setopt(CURL *handle, CURLOPT_HEADERFUNCTION_EXTENDED,
                          header_callback_ex);
~~~

# DESCRIPTION

Pass a pointer to your callback function, which should match the prototype
shown above.

This is an extended version of CURLOPT_HEADERFUNCTION(3) that provides
additional information about the header origin/type through the *origin*
parameter.

This callback function gets invoked by libcurl as soon as it has received
header data. The header callback is called once for each header and only
complete header lines are passed on to the callback. Parsing headers is easy
to do using this callback. *buffer* points to the delivered data, and the size
of that data is *nitems*; *size* is always 1. The provided header line is not
null-terminated. Do not modify the passed in buffer.

The *origin* parameter indicates the type of header being processed and can be
one of the following values from *curl/header.h*:

## CURLH_HEADER

Regular response header.

## CURLH_TRAILER

Header is a trailer. Trailers are headers that arrive after the response body
in chunked encoded transfers.

## CURLH_1XX

Header is part of an HTTP 1xx informational response.

## CURLH_CONNECT

Header is from a CONNECT response, received when using a proxy.

## CURLH_PSEUDO

HTTP/2 or HTTP/3 pseudo header (like :status, :path).

The pointer named *userdata* is the one you set with the CURLOPT_HEADERDATA(3)
option.

Your callback should return the number of bytes actually taken care of. If
that amount differs from the amount passed to your callback function, it
signals an error condition to the library. This causes the transfer to get
aborted and the libcurl function used returns *CURLE_WRITE_ERROR*.

You can also abort the transfer by returning CURL_WRITEFUNC_ERROR.

A complete HTTP header that is passed to this function can be up to
*CURL_MAX_HTTP_HEADER* (100K) bytes and includes the final line terminator.

If CURLOPT_HEADERFUNCTION_EXTENDED(3) is set, it takes precedence over
CURLOPT_HEADERFUNCTION(3). If neither is set, or if both are set to NULL,
but CURLOPT_HEADERDATA(3) is set to anything but NULL, the function used to
accept response data is used instead. That is the function specified with
CURLOPT_WRITEFUNCTION(3), or if it is not specified or NULL - the
default, stream-writing function.

It is important to note that the callback is invoked for the headers of all
responses received after initiating a request and not just the final response.
This includes all responses which occur during authentication negotiation. The
*origin* parameter can help distinguish between different types of headers
(e.g., 1xx informational responses vs. the final response).

For an HTTP transfer, the status line and the blank line preceding the response
body are both included as headers and passed to this function.

When a server sends a chunked encoded transfer, it may contain a trailer. That
trailer is identical to an HTTP header and if such a trailer is received it is
passed to the application using this callback with origin set to CURLH_TRAILER.

For non-HTTP protocols like FTP, POP3, IMAP and SMTP this function gets called
with the server responses to the commands that libcurl sends. For these
protocols, the *origin* parameter is set to CURLH_HEADER.

# LIMITATIONS

libcurl does not unfold HTTP "folded headers" (deprecated since RFC 7230). A
folded header is a header that continues on a subsequent line and starts with
a whitespace. Such folds are passed to the header callback as separate ones,
although strictly they are continuations of the previous lines.

# DEFAULT

NULL

# %PROTOCOLS%

# EXAMPLE

~~~c
#include <curl/curl.h>
#include <curl/header.h>

static size_t header_callback_ex(char *buffer, size_t size,
                                  size_t nitems, unsigned int origin,
                                  void *userdata)
{
  /* received header is 'nitems' bytes in 'buffer' NOT NULL-TERMINATED */
  /* 'userdata' is set with CURLOPT_HEADERDATA */

  /* Check header origin/type */
  if(origin & CURLH_TRAILER) {
    printf("Trailer: ");
  }
  else if(origin & CURLH_1XX) {
    printf("1xx response header: ");
  }
  else if(origin & CURLH_CONNECT) {
    printf("CONNECT header: ");
  }
  else if(origin & CURLH_PSEUDO) {
    printf("Pseudo header: ");
  }
  else {
    printf("Regular header: ");
  }

  /* Print the header (not null-terminated) */
  printf("%.*s", (int)nitems, buffer);

  return nitems;
}

int main(void)
{
  CURL *curl = curl_easy_init();
  if(curl) {
    curl_easy_setopt(curl, CURLOPT_URL, "https://example.com");

    curl_easy_setopt(curl, CURLOPT_HEADERFUNCTION_EXTENDED,
                     header_callback_ex);

    curl_easy_perform(curl);

    curl_easy_cleanup(curl);
  }
  return 0;
}
~~~

# %AVAILABILITY%

# RETURN VALUE

curl_easy_setopt(3) returns a CURLcode indicating success or error.

CURLE_OK (0) means everything was OK, non-zero means an error occurred, see
libcurl-errors(3).
