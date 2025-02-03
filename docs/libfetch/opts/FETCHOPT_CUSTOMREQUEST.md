---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: fetch
Title: FETCHOPT_CUSTOMREQUEST
Section: 3
Source: libfetch
See-also:
  - FETCHINFO_EFFECTIVE_METHOD (3)
  - FETCHOPT_HTTPHEADER (3)
  - FETCHOPT_NOBODY (3)
  - FETCHOPT_REQUEST_TARGET (3)
Protocol:
  - HTTP
  - FTP
  - IMAP
  - POP3
  - SMTP
Added-in: 7.1
---

# NAME

FETCHOPT_CUSTOMREQUEST - custom request method

# SYNOPSIS

~~~c
#include <fetch/fetch.h>

FETCHcode fetch_easy_setopt(FETCH *handle, FETCHOPT_CUSTOMREQUEST, char *method);
~~~

# DESCRIPTION

Pass a pointer to a null-terminated string as parameter.

When changing the request *method* by setting FETCHOPT_CUSTOMREQUEST(3), you do
not actually change how libfetch behaves or acts: you only change the actual
string sent in the request.

libfetch passes on the verbatim string in its request without any filter or
other safe guards. That includes white space and control characters.

The application does not have to keep the string around after setting this
option.

Using this option multiple times makes the last set string override the
previous ones. Restore to the internal default by setting this to NULL.

This option can be used to specify the request:

## HTTP

Instead of GET or HEAD when performing HTTP based requests. This is
particularly useful, for example, for performing an HTTP DELETE request.

For example:

When you tell libfetch to do a HEAD request, but then specify a GET though a
custom request libfetch still acts as if it sent a HEAD. To switch to a proper
HEAD use FETCHOPT_NOBODY(3), to switch to a proper POST use
FETCHOPT_POST(3) or FETCHOPT_POSTFIELDS(3) and to switch to a proper
GET use FETCHOPT_HTTPGET(3).

Many people have wrongly used this option to replace the entire request with
their own, including multiple headers and POST contents. While that might work
in many cases, it might cause libfetch to send invalid requests and it could
possibly confuse the remote server badly. Use FETCHOPT_POST(3) and
FETCHOPT_POSTFIELDS(3) to set POST data. Use FETCHOPT_HTTPHEADER(3)
to replace or extend the set of headers sent by libfetch. Use
FETCHOPT_HTTP_VERSION(3) to change HTTP version.

## FTP

Instead of LIST and NLST when performing FTP directory listings.

## IMAP

Instead of LIST when issuing IMAP based requests.

## POP3

Instead of LIST and RETR when issuing POP3 based requests.

For example:

When you tell libfetch to use a custom request it behaves like a LIST or RETR
command was sent where it expects data to be returned by the server. As such
FETCHOPT_NOBODY(3) should be used when specifying commands such as
**DELE** and **NOOP** for example.

## SMTP

Instead of a **HELP** or **VRFY** when issuing SMTP based requests.

For example:

Normally a multi line response is returned which can be used, in conjunction
with FETCHOPT_MAIL_RCPT(3), to specify an EXPN request. If the
FETCHOPT_NOBODY(3) option is specified then the request can be used to
issue **NOOP** and **RSET** commands.

# DEFAULT

NULL

# %PROTOCOLS%

# EXAMPLE

~~~c
int main(void)
{
  FETCH *fetch = fetch_easy_init();
  if(fetch) {
    FETCHcode res;
    fetch_easy_setopt(fetch, FETCHOPT_URL, "https://example.com/foo.bin");

    /* DELETE the given path */
    fetch_easy_setopt(fetch, FETCHOPT_CUSTOMREQUEST, "DELETE");

    res = fetch_easy_perform(fetch);

    fetch_easy_cleanup(fetch);
  }
}
~~~

# %AVAILABILITY%

# RETURN VALUE

fetch_easy_setopt(3) returns a FETCHcode indicating success or error.

FETCHE_OK (0) means everything was OK, non-zero means an error occurred, see
libfetch-errors(3).
