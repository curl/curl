---
c: Copyright (C) Daniel Stenberg, <daniel.se>, et al.
SPDX-License-Identifier: curl
Title: CURLOPT_CUSTOMREQUEST
Section: 3
Source: libcurl
See-also:
  - CURLINFO_EFFECTIVE_METHOD (3)
  - CURLOPT_HTTPHEADER (3)
  - CURLOPT_NOBODY (3)
  - CURLOPT_REQUEST_TARGET (3)
---

# NAME

CURLOPT_CUSTOMREQUEST - custom request method

# SYNOPSIS

~~~c
#include <curl/curl.h>

CURLcode curl_easy_setopt(CURL *handle, CURLOPT_CUSTOMREQUEST, char *method);
~~~

# DESCRIPTION

Pass a pointer to a null-terminated string as parameter.

When changing the request *method* by setting CURLOPT_CUSTOMREQUEST(3), you
do not actually change how libcurl behaves or acts: you only change the actual
string sent in the request.

libcurl passes on the verbatim string in its request without any filter or
other safe guards. That includes white space and control characters.

Restore to the internal default by setting this to NULL.

This option can be used to specify the request:

## HTTP

Instead of GET or HEAD when performing HTTP based requests. This is
particularly useful, for example, for performing an HTTP DELETE request.

For example:

When you tell libcurl to do a HEAD request, but then specify a GET though a
custom request libcurl still acts as if it sent a HEAD. To switch to a proper
HEAD use CURLOPT_NOBODY(3), to switch to a proper POST use
CURLOPT_POST(3) or CURLOPT_POSTFIELDS(3) and to switch to a proper
GET use CURLOPT_HTTPGET(3).

Many people have wrongly used this option to replace the entire request with
their own, including multiple headers and POST contents. While that might work
in many cases, it might cause libcurl to send invalid requests and it could
possibly confuse the remote server badly. Use CURLOPT_POST(3) and
CURLOPT_POSTFIELDS(3) to set POST data. Use CURLOPT_HTTPHEADER(3)
to replace or extend the set of headers sent by libcurl. Use
CURLOPT_HTTP_VERSION(3) to change HTTP version.

## FTP

Instead of LIST and NLST when performing FTP directory listings.

## IMAP

Instead of LIST when issuing IMAP based requests.

## POP3

Instead of LIST and RETR when issuing POP3 based requests.

For example:

When you tell libcurl to use a custom request it behaves like a LIST or RETR
command was sent where it expects data to be returned by the server. As such
CURLOPT_NOBODY(3) should be used when specifying commands such as
**DELE** and **NOOP** for example.

## SMTP

Instead of a **HELP** or **VRFY** when issuing SMTP based requests.

For example:

Normally a multi line response is returned which can be used, in conjunction
with CURLOPT_MAIL_RCPT(3), to specify an EXPN request. If the
CURLOPT_NOBODY(3) option is specified then the request can be used to
issue **NOOP** and **RSET** commands.

The application does not have to keep the string around after setting this
option.

# DEFAULT

NULL

# PROTOCOLS

HTTP, FTP, IMAP, POP3 and SMTP

# EXAMPLE

~~~c
int main(void)
{
  CURL *curl = curl_easy_init();
  if(curl) {
    CURLcode res;
    curl_easy_setopt(curl, CURLOPT_URL, "https://example.com/foo.bin");

    /* DELETE the given path */
    curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST, "DELETE");

    res = curl_easy_perform(curl);

    curl_easy_cleanup(curl);
  }
}
~~~

# AVAILABILITY

IMAP is supported since 7.30.0, POP3 since 7.26.0 and SMTP since 7.34.0.

# RETURN VALUE

Returns CURLE_OK if the option is supported, CURLE_UNKNOWN_OPTION if not, or
CURLE_OUT_OF_MEMORY if there was insufficient heap space.
