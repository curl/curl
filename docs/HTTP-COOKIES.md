<!--
Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.

SPDX-License-Identifier: curl
-->

# HTTP Cookies

## Cookie overview

  Cookies are `name=contents` pairs that an HTTP server tells the client to
  hold and then the client sends back those to the server on subsequent
  requests to the same domains and paths for which the cookies were set.

  Cookies are either "session cookies" which typically are forgotten when the
  session is over which is often translated to equal when browser quits, or
  the cookies are not session cookies they have expiration dates after which
  the client throws them away.

  Cookies are set to the client with the Set-Cookie: header and are sent to
  servers with the Cookie: header.

  For a long time, the only spec explaining how to use cookies was the
  original [Netscape spec from 1994](https://curl.se/rfc/cookie_spec.html).

  In 2011, [RFC 6265](https://www.ietf.org/rfc/rfc6265.txt) was finally
  published and details how cookies work within HTTP. In 2016, an update which
  added support for prefixes was
  [proposed](https://datatracker.ietf.org/doc/html/draft-ietf-httpbis-cookie-prefixes-00),
  and in 2017, another update was
  [drafted](https://datatracker.ietf.org/doc/html/draft-ietf-httpbis-cookie-alone-01)
  to deprecate modification of 'secure' cookies from non-secure origins. Both
  of these drafts have been incorporated into a proposal to
  [replace](https://datatracker.ietf.org/doc/html/draft-ietf-httpbis-rfc6265bis-11)
  RFC 6265. Cookie prefixes and secure cookie modification protection has been
  implemented by curl.

  curl considers `http://localhost` to be a *secure context*, meaning that it
  allows and uses cookies marked with the `secure` keyword even when done over
  plain HTTP for this host. curl does this to match how popular browsers work
  with secure cookies.

## Super cookies

  A single cookie can be set for a domain that matches multiple hosts. Like if
  set for `example.com` it gets sent to both `aa.example.com` as well as
  `bb.example.com`.

  A challenge with this concept is that there are certain domains for which
  cookies should not be allowed at all, because they are *Public
  Suffixes*. Similarly, a client never accepts cookies set directly for the
  top-level domain like for example `.com`. Cookies set for *too broad*
  domains are generally referred to as *super cookies*.

  If curl is built with PSL (**Public Suffix List**) support, it detects and
  discards cookies that are specified for such suffix domains that should not
  be allowed to have cookies.

  if curl is *not* built with PSL support, it has no ability to stop super
  cookies.

## Cookies saved to disk

  Netscape once created a file format for storing cookies on disk so that they
  would survive browser restarts. curl adopted that file format to allow
  sharing the cookies with browsers, only to see browsers move away from that
  format. Modern browsers no longer use it, while curl still does.

  The Netscape cookie file format stores one cookie per physical line in the
  file with a bunch of associated meta data, each field separated with
  TAB. That file is called the cookie jar in curl terminology.

  When libcurl saves a cookie jar, it creates a file header of its own in
  which there is a URL mention that links to the web version of this document.

## Cookie file format

  The cookie file format is text based and stores one cookie per line. Lines
  that start with `#` are treated as comments. An exception is lines that
  start with `#HttpOnly_`, which is a prefix for cookies that have the
  `HttpOnly` attribute set.

  Each line that specifies a single cookie consists of seven text fields
  separated with TAB characters. A valid line must end with a newline
  character.

### Fields in the file

  Field number, what type and example data and the meaning of it:

  0. string `example.com` - the domain name
  1. boolean `FALSE` - include subdomains
  2. string `/foobar/` - path
  3. boolean `TRUE` - send/receive over HTTPS only
  4. number `1462299217` - expires at - seconds since Jan 1st 1970, or 0
  5. string `person` - name of the cookie
  6. string `daniel` - value of the cookie

## Cookies with curl the command line tool

  curl has a full cookie "engine" built in. If you just activate it, you can
  have curl receive and send cookies exactly as mandated in the specs.

  Command line options:

  [`-b, --cookie`](https://curl.se/docs/manpage.html#-b)

  tell curl a file to read cookies from and start the cookie engine, or if it
  is not a file it passes on the given string. `-b name=var` works and so does
  `-b cookiefile`.

  [`-j, --junk-session-cookies`](https://curl.se/docs/manpage.html#-j)

  when used in combination with -b, it skips all "session cookies" on load so
  as to appear to start a new cookie session.

  [`-c, --cookie-jar`](https://curl.se/docs/manpage.html#-c)

  tell curl to start the cookie engine and write cookies to the given file
  after the request(s)

## Cookies with libcurl

libcurl offers several ways to enable and interface the cookie engine. These
options are the ones provided by the native API. libcurl bindings may offer
access to them using other means.

[`CURLOPT_COOKIE`](https://curl.se/libcurl/c/CURLOPT_COOKIE.html)

Is used when you want to specify the exact contents of a cookie header to
send to the server.

[`CURLOPT_COOKIEFILE`](https://curl.se/libcurl/c/CURLOPT_COOKIEFILE.html)

Tell libcurl to activate the cookie engine, and to read the initial set of
cookies from the given file. Read-only.

[`CURLOPT_COOKIEJAR`](https://curl.se/libcurl/c/CURLOPT_COOKIEJAR.html)

Tell libcurl to activate the cookie engine, and when the easy handle is
closed save all known cookies to the given cookie jar file. Write-only.

[`CURLOPT_COOKIELIST`](https://curl.se/libcurl/c/CURLOPT_COOKIELIST.html)

Provide detailed information about a single cookie to add to the internal
storage of cookies. Pass in the cookie as an HTTP header with all the
details set, or pass in a line from a Netscape cookie file. This option can
also be used to flush the cookies etc.

[`CURLOPT_COOKIESESSION`](https://curl.se/libcurl/c/CURLOPT_COOKIESESSION.html)

Tell libcurl to ignore all cookies it is about to load that are session
cookies.

[`CURLINFO_COOKIELIST`](https://curl.se/libcurl/c/CURLINFO_COOKIELIST.html)

Extract cookie information from the internal cookie storage as a linked
list.

## Cookies with JavaScript

These days a lot of the web is built up by JavaScript. The web browser loads
complete programs that render the page you see. These JavaScript programs
can also set and access cookies.

Since curl and libcurl are plain HTTP clients without any knowledge of or
capability to handle JavaScript, such cookies are not detected or used.

Often, if you want to mimic what a browser does on such websites, you can
record web browser HTTP traffic when using such a site and then repeat the
cookie operations using curl or libcurl.
