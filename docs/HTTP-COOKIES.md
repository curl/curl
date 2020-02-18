# HTTP Cookies

## Cookie overview

  Cookies are `name=contents` pairs that a HTTP server tells the client to
  hold and then the client sends back those to the server on subsequent
  requests to the same domains and paths for which the cookies were set.

  Cookies are either "session cookies" which typically are forgotten when the
  session is over which is often translated to equal when browser quits, or
  the cookies aren't session cookies they have expiration dates after which
  the client will throw them away.

  Cookies are set to the client with the Set-Cookie: header and are sent to
  servers with the Cookie: header.

  For a very long time, the only spec explaining how to use cookies was the
  original [Netscape spec from 1994](https://curl.haxx.se/rfc/cookie_spec.html).

  In 2011, [RFC6265](https://www.ietf.org/rfc/rfc6265.txt) was finally
  published and details how cookies work within HTTP. In 2016, an update which
  added support for prefixes was
  [proposed](https://tools.ietf.org/html/draft-ietf-httpbis-cookie-prefixes-00),
  and in 2017, another update was
  [drafted](https://tools.ietf.org/html/draft-ietf-httpbis-cookie-alone-01)
  to deprecate modification of 'secure' cookies from non-secure origins. Both
  of these drafts have been incorporated into a proposal to
  [replace](https://tools.ietf.org/html/draft-ietf-httpbis-rfc6265bis-02)
  RFC6265. Cookie prefixes and secure cookie modification protection has been
  implemented by curl.

## Cookies saved to disk

  Netscape once created a file format for storing cookies on disk so that they
  would survive browser restarts. curl adopted that file format to allow
  sharing the cookies with browsers, only to see browsers move away from that
  format. Modern browsers no longer use it, while curl still does.

  The netscape cookie file format stores one cookie per physical line in the
  file with a bunch of associated meta data, each field separated with
  TAB. That file is called the cookiejar in curl terminology.

  When libcurl saves a cookiejar, it creates a file header of its own in which
  there is a URL mention that will link to the web version of this document.

## Cookie file format

  The cookie file format is text based and stores one cookie per line. Lines
  that start with `#` are treated as comments.

  Each line that each specifies a single cookie consists of seven text fields
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

  `-b, --cookie`

  tell curl a file to read cookies from and start the cookie engine, or if it
  isn't a file it will pass on the given string. -b name=var works and so does
  -b cookiefile.

  `-j, --junk-session-cookies`

  when used in combination with -b, it will skip all "session cookies" on load
  so as to appear to start a new cookie session.

  `-c, --cookie-jar`

  tell curl to start the cookie engine and write cookies to the given file
  after the request(s)

## Cookies with libcurl

  libcurl offers several ways to enable and interface the cookie engine. These
  options are the ones provided by the native API. libcurl bindings may offer
  access to them using other means.

  `CURLOPT_COOKIE`

  Is used when you want to specify the exact contents of a cookie header to
  send to the server.

  `CURLOPT_COOKIEFILE`

  Tell libcurl to activate the cookie engine, and to read the initial set of
  cookies from the given file. Read-only.

  `CURLOPT_COOKIEJAR`

  Tell libcurl to activate the cookie engine, and when the easy handle is
  closed save all known cookies to the given cookiejar file. Write-only.

  `CURLOPT_COOKIELIST`

  Provide detailed information about a single cookie to add to the internal
  storage of cookies. Pass in the cookie as a HTTP header with all the details
  set, or pass in a line from a netscape cookie file. This option can also be
  used to flush the cookies etc.

  `CURLINFO_COOKIELIST`

  Extract cookie information from the internal cookie storage as a linked
  list.

## Cookies with javascript

  These days a lot of the web is built up by javascript. The webbrowser loads
  complete programs that render the page you see. These javascript programs
  can also set and access cookies.

  Since curl and libcurl are plain HTTP clients without any knowledge of or
  capability to handle javascript, such cookies will not be detected or used.

  Often, if you want to mimic what a browser does on such web sites, you can
  record web browser HTTP traffic when using such a site and then repeat the
  cookie operations using curl or libcurl.
