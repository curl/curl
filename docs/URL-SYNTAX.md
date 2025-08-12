<!--
Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.

SPDX-License-Identifier: curl
-->

# URL syntax and their use in curl

## Specifications

The official "URL syntax" is primarily defined in these two different
specifications:

 - [RFC 3986](https://datatracker.ietf.org/doc/html/rfc3986) (although URL is called
   "URI" in there)
 - [The WHATWG URL Specification](https://url.spec.whatwg.org/)

RFC 3986 is the earlier one, and curl has always tried to adhere to that one
(since it shipped in January 2005).

The WHATWG URL spec was written later, is incompatible with the RFC 3986 and
changes over time.

## Variations

URL parsers as implemented in browsers, libraries and tools usually opt to
support one of the mentioned specifications. Bugs, differences in
interpretations and the moving nature of the WHATWG spec does however make it
unlikely that multiple parsers treat URLs the same way.

## Security

Due to the inherent differences between URL parser implementations, it is
considered a security risk to mix different implementations and assume the
same behavior.

For example, if you use one parser to check if a URL uses a good hostname or
the correct auth field, and then pass on that same URL to a *second* parser,
there is always a risk it treats the same URL differently. There is no right
and wrong in URL land, only differences of opinions.

libcurl offers a separate API to its URL parser for this reason, among others.

Applications may at times find it convenient to allow users to specify URLs
for various purposes and that string would then end up fed to curl. Getting a
URL from an external untrusted party and using it with curl brings several
security concerns:

1. If you have an application that runs as or in a server application, getting
   an unfiltered URL can trick your application to access a local resource
   instead of a remote resource. Protecting yourself against localhost accesses
   is hard when accepting user provided URLs.

2. Such custom URLs can access other ports than you planned as port numbers
   are part of the regular URL format. The combination of a local host and a
   custom port number can allow external users to play tricks with your local
   services.

3. Such a URL might use other schemes than you thought of or planned for.

## "RFC 3986 plus"

curl recognizes a URL syntax that we call "RFC 3986 plus". It is grounded on
the well established RFC 3986 to make sure previously written command lines
and curl using scripts remain working.

curl's URL parser allows a few deviations from the spec in order to
inter-operate better with URLs that appear in the wild.

### Spaces

A URL provided to curl cannot contain spaces. They need to be provided URL
encoded to be accepted in a URL by curl.

An exception to this rule: `Location:` response headers that indicate to a
client where a resource has been redirected to, sometimes contain spaces. This
is a violation of RFC 3986 but is fine in the WHATWG spec. curl handles these
by re-encoding them to `%20`.

### Non-ASCII

Byte values in a provided URL that are outside of the printable ASCII range
are percent-encoded by curl.

### Multiple slashes

An absolute URL always starts with a "scheme" followed by a colon. For all the
schemes curl supports, the colon must be followed by two slashes according to
RFC 3986 but not according to the WHATWG spec - which allows one to infinity
amount.

curl allows one, two or three slashes after the colon to still be considered a
valid URL.

### "scheme-less"

curl supports "URLs" that do not start with a scheme. This is not supported by
any of the specifications. This is a shortcut to entering URLs that was
supported by browsers early on and has been mimicked by curl.

Based on what the hostname starts with, curl "guesses" what protocol to use:

 - `ftp.` means FTP
 - `dict.` means DICT
 - `ldap.` means LDAP
 - `imap.` means IMAP
 - `smtp.` means SMTP
 - `pop3.` means POP3
 - all other means HTTP

### Globbing letters

The curl command line tool supports "globbing" of URLs. It means that you can
create ranges and lists using `[N-M]` and `{one,two,three}` sequences. The
letters used for this (`[]{}`) are reserved in RFC 3986 and can therefore not
legitimately be part of such a URL.

They are however not reserved or special in the WHATWG specification, so
globbing can mess up such URLs. Globbing can be turned off for such occasions
(using `--globoff`).

# URL syntax details

A URL may consist of the following components - many of them are optional:

    [scheme][divider][userinfo][hostname][port number][path][query][fragment]

Each component is separated from the following component with a divider
character or string.

For example, this could look like:

    http://user:password@www.example.com:80/index.html?foo=bar#top

## Scheme

The scheme specifies the protocol to use. A curl build can support a few or
many different schemes. You can limit what schemes curl should accept.

curl supports the following schemes on URLs specified to transfer. They are
matched case insensitively:

`dict`, `file`, `ftp`, `ftps`, `gopher`, `gophers`, `http`, `https`, `imap`,
`imaps`, `ldap`, `ldaps`, `mqtt`, `pop3`, `pop3s`, `rtmp`, `rtmpe`, `rtmps`,
`rtmpt`, `rtmpte`, `rtmpts`, `rtsp`, `smb`, `smbs`, `smtp`, `smtps`, `telnet`,
`tftp`

When the URL is specified to identify a proxy, curl recognizes the following
schemes:

`http`, `https`, `socks4`, `socks4a`, `socks5`, `socks5h`, `socks`

## Userinfo

The userinfo field can be used to set username and password for
authentication purposes in this transfer. The use of this field is discouraged
since it often means passing around the password in plain text and is thus a
security risk.

URLs for IMAP, POP3 and SMTP also support *login options* as part of the
userinfo field. They are provided as a semicolon after the password and then
the options.

## Hostname

The hostname part of the URL contains the address of the server that you want
to connect to. This can be the fully qualified domain name of the server, the
local network name of the machine on your network or the IP address of the
server or machine represented by either an IPv4 or IPv6 address (within
brackets). For example:

    http://www.example.com/

    http://hostname/

    http://192.168.0.1/

    http://[2001:1890:1112:1::20]/

### "localhost"

Starting in curl 7.77.0, curl uses loopback IP addresses for the name
`localhost`: `127.0.0.1` and `::1`. It does not resolve the name using the
resolver functions.

This is done to make sure the host accessed is truly the localhost - the local
machine.

### IDNA

If curl was built with International Domain Name (IDN) support, it can also
handle hostnames using non-ASCII characters.

When built with libidn2, curl uses the IDNA 2008 standard. This is equivalent
to the WHATWG URL spec, but differs from certain browsers that use IDNA 2003
Transitional Processing. The two standards have a huge overlap but differ
slightly, perhaps most famously in how they deal with the
[German "double s"](https://en.wikipedia.org/wiki/%c3%9f).

When WinIDN is used, curl uses IDNA 2003 Transitional Processing, like the rest
of Windows.

## Port number

If there is a colon after the hostname, that should be followed by the port
number to use. 1 - 65535. curl also supports a blank port number field - but
only if the URL starts with a scheme.

If the port number is not specified in the URL, curl uses a default port
number based on the provide scheme:

DICT 2628, FTP 21, FTPS 990, GOPHER 70, GOPHERS 70, HTTP 80, HTTPS 443,
IMAP 132, IMAPS 993, LDAP 369, LDAPS 636, MQTT 1883, POP3 110, POP3S 995,
RTMP 1935, RTMPS 443, RTMPT 80, RTSP 554, SCP 22, SFTP 22, SMB 445, SMBS 445,
SMTP 25, SMTPS 465, TELNET 23, TFTP 69

# Scheme specific behaviors

## FTP

The path part of an FTP request specifies the file to retrieve and from which
directory. If the file part is omitted then libcurl downloads the directory
listing for the directory specified. If the directory is omitted then the
directory listing for the root / home directory is returned.

FTP servers typically put the user in its "home directory" after login, which
then differs between users. To explicitly specify the root directory of an FTP
server, start the path with double slash `//` or `/%2f` (2F is the hexadecimal
value of the ASCII code for the slash).

## FILE

When a `FILE://` URL is accessed on Windows systems, it can be crafted in a
way so that Windows attempts to connect to a (remote) machine when curl wants
to read or write such a path.

curl only allows the hostname part of a FILE URL to be one out of these three
alternatives: `localhost`, `127.0.0.1` or blank ("", zero characters).
Anything else makes curl fail to parse the URL.

### Windows-specific FILE details

curl accepts that the FILE URL's path starts with a "drive letter". That is a
single letter `a` to `z` followed by a colon or a pipe character (`|`).

The Windows operating system itself converts some file accesses to perform
network accesses over SMB/CIFS, through several different file path patterns.
This way, a `file://` URL passed to curl *might* be converted into a network
access inadvertently and unknowingly to curl. This is a Windows feature curl
cannot control or disable.

## IMAP

The path part of an IMAP request not only specifies the mailbox to list or
select, but can also be used to check the `UIDVALIDITY` of the mailbox, to
specify the `UID`, `SECTION` and `PARTIAL` octets of the message to fetch and
to specify what messages to search for.

A top level folder list:

    imap://user:password@mail.example.com

A folder list on the user's inbox:

    imap://user:password@mail.example.com/INBOX

Select the user's inbox and fetch message with `uid = 1`:

    imap://user:password@mail.example.com/INBOX/;UID=1

Select the user's inbox and fetch the first message in the mail box:

    imap://user:password@mail.example.com/INBOX/;MAILINDEX=1

Select the user's inbox, check the `UIDVALIDITY` of the mailbox is 50 and
fetch message 2 if it is:

    imap://user:password@mail.example.com/INBOX;UIDVALIDITY=50/;UID=2

Select the user's inbox and fetch the text portion of message 3:

    imap://user:password@mail.example.com/INBOX/;UID=3/;SECTION=TEXT

Select the user's inbox and fetch the first 1024 octets of message 4:

    imap://user:password@mail.example.com/INBOX/;UID=4/;PARTIAL=0.1024

Select the user's inbox and check for NEW messages:

    imap://user:password@mail.example.com/INBOX?NEW

Select the user's inbox and search for messages containing "shadows" in the
subject line:

    imap://user:password@mail.example.com/INBOX?SUBJECT%20shadows

Searching via the query part of the URL `?` is a search request for the
results to be returned as message sequence numbers (`MAILINDEX`). It is
possible to make a search request for results to be returned as unique ID
numbers (`UID`) by using a custom curl request via `-X`. `UID` numbers are
unique per session (and multiple sessions when `UIDVALIDITY` is the same). For
example, if you are searching for `"foo bar"` in header+body (`TEXT`) and you
want the matching `MAILINDEX` numbers returned then you could search via URL:

    imap://user:password@mail.example.com/INBOX?TEXT%20%22foo%20bar%22

If you want matching `UID` numbers you have to use a custom request:

    imap://user:password@mail.example.com/INBOX -X "UID SEARCH TEXT \"foo bar\""

For more information about IMAP commands please see RFC 9051. For more
information about the individual components of an IMAP URL please see RFC 5092.

* Note old curl versions would `FETCH` by message sequence number when `UID`
was specified in the URL. That was a bug fixed in 7.62.0, which added
`MAILINDEX` to `FETCH` by mail sequence number.

## LDAP

The path part of an LDAP request can be used to specify the: Distinguished
Name, Attributes, Scope, Filter and Extension for an LDAP search. Each field
is separated by a question mark and when that field is not required an empty
string with the question mark separator should be included.

Search for the `DN` as `My Organization`:

    ldap://ldap.example.com/o=My%20Organization

the same search but only return `postalAddress` attributes:

    ldap://ldap.example.com/o=My%20Organization?postalAddress

Search for an empty `DN` and request information about the
`rootDomainNamingContext` attribute for an Active Directory server:

    ldap://ldap.example.com/?rootDomainNamingContext

For more information about the individual components of an LDAP URL please see
[RFC 4516](https://datatracker.ietf.org/doc/html/rfc4516).

## POP3

The path part of a POP3 request specifies the message ID to retrieve. If the
ID is not specified then a list of waiting messages is returned instead.

## SCP

The path part of an SCP URL specifies the path and file to retrieve or
upload. The file is taken as an absolute path from the root directory on the
server.

To specify a path relative to the user's home directory on the server, prepend
`~/` to the path portion.

## SFTP

The path part of an SFTP URL specifies the file to retrieve or upload. If the
path ends with a slash (`/`) then a directory listing is returned instead of a
file. If the path is omitted entirely then the directory listing for the root
/ home directory is returned.

## SMB
The path part of an SMB request specifies the file to retrieve and from what
share and directory or the share to upload to and as such, may not be omitted.
If the username is embedded in the URL then it must contain the domain name
and as such, the backslash must be URL encoded as %2f.

When uploading to SMB, the size of the file needs to be known ahead of time,
meaning that you can upload a file passed to curl over a pipe like stdin.

curl supports SMB version 1 (only)

## SMTP

The path part of an SMTP request specifies the hostname to present during
communication with the mail server. If the path is omitted, then libcurl
attempts to resolve the local computer's hostname. However, this may not
return the fully qualified domain name that is required by some mail servers
and specifying this path allows you to set an alternative name, such as your
machine's fully qualified domain name, which you might have obtained from an
external function such as gethostname or getaddrinfo.

The default smtp port is 25. Some servers use port 587 as an alternative.

## RTMP

There is no official URL spec for RTMP so libcurl uses the URL syntax supported
by the underlying librtmp library. It has a syntax where it wants a
traditional URL, followed by a space and a series of space-separated
`name=value` pairs.

While space is not typically a "legal" letter, libcurl accepts them. When a
user wants to pass in a `#` (hash) character it is treated as a fragment and
it gets cut off by libcurl if provided literally. You have to escape it by
providing it as backslash and its ASCII value in hexadecimal: `\23`.
