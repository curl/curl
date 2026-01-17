<!--
Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.

SPDX-License-Identifier: curl
-->

# Frequently Asked Questions

# Philosophy

## What is curl?

curl is the name of the project. The name is a play on *Client for URLs*,
originally with URL spelled in uppercase to make it obvious it deals with
URLs. The fact it can also be read as *see URL* also helped, it works as an
abbreviation for *Client URL Request Library* or why not the recursive
version: *curl URL Request Library*.

The curl project produces two products:

### libcurl

A client-side URL transfer library, supporting DICT, FILE, FTP, FTPS, GOPHER,
GOPHERS, HTTP, HTTPS, IMAP, IMAPS, LDAP, LDAPS, MQTT, MQTTS, POP3, POP3S, RTMP,
RTMPS, RTSP, SCP, SFTP, SMB, SMBS, SMTP, SMTPS, TELNET, TFTP, WS and WSS.

libcurl supports HTTPS certificates, HTTP POST, HTTP PUT, FTP uploading,
Kerberos, SPNEGO, HTTP form based upload, proxies, cookies, user+password
authentication, file transfer resume, http proxy tunneling and more.

libcurl is highly portable, it builds and works identically on numerous
platforms. The [internals document](https://curl.se/docs/install.html#Ports)
lists more than 110 operating systems and 28 CPU architectures on which curl
has been reported to run.

libcurl is free, thread-safe, IPv6 compatible, feature rich, well supported
and fast.

### curl

A command line tool for getting or sending data using URL syntax.

Since curl uses libcurl, curl supports the same wide range of common Internet
protocols that libcurl does.

We pronounce curl with an initial k sound. It rhymes with words like girl and
earl. [This is a short WAV
file](https://media.merriam-webster.com/soundc11/c/curl0001.wav) to help you.

There are numerous sub-projects and related projects that also use the word
curl in the project names in various combinations, but you should take notice
that this FAQ is directed at the command-line tool named curl (and libcurl the
library), and may therefore not be valid for other curl-related projects.
(There is however a small section for the PHP/CURL in this FAQ.)

## What is libcurl?

libcurl is a reliable and portable library for doing Internet data transfers
using one or more of its supported Internet protocols.

You can use libcurl freely in your application, be it open source, commercial
or closed-source.

libcurl is most probably the most portable, most powerful and most often used
C-based multi-platform file transfer library on this planet - be it open
source or commercial.

## What is curl not?

curl is not a Wget clone. That is a common misconception. Never, during curl's
development, have we intended curl to replace Wget or compete on its market.
curl is targeted at single-shot file transfers.

curl is not a website mirroring program. If you want to use curl to mirror
something: fine, go ahead and write a script that wraps around curl or use
libcurl to make it reality.

curl is not an FTP site mirroring program. Sure, get and send FTP with curl
but if you want systematic and sequential behavior you should write a script
(or write a new program that interfaces libcurl) and do it.

curl is not a PHP tool, even though it works perfectly well when used from or
with PHP (when using the PHP/CURL module).

curl is not a program for a single operating system. curl exists, compiles,
builds and runs under a wide range of operating systems, including all modern
Unixes (and a bunch of older ones too), Windows, Amiga, OS/2, macOS, QNX etc.

## When will you make curl do ... ?

We love suggestions of what to change in order to make curl and libcurl
better. We do however believe in a few rules when it comes to the future of
curl:

curl the command line tool is to remain a non-graphical command line tool. If
you want GUIs or fancy scripting capabilities, you should look for another
tool that uses libcurl.

We do not add things to curl that other small and available tools already do
well at the side. curl's output can be piped into another program or
redirected to another file for the next program to interpret.

We focus on protocol related issues and improvements. If you want to do more
magic with the supported protocols than curl currently does, chances are good
we will agree. If you want to add more protocols, we may agree.

If you want someone else to do all the work while you wait for us to implement
it for you, that is not a friendly attitude. We spend a considerable time
already on maintaining and developing curl. In order to get more out of us,
you should consider trading in some of your time and effort in return. Simply
go to the [GitHub repository](https://github.com/curl/curl), fork the project,
and create pull requests with your proposed changes.

If you write the code, chances are better that it will get into curl faster.

## Who makes curl?

curl and libcurl are not made by any single individual. Daniel Stenberg is
project leader and main developer, but other persons' submissions are
important and crucial. Anyone can contribute and post their changes and
improvements and have them inserted in the main sources (of course on the
condition that developers agree that the fixes are good).

The full list of all contributors is found in the docs/THANKS file.

curl is developed by a community, with Daniel at the wheel.

## What do you get for making curl?

Project curl is entirely free and open. We do this voluntarily, mostly in our
spare time. Companies may pay individual developers to work on curl. This is
not controlled by nor supervised in any way by the curl project.

We get help from companies. Haxx provides website, bandwidth, mailing lists
etc, GitHub hosts [the primary git repository](https://github.com/curl/curl)
and other services like the bug tracker. Also again, some companies have
sponsored certain parts of the development in the past and I hope some will
continue to do so in the future.

If you want to [support our project](https://curl.se/sponsors.html), consider
a donation or a banner-program or even better: by helping us with coding,
documenting or testing etc.

## What about CURL from curl.com?

During the summer of 2001, curl.com was busy advertising their client-side
programming language for the web, named CURL.

We are in no way associated with curl.com or their CURL programming language.

Our project name curl has been in effective use since 1998. We were not the
first computer related project to use the name *curl* and do not claim any
rights to the name.

We recognize that we will be living in parallel with curl.com and wish them
every success.

## I have a problem, who do I mail?

Please do not mail any single individual unless you really need to. Keep
curl-related questions on a suitable mailing list. All available mailing lists
are listed [online](https://curl.se/mail/).

Keeping curl-related questions and discussions on mailing lists allows others
to join in and help, to share their ideas, to contribute their suggestions and
to spread their wisdom. Keeping discussions on public mailing lists also
allows for others to learn from this (both current and future users thanks to
the web based archives of the mailing lists), thus saving us from having to
repeat ourselves even more. Thanks for respecting this.

If you have found or simply suspect a security problem in curl or libcurl,
submit all the details at [HackerOne](https://hackerone.com/curl). On there we
keep the issue private while we investigate, confirm it, work and validate a
fix and agree on a time schedule for publication etc. That way we produce a
fix in a timely manner before the flaw is announced to the world, reducing the
impact the problem risks having on existing users.

Security issues can also be taking to the curl security team by emailing
security at curl.se (closed list of receivers, mails are not disclosed).

## Where do I buy commercial support for curl?

curl is fully open source. It means you can hire any skilled engineer to fix
your curl-related problems.

We list [available alternatives](https://curl.se/support.html).

## How many are using curl?

It is impossible to tell.

We do not know how many users that knowingly have installed and use curl.

We do not know how many users that use curl without knowing that they are in
fact using it.

We do not know how many users that downloaded or installed curl and then never
use it.

In 2025, we estimate that curl runs in roughly thirty billion installations
world wide.

## Why do you not update ca-bundle.crt

In the curl project we have decided not to attempt to keep this file updated
(or even present) since deciding what to add to a ca cert bundle is an
undertaking we have not been ready to accept, and the one we can get from
Mozilla is perfectly fine so there is no need to duplicate that work.

Today, with many services performed over HTTPS, every operating system should
come with a default ca cert bundle that can be deemed somewhat trustworthy and
that collection (if reasonably updated) should be deemed to be a lot better
than a private curl version.

If you want the most recent collection of ca certs that Mozilla Firefox uses,
we recommend that using our online [CA certificate
service](https://curl.se/docs/caextract.html) setup for this purpose.

## I have a problem who, can I chat with?

There is a bunch of friendly people hanging out in the #curl channel on the
IRC network libera.chat. If you are polite and nice, chances are good that you
can get -- or provide -- help instantly.

## curl's ECCN number?

The US government restricts exports of software that contains or uses
cryptography. When doing so, the Export Control Classification Number (ECCN)
is used to identify the level of export control etc.

Apache Software Foundation has [a good explanation of
ECCN](https://www.apache.org/dev/crypto.html).

We believe curl's number might be ECCN 5D002, another possibility is 5D992. It
seems necessary to write them (the authority that administers ECCN numbers),
asking to confirm.

Comprehensible explanations of the meaning of such numbers and how to obtain
them (resp.) are [here](https://www.bis.gov/licensing/classify-your-item)
and [here](https://www.bis.gov/licensing/classify-your-item/publicly-available-classification-information).

An incomprehensible description of the two numbers above is available on
[bis.doc.gov](https://www.bis.doc.gov/index.php/documents/new-encryption/1653-ccl5-pt2-3)

## How do I submit my patch?

We strongly encourage you to submit changes and improvements directly as [pull
requests on GitHub](https://github.com/curl/curl/pulls).

If you for any reason cannot or will not deal with GitHub, send your patch to
the curl-library mailing list. We are many subscribers there and there are
lots of people who can review patches, comment on them and receive them
properly.

Lots of more details are found in the
[contribute](https://curl.se/dev/contribute.html) and
[internals](https://curl.se/dev/internals.html)
documents.

## How do I port libcurl to my OS?

Here's a rough step-by-step:

1. copy a suitable lib/config-*.h file as a start to `lib/config-[youros].h`
2. edit `lib/config-[youros].h` to match your OS and setup
3. edit `lib/curl_setup.h` to include `config-[youros].h` when your OS is
   detected by the preprocessor, in the style others already exist
4. compile `lib/*.c` and make them into a library

# Install

## configure fails when using static libraries

You may find that configure fails to properly detect the entire dependency
chain of libraries when you provide static versions of the libraries that
configure checks for.

The reason why static libraries is much harder to deal with is that for them
we do not get any help but the script itself must know or check what more
libraries that are needed (with shared libraries, that dependency chain is
handled automatically). This is an error-prone process and one that also tends
to vary over time depending on the release versions of the involved components
and may also differ between operating systems.

For that reason, configure does few attempts to actually figure this out and
you are instead encouraged to set `LIBS` and `LDFLAGS` accordingly when you invoke
configure, and point out the needed libraries and set the necessary flags
yourself.

## Does curl work with other SSL libraries?

curl has been written to use a generic SSL function layer internally, and
that SSL functionality can then be provided by one out of many different SSL
backends.

curl can be built to use one of the following SSL alternatives: OpenSSL,
LibreSSL, BoringSSL, AWS-LC, GnuTLS, wolfSSL, mbedTLS, Schannel (native
Windows) or Rustls. They all have their pros and cons, and we maintain [a TLS
library comparison](https://curl.se/docs/ssl-compared.html).

## How do I upgrade curl.exe in Windows?

The curl tool that is shipped as an integrated component of Windows 10 and
Windows 11 is managed by Microsoft. If you were to delete the file or replace
it with a newer version downloaded from [the curl
website](https://curl.se/windows/), then Windows Update will cease to work on
your system.

There is no way to independently force an upgrade of the curl.exe that is part
of Windows other than through the regular Windows update process. There is
also nothing the curl project itself can do about this, since this is managed
and controlled entirely by Microsoft as owners of the operating system.

You can always download and install [the latest version of curl for
Windows](https://curl.se/windows/) into a separate location.

## Does curl support SOCKS (RFC 1928) ?

Yes, SOCKS 4 and 5 are supported.

# Usage

## curl: (1) SSL is disabled, https: not supported

If you get this output when trying to get anything from an HTTPS server, it
means that the instance of curl/libcurl that you are using was built without
support for this protocol.

This could have happened if the configure script that was run at build time
could not find all libs and include files curl requires for SSL to work. If
the configure script fails to find them, curl is simply built without SSL
support.

To get HTTPS support into a curl that was previously built but that reports
that HTTPS is not supported, you should dig through the document and logs and
check out why the configure script does not find the SSL libs and/or include
files.

## How do I tell curl to resume a transfer?

curl supports resumed transfers both ways on both FTP and HTTP. Try the `-C`
option.

## Why does my posting using -F not work?

You cannot arbitrarily use `-F` or `-d`, the choice between `-F` or `-d`
depends on the HTTP operation you need curl to do and what the web server that
will receive your post expects.

If the form you are trying to submit uses the type 'multipart/form-data',
then and only then you must use the -F type. In all the most common cases,
you should use `-d` which then causes a posting with the type
`application/x-www-form-urlencoded`.

This is described in some detail in the
[Manual](https://curl.se/docs/tutorial.html) and [The Art Of HTTP
Scripting](https://curl.se/docs/httpscripting.html) documents, and if you do
not understand it the first time, read it again before you post questions
about this to the mailing list. Also, try reading through the mailing list
archives for old postings and questions regarding this.

## How do I tell curl to run custom FTP commands?

You can tell curl to perform optional commands both before and/or after a file
transfer. Study the `-Q`/`--quote` option.

Since curl is used for file transfers, you do not normally use curl to perform
FTP commands without transferring anything. Therefore you must always specify
a URL to transfer to/from even when doing custom FTP commands, or use `-I`
which implies the *no body*" option sent to libcurl.

## How can I disable the Accept: header?

You can change this and all internally generated headers by adding a
replacement with the `-H`/`--header` option. By adding a header with empty
contents you safely disable that one. Use `-H Accept:` to disable that
specific header.

## Does curl support ASP, XML, XHTML or HTML version Y?

To curl, all contents are alike. It does not matter how the page was
generated. It may be ASP, PHP, Perl, shell-script, SSI or plain HTML
files. There is no difference to curl and it does not even know what kind of
language that generated the page.

See also the separate question about JavaScript.

## Can I use curl to delete/rename a file through FTP?

Yes. You specify custom FTP commands with `-Q`/`--quote`.

One example would be to delete a file after you have downloaded it:

    curl -O ftp://example.com/coolfile -Q '-DELE coolfile'

or rename a file after upload:

    curl -T infile ftp://example.com/dir/ -Q "-RNFR infile" -Q "-RNTO newname"

## How do I tell curl to follow HTTP redirects?

curl does not follow so-called redirects by default. The `Location:` header that
informs the client about this is only interpreted if you are using the
`-L`/`--location` option. As in:

    curl -L https://example.com

Not all redirects are HTTP ones. See [Redirects work in browser but not with
curl](#redirects-work-in-browser-but-not-with-curl)

## How do I use curl in my favorite programming language?

Many programming languages have interfaces and bindings that allow you to use
curl without having to use the command line tool. If you are fluent in such a
language, you may prefer to use one of these interfaces instead.

Find out more about which languages that support curl directly, and how to
install and use them, in the [libcurl section of the curl
website](https://curl.se/libcurl/).

All the various bindings to libcurl are made by other projects and people,
outside of the curl project. The curl project itself only produces libcurl
with its plain C API. If you do not find anywhere else to ask you can ask
about bindings on the curl-library list too, but be prepared that people on
that list may not know anything about bindings.

In December 2025 there were around **60** different [interfaces
available](https://curl.se/libcurl/bindings.html) for just about all the
languages you can imagine.

## What about SOAP, WebDAV, XML-RPC or similar protocols over HTTP?

curl adheres to the HTTP spec, which basically means you can play with *any*
protocol that is built on top of HTTP. Protocols such as SOAP, WebDAV and
XML-RPC are all such ones. You can use `-X` to set custom requests and -H to
set custom headers (or replace internally generated ones).

Using libcurl is of course just as good and you would just use the proper
library options to do the same.

## How do I POST with a different Content-Type?

You can always replace the internally generated headers with `-H`/`--header`.
To make a simple HTTP POST with `text/xml` as content-type, do something like:

    curl -d "datatopost" -H "Content-Type: text/xml" [URL]

## Why do FTP-specific features over HTTP proxy fail?

Because when you use an HTTP proxy, the protocol spoken on the network will be
HTTP, even if you specify an FTP URL. This effectively means that you normally
cannot use FTP-specific features such as FTP upload and FTP quote etc.

There is one exception to this rule, and that is if you can *tunnel through*
the given HTTP proxy. Proxy tunneling is enabled with a special option (`-p`)
and is generally not available as proxy admins usually disable tunneling to
ports other than 443 (which is used for HTTPS access through proxies).

## Why do my single/double quotes fail?

To specify a command line option that includes spaces, you might need to put
the entire option within quotes. Like in:

    curl -d " with spaces " example.com

or perhaps

    curl -d ' with spaces ' example.com

Exactly what kind of quotes and how to do this is entirely up to the shell or
command line interpreter that you are using. For most Unix shells, you can
more or less pick either single (`'`) or double (`"`) quotes. For Windows/DOS
command prompts you must use double (") quotes, and if the option string
contains inner double quotes you can escape them with a backslash.

For Windows PowerShell the arguments are not always passed on as expected
because curl is not a PowerShell script. You may or may not be able to use
single quotes. To escape inner double quotes seems to require a
backslash-backtick escape sequence and the outer quotes as double quotes.

Please study the documentation for your particular environment. Examples in
the curl docs will use a mix of both of these as shown above. You must adjust
them to work in your environment.

Remember that curl works and runs on more operating systems than most single
individuals have ever tried.

## Does curl support JavaScript or PAC (automated proxy config)?

Many webpages do magic stuff using embedded JavaScript. curl and libcurl have
no built-in support for that, so it will be treated just like any other
contents.

`.pac` files are a Netscape invention and are sometimes used by organizations
to allow them to differentiate which proxies to use. The `.pac` contents is
just a JavaScript program that gets invoked by the browser and that returns
the name of the proxy to connect to. Since curl does not support JavaScript,
it cannot support .pac proxy configuration either.

Some workarounds usually suggested to overcome this JavaScript dependency:

Depending on the JavaScript complexity, write up a script that translates it
to another language and execute that.

Read the JavaScript code and rewrite the same logic in another language.

Implement a JavaScript interpreter, people have successfully used the
Mozilla JavaScript engine in the past.

Ask your admins to stop this, for a static proxy setup or similar.

## Can I do recursive fetches with curl?

No. curl itself has no code that performs recursive operations, such as those
performed by Wget and similar tools.

There exists curl using scripts with that functionality, and you can write
programs based on libcurl to do it, but the command line tool curl itself
cannot.

## What certificates do I need when I use SSL?

There are three different kinds of certificates to keep track of when we talk
about using SSL-based protocols (HTTPS or FTPS) using curl or libcurl.

### Client certificate

The server you communicate with may require that you can provide this in
order to prove that you actually are who you claim to be. If the server
does not require this, you do not need a client certificate.

A client certificate is always used together with a private key, and the
private key has a passphrase that protects it.

### Server certificate

The server you communicate with has a server certificate. You can and should
verify this certificate to make sure that you are truly talking to the real
server and not a server impersonating it.

Servers often also provide an intermediate certificate. It acts as a bridge
between a website's SSL certificate and a Certificate Authority's (CA) root
certificate, creating a "chain of trust".

### Certificate Authority Certificate ("CA cert")

You often have several CA certs in a CA cert bundle that can be used to verify
a server certificate that was signed by one of the authorities in the bundle.
curl does not come with a CA cert bundle but most curl installs provide one.
You can also override the default.

Server certificate verification is enabled by default in curl and libcurl.
Server certificates that are *self-signed* or otherwise signed by a CA that
you do not have a CA cert for, cannot be verified. If the verification during
a connect fails, you are refused access. You then might have to explicitly
disable the verification to connect to the server.

## How do I list the root directory of an FTP server?

There are two ways. The way defined in the RFC is to use an encoded slash in
the first path part. List the `/tmp` directory like this:

    curl ftp://ftp.example.com/%2ftmp/

or the not-quite-kosher-but-more-readable way, by simply starting the path
section of the URL with a slash:

    curl ftp://ftp.example.com//tmp/

## Can I use curl to send a POST/PUT and not wait for a response?

No.

You can easily write your own program using libcurl to do such stunts.

## How do I get HTTP from a host using a specific IP address?

For example, you may be trying out a website installation that is not yet in
the DNS. Or you have a site using multiple IP addresses for a given host
name and you want to address a specific one out of the set.

Set a custom `Host:` header that identifies the server name you want to reach
but use the target IP address in the URL:

    curl --header "Host: www.example.com" https://somewhere.example/

You can also opt to add faked hostname entries to curl with the --resolve
option. That has the added benefit that things like redirects will also work
properly. The above operation would instead be done as:

    curl --resolve www.example.com:80:127.0.0.1 https://www.example.com/

## How to SFTP from my user's home directory?

Contrary to how FTP works, SFTP and SCP URLs specify the exact directory to
work with. It means that if you do not specify that you want the user's home
directory, you get the actual root directory.

To specify a file in your user's home directory, you need to use the correct
URL syntax which for SFTP might look similar to:

    curl -O -u user:password sftp://example.com/~/file.txt

and for SCP it is just a different protocol prefix:

    curl -O -u user:password scp://example.com/~/file.txt

## Protocol xxx not supported or disabled in libcurl

When passing on a URL to curl to use, it may respond that the particular
protocol is not supported or disabled. The particular way this error message
is phrased is because curl does not make a distinction internally of whether a
particular protocol is not supported (i.e. never got any code added that knows
how to speak that protocol) or if it was explicitly disabled. curl can be
built to only support a given set of protocols, and the rest would then be
disabled or not supported.

Note that this error will also occur if you pass a wrongly spelled protocol
part as in `htpts://example.com` or as in the less evident case if you prefix
the protocol part with a space as in `" https://example.com/"`.

## curl `-X` gives me HTTP problems

In normal circumstances, `-X` should hardly ever be used.

By default you use curl without explicitly saying which request method to use
when the URL identifies an HTTP transfer. If you just pass in a URL like `curl
https://example.com` it will use GET. If you use `-d` or `-F`, curl will use
POST, `-I` will cause a HEAD and `-T` will make it a PUT.

If for whatever reason you are not happy with these default choices that curl
does for you, you can override those request methods by specifying `-X
[WHATEVER]`. This way you can for example send a DELETE by doing
`curl -X DELETE [URL]`.

It is thus pointless to do `curl -XGET [URL]` as GET would be used anyway. In
the same vein it is pointless to do `curl -X POST -d data [URL`. You can make
a fun and somewhat rare request that sends a request-body in a GET request
with something like `curl -X GET -d data [URL]`.

Note that `-X` does not actually change curl's behavior as it only modifies
the actual string sent in the request, but that may of course trigger a
different set of events.

Accordingly, by using `-XPOST` on a command line that for example would follow
a 303 redirect, you will effectively prevent curl from behaving correctly. Be
aware.

# Running

## Why do I get problems when I use & or % in the URL?

In general Unix shells, the & symbol is treated specially and when used, it
runs the specified command in the background. To safely send the & as a part
of a URL, you should quote the entire URL by using single (`'`) or double
(`"`) quotes around it. Similar problems can also occur on some shells with
other characters, including ?*!$~(){}<>\|;`. When in doubt, quote the URL.

An example that would invoke a remote CGI that uses &-symbols could be:

    curl 'https://www.example.com/cgi-bin/query?text=yes&q=curl'

In Windows, the standard DOS shell treats the percent sign specially and you
need to use TWO percent signs for each single one you want to use in the URL.

If you want a literal percent sign to be part of the data you pass in a POST
using `-d`/`--data` you must encode it as `%25` (which then also needs the
percent sign doubled on Windows machines).

## How can I use {, }, [ or ] to specify multiple URLs?

Because those letters have a special meaning to the shell, to be used in a URL
specified to curl you must quote them.

An example that downloads two URLs (sequentially) would be:

    curl '{curl,www}.haxx.se'

To be able to use those characters as actual parts of the URL (without using
them for the curl URL *globbing* system), use the `-g`/`--globoff` option:

    curl -g 'www.example.com/weirdname[].html'

## Why do I get downloaded data even though the webpage does not exist?

curl asks remote servers for the page you specify. If the page does not exist
at the server, the HTTP protocol defines how the server should respond and
that means that headers and a page will be returned. That is simply how HTTP
works.

By using the `--fail` option you can tell curl explicitly to not get any data
if the HTTP return code does not say success.

## Why do I get return code XXX from an HTTP server?

RFC 2616 clearly explains the return codes. This is a short transcript. Go
read the RFC for exact details:

### 400 Bad Request

The request could not be understood by the server due to malformed
syntax. The client SHOULD NOT repeat the request without modifications.

### 401 Unauthorized

The request requires user authentication.

### 403 Forbidden

The server understood the request, but is refusing to fulfill it.
Authorization will not help and the request SHOULD NOT be repeated.

### 404 Not Found

The server has not found anything matching the Request-URI. No indication is
given as to whether the condition is temporary or permanent.

### 405 Method Not Allowed

The method specified in the Request-Line is not allowed for the resource
identified by the Request-URI. The response MUST include an `Allow:` header
containing a list of valid methods for the requested resource.

### 301 Moved Permanently

If you get this return code and an HTML output similar to this:

    <H1>Moved Permanently</H1> The document has moved <A
    HREF="https://same_url_now_with_a_trailing_slash.example/">here</A>.

it might be because you requested a directory URL but without the trailing
slash. Try the same operation again _with_ the trailing URL, or use the
`-L`/`--location` option to follow the redirection.

## Can you tell me what error code 142 means?

All curl error codes are described at the end of the man page, in the section
called **EXIT CODES**.

Error codes that are larger than the highest documented error code means that
curl has exited due to a crash. This is a serious error, and we appreciate a
detailed bug report from you that describes how we could go ahead and repeat
this.

## How do I keep usernames and passwords secret in curl command lines?

This problem has two sides:

The first part is to avoid having clear-text passwords in the command line so
that they do not appear in *ps* outputs and similar. That is easily avoided by
using the `-K` option to tell curl to read parameters from a file or stdin to
which you can pass the secret info. curl itself will also attempt to hide the
given password by blanking out the option - this does not work on all
platforms.

To keep the passwords in your account secret from the rest of the world is
not a task that curl addresses. You could of course encrypt them somehow to
at least hide them from being read by human eyes, but that is not what
anyone would call security.

Also note that regular HTTP (using Basic authentication) and FTP passwords are
sent as cleartext across the network. All it takes for anyone to fetch them is
to listen on the network. Eavesdropping is easy. Use more secure
authentication methods (like Digest, Negotiate or even NTLM) or consider the
SSL-based alternatives HTTPS and FTPS.

## I found a bug

It is not a bug if the behavior is documented. Read the docs first. Especially
check out the KNOWN_BUGS file, it may be a documented bug.

If it is a problem with a binary you have downloaded or a package for your
particular platform, try contacting the person who built the package/archive
you have.

If there is a bug, read the BUGS document first. Then report it as described
in there.

## curl cannot authenticate to a server that requires NTLM?

NTLM support requires OpenSSL, GnuTLS, mbedTLS or Microsoft Windows libraries
at build-time to provide this functionality.

## My HTTP request using HEAD, PUT or DELETE does not work

Many web servers allow or demand that the administrator configures the server
properly for these requests to work on the web server.

Some servers seem to support HEAD only on certain kinds of URLs.

To fully grasp this, try the documentation for the particular server software
you are trying to interact with. This is not anything curl can do anything
about.

## Why do my HTTP range requests return the full document?

Because the range may not be supported by the server, or the server may choose
to ignore it and return the full document anyway.

## Why do I get "certificate verify failed" ?

When you invoke curl and get an error 60 error back it means that curl could
not verify that the server's certificate was good. curl verifies the
certificate using the CA cert bundle and verifying for which names the
certificate has been granted.

To completely disable the certificate verification, use `-k`. This does
however enable man-in-the-middle attacks and makes the transfer **insecure**.
We strongly advise against doing this for more than experiments.

If you get this failure with a CA cert bundle installed and used, the server's
certificate might not be signed by one of the certificate authorities in your
CA store. It might for example be self-signed. You then correct this problem
by obtaining a valid CA cert for the server. Or again, decrease the security
by disabling this check.

At times, you find that the verification works in your favorite browser but
fails in curl. When this happens, the reason is usually that the server sends
an incomplete cert chain. The server is mandated to send all *intermediate
certificates* but does not. This typically works with browsers anyway since
they A) cache such certs and B) supports AIA which downloads such missing
certificates on demand. This is a bad server configuration. A good way to
figure out if this is the case it to use [the SSL Labs
server](https://www.ssllabs.com/ssltest/) test and check the certificate
chain.

Details are also in [the SSL certificates
document](https://curl.se/docs/sslcerts.html).

## Why is curl -R on Windows one hour off?

Since curl 7.53.0 this issue should be fixed as long as curl was built with
any modern compiler that allows for a 64-bit curl_off_t type. For older
compilers or prior curl versions it may set a time that appears one hour off.
This happens due to a flaw in how Windows stores and uses file modification
times and it is not easily worked around. For more details [read
this](https://www.codeproject.com/articles/Beating-the-Daylight-Savings-Time-Bug-and-Getting#comments-section).

## Redirects work in browser but not with curl

curl supports HTTP redirects well (see a previous question above). Browsers
generally support at least two other ways to perform redirects that curl does
not:

Meta tags. You can write an HTML tag that will cause the browser to redirect
to another given URL after a certain time.

JavaScript. You can write a JavaScript program embedded in an HTML page that
redirects the browser to another given URL.

There is no way to make curl follow these redirects. You must either manually
figure out what the page is set to do, or write a script that parses the
results and fetches the new URL.

## FTPS does not work

curl supports FTPS (sometimes known as FTP-SSL) both implicit and explicit
mode.

When a URL is used that starts with `FTPS://`, curl assumes implicit SSL on
the control connection and will therefore immediately connect and try to speak
SSL. `FTPS://` connections default to port 990.

To use explicit FTPS, you use an `FTP://` URL and the `--ssl-reqd` option (or
one of its related flavors). This is the most common method, and the one
mandated by RFC 4217. This kind of connection will then of course use the
standard FTP port 21 by default.

## My HTTP POST or PUT requests are slow

libcurl makes all POST and PUT requests (except for requests with a small
request body) use the `Expect: 100-continue` header. This header allows the
server to deny the operation early so that libcurl can bail out before having
to send any data. This is useful in authentication cases and others.

However, many servers do not implement the `Expect:` stuff properly and if the
server does not respond (positively) within 1 second libcurl will continue and
send off the data anyway.

You can disable libcurl's use of the `Expect:` header the same way you disable
any header, using `-H` / `CURLOPT_HTTPHEADER`, or by forcing it to use HTTP
1.0.

## Non-functional connect timeouts

In most Windows setups having a timeout longer than 21 seconds make no
difference, as it will only send 3 TCP SYN packets and no more. The second
packet sent three seconds after the first and the third six seconds after
the second. No more than three packets are sent, no matter how long the
timeout is set.

See option `TcpMaxConnectRetransmissions` on [this
page](https://support.microsoft.com/topic/hotfix-enables-the-configuration-of-the-tcp-maximum-syn-retransmission-amount-in-windows-7-or-windows-server-2008-r2-1b6f8352-2c5f-58bb-ead7-2cf021407c8e).

Also, even on non-Windows systems there may run a firewall or anti-virus
software or similar that accepts the connection but does not actually do
anything else. This will make (lib)curl to consider the connection connected
and thus the connect timeout will not trigger.

## file:// URLs containing drive letters (Windows, NetWare)

When using curl to try to download a local file, one might use a URL in this
format:

    file://D:/blah.txt

you will find that even if `D:\blah.txt` does exist, curl returns a 'file not
found' error.

According to [RFC 1738](https://datatracker.ietf.org/doc/html/rfc1738),
`file://` URLs must contain a host component, but it is ignored by most
implementations. In the above example, `D:` is treated as the host component,
and is taken away. Thus, curl tries to open `/blah.txt`. If your system is
installed to drive C:, that will resolve to `C:\blah.txt`, and if that does
not exist you will get the not found error.

To fix this problem, use `file://` URLs with *three* leading slashes:

    file:///D:/blah.txt

Alternatively, if it makes more sense, specify `localhost` as the host
component:

    file://localhost/D:/blah.txt

In either case, curl should now be looking for the correct file.

## Why does not curl return an error when the network cable is unplugged?

Unplugging a cable is not an error situation. The TCP/IP protocol stack was
designed to be fault tolerant, so even though there may be a physical break
somewhere the connection should not be affected, just possibly delayed.
Eventually, the physical break will be fixed or the data will be re-routed
around the physical problem through another path.

In such cases, the TCP/IP stack is responsible for detecting when the network
connection is irrevocably lost. Since with some protocols it is perfectly
legal for the client to wait indefinitely for data, the stack may never report
a problem, and even when it does, it can take up to 20 minutes for it to
detect an issue. The curl option `--keepalive-time` enables keep-alive support
in the TCP/IP stack which makes it periodically probe the connection to make
sure it is still available to send data. That should reliably detect any
TCP/IP network failure.

TCP keep alive will not detect the network going down before the TCP/IP
connection is established (e.g. during a DNS lookup) or using protocols that
do not use TCP. To handle those situations, curl offers a number of timeouts
on its own. `--speed-limit`/`--speed-time` will abort if the data transfer
rate falls too low, and `--connect-timeout` and `--max-time` can be used to
put an overall timeout on the connection phase or the entire transfer.

A libcurl-using application running in a known physical environment (e.g. an
embedded device with only a single network connection) may want to act
immediately if its lone network connection goes down. That can be achieved by
having the application monitor the network connection on its own using an
OS-specific mechanism, then signaling libcurl to abort.

## curl does not return error for HTTP non-200 responses

Correct. Unless you use `-f` (`--fail`) or `--fail-with-body`.

When doing HTTP transfers, curl will perform exactly what you are asking it to
do and if successful it will not return an error. You can use curl to test
your web server's "file not found" page (that gets 404 back), you can use it
to check your authentication protected webpages (that gets a 401 back) and so
on.

The specific HTTP response code does not constitute a problem or error for
curl. It simply sends and delivers HTTP as you asked and if that worked,
everything is fine and dandy. The response code is generally providing more
higher level error information that curl does not care about. The error was
not in the HTTP transfer.

If you want your command line to treat error codes in the 400 and up range as
errors and thus return a non-zero value and possibly show an error message,
curl has a dedicated option for that: `-f` (`CURLOPT_FAILONERROR` in libcurl
speak).

You can also use the `-w` option and the variable `%{response_code}` to
extract the exact response code that was returned in the response.

# libcurl

## Is libcurl thread-safe?

Yes.

We have written the libcurl code specifically adjusted for multi-threaded
programs. libcurl will use thread-safe functions instead of non-safe ones if
your system has such. Note that you must never share the same handle in
multiple threads.

There may be some exceptions to thread safety depending on how libcurl was
built. Please review [the guidelines for thread
safety](https://curl.se/libcurl/c/threadsafe.html) to learn more.

## How can I receive all data into a large memory chunk?

(See the [get in memory](https://curl.se/libcurl/c/getinmemory.html) example.)

You are in full control of the callback function that gets called every time
there is data received from the remote server. You can make that callback do
whatever you want. You do not have to write the received data to a file.

One solution to this problem could be to have a pointer to a struct that you
pass to the callback function. You set the pointer using the CURLOPT_WRITEDATA
option. Then that pointer will be passed to the callback instead of a FILE *
to a file:

~~~c
/* store data this struct */
struct MemoryStruct {
  char *memory;
  size_t size;
};

/* imaginary callback function */
size_t
WriteMemoryCallback(void *ptr, size_t size, size_t nmemb, void *data)
{
  size_t realsize = size * nmemb;
  struct MemoryStruct *mem = (struct MemoryStruct *)data;

  mem->memory = (char *)realloc(mem->memory, mem->size + realsize + 1);
  if(mem->memory) {
    memcpy(&(mem->memory[mem->size]), ptr, realsize);
    mem->size += realsize;
    mem->memory[mem->size] = 0;
  }
  return realsize;
}
~~~

## How do I fetch multiple files with libcurl?

libcurl has excellent support for transferring multiple files. You should just
repeatedly set new URLs with `curl_easy_setopt()` and then transfer it with
`curl_easy_perform()`. The handle you get from curl_easy_init() is not only
reusable, but you are even encouraged to reuse it if you can, as that will
enable libcurl to use persistent connections.

## Does libcurl do Winsock initialization on Win32 systems?

Yes, if told to in the `curl_global_init()` call.

## Does CURLOPT_WRITEDATA and CURLOPT_READDATA work on Win32 ?

Yes, but you cannot open a FILE * and pass the pointer to a DLL and have that
DLL use the FILE * (as the DLL and the client application cannot access each
others' variable memory areas). If you set `CURLOPT_WRITEDATA` you must also use
`CURLOPT_WRITEFUNCTION` as well to set a function that writes the file, even if
that simply writes the data to the specified FILE *. Similarly, if you use
`CURLOPT_READDATA` you must also specify `CURLOPT_READFUNCTION`.

## What about Keep-Alive or persistent connections?

curl and libcurl have excellent support for persistent connections when
transferring several files from the same server. curl will attempt to reuse
connections for all URLs specified on the same command line/config file, and
libcurl will reuse connections for all transfers that are made using the same
libcurl handle.

When you use the easy interface the connection cache is kept within the easy
handle. If you instead use the multi interface, the connection cache will be
kept within the multi handle and will be shared among all the easy handles
that are used within the same multi handle.

## Link errors when building libcurl on Windows

You need to make sure that your project, and all the libraries (both static
and dynamic) that it links against, are compiled/linked against the same run
time library.

This is determined by the `/MD`, `/ML`, `/MT` (and their corresponding `/M?d`)
options to the command line compiler. `/MD` (linking against `MSVCRT.dll`)
seems to be the most commonly used option.

When building an application that uses the static libcurl library, you must
add `-DCURL_STATICLIB` to your `CFLAGS`. Otherwise the linker will look for
dynamic import symbols. If you are using Visual Studio, you need to instead
add `CURL_STATICLIB` in the "Preprocessor Definitions" section.

If you get a linker error like `unknown symbol __imp__curl_easy_init ...` you
have linked against the wrong (static) library. If you want to use the
libcurl.dll and import lib, you do not need any extra `CFLAGS`, but use one of
the import libraries below. These are the libraries produced by the various
lib/Makefile.* files:

| Target         | static lib     | import lib for DLL |
|----------------|----------------|--------------------|
| MinGW          | `libcurl.a`    | `libcurldll.a`     |
| MSVC (release) | `libcurl.lib`  | `libcurl_imp.lib`  |
| MSVC (debug)   | `libcurld.lib` | `libcurld_imp.lib` |

## libcurl.so.X: open failed: No such file or directory

This is an error message you might get when you try to run a program linked
with a shared version of libcurl and your runtime linker (`ld.so`) could not
find the shared library named `libcurl.so.X`. (Where X is the number of the
current libcurl ABI, typically 3 or 4).

You need to make sure that `ld.so` finds `libcurl.so.X`. You can do that
multiple ways, and it differs somewhat between different operating systems.
They are usually:

* Add an option to the linker command line that specify the hard-coded path
  the runtime linker should check for the lib (usually `-R`)
* Set an environment variable (`LD_LIBRARY_PATH` for example) where `ld.so`
  should check for libs
* Adjust the system's config to check for libs in the directory where you have
  put the library (like Linux's `/etc/ld.so.conf`)

`man ld.so` and`'man ld` will tell you more details

## How does libcurl resolve hostnames?

libcurl supports a large number of name resolve functions. One of them is
picked at build-time and will be used unconditionally. Thus, if you want to
change name resolver function you must rebuild libcurl and tell it to use a
different function.

### The non-IPv6 resolver

The non-IPv6 resolver that can use one of four different hostname resolve
calls depending on what your system supports:

1. gethostbyname()
2. gethostbyname_r() with 3 arguments
3. gethostbyname_r() with 5 arguments
4. gethostbyname_r() with 6 arguments

### The IPv6 resolver

Uses getaddrinfo()

### The cares resolver

The c-ares based name resolver that uses the c-ares library for resolves.
Using this offers asynchronous name resolves.

## The threaded resolver

It uses the IPv6 or the non-IPv6 resolver solution in a temporary thread.

## How do I prevent libcurl from writing the response to stdout?

libcurl provides a default built-in write function that writes received data
to stdout. Set the `CURLOPT_WRITEFUNCTION` to receive the data, or possibly
set `CURLOPT_WRITEDATA` to a different FILE * handle.

## How do I make libcurl not receive the whole HTTP response?

You make the write callback (or progress callback) return an error and libcurl
will then abort the transfer.

## Can I make libcurl fake or hide my real IP address?

No. libcurl operates on a higher level. Besides, faking IP address would
imply sending IP packets with a made-up source address, and then you normally
get a problem with receiving the packet sent back as they would then not be
routed to you.

If you use a proxy to access remote sites, the sites will not see your local
IP address but instead the address of the proxy.

Also note that on many networks NATs or other IP-munging techniques are used
that makes you see and use a different IP address locally than what the remote
server will see you coming from. You may also consider using
[Tor](https://www.torproject.org/).

## How do I stop an ongoing transfer?

With the easy interface you make sure to return the correct error code from
one of the callbacks, but none of them are instant. There is no function you
can call from another thread or similar that will stop it immediately.
Instead, you need to make sure that one of the callbacks you use returns an
appropriate value that will stop the transfer. Suitable callbacks that you can
do this with include the progress callback, the read callback and the write
callback.

If you are using the multi interface, you can also stop a transfer by removing
the particular easy handle from the multi stack at any moment you think the
transfer is done or when you wish to abort the transfer.

## Using C++ non-static functions for callbacks?

libcurl is a C library, it does not know anything about C++ member functions.

You can overcome this limitation with relative ease using a static member
function that is passed a pointer to the class:

~~~c++
// f is the pointer to your object.
static size_t YourClass::func(void *buffer, size_t sz, size_t n, void *f)
{
  // Call non-static member function.
  static_cast<YourClass*>(f)->nonStaticFunction();
}

// This is how you pass pointer to the static function:
curl_easy_setopt(hcurl, CURLOPT_WRITEFUNCTION, YourClass::func);
curl_easy_setopt(hcurl, CURLOPT_WRITEDATA, this);
~~~

## How do I get an FTP directory listing?

If you end the FTP URL you request with a slash, libcurl will provide you with
a directory listing of that given directory. You can also set
`CURLOPT_CUSTOMREQUEST` to alter what exact listing command libcurl would use
to list the files.

The follow-up question tends to be how is a program supposed to parse the
directory listing. How does it know what's a file and what's a directory and
what's a symlink etc. If the FTP server supports the `MLSD` command then it
will return data in a machine-readable format that can be parsed for type. The
types are specified by RFC 3659 section 7.5.1. If `MLSD` is not supported then
you have to work with what you are given. The `LIST` output format is entirely
at the server's own liking and the `NLST` output does not reveal any types and
in many cases does not even include all the directory entries. Also, both
`LIST` and `NLST` tend to hide Unix-style hidden files (those that start with
a dot) by default so you need to do `LIST -a` or similar to see them.

Example - List only directories. `ftp.funet.fi` supports `MLSD` and
`ftp.kernel.org` does not:

    curl -s ftp.funet.fi/pub/ -X MLSD | \
      perl -lne 'print if s/(?:^|;)type=dir;[^ ]+ (.+)$/$1/'

    curl -s ftp.kernel.org/pub/linux/kernel/ | \
      perl -lne 'print if s/^d[-rwx]{9}(?: +[^ ]+){7} (.+)$/$1/'

If you need to parse LIST output, libcurl provides the ability to specify a
wildcard to download multiple files from an FTP directory.

## I want a different time-out

Sometimes users realize that `CURLOPT_TIMEOUT` and `CURLOPT_CONNECTIMEOUT` are
not sufficiently advanced or flexible to cover all the various use cases and
scenarios applications end up with.

libcurl offers many more ways to time-out operations. A common alternative is
to use the `CURLOPT_LOW_SPEED_LIMIT` and `CURLOPT_LOW_SPEED_TIME` options to
specify the lowest possible speed to accept before to consider the transfer
timed out.

The most flexible way is by writing your own time-out logic and using
`CURLOPT_XFERINFOFUNCTION` (perhaps in combination with other callbacks) and
use that to figure out exactly when the right condition is met when the
transfer should get stopped.

## Can I write a server with libcurl?

No. libcurl offers no functions or building blocks to build any kind of
Internet protocol server. libcurl is only a client-side library. For server
libraries, you need to continue your search elsewhere but there exist many
good open source ones out there for most protocols you could want a server
for. There are also really good stand-alone servers that have been tested and
proven for many years. There is no need for you to reinvent them.

## Does libcurl use threads?

Put simply: no, libcurl will execute in the same thread you call it in. All
callbacks will be called in the same thread as the one you call libcurl in.

If you want to avoid your thread to be blocked by the libcurl call, you make
sure you use the non-blocking multi API which will do transfers
asynchronously - still in the same single thread.

libcurl will potentially internally use threads for name resolving, if it was
built to work like that, but in those cases it will create the child threads
by itself and they will only be used and then killed internally by libcurl and
never exposed to the outside.

# License

curl and libcurl are released under an MIT/X derivative license. The license
is liberal and should not impose a problem for your project. This section is
just a brief summary for the cases we get the most questions.

We are not lawyers and this is not legal advice. You should probably consult
one if you want true and accurate legal insights without our prejudice. Note
especially that this section concerns the libcurl license only; compiling in
features of libcurl that depend on other libraries (e.g. OpenSSL) may affect
the licensing obligations of your application.

## I have a GPL program, can I use the libcurl library?

Yes

Since libcurl may be distributed under the MIT/X derivative license, it can be
used together with GPL in any software.

## I have a closed-source program, can I use the libcurl library?

Yes

libcurl does not put any restrictions on the program that uses the library.

## I have a BSD licensed program, can I use the libcurl library?

Yes

libcurl does not put any restrictions on the program that uses the library.

## I have a program that uses LGPL libraries, can I use libcurl?

Yes

The LGPL license does not clash with other licenses.

## Can I modify curl/libcurl for my program and keep the changes secret?

Yes

The MIT/X derivative license practically allows you to do almost anything with
the sources, on the condition that the copyright texts in the sources are left
intact.

## Can you please change the curl/libcurl license?

No.

We have carefully picked this license after years of development and
discussions and a large amount of people have contributed with source code
knowing that this is the license we use. This license puts the restrictions we
want on curl/libcurl and it does not spread to other programs or libraries
that use it. It should be possible for everyone to use libcurl or curl in
their projects, no matter what license they already have in use.

## What are my obligations when using libcurl in my commercial apps?

Next to none. All you need to adhere to is the MIT-style license (stated in
the COPYING file) which basically says you have to include the copyright
notice in *all copies* and that you may not use the copyright holder's name
when promoting your software.

You do not have to release any of your source code.

You do not have to reveal or make public any changes to the libcurl source
code.

You do not have to broadcast to the world that you are using libcurl within
your app.

All we ask is that you disclose *the copyright notice and this permission
notice* somewhere. Most probably like in the documentation or in the section
where other third party dependencies already are mentioned and acknowledged.

As can be seen [here](https://curl.se/docs/companies.html) and elsewhere, more
and more companies are discovering the power of libcurl and take advantage of
it even in commercial environments.

## What license does curl use exactly?

curl is released under an [MIT derivative
license](https://curl.se/docs/copyright.html). It is similar but not identical
to the MIT license.

The difference is considered big enough to make SPDX list it under its own
identifier: [curl](https://spdx.org/licenses/curl.html).

The changes done to the license that make it uniquely curl were tiny and
well-intended, but the reasons for them have been forgotten and we strongly
discourage others from doing the same thing.

# PHP/CURL

## What is PHP/CURL?

The module for PHP that makes it possible for PHP programs to access curl
functions from within PHP.

In the curl project we call this module PHP/CURL to differentiate it from curl
the command line tool and libcurl the library. The PHP team however does not
refer to it like this (for unknown reasons). They call it plain CURL (often
using all caps) or sometimes ext/curl, but both cause much confusion to users
which in turn gives us a higher question load.

## Who wrote PHP/CURL?

PHP/CURL was initially written by Sterling Hughes.

## Can I perform multiple requests using the same handle?

Yes.

After a transfer, you just set new options in the handle and make another
transfer. This will make libcurl reuse the same connection if it can.

## Does PHP/CURL have dependencies?

PHP/CURL is a module that comes with the regular PHP package. It depends on
and uses libcurl, so you need to have libcurl installed properly before
PHP/CURL can be used.

# Development

## Why does curl use C89?

As with everything in curl, there is a history and we keep using what we have
used before until someone brings up the subject and argues for and works on
changing it.

We started out using C89 in the 1990s because that was the only way to write a
truly portable C program and have it run as widely as possible. C89 was for a
long time even necessary to make things work on otherwise considered modern
platforms such as Windows. Today, we do not really know how many users that
still require the use of a C89 compiler.

We will continue to use C89 for as long as nobody brings up a strong enough
reason for us to change our minds. The core developers of the project do not
feel restricted by this and we are not convinced that going C99 will offer us
enough of a benefit to warrant the risk of cutting off a share of users.

## Will curl be rewritten?

In one go: no. Little by little over time? Sure.

Over the years, new languages and clever operating environments come and go.
Every now and then the urge apparently arises to request that we rewrite curl
in another language.

Some the most important properties in curl are maintaining the API and ABI for
libcurl and keeping the behavior for the command line tool. As long as we can
do that, everything else is up for discussion. To maintain the ABI, we
probably have to maintain a certain amount of code in C, and to remain rock
stable, we will never risk anything by rewriting a lot of things in one go.
That said, we can certainly offer more and more optional backends written in
other languages, as long as those backends can be plugged in at build-time.
Backends can be written in any language, but should probably provide APIs
usable from C to ease integration and transition.
