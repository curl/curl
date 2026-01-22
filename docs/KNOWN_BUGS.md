<!--
Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.

SPDX-License-Identifier: curl
-->

# Known bugs intro

These are problems and bugs known to exist at the time of this release. Feel
free to join in and help us correct one or more of these. Also be sure to
check the changelog of the current development status, as one or more of these
problems may have been fixed or changed somewhat since this was written.

# TLS

## IMAPS connection fails with Rustls error

[curl issue 10457](https://github.com/curl/curl/issues/10457)

## Access violation sending client cert with Schannel

When using Schannel to do client certs, curl sets `PKCS12_NO_PERSIST_KEY` to
avoid leaking the private key into the filesystem. Unfortunately that flag
instead seems to trigger a crash.

See [curl issue 17626](https://github.com/curl/curl/issues/17626)

## Client cert handling with Issuer `DN` differs between backends

When the specified client certificate does not match any of the
server-specified `DN` fields, the OpenSSL and GnuTLS backends behave
differently. The GitHub discussion may contain a solution.

See [curl issue 1411](https://github.com/curl/curl/issues/1411)

## Client cert (MTLS) issues with Schannel

See [curl issue 3145](https://github.com/curl/curl/issues/3145)

## Schannel TLS 1.2 handshake bug in old Windows versions

In old versions of Windows such as 7 and 8.1 the Schannel TLS 1.2 handshake
implementation likely has a bug that can rarely cause the key exchange to
fail, resulting in error SEC_E_BUFFER_TOO_SMALL or SEC_E_MESSAGE_ALTERED.

[curl issue 5488](https://github.com/curl/curl/issues/5488)

## `CURLOPT_CERTINFO` results in `CURLE_OUT_OF_MEMORY` with Schannel

[curl issue 8741](https://github.com/curl/curl/issues/8741)

## mbedTLS and CURLE_AGAIN handling

[curl issue 15801](https://github.com/curl/curl/issues/15801)

# Email protocols

## IMAP `SEARCH ALL` truncated response

IMAP `SEARCH ALL` truncates output on large boxes. "A quick search of the code
reveals that `pingpong.c` contains some truncation code, at line 408, when it
deems the server response to be too large truncating it to 40 characters"

https://curl.se/bug/view.cgi?id=1366

## No disconnect command

The disconnect commands (`LOGOUT` and `QUIT`) may not be sent by IMAP, POP3
and SMTP if a failure occurs during the authentication phase of a connection.

## `AUTH PLAIN` for SMTP is not working on all servers

Specifying `--login-options AUTH=PLAIN` on the command line does not seem to
work correctly.

See [curl issue 4080](https://github.com/curl/curl/issues/4080)

## `APOP` authentication fails on POP3

See [curl issue 10073](https://github.com/curl/curl/issues/10073)

## POP3 issue when reading small chunks

    CURL_DBG_SOCK_RMAX=4 ./runtests.pl -v 982

See [curl issue 12063](https://github.com/curl/curl/issues/12063)

# Command line

## `-T /dev/stdin` may upload with an incorrect content length

`-T` stats the path to figure out its size in bytes to use it as
`Content-Length` if it is a regular file.

The problem with that is that on BSD and some other UNIX systems (not Linux),
open(path) may not give you a file descriptor with a 0 offset from the start
of the file.

See [curl issue 12177](https://github.com/curl/curl/issues/12177)

## `-T -` always uploads chunked

When the `<` shell operator is used. curl should realize that stdin is a
regular file in this case, and that it can do a non-chunked upload, like it
would do if you used `-T` file.

See [curl issue 12171](https://github.com/curl/curl/issues/12171)

# Build and portability issues

## OS400 port requires deprecated IBM library

curl for OS400 requires `QADRT` to build, which provides ASCII wrappers for
libc/POSIX functions in the ILE, but IBM no longer supports or even offers
this library to download.

See [curl issue 5176](https://github.com/curl/curl/issues/5176)

## `curl-config --libs` contains private details

`curl-config --libs` include details set in `LDFLAGS` when configure is run
that might be needed only for building libcurl. Further, `curl-config
--cflags` suffers from the same effects with `CFLAGS`/`CPPFLAGS`.

## `LDFLAGS` passed too late making libs linked incorrectly

Compiling latest curl on HP-UX and linking against a custom OpenSSL (which is
on the default loader/linker path), fails because the generated Makefile has
`LDFLAGS` passed on after `LIBS`.

See [curl issue 14893](https://github.com/curl/curl/issues/14893)

## Cygwin: make install installs curl-config.1 twice

[curl issue 8839](https://github.com/curl/curl/issues/8839)

## flaky CI builds

We run many CI builds for each commit and PR on GitHub, and especially a
number of the Windows builds are flaky. This means that we rarely get all CI
builds go green and complete without errors. This is unfortunate as it makes
us sometimes miss actual build problems and it is surprising to newcomers to
the project who (rightfully) do not expect this.

See [curl issue 6972](https://github.com/curl/curl/issues/6972)

## long paths are not fully supported on Windows

curl on Windows cannot access long paths (paths longer than 260 characters).
However, as a workaround, the Windows path prefix `\\?\` which disables all
path interpretation may work to allow curl to access the path. For example:
`\\?\c:\longpath`.

See [curl issue 8361](https://github.com/curl/curl/issues/8361)

## Unicode on Windows

Passing in a Unicode filename with -o:

[curl issue 11461](https://github.com/curl/curl/issues/11461)

Passing in Unicode character with -d:

[curl issue 12231](https://github.com/curl/curl/issues/12231)

Windows Unicode builds use the home directory in current locale.

The Windows Unicode builds of curl use the current locale, but expect Unicode
UTF-8 encoded paths for internal use such as open, access and stat. The user's
home directory is retrieved via curl_getenv in the current locale and not as
UTF-8 encoded Unicode.

See [curl pull request 7252](https://github.com/curl/curl/pull/7252) and [curl pull request 7281](https://github.com/curl/curl/pull/7281)

Cannot handle Unicode arguments in non-Unicode builds on Windows

If a URL or filename cannot be encoded using the user's current code page then
it can only be encoded properly in the Unicode character set. Windows uses
UTF-16 encoding for Unicode and stores it in wide characters, however curl and
libcurl are not equipped for that at the moment except when built with
_UNICODE and UNICODE defined. Except for Cygwin, Windows cannot use UTF-8 as a
locale.

https://curl.se/bug/?i=345
https://curl.se/bug/?i=731
https://curl.se/bug/?i=3747

NTLM authentication and Unicode

NTLM authentication involving Unicode username or password only works properly
if built with UNICODE defined together with the Schannel backend. The original
problem was mentioned in: https://curl.se/mail/lib-2009-10/0024.html and
https://curl.se/bug/view.cgi?id=896

The Schannel version verified to work as mentioned in
https://curl.se/mail/lib-2012-07/0073.html

# Authentication

## Digest `auth-int` for PUT/POST

We do not support auth-int for Digest using PUT or POST

## MIT Kerberos for Windows build

libcurl fails to build with MIT Kerberos for Windows (`KfW`) due to its
library header files exporting symbols/macros that should be kept private to
the library.

## NTLM in system context uses wrong name

NTLM authentication using SSPI (on Windows) when (lib)curl is running in
"system context" makes it use wrong(?) username - at least when compared to
what `winhttp` does. See https://curl.se/bug/view.cgi?id=535

## NTLM does not support password with Unicode 'SECTION SIGN' character

Code point: U+00A7

https://en.wikipedia.org/wiki/Section_sign
[curl issue 2120](https://github.com/curl/curl/issues/2120)

## libcurl can fail to try alternatives with `--proxy-any`

When connecting via a proxy using `--proxy-any`, a failure to establish an
authentication causes libcurl to abort trying other options if the failed
method has a higher preference than the alternatives. As an example,
`--proxy-any` against a proxy which advertise Negotiate and NTLM, but which
fails to set up Kerberos authentication does not proceed to try authentication
using NTLM.

[curl issue 876](https://github.com/curl/curl/issues/876)

## Do not clear digest for single realm

[curl issue 3267](https://github.com/curl/curl/issues/3267)

## SHA-256 digest not supported in Windows SSPI builds

Windows builds of curl that have SSPI enabled use the native Windows API calls
to create authentication strings. The call to `InitializeSecurityContext` fails
with `SEC_E_QOP_NOT_SUPPORTED` which causes curl to fail with
`CURLE_AUTH_ERROR`.

Microsoft does not document supported digest algorithms and that `SEC_E` error
code is not a documented error for `InitializeSecurityContext` (digest).

[curl issue 6302](https://github.com/curl/curl/issues/6302)

## curl never completes Negotiate over HTTP

Apparently it is not working correctly...?

See [curl issue 5235](https://github.com/curl/curl/issues/5235)

## Negotiate on Windows fails

When using `--negotiate` (or NTLM) with curl on Windows, SSL/TLS handshake
fails despite having a valid kerberos ticket cached. Works without any issue
in Unix/Linux.

[curl issue 5881](https://github.com/curl/curl/issues/5881)

## Negotiate authentication against Hadoop

[curl issue 8264](https://github.com/curl/curl/issues/8264)

# FTP

## FTP with ACCT

When doing an operation over FTP that requires the `ACCT` command (but not when
logging in), the operation fails since libcurl does not detect this and thus
fails to issue the correct command: https://curl.se/bug/view.cgi?id=635

## FTPS server compatibility on Windows with Schannel

FTPS is not widely used with the Schannel TLS backend and so there may be more
bugs compared to other TLS backends such as OpenSSL. In the past users have
reported hanging and failed connections. It is likely some changes to curl
since then fixed the issues. None of the reported issues can be reproduced any
longer.

If you encounter an issue connecting to your server via FTPS with the latest
curl and Schannel then please search for open issues or file a new issue.

# SFTP and SCP

## SFTP does not do `CURLOPT_POSTQUOTE` correct

When libcurl sends `CURLOPT_POSTQUOTE` commands when connected to an SFTP
server using the multi interface, the commands are not being sent correctly
and instead the connection is canceled (the operation is considered done)
prematurely. There is a half-baked (busy-looping) patch provided in the bug
report but it cannot be accepted as-is. See
https://curl.se/bug/view.cgi?id=748

## Remote recursive folder creation with SFTP

On this servers, the curl fails to create directories on the remote server
even when the `CURLOPT_FTP_CREATE_MISSING_DIRS` option is set.

See [curl issue 5204](https://github.com/curl/curl/issues/5204)

## libssh blocking and infinite loop problem

In the `SSH_SFTP_INIT` state for libssh, the ssh session working mode is set
to blocking mode. If the network is suddenly disconnected during sftp
transmission, curl is stuck, even if curl is configured with a timeout.

[curl issue 8632](https://github.com/curl/curl/issues/8632)

## Cygwin: "WARNING: UNPROTECTED PRIVATE KEY FILE!"

Running SCP and SFTP tests on Cygwin makes this warning message appear.

[curl issue 11244](https://github.com/curl/curl/issues/11244)

# Connection

## `--interface` with link-scoped IPv6 address

When you give the `--interface` option telling curl to use a specific
interface for its outgoing traffic in combination with an IPv6 address in the
URL that uses a link-local scope, curl might pick the wrong address from the
named interface and the subsequent transfer fails.

Example command line:

    curl --interface eth0 'http://[fe80:928d:xxff:fexx:xxxx]/'

The fact that the given IP address is link-scoped should probably be used as
input to somehow make curl make a better choice for this.

[curl issue 14782](https://github.com/curl/curl/issues/14782)

## Does not acknowledge getaddrinfo sorting policy

Even if a user edits `/etc/gai.conf` to prefer IPv4, curl still prefers and
tries IPv6 addresses first.

[curl issue 16718](https://github.com/curl/curl/issues/16718)

## SOCKS-SSPI discards the security context

After a successful SSPI/GSS-API exchange, the function queries and logs the
authenticated username and reports the supported data-protection level, but
then immediately deletes the negotiated SSPI security context and frees the
credentials before returning. The negotiated context is not stored on the
connection and is therefore never used to protect later SOCKS5 traffic.

## cannot use absolute Unix domain filename for SOCKS on Windows

curl supports using a Unix domain socket path for speaking SOCKS to a proxy,
by providing a filename in the URL used for `-x` (`CURLOPT_PROXY`), but that
path cannot be a proper absolute Windows path with a drive letter etc.

A solution for this probably requires that we add and provide a
`--unix-socket` (`CURLOPT_UNIX_SOCKET_PATH`) option alternative for proxy
communication.

See [curl issue 19825](https://github.com/curl/curl/issues/19825)

# Internals

## GSSAPI library name + version is missing in `curl_version_info()`

The struct needs to be expanded and code added to store this info.

See [curl issue 13492](https://github.com/curl/curl/issues/13492)

## error buffer not set if connection to multiple addresses fails

If you ask libcurl to resolve a hostname like example.com to IPv6 addresses
when you only have IPv4 connectivity. libcurl fails with
`CURLE_COULDNT_CONNECT`, but the error buffer set by `CURLOPT_ERRORBUFFER`
remains empty. Issue: [curl issue 544](https://github.com/curl/curl/issues/544)

## HTTP test server 'connection-monitor' problems

The `connection-monitor` feature of the HTTP test server does not work
properly if some tests are run in unexpected order. Like 1509 and then 1525.

See [curl issue 868](https://github.com/curl/curl/issues/868)

## Connection information when using TCP Fast Open

`CURLINFO_LOCAL_PORT` (and possibly a few other) fails when TCP Fast Open is
enabled.

See [curl issue 1332](https://github.com/curl/curl/issues/1332) and
[curl issue 4296](https://github.com/curl/curl/issues/4296)

## test cases sometimes timeout

Occasionally, one of the tests timeouts. Inexplicably.

See [curl issue 13350](https://github.com/curl/curl/issues/13350)

## `CURLOPT_CONNECT_TO` does not work for HTTPS proxy

It is unclear if the same option should even cover the proxy connection or if
if requires a separate option.

See [curl issue 14481](https://github.com/curl/curl/issues/14481)

## WinIDN test failures

Test 165 disabled when built with WinIDN.

## setting a disabled option should return `CURLE_NOT_BUILT_IN`

When curl has been built with specific features or protocols disabled, setting
such options with `curl_easy_setopt()` should rather return
`CURLE_NOT_BUILT_IN` instead of `CURLE_UNKNOWN_OPTION` to signal the
difference to the application

See [curl issue 15472](https://github.com/curl/curl/issues/15472)

# LDAP

## OpenLDAP hangs after returning results

By configuration defaults, OpenLDAP automatically chase referrals on secondary
socket descriptors. The OpenLDAP backend is asynchronous and thus should
monitor all socket descriptors involved. Currently, these secondary
descriptors are not monitored, causing OpenLDAP library to never receive data
from them.

As a temporary workaround, disable referrals chasing by configuration.

The fix is not easy: proper automatic referrals chasing requires a synchronous
bind callback and monitoring an arbitrary number of socket descriptors for a
single easy handle (currently limited to 5).

Generic LDAP is synchronous: OK.

See [curl issue 622](https://github.com/curl/curl/issues/622) and
https://curl.se/mail/lib-2016-01/0101.html

## LDAP on Windows does authentication wrong?

[curl issue 3116](https://github.com/curl/curl/issues/3116)

## LDAP on Windows does not work

A simple curl command line getting `ldap://ldap.forumsys.com` returns an error
that says `no memory` !

[curl issue 4261](https://github.com/curl/curl/issues/4261)

## LDAPS requests to Active Directory server hang

[curl issue 9580](https://github.com/curl/curl/issues/9580)

# TCP/IP

## telnet code does not handle partial writes properly

It probably does not happen too easily because of how slow and infrequent
sends are normally performed.

## Trying local ports fails on Windows

This makes `--local-port [range]` to not work since curl cannot properly
detect if a port is already in use, so it tries the first port, uses that and
then subsequently fails anyway if that was actually in use.

[curl issue 8112](https://github.com/curl/curl/issues/8112)

# CMake

## cmake outputs: no version information available

Something in the SONAME generation seems to be wrong in the cmake build.

[curl issue 11158](https://github.com/curl/curl/issues/11158)

## uses `-lpthread` instead of `Threads::Threads`

See [curl issue 6166](https://github.com/curl/curl/issues/6166)

## generated `.pc` file contains strange entries

The `Libs.private` field of the generated `.pc` file contains `-lgcc -lgcc_s
-lc -lgcc -lgcc_s`.

See [curl issue 6167](https://github.com/curl/curl/issues/6167)

## CMake build with MIT Kerberos does not work

Minimum CMake version was bumped in curl 7.71.0 (#5358) Since CMake 3.2
try_compile started respecting the `CMAKE_EXE_FLAGS`. The code dealing with
MIT Kerberos detection sets few variables to potentially weird mix of space,
and ;-separated flags. It had to blow up at some point. All the CMake checks
that involve compilation are doomed from that point, the configured tree
cannot be built.

[curl issue 6904](https://github.com/curl/curl/issues/6904)

# Authentication

## `--aws-sigv4` does not handle multipart/form-data correctly

[curl issue 13351](https://github.com/curl/curl/issues/13351)

# HTTP/2

## HTTP/2 prior knowledge over proxy

[curl issue 12641](https://github.com/curl/curl/issues/12641)

## HTTP/2 frames while in the connection pool kill reuse

If the server sends HTTP/2 frames (like for example an HTTP/2 PING frame) to
curl while the connection is held in curl's connection pool, the socket is
found readable when considered for reuse and that makes curl think it is dead
and then it is closed and a new connection gets created instead.

This is *best* fixed by adding monitoring to connections while they are kept
in the pool so that pings can be responded to appropriately.

## `ENHANCE_YOUR_CALM` causes infinite retries

Infinite retries with 2 parallel requests on one connection receiving `GOAWAY`
with `ENHANCE_YOUR_CALM` error code.

See [curl issue 5119](https://github.com/curl/curl/issues/5119)

## HTTP/2 + TLS spends a lot of time in recv

It has been observed that by making the speed limit less accurate we could
improve this performance. (by reverting
[db5c9f4f9e0779](https://github.com/curl/curl/commit/db5c9f4f9e0779b49624752b135281a0717b277b))
Can we find a golden middle ground?

See https://curl.se/mail/lib-2024-05/0026.html and
[curl issue 13416](https://github.com/curl/curl/issues/13416)

# HTTP/3

## connection migration does not work

[curl issue 7695](https://github.com/curl/curl/issues/7695)

## quiche: QUIC connection is draining

The transfer ends with error "QUIC connection is draining".

[curl issue 12037](https://github.com/curl/curl/issues/12037)

# RTSP

## Some methods do not support response bodies

The RTSP implementation is written to assume that a number of RTSP methods
always get responses without bodies, even though there seems to be no
indication in the RFC that this is always the case.

[curl issue 12414](https://github.com/curl/curl/issues/12414)
