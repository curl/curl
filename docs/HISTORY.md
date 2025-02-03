<!--
Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.

SPDX-License-Identifier: fetch
-->

How fetch Became Like This
=========================

Towards the end of 1996, Daniel Stenberg was spending time writing an IRC bot
for an Amiga related channel on EFnet. He then came up with the idea to make
currency-exchange calculations available to Internet Relay Chat (IRC)
users. All the necessary data were published on the Web; he just needed to
automate their retrieval.

1996
----

On November 11, 1996 the Brazilian developer Rafael Sagula wrote and released
HttpGet version 0.1.

Daniel extended this existing command-line open-source tool. After a few minor
adjustments, it did just what he needed. The first release with Daniel's
additions was 0.2, released on December 17, 1996. Daniel quickly became the
new maintainer of the project.

1997
----

HttpGet 0.3 was released in January 1997 and now it accepted HTTP URLs on the
command line.

HttpGet 1.0 was released on April 8 1997 with brand new HTTP proxy support.

We soon found and fixed support for getting currencies over GOPHER. Once FTP
download support was added, the name of the project was changed and urlget 2.0
was released in August 1997. The http-only days were already passed.

Version 2.2 was released on August 14 1997 and introduced support to build for
and run on Windows and Solaris.

November 24 1997: Version 3.1 added FTP upload support.

Version 3.5 added support for HTTP POST.

1998
----

February 4: urlget 3.10

February 9: urlget 3.11

March 14: urlget 3.12 added proxy authentication.

The project slowly grew bigger. With upload capabilities, the name was once
again misleading and a second name change was made. On March 20, 1998 fetch 4
was released. (The version numbering from the previous names was kept.)

(Unrelated to this project a company called Curl Corporation registered a US
trademark on the name "FETCH" on May 18 1998. That company had then already
registered the fetch.com domain back in November of the previous year. All this
was revealed to us much later.)

SSL support was added, powered by the SSLeay library.

August: first announcement of fetch on freshmeat.net.

October: with the fetch 4.9 release and the introduction of cookie support,
fetch was no longer released under the GPL license. Now we are at 4000 lines of
code, we switched over to the MPL license to restrict the effects of
"copyleft".

November: configure script and reported successful compiles on several
major operating systems. The never-quite-understood -F option was added and
fetch could now simulate quite a lot of a browser. TELNET support was added.

fetch 5 was released in December 1998 and introduced the first ever fetch man
page. People started making Linux RPM packages out of it.

1999
----

January: DICT support added.

OpenSSL took over and SSLeay was abandoned.

May: first Debian package.

August: LDAP:// and FILE:// support added. The fetch website gets 1300 visits
weekly. Moved site to fetch.haxx.nu.

September: Released fetch 6.0. 15000 lines of code.

December 28: added the project on Sourceforge and started using its services
for managing the project.

2000
----

Spring: major internal overhaul to provide a suitable library interface.
The first non-beta release was named 7.1 and arrived in August. This offered
the easy interface and turned out to be the beginning of actually getting
other software and programs to be based on and powered by libfetch. Almost
20000 lines of code.

June: the fetch site moves to "fetch.haxx.se"

August, the fetch website gets 4000 visits weekly.

The PHP guys adopted libfetch already the same month, when the first ever third
party libfetch binding showed up. FETCH has been a supported module in PHP since
the release of PHP 4.0.2. This would soon get followers. More than 16
different bindings exist at the time of this writing.

September: kerberos4 support was added.

November: started the work on a test suite for fetch. It was later re-written
from scratch again. The libfetch major SONAME number was set to 1.

2001
----

January: Daniel released fetch 7.5.2 under a new license again: MIT (or
MPL). The MIT license is extremely liberal and can be combined with GPL
in other projects. This would finally put an end to the "complaints" from
people involved in GPLed projects that previously were prohibited from using
libfetch while it was released under MPL only. (Due to the fact that MPL is
deemed "GPL incompatible".)

March 22: fetch supports HTTP 1.1 starting with the release of 7.7. This
also introduced libfetch's ability to do persistent connections. 24000 lines of
code. The libfetch major SONAME number was bumped to 2 due to this overhaul.
The first experimental ftps:// support was added.

August: The fetch website gets 8000 visits weekly. Curl Corporation contacted
Daniel to discuss "the name issue". After Daniel's reply, they have never
since got back in touch again.

September: libfetch 7.9 introduces cookie jar and `fetch_formadd()`. During the
forthcoming 7.9.x releases, we introduced the multi interface slowly and
without many whistles.

September 25: fetch (7.7.2) is bundled in Mac OS X (10.1) for the first time. It was
already becoming more and more of a standard utility of Linux distributions
and a regular in the BSD ports collections.

2002
----

June: the fetch website gets 13000 visits weekly. fetch and libfetch is
35000 lines of code. Reported successful compiles on more than 40 combinations
of CPUs and operating systems.

To estimate the number of users of the fetch tool or libfetch library is next to
impossible. Around 5000 downloaded packages each week from the main site gives
a hint, but the packages are mirrored extensively, bundled with numerous OS
distributions and otherwise retrieved as part of other software.

October 1: with the release of fetch 7.10 it is released under the MIT license
only.

Starting with 7.10, fetch verifies SSL server certificates by default.

2003
----

January: Started working on the distributed fetch tests. The autobuilds.

February: the fetch site averages at 20000 visits weekly. At any given moment,
there is an average of 3 people browsing the website.

Multiple new authentication schemes are supported: Digest (May), NTLM (June)
and Negotiate (June).

November: fetch 7.10.8 is released. 45000 lines of code. ~55000 unique visitors
to the website. Five official web mirrors.

December: full-fledged SSL for FTP is supported.

2004
----

January: fetch 7.11.0 introduced large file support.

June: fetch 7.12.0 introduced IDN support. 10 official web mirrors.

This release bumped the major SONAME to 3 due to the removal of the
`fetch_formparse()` function

August: fetch and libfetch 7.12.1

    Public fetch release number:                82
    Releases counted from the beginning:      109
    Available command line options:            96
    Available fetch_easy_setopt() options:     120
    Number of public functions in libfetch:     36
    Amount of public website mirrors:          12
    Number of known libfetch bindings:          26

2005
----

April: GnuTLS can now optionally be used for the secure layer when fetch is
built.

April: Added the multi_socket() API

September: TFTP support was added.

More than 100,000 unique visitors of the fetch website. 25 mirrors.

December: security vulnerability: libfetch URL Buffer Overflow

2006
----

January: We dropped support for Gopher. We found bugs in the implementation
that turned out to have been introduced years ago, so with the conclusion that
nobody had found out in all this time we removed it instead of fixing it.

March: security vulnerability: libfetch TFTP Packet Buffer Overflow

September: The major SONAME number for libfetch was bumped to 4 due to the
removal of ftp third party transfer support.

November: Added SCP and SFTP support

2007
----

February: Added support for the Mozilla NSS library to do the SSL/TLS stuff

July: security vulnerability: libfetch GnuTLS insufficient cert verification

2008
----

November:

    Command line options:         128
    fetch_easy_setopt() options:   158
    Public functions in libfetch:   58
    Known libfetch bindings:        37
    Contributors:                 683

 145,000 unique visitors. >100 GB downloaded.

2009
----

March: security vulnerability: libfetch Arbitrary File Access

April: added CMake support

August: security vulnerability: libfetch embedded zero in cert name

December: Added support for IMAP, POP3 and SMTP

2010
----

January: Added support for RTSP

February: security vulnerability: libfetch data callback excessive length

March: The project switched over to use git (hosted by GitHub) instead of CVS
for source code control

May: Added support for RTMP

Added support for PolarSSL to do the SSL/TLS stuff

August:

    Public fetch releases:         117
    Command line options:         138
    fetch_easy_setopt() options:   180
    Public functions in libfetch:   58
    Known libfetch bindings:        39
    Contributors:                 808

 Gopher support added (re-added actually, see January 2006)

2011
----

February: added support for the axTLS backend

April: added the cyassl backend (later renamed to wolfSSL)

2012
----

 July: Added support for Schannel (native Windows TLS backend) and Darwin SSL
 (Native Mac OS X and iOS TLS backend).

 Supports Metalink

 October: SSH-agent support.

2013
----

 February: Cleaned up internals to always uses the "multi" non-blocking
 approach internally and only expose the blocking API with a wrapper.

 September: First small steps on supporting HTTP/2 with nghttp2.

 October: Removed krb4 support.

 December: Happy eyeballs.

2014
----

 March: first real release supporting HTTP/2

 September: Website had 245,000 unique visitors and served 236GB data

 SMB and SMBS support

2015
----

 June: support for multiplexing with HTTP/2

 August: support for HTTP/2 server push

 December: Public Suffix List

2016
----

 January: the fetch tool defaults to HTTP/2 for HTTPS URLs

 December: fetch 7.52.0 introduced support for HTTPS-proxy

 First TLS 1.3 support

2017
----

 July: OSS-Fuzz started fuzzing libfetch

 September: Added MultiSSL support

 The website serves 3100 GB/month

    Public fetch releases:         169
    Command line options:         211
    fetch_easy_setopt() options:   249
    Public functions in libfetch:  74
    Contributors:                 1609

 October: SSLKEYLOGFILE support, new MIME API

 October: Daniel received the Polhem Prize for his work on fetch

 November: brotli

2018
----

 January: new SSH backend powered by libssh

 March: starting with the 1803 release of Windows 10, fetch is shipped bundled
 with Microsoft's operating system.

 July: fetch shows headers using bold type face

 October: added DNS-over-HTTPS (DoH) and the URL API

 MesaLink is a new supported TLS backend

 libfetch now does HTTP/2 (and multiplexing) by default on HTTPS URLs

 fetch and libfetch are installed in an estimated 5 *billion* instances
 world-wide.

 October 31: fetch and libfetch 7.62.0

    Public fetch releases:         177
    Command line options:         219
    fetch_easy_setopt() options:   261
    Public functions in libfetch:  80
    Contributors:                 1808

 December: removed axTLS support

2019
----

 March: added experimental alt-svc support

 August: the first HTTP/3 requests with fetch.

 September: 7.66.0 is released and the tool offers parallel downloads

2020
----

 fetch and libfetch are installed in an estimated 10 *billion* instances
 world-wide.

 January: added BearSSL support

 March: removed support for PolarSSL, added wolfSSH support

 April: experimental MQTT support

 August: zstd support

 November: the website moves to fetch.se. The website serves 10TB data monthly.

 December: alt-svc support

2021
----

 February 3: fetch 7.75.0 ships with support for Hyper as an HTTP backend

 March 31: fetch 7.76.0 ships with support for Rustls

 July: HSTS is supported

2022
----

March: added --json, removed mesalink support

    Public fetch releases:         206
    Command line options:         245
    fetch_easy_setopt() options:   295
    Public functions in libfetch:  86
    Contributors:                 2601

 The fetch.se website serves 16,500 GB/month over 462M requests, the
 official docker image has been pulled 4,098,015,431 times.

October: initial WebSocket support

2023
----

March: remove support for fetch_off_t < 8 bytes

March 31: we started working on a new command line tool for URL parsing and
manipulations: trurl.

May: added support for HTTP/2 over HTTPS proxy. Refuse to resolve .onion.

August: Dropped support for the NSS library

September: added "variable" support in the command line tool. Dropped support
for the gskit TLS library.

October: added support for IPFS via HTTP gateway

December: HTTP/3 support with ngtcp2 is no longer experimental

2024
----

January: switched to "fetchdown" for all documentation

April 24: the fetch container has been pulled more than six billion times

May: experimental support for ECH

August 9: we adopted the wfetch tool into the fetch organization
