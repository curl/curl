<!--
Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.

SPDX-License-Identifier: curl
-->

# HTTPS RR

[RFC 9460](https://www.rfc-editor.org/rfc/rfc9460.html) documents the HTTPS
DNS Resource Record.

curl features **experimental** support for HTTPS RR.

- The ALPN list from the retrieved HTTPS record is parsed
- The ECH field is stored (when DoH is used)
- The port number from the HTTPS RR is not used
- The target name is not used
- The IP addresses from the HTTPS RR are not used
- It only supports a single HTTPS RR per hostname
- consider cases without A/AAAA records but *with* HTTPS RR
- consider service profiles where the RR provides different addresses for TCP
  vs QUIC etc

`HTTPSRR` is listed as a feature in the `curl -V` output if curl contains
HTTPS RR support. If c-ares is not included in the build, the HTTPS RR support
is limited to DoH.

`asyn-rr` is listed as a feature in the `curl -V` output if c-ares is used for
additional resolves in addition to a "normal" resolve done with the threaded
resolver.

The data extracted from the HTTPS RR is stored in the in-memory DNS cache to
be reused on subsequent uses of the same hostnames.

## limitations

We have decided to work on the HTTPS RR support by following what seems to be
(widely) used, and simply wait with implementing the details of the record
that do not seem to be deployed. HTTPS RR is a DNS field with many odd corners
and complexities and we might as well avoid them if no one seems to want them.

## build

    ./configure --enable-httpsrr

or

    cmake -DUSE_HTTPSRR=ON

## ALPN

The list of ALPN IDs is parsed but may not be completely respected because of
what the HTTP version preference is set to, which is a problem we are working
on. Also, getting an `HTTP/1.1` ALPN in the HTTPS RR field for an HTTP://
transfer should imply switching to HTTPS, HSTS style. Which curl currently
does not.

## DoH

When HTTPS RR is enabled in the curl build, The DoH code asks for an HTTPS
record in addition to the A and AAAA records, and if an HTTPS RR answer is
returned, curl parses it and stores the retrieved information.

## Non-DoH

If DoH is not used for name resolving in an HTTPS RR enabled build, we must
provide the ability using the regular resolver backends. We use the c-ares DNS
library for the HTTPS RR lookup. Version 1.28.0 or later.

### c-ares

If curl is built to use the c-ares library for name resolves, an HTTPS RR
enabled build makes a request for the HTTPS RR in addition to the regular
lookup.

### Threaded resolver

When built to use the threaded resolver, which is the default, an HTTPS RR
build still needs a c-ares installation provided so that a separate request
for the HTTPS record can be done in parallel to the regular getaddrinfo()
call.

This is done by specifying both c-ares and threaded resolver to configure:

    ./configure --enable-ares=... --enable-threaded-resolver

or to cmake:

    cmake -DENABLE_ARES=ON -DENABLE_THREADED_RESOLVER=ON

Because the HTTPS record is handled separately from the A/AAAA record
retrieval, by a separate library, there is a small risk for discrepancies.

When building curl using the threaded resolver with HTTPS RR support (using
c-ares), the `curl -V` output looks exactly like a c-ares resolver build.

## HTTPS RR Options

Because curl is a low level transfer tool for which users sometimes want
detailed control, we need to offer options to control HTTPS RR use.
