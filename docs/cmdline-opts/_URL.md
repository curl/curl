<!-- Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al. -->
<!-- SPDX-License-Identifier: curl -->
# URL
The URL syntax is protocol-dependent. You find a detailed description in
RFC 3986.

If you provide a URL without a leading **protocol://** scheme, curl guesses
what protocol you want. It then defaults to HTTP but assumes others based on
often-used hostname prefixes. For example, for hostnames starting with `ftp.`
curl assumes you want FTP.

You can specify any amount of URLs on the command line. They are fetched in a
sequential manner in the specified order unless you use --parallel. You can
specify command line options and URLs mixed and in any order on the command
line.

curl attempts to reuse connections when doing multiple transfers, so that
getting many files from the same server do not use multiple connects and setup
handshakes. This improves speed. Connection reuse can only be done for URLs
specified for a single command line invocation and cannot be performed between
separate curl runs.

Provide an IPv6 zone id in the URL with an escaped percentage sign. Like in

    "http://[fe80::3%25eth0]/"

Everything provided on the command line that is not a command line option or
its argument, curl assumes is a URL and treats it as such.
