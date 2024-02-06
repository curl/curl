<!-- Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al. -->
<!-- SPDX-License-Identifier: curl -->
# GLOBBING
You can specify multiple URLs or parts of URLs by writing lists within braces
or ranges within brackets. We call this "globbing".

Provide a list with three different names like this:

    "http://site.{one,two,three}.com"

Do sequences of alphanumeric series by using [] as in:

    "ftp://ftp.example.com/file[1-100].txt"

With leading zeroes:

    "ftp://ftp.example.com/file[001-100].txt"

With letters through the alphabet:

    "ftp://ftp.example.com/file[a-z].txt"

Nested sequences are not supported, but you can use several ones next to each
other:

    "http://example.com/archive[1996-1999]/vol[1-4]/part{a,b,c}.html"

You can specify a step counter for the ranges to get every Nth number or
letter:

    "http://example.com/file[1-100:10].txt"

    "http://example.com/file[a-z:2].txt"

When using [] or {} sequences when invoked from a command line prompt, you
probably have to put the full URL within double quotes to avoid the shell from
interfering with it. This also goes for other characters treated special, like
for example '&', '?' and '*'.

Switch off globbing with --globoff.
