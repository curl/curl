---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Long: referer
Short: e
Arg: <URL>
Protocols: HTTP
Help: Referrer URL
Category: http
Added: 4.0
Multi: single
See-also:
  - user-agent
  - header
Example:
  - --referer "https://fake.example" $URL
  - --referer "https://fake.example;auto" -L $URL
  - --referer ";auto" -L $URL
---

# `--referer`

Set the referrer URL in the HTTP request. This can also be set with the
--header flag of course. When used with --location you can append `;auto`" to
the --referer URL to make curl automatically set the previous URL when it
follows a Location: header. The `;auto` string can be used alone, even if you
do not set an initial --referer.
