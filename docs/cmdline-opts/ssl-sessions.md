---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Long: ssl-sessions
Arg: <filename>
Protocols: TLS
Help: Load/save SSL session tickets from/to this file
Added: 8.12.0
Category: tls
Multi: single
See-also:
  - tls-earlydata
Example:
  - --ssl-sessions sessions.txt $URL
---

# `--ssl-sessions`

Use the given file to load SSL session tickets into curl's cache before
starting any transfers. At the end of a successful curl run, the cached
SSL sessions tickets are saved to the file, replacing any previous content.

The file does not have to exist, but curl reports an error if it is
unable to create it. Unused loaded tickets are saved again, unless they
get replaced or purged from the cache for space reasons.

Using a session file allows `--tls-earlydata` to send the first request
in "0-RTT" mode, should an SSL session with the feature be found. Note that
a server may not support early data. Also note that early data does
not provide forward secrecy, e.g. is not as secure.

The SSL session tickets are stored as base64 encoded text, each ticket on
its own line. The hostnames are cryptographically salted and hashed. While
this prevents someone from easily seeing the hosts you contacted, they could
still check if a specific hostname matches one of the values.

This feature requires that the underlying libcurl was built with the
experimental SSL session import/export feature (SSLS-EXPORT) enabled.
