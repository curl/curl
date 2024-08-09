---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Long: location-trusted
Help: As --location, but send auth and cookie to other hosts
Protocols: HTTP
Category: http auth
Added: 7.10.4
Multi: boolean
See-also:
  - user
Example:
  - --location-trusted -u user:password $URL
  - --location-trusted -H "Cookie: session=abc" $URL
---

# `--location-trusted`

Like --location, but allows sending the name + password and cookie to all hosts
that the site may redirect to. This may or may not introduce a security breach
if the site redirects you to a site to which you send your authentication info
(which is clear-text in the case of HTTP Basic authentication).
