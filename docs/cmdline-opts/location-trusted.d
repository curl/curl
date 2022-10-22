c: Copyright (C) 1998 - 2022, Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Long: location-trusted
Help: Like --location, and send auth to other hosts
Protocols: HTTP
See-also: user
Category: http auth
Example: --location-trusted -u user:password $URL
Added: 7.10.4
Multi: boolean
---
Like --location, but will allow sending the name + password to all hosts that
the site may redirect to. This may or may not introduce a security breach if
the site redirects you to a site to which you will send your authentication
info (which is plaintext in the case of HTTP Basic authentication).
