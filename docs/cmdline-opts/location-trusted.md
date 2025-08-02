---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Long: location-trusted
Help: As --location, but send secrets to other hosts
Protocols: HTTP
Category: http auth
Added: 7.10.4
Multi: boolean
See-also:
  - user
  - follow
Example:
  - --location-trusted -u user:password $URL
  - --location-trusted -H "Cookie: session=abc" $URL
---

# `--location-trusted`

Instruct curl to follow HTTP redirects like --location, but permit curl to
send credentials and other secrets along to other hosts than the initial one.

This may or may not introduce a security breach if the site redirects you to a
site to which you send this sensitive data to. Another host means that one or
more of hostname, protocol scheme or port number changed.

This option also allows curl to pass long cookies set explicitly with --header.
