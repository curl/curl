c: Copyright (C) 1998 - 2022, Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Long: digest
Help: Use HTTP Digest Authentication
Protocols: HTTP
Mutexed: basic ntlm negotiate
See-also: user proxy-digest anyauth
Category: proxy auth http
Example: -u name:password --digest $URL
Added: 7.10.6
Multi: boolean
---
Enables HTTP Digest authentication. This is an authentication scheme that
prevents the password from being sent over the wire in clear text. Use this in
combination with the normal --user option to set user name and password.
