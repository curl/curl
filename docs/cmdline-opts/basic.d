c: Copyright (C) 1998 - 2022, Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Long: basic
Help: Use HTTP Basic Authentication
See-also: proxy-basic
Protocols: HTTP
Category: auth
Example: -u name:password --basic $URL
Added: 7.10.6
---
Tells curl to use HTTP Basic authentication with the remote host. This is the
default and this option is usually pointless, unless you use it to override a
previously set option that sets a different authentication method (such as
--ntlm, --digest, or --negotiate).

Used together with --user.
