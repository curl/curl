---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Long: anyauth
Help: Pick any authentication method
Protocols: HTTP
Category: http proxy auth
Added: 7.10.6
Multi: custom
See-also:
  - proxy-anyauth
  - basic
  - digest
Example:
  - --anyauth --user me:pwd $URL
---

# `--anyauth`

Figure out authentication method automatically, and use the most secure one
the remote site claims to support. This is done by first doing a request and
checking the response-headers, thus possibly inducing an extra network
round-trip. This option is used instead of setting a specific authentication
method, which you can do with --basic, --digest, --ntlm, and --negotiate.

Using --anyauth is not recommended if you do uploads from stdin, since it may
require data to be sent twice and then the client must be able to rewind. If
the need should arise when uploading from stdin, the upload operation fails.

Used together with --user.
