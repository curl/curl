---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Long: negotiate
Help: Use HTTP Negotiate (SPNEGO) authentication
Protocols: HTTP
Category: auth http
Added: 7.10.6
Multi: mutex
See-also:
  - basic
  - ntlm
  - anyauth
  - proxy-negotiate
Example:
  - --negotiate -u : $URL
---

# `--negotiate`

Enable Negotiate (SPNEGO) authentication.

This option requires a library built with GSS-API or SSPI support. Use
--version to see if your curl supports GSS-API/SSPI or SPNEGO.

When using this option, you must also provide a fake --user option to activate
the authentication code properly. Sending a '-u :' is enough as the username
and password from the --user option are not actually used.
