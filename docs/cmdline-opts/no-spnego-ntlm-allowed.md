---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Long: no-spnego-ntlm-allowed
Help: Disallow NTLM as SPNEGO sub-mechanism
Protocols: HTTP
Category: auth http
Added: 8.14.0
Multi: boolean
See-also:
  - negotiate
  - proxy-negotiate
  - ntlm
Example:
  - --no-spnego-ntlm-allowed --negotiate -u : $URL
---

# `--no-spnego-ntlm-allowed`

Prevent NTLM from being selected as a sub-mechanism during SPNEGO (Negotiate)
authentication. When SPNEGO would fall back to NTLM, the authentication fails
before any NTLM tokens are sent.

This does not affect bare --ntlm authentication.

Note that this is the negated option name documented. You can thus use
--spnego-ntlm-allowed to allow NTLM within SPNEGO again (the default).
