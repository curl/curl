---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Long: spnego-fail-on-error
Help: Fail on SPNEGO authentication errors
Protocols: HTTP
Category: auth http
Added: 8.14.0
Multi: boolean
See-also:
  - negotiate
  - proxy-negotiate
Example:
  - --spnego-fail-on-error --negotiate -u : $URL
---

# `--spnego-fail-on-error`

Fail with an error if SPNEGO (Negotiate) authentication fails, instead of
continuing unauthenticated. By default, when SPNEGO authentication cannot
proceed (for example, no Kerberos ticket available or the negotiated mechanism
is disallowed), curl silently continues without authentication.

When this option is set, curl returns **CURLE_AUTH_ERROR** (exit code 94)
on SPNEGO failures.
