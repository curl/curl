---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Long: delegation
Arg: <LEVEL>
Help: GSS-API delegation permission
Protocols: GSS/kerberos
Category: auth
Added: 7.22.0
Multi: single
See-also:
  - insecure
  - ssl
Example:
  - --delegation "none" $URL
---

# `--delegation`

Set LEVEL to tell the server what it is allowed to delegate when it
comes to user credentials.

## none
Do not allow any delegation.

## policy
Delegates if and only if the OK-AS-DELEGATE flag is set in the Kerberos
service ticket, which is a matter of realm policy.

## always
Unconditionally allow the server to delegate.
