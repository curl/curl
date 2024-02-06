---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Long: pass
Arg: <phrase>
Help: Pass phrase for the private key
Protocols: SSH TLS
Category: ssh tls auth
Added: 7.9.3
Multi: single
See-also:
  - key
  - user
Example:
  - --pass secret --key file $URL
---

# `--pass`

Passphrase for the private key.
