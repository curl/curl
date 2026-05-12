---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Long: httpsig-key
Protocols: HTTP
Arg: <file>
Help: Key file for HTTP Message Signatures
Category: auth http
Added: 8.21.0
Multi: single
See-also:
  - httpsig
  - httpsig-keyid
Example:
  - --httpsig ed25519 --httpsig-key key.hex --httpsig-keyid "my-key" $URL
---

# `--httpsig-key`

Path to the key file used for RFC 9421 HTTP Message Signatures.

The file must contain a hex-encoded key on its first line. For **ed25519**,
this is the 32-byte private seed (64 hex characters). For **hmac-sha256**,
this is the shared secret.
