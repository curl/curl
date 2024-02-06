---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Long: pubkey
Arg: <key>
Protocols: SFTP SCP
Help: SSH Public key file name
Category: sftp scp auth
Added: 7.16.2
Multi: single
See-also:
  - pass
Example:
  - --pubkey file.pub sftp://example.com/
---

# `--pubkey`

Public key file name. Allows you to provide your public key in this separate
file.

curl attempts to automatically extract the public key from the private key
file, so passing this option is generally not required. Note that this public
key extraction requires libcurl to be linked against a copy of libssh2 1.2.8
or higher that is itself linked against OpenSSL. (Added in 7.39.0.)
