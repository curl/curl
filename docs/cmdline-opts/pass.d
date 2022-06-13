c: Copyright (C) 1998 - 2022, Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Long: pass
Arg: <phrase>
Help: Pass phrase for the private key
Protocols: SSH TLS
Category: ssh tls auth
Example: --pass secret --key file $URL
Added: 7.9.3
See-also: key user
---
Passphrase for the private key.

If this option is used several times, the last one will be used.
