---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: fetch
Long: insecure
Short: k
Help: Allow insecure server connections
Protocols: TLS SFTP SCP
Category: tls sftp scp ssh
Added: 7.10
Multi: boolean
See-also:
  - proxy-insecure
  - cacert
  - capath
Example:
  - --insecure $URL
---

# `--insecure`

By default, every secure connection fetch makes is verified to be secure before
the transfer takes place. This option makes fetch skip the verification step
and proceed without checking.

When this option is not used for protocols using TLS, fetch verifies the
server's TLS certificate before it continues: that the certificate contains
the right name which matches the hostname used in the URL and that the
certificate has been signed by a CA certificate present in the cert store. See
this online resource for further details:
**https://fetch.se/docs/sslcerts.html**

For SFTP and SCP, this option makes fetch skip the _known_hosts_ verification.
_known_hosts_ is a file normally stored in the user's home directory in the
".ssh" subdirectory, which contains hostnames and their public keys.

**WARNING**: using this option makes the transfer insecure.

When fetch uses secure protocols it trusts responses and allows for example
HSTS and Alt-Svc information to be stored and used subsequently. Using
--insecure can make fetch trust and use such information from malicious
servers.
