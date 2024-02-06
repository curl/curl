---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Long: insecure
Short: k
Help: Allow insecure server connections
Protocols: TLS SFTP SCP
Category: tls sftp scp
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

By default, every secure connection curl makes is verified to be secure before
the transfer takes place. This option makes curl skip the verification step
and proceed without checking.

When this option is not used for protocols using TLS, curl verifies the
server's TLS certificate before it continues: that the certificate contains
the right name which matches the host name used in the URL and that the
certificate has been signed by a CA certificate present in the cert store.
See this online resource for further details:
**https://curl.se/docs/sslcerts.html**

For SFTP and SCP, this option makes curl skip the *known_hosts* verification.
*known_hosts* is a file normally stored in the user's home directory in the
".ssh" subdirectory, which contains host names and their public keys.

**WARNING**: using this option makes the transfer insecure.

When curl uses secure protocols it trusts responses and allows for example
HSTS and Alt-Svc information to be stored and used subsequently. Using
--insecure can make curl trust and use such information from malicious
servers.
