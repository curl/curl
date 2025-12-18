---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Long: capath
Arg: <dir>
Help: CA directory to verify peer against
Protocols: TLS
Category: tls
Added: 7.9.8
Multi: single
See-also:
  - cacert
  - dump-ca-embed
  - insecure
Example:
  - --capath /local/directory $URL
---

# `--capath`

Use the specified certificate directory to verify the peer. If curl is built against
OpenSSL, multiple paths can be provided by separating them with the appropriate platform-specific
separator (e.g. `path1:path2:path3` on Unix-style platforms for `path1;path2;path3` on Windows).

The certificates must be in PEM format, and if curl is built against OpenSSL, the
directory must have been processed using the c_rehash utility supplied with
OpenSSL. Using --capath can allow OpenSSL-powered curl to make SSL-connections
much more efficiently than using --cacert if the --cacert file contains many
CA certificates.

If this option is set, the default capath value is ignored.
