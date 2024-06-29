---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Long: proxy-capath
Help: CA directory to verify proxy against
Arg: <dir>
Added: 7.52.0
Category: proxy tls
Multi: single
See-also:
  - proxy-cacert
  - proxy
  - capath
  - dump-ca-embed
Example:
  - --proxy-capath /local/directory -x https://proxy $URL
---

# `--proxy-capath`

Same as --capath but used in HTTPS proxy context.

Use the specified certificate directory to verify the proxy. Multiple paths
can be provided by separated with colon (`:`) (e.g. `path1:path2:path3`). The
certificates must be in PEM format, and if curl is built against OpenSSL, the
directory must have been processed using the c_rehash utility supplied with
OpenSSL. Using --proxy-capath can allow OpenSSL-powered curl to make
SSL-connections much more efficiently than using --proxy-cacert if the
--proxy-cacert file contains many CA certificates.

If this option is set, the default capath value is ignored.
