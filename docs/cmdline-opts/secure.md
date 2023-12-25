---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Long: secure
Protocols: TLS SFTP SCP
Help: Enforce secure server connections
Arg: <name>
Added: 8.7.0
Category: tls sftp scp
Multi: custom
See-also:
  - insecure
  - doh-insecure
  - proxy-insecure
Example:
  - --secure $URL
---

# `--secure`

By default, curl wants to connect securely. It is possible to override this
with the `--insecure`, `--proxy-insecure` and `--doh-insecure` options and
allow connecting insecurely.

When this option is set anywhere in the curl configuration, it will override
all above options and ensure to try connecting securely.
