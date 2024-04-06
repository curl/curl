---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Long: ftp-pasv
Help: Send PASV/EPSV instead of PORT
Protocols: FTP
Added: 7.11.0
Category: ftp
Multi: boolean
See-also:
  - disable-epsv
Example:
  - --ftp-pasv ftp://example.com/
---

# `--ftp-pasv`

Use passive mode for the data connection. Passive is the internal default
behavior, but using this option can be used to override a previous --ftp-port
option.

Reversing an enforced passive really is not doable but you must then instead
enforce the correct --ftp-port again.

Passive mode means that curl tries the EPSV command first and then PASV,
unless --disable-epsv is used.
