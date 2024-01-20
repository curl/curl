---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Long: disable-epsv
Help: Inhibit using EPSV
Protocols: FTP
Category: ftp
Added: 7.9.2
Multi: boolean
See-also:
  - disable-eprt
  - ftp-port
Example:
  - --disable-epsv ftp://example.com/
---

# `--disable-epsv`

Tell curl to disable the use of the EPSV command when doing passive FTP
transfers. Curl normally first attempts to use EPSV before PASV, but with this
option, it does not try EPSV.

--epsv can be used to explicitly enable EPSV again and --no-epsv is an alias
for --disable-epsv.

If the server is an IPv6 host, this option has no effect as EPSV is necessary
then.

Disabling EPSV only changes the passive behavior. If you want to switch to
active mode you need to use --ftp-port.
