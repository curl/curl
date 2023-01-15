c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Long: disable-epsv
Help: Inhibit using EPSV
Protocols: FTP
Category: ftp
Example: --disable-epsv ftp://example.com/
Added: 7.9.2
See-also: disable-eprt ftp-port
Multi: boolean
---
Tell curl to disable the use of the EPSV command when doing passive FTP
transfers. Curl will normally always first attempt to use EPSV before
PASV, but with this option, it will not try using EPSV.

--epsv can be used to explicitly enable EPSV again and --no-epsv is an alias
for --disable-epsv.

If the server is an IPv6 host, this option will have no effect as EPSV is
necessary then.

Disabling EPSV only changes the passive behavior. If you want to switch to
active mode you need to use --ftp-port.
