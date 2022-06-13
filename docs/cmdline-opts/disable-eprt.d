c: Copyright (C) 1998 - 2022, Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Long: disable-eprt
Help: Inhibit using EPRT or LPRT
Protocols: FTP
Category: ftp
Example: --disable-eprt ftp://example.com/
Added: 7.10.5
See-also: disable-epsv ftp-port
---
Tell curl to disable the use of the EPRT and LPRT commands when doing active
FTP transfers. Curl will normally always first attempt to use EPRT, then LPRT
before using PORT, but with this option, it will use PORT right away. EPRT and
LPRT are extensions to the original FTP protocol, and may not work on all
servers, but they enable more functionality in a better way than the
traditional PORT command.

--eprt can be used to explicitly enable EPRT again and --no-eprt is an alias
for --disable-eprt.

If the server is accessed using IPv6, this option will have no effect as EPRT
is necessary then.

Disabling EPRT only changes the active behavior. If you want to switch to
passive mode you need to not use --ftp-port or force it with --ftp-pasv.
