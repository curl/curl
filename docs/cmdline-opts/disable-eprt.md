---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Long: disable-eprt
Help: Inhibit using EPRT or LPRT
Protocols: FTP
Category: ftp
Added: 7.10.5
Multi: boolean
See-also:
  - disable-epsv
  - ftp-port
Example:
  - --disable-eprt ftp://example.com/
---

# `--disable-eprt`

Disable the use of the EPRT and LPRT commands when doing active FTP transfers.
curl normally first attempts to use EPRT before using PORT, but with this
option, it uses PORT right away. EPRT is an extension to the original FTP
protocol, and does not work on all servers, but enables more functionality in
a better way than the traditional PORT command.

--eprt can be used to explicitly enable EPRT again and --no-eprt is an alias
for --disable-eprt.

If the server is accessed using IPv6, this option has no effect as EPRT is
necessary then.

Disabling EPRT only changes the active behavior. If you want to switch to
passive mode you need to not use --ftp-port or force it with --ftp-pasv.
