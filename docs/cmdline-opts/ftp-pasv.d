c: Copyright (C) 1998 - 2022, Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Long: ftp-pasv
Help: Use PASV/EPSV instead of PORT
Protocols: FTP
Added: 7.11.0
See-also: disable-epsv
Category: ftp
Example: --ftp-pasv ftp://example.com/
---
Use passive mode for the data connection. Passive is the internal default
behavior, but using this option can be used to override a previous --ftp-port
option.

If this option is used several times, only the first one is used. Undoing an
enforced passive really is not doable but you must then instead enforce the
correct --ftp-port again.

Passive mode means that curl will try the EPSV command first and then PASV,
unless --disable-epsv is used.
