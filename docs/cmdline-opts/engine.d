c: Copyright (C) 1998 - 2022, Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Long: engine
Arg: <name>
Help: Crypto engine to use
Protocols: TLS
Category: tls
Example: --engine flavor $URL
Added: 7.9.3
See-also: ciphers curves
---
Select the OpenSSL crypto engine to use for cipher operations. Use --engine
list to print a list of build-time supported engines. Note that not all (and
possibly none) of the engines may be available at runtime.
