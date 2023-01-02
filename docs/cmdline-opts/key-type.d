c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Long: key-type
Arg: <type>
Help: Private key file type (DER/PEM/ENG)
Protocols: TLS
Category: tls
Example: --key-type DER --key here $URL
Added: 7.9.3
See-also: key
Multi: single
---
Private key file type. Specify which type your --key provided private key
is. DER, PEM, and ENG are supported. If not specified, PEM is assumed.
