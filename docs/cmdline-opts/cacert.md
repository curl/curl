---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Long: cacert
Arg: <file>
Help: CA certificate to verify peer against
Protocols: TLS
Category: tls
Added: 7.5
Multi: single
See-also:
  - capath
  - dump-ca-embed
  - insecure
Example:
  - --cacert CA-file.txt $URL
---

# `--cacert`

Use the specified certificate file to verify the peer. The file may contain
multiple CA certificates. The certificate(s) must be in PEM format. Normally
curl is built to use a default file for this, so this option is typically used
to alter that default file.

curl recognizes the environment variable named 'CURL_CA_BUNDLE' if it is set
and the TLS backend is not Schannel, and uses the given path as a path to a CA
cert bundle. This option overrides that variable.

(Windows) curl automatically looks for a CA certs file named
'curl-ca-bundle.crt', either in the same directory as curl.exe, or in the
Current Working Directory, or in any folder along your PATH.

curl 8.11.0 added a build-time option to disable this search behavior, and
another option to restrict search to the application's directory.

(Schannel) This option is supported for Schannel in Windows 7 or later (added
in 7.60.0). This option is supported for backward compatibility with other SSL
engines; instead it is recommended to use Windows' store of root certificates
(the default for Schannel).
