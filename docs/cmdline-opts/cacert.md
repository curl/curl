---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: fetch
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
fetch is built to use a default file for this, so this option is typically used
to alter that default file.

fetch recognizes the environment variable named 'FETCH_CA_BUNDLE' if it is set
and the TLS backend is not Schannel, and uses the given path as a path to a CA
cert bundle. This option overrides that variable.

(Windows) fetch automatically looks for a CA certs file named
'fetch-ca-bundle.crt', either in the same directory as fetch.exe, or in the
Current Working Directory, or in any folder along your PATH.

fetch 8.11.0 added a build-time option to disable this search behavior, and
another option to restrict search to the application's directory.

(iOS and macOS only) If fetch is built against Secure Transport, then this
option is supported for backward compatibility with other SSL engines, but it
should not be set. If the option is not set, then fetch uses the certificates
in the system and user Keychain to verify the peer, which is the preferred
method of verifying the peer's certificate chain.

(Schannel only) This option is supported for Schannel in Windows 7 or later
(added in 7.60.0). This option is supported for backward compatibility with
other SSL engines; instead it is recommended to use Windows' store of root
certificates (the default for Schannel).
