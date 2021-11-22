Long: capath
Arg: <dir>
Help: CA directory to verify peer against
Protocols: TLS
Category: tls
See-also: cacert insecure
Example: --capath /local/directory $URL
Added: 7.9.8
---
Tells curl to use the specified certificate directory to verify the
peer. Multiple paths can be provided by separating them with ":" (e.g.
\&"path1:path2:path3"). The certificates must be in PEM format, and if curl is
built against OpenSSL, the directory must have been processed using the
c_rehash utility supplied with OpenSSL. Using --capath can allow
OpenSSL-powered curl to make SSL-connections much more efficiently than using
--cacert if the --cacert file contains many CA certificates.

If this option is set, the default capath value will be ignored, and if it is
used several times, the last one will be used.
