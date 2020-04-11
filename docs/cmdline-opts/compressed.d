Long: compressed
Help: Request compressed response
Protocols: HTTP
---
Request a compressed response using one of the algorithms curl supports, and
automatically decompress the content. Headers are not modified.

If this option is used and the server sends an unsupported encoding, curl will
report an error.
