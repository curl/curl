Long: tftp-no-options
Help: Do not send any TFTP options
Protocols: TFTP
Added: 7.48.0
---
Tells curl not to send TFTP options requests.

This option improves interop with some legacy servers that do not acknowledge
or properly implement TFTP options. When this option is used --tftp-blksize is
ignored.
