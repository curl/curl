Long: tftp-blksize
Arg: <value>
Help: Set TFTP BLKSIZE option
Protocols: TFTP
Added: 7.20.0
Category: tftp
---
Set TFTP BLKSIZE option (must be >512). This is the block size that curl will
try to use when transferring data to or from a TFTP server. By default 512
bytes will be used.

If this option is used several times, the last one will be used.
