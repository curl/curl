Long: hostpubmd5
Arg: <md5>
Help: Acceptable MD5 hash of the host public key
Protocols: SFTP SCP
Added: 7.17.1
Category: sftp scp
---
Pass a string containing 32 hexadecimal digits. The string should
be the 128 bit MD5 checksum of the remote host's public key, curl will refuse
the connection with the host unless the md5sums match.
