Short: a
Long: append
Help: Append to target file when uploading
Protocols: FTP SFTP
Category: ftp sftp
---
When used in an upload, this makes curl append to the target file instead of
overwriting it. If the remote file doesn't exist, it will be created.  Note
that this flag is ignored by some SFTP servers (including OpenSSH).
