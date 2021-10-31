Long: ftp-create-dirs
Protocols: FTP SFTP
Help: Create the remote dirs if not present
See-also: create-dirs
Category: ftp sftp curl
Example: --ftp-create-dirs -T file ftp://example.com/remote/path/file
Added: 7.10.7
---
When an FTP or SFTP URL/operation uses a path that does not currently exist on
the server, the standard behavior of curl is to fail. Using this option, curl
will instead attempt to create missing directories.
