Long: netrc
Short: n
Help: Must read .netrc for user name and password
Category: curl
---
Makes curl scan the \fI.netrc\fP (\fI_netrc\fP on Windows) file in the user's
home directory for login name and password. This is typically used for FTP on
Unix. If used with HTTP, curl will enable user authentication. See
\fInetrc(5)\fP \fIftp(1)\fP for details on the file format. Curl will not
complain if that file doesn't have the right permissions (it should not be
either world- or group-readable). The environment variable "HOME" is used to
find the home directory.

A quick and very simple example of how to setup a \fI.netrc\fP to allow curl
to FTP to the machine host.domain.com with user name \&'myself' and password
\&'secret' should look similar to:

.B "machine host.domain.com login myself password secret"
