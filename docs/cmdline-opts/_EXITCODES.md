<!-- Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al. -->
<!-- SPDX-License-Identifier: curl -->
# EXIT CODES
There are a bunch of different error codes and their corresponding error
messages that may appear under error conditions. At the time of this writing,
the exit codes are:
## 0
Success. The operation completed successfully according to the instructions.
## 1
Unsupported protocol. This build of curl has no support for this protocol.
## 2
Failed to initialize.
## 3
URL malformed. The syntax was not correct.
## 4
A feature or option that was needed to perform the desired request was not
enabled or was explicitly disabled at build-time. To make curl able to do
this, you probably need another build of libcurl.
## 5
Could not resolve proxy. The given proxy host could not be resolved.
## 6
Could not resolve host. The given remote host could not be resolved.
## 7
Failed to connect to host.
## 8
Weird server reply. The server sent data curl could not parse.
## 9
FTP access denied. The server denied login or denied access to the particular
resource or directory you wanted to reach. Most often you tried to change to a
directory that does not exist on the server.
## 10
FTP accept failed. While waiting for the server to connect back when an active
FTP session is used, an error code was sent over the control connection or
similar.
## 11
FTP weird PASS reply. Curl could not parse the reply sent to the PASS request.
## 12
During an active FTP session while waiting for the server to connect back to
curl, the timeout expired.
## 13
FTP weird PASV reply, Curl could not parse the reply sent to the PASV request.
## 14
FTP weird 227 format. Curl could not parse the 227-line the server sent.
## 15
FTP cannot use host. Could not resolve the host IP we got in the 227-line.
## 16
HTTP/2 error. A problem was detected in the HTTP2 framing layer. This is
somewhat generic and can be one out of several problems, see the error message
for details.
## 17
FTP could not set binary. Could not change transfer method to binary.
## 18
Partial file. Only a part of the file was transferred.
## 19
FTP could not download/access the given file, the RETR (or similar) command
failed.
## 21
FTP quote error. A quote command returned error from the server.
## 22
HTTP page not retrieved. The requested URL was not found or returned another
error with the HTTP error code being 400 or above. This return code only
appears if --fail is used.
## 23
Write error. Curl could not write data to a local filesystem or similar.
## 25
Failed starting the upload. For FTP, the server typically denied the STOR
command.
## 26
Read error. Various reading problems.
## 27
Out of memory. A memory allocation request failed.
## 28
Operation timeout. The specified time-out period was reached according to the
conditions.
## 30
FTP PORT failed. The PORT command failed. Not all FTP servers support the PORT
command, try doing a transfer using PASV instead.
## 31
FTP could not use REST. The REST command failed. This command is used for
resumed FTP transfers.
## 33
HTTP range error. The range "command" did not work.
## 34
HTTP post error. Internal post-request generation error.
## 35
SSL connect error. The SSL handshaking failed.
## 36
Bad download resume. Could not continue an earlier aborted download.
## 37
FILE could not read file. Failed to open the file. Permissions?
## 38
LDAP cannot bind. LDAP bind operation failed.
## 39
LDAP search failed.
## 41
Function not found. A required LDAP function was not found.
## 42
Aborted by callback. An application told curl to abort the operation.
## 43
Internal error. A function was called with a bad parameter.
## 45
Interface error. A specified outgoing interface could not be used.
## 47
Too many redirects. When following redirects, curl hit the maximum amount.
## 48
Unknown option specified to libcurl. This indicates that you passed a weird
option to curl that was passed on to libcurl and rejected. Read up in the
manual.
## 49
Malformed telnet option.
## 52
The server did not reply anything, which here is considered an error.
## 53
SSL crypto engine not found.
## 54
Cannot set SSL crypto engine as default.
## 55
Failed sending network data.
## 56
Failure in receiving network data.
## 58
Problem with the local certificate.
## 59
Could not use specified SSL cipher.
## 60
Peer certificate cannot be authenticated with known CA certificates.
## 61
Unrecognized transfer encoding.
## 63
Maximum file size exceeded.
## 64
Requested FTP SSL level failed.
## 65
Sending the data requires a rewind that failed.
## 66
Failed to initialize SSL Engine.
## 67
The username, password, or similar was not accepted and curl failed to log in.
## 68
File not found on TFTP server.
## 69
Permission problem on TFTP server.
## 70
Out of disk space on TFTP server.
## 71
Illegal TFTP operation.
## 72
Unknown TFTP transfer ID.
## 73
File already exists (TFTP).
## 74
No such user (TFTP).
## 77
Problem reading the SSL CA cert (path? access rights?).
## 78
The resource referenced in the URL does not exist.
## 79
An unspecified error occurred during the SSH session.
## 80
Failed to shut down the SSL connection.
## 82
Could not load CRL file, missing or wrong format (added in 7.19.0).
## 83
Issuer check failed (added in 7.19.0).
## 84
The FTP PRET command failed.
## 85
Mismatch of RTSP CSeq numbers.
## 86
Mismatch of RTSP Session Identifiers.
## 87
Unable to parse FTP file list.
## 88
FTP chunk callback reported error.
## 89
No connection available, the session is queued.
## 90
SSL public key does not matched pinned public key.
## 91
Invalid SSL certificate status.
## 92
Stream error in HTTP/2 framing layer.
## 93
An API function was called from inside a callback.
## 94
An authentication function returned an error.
## 95
A problem was detected in the HTTP/3 layer. This is somewhat generic and can
be one out of several problems, see the error message for details.
## 96
QUIC connection error. This error may be caused by an SSL library error. QUIC
is the protocol used for HTTP/3 transfers.
## 97
Proxy handshake error.
## 98
A client-side certificate is required to complete the TLS handshake.
## 99
Poll or select returned fatal error.
## 100
A value or data field grew larger than allowed.
## XX
More error codes might appear here in future releases. The existing ones are
meant to never change.
