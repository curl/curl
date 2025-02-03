---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: fetch
Title: libfetch-errors
Section: 3
Source: libfetch
See-also:
  - FETCHOPT_DEBUGFUNCTION (3)
  - FETCHOPT_ERRORBUFFER (3)
  - FETCHOPT_VERBOSE (3)
  - fetch_easy_strerror (3)
  - fetch_multi_strerror (3)
  - fetch_share_strerror (3)
  - fetch_url_strerror (3)
Protocol:
  - All
Added-in: n/a
---

# NAME

libfetch-errors - error codes in libfetch

# DESCRIPTION

This man page includes most, if not all, available error codes in libfetch.
Why they occur and possibly what you can do to fix the problem are also included.

# FETCHcode

Almost all "easy" interface functions return a FETCHcode error code. No matter
what, using the fetch_easy_setopt(3) option FETCHOPT_ERRORBUFFER(3)
is a good idea as it gives you a human readable error string that may offer
more details about the cause of the error than just the error code.
fetch_easy_strerror(3) can be called to get an error string from a given
FETCHcode number.

FETCHcode is one of the following:

## FETCHE_OK (0)

All fine. Proceed as usual.

## FETCHE_UNSUPPORTED_PROTOCOL (1)

The URL you passed to libfetch used a protocol that this libfetch does not
support. The support might be a compile-time option that you did not use, it
can be a misspelled protocol string or just a protocol libfetch has no code
for.

## FETCHE_FAILED_INIT (2)

Early initialization code failed. This is likely to be an internal error or
problem, or a resource problem where something fundamental could not get done
at init time.

## FETCHE_URL_MALFORMAT (3)

The URL was not properly formatted.

## FETCHE_NOT_BUILT_IN (4)

A requested feature, protocol or option was not found built into this libfetch
due to a build-time decision. This means that a feature or option was not
enabled or explicitly disabled when libfetch was built and in order to get it
to function you have to get a rebuilt libfetch.

## FETCHE_COULDNT_RESOLVE_PROXY (5)

Could not resolve proxy. The given proxy host could not be resolved.

## FETCHE_COULDNT_RESOLVE_HOST (6)

Could not resolve host. The given remote host was not resolved.

## FETCHE_COULDNT_CONNECT (7)

Failed to connect() to host or proxy.

## FETCHE_WEIRD_SERVER_REPLY (8)

The server sent data libfetch could not parse. This error code was known as
*FETCHE_FTP_WEIRD_SERVER_REPLY* before 7.51.0.

## FETCHE_REMOTE_ACCESS_DENIED (9)

We were denied access to the resource given in the URL. For FTP, this occurs
while trying to change to the remote directory.

## FETCHE_FTP_ACCEPT_FAILED (10)

While waiting for the server to connect back when an active FTP session is
used, an error code was sent over the control connection or similar.

## FETCHE_FTP_WEIRD_PASS_REPLY (11)

After having sent the FTP password to the server, libfetch expects a proper
reply. This error code indicates that an unexpected code was returned.

## FETCHE_FTP_ACCEPT_TIMEOUT (12)

During an active FTP session while waiting for the server to connect, the
FETCHOPT_ACCEPTTIMEOUT_MS(3) (or the internal default) timeout expired.

## FETCHE_FTP_WEIRD_PASV_REPLY (13)

libfetch failed to get a sensible result back from the server as a response to
either a PASV or a EPSV command. The server is flawed.

## FETCHE_FTP_WEIRD_227_FORMAT (14)

FTP servers return a 227-line as a response to a PASV command. If libfetch
fails to parse that line, this return code is passed back.

## FETCHE_FTP_CANT_GET_HOST (15)

An internal failure to lookup the host used for the new connection.

## FETCHE_HTTP2 (16)

A problem was detected in the HTTP2 framing layer. This is somewhat generic
and can be one out of several problems, see the error buffer for details.

## FETCHE_FTP_COULDNT_SET_TYPE (17)

Received an error when trying to set the transfer mode to binary or ASCII.

## FETCHE_PARTIAL_FILE (18)

A file transfer was shorter or larger than expected. This happens when the
server first reports an expected transfer size, and then delivers data that
does not match the previously given size.

## FETCHE_FTP_COULDNT_RETR_FILE (19)

This was either a weird reply to a 'RETR' command or a zero byte transfer
complete.

## Obsolete error (20)

Not used in modern versions.

## FETCHE_QUOTE_ERROR (21)

When sending custom "QUOTE" commands to the remote server, one of the commands
returned an error code that was 400 or higher (for FTP) or otherwise
indicated unsuccessful completion of the command.

## FETCHE_HTTP_RETURNED_ERROR (22)

This is returned if FETCHOPT_FAILONERROR(3) is set TRUE and the HTTP server
returns an error code that is \>= 400.

## FETCHE_WRITE_ERROR (23)

An error occurred when writing received data to a local file, or an error was
returned to libfetch from a write callback.

## Obsolete error (24)

Not used in modern versions.

## FETCHE_UPLOAD_FAILED (25)

Failed starting the upload. For FTP, the server typically denied the STOR
command. The error buffer usually contains the server's explanation for this.

## FETCHE_READ_ERROR (26)

There was a problem reading a local file or an error returned by the read
callback.

## FETCHE_OUT_OF_MEMORY (27)

A memory allocation request failed. This is serious badness and
things are severely screwed up if this ever occurs.

## FETCHE_OPERATION_TIMEDOUT (28)

Operation timeout. The specified time-out period was reached according to the
conditions.

## Obsolete error (29)

Not used in modern versions.

## FETCHE_FTP_PORT_FAILED (30)

The FTP PORT command returned error. This mostly happens when you have not
specified a good enough address for libfetch to use. See
FETCHOPT_FTPPORT(3).

## FETCHE_FTP_COULDNT_USE_REST (31)

The FTP REST command returned error. This should never happen if the server is
sane.

## Obsolete error (32)

Not used in modern versions.

## FETCHE_RANGE_ERROR (33)

The server does not support or accept range requests.

## Obsolete error (34)

Not used since 7.56.0.

## FETCHE_SSL_CONNECT_ERROR (35)

A problem occurred somewhere in the SSL/TLS handshake. You really want the
error buffer and read the message there as it pinpoints the problem slightly
more. Could be certificates (file formats, paths, permissions), passwords, and
others.

## FETCHE_BAD_DOWNLOAD_RESUME (36)

The download could not be resumed because the specified offset was out of the
file boundary.

## FETCHE_FILE_COULDNT_READ_FILE (37)

A file given with FILE:// could not be opened. Most likely because the file
path does not identify an existing file. Did you check file permissions?

## FETCHE_LDAP_CANNOT_BIND (38)

LDAP cannot bind. LDAP bind operation failed.

## FETCHE_LDAP_SEARCH_FAILED (39)

LDAP search failed.

## Obsolete error (40)

Not used in modern versions.

## Obsolete error (41)

Not used since 7.53.0.

## FETCHE_ABORTED_BY_CALLBACK (42)

Aborted by callback. A callback returned "abort" to libfetch.

## FETCHE_BAD_FUNCTION_ARGUMENT (43)

A function was called with a bad parameter.

## Obsolete error (44)

Not used in modern versions.

## FETCHE_INTERFACE_FAILED (45)

Interface error. A specified outgoing interface could not be used. Set which
interface to use for outgoing connections' source IP address with
FETCHOPT_INTERFACE(3).

## Obsolete error (46)

Not used in modern versions.

## FETCHE_TOO_MANY_REDIRECTS (47)

Too many redirects. When following redirects, libfetch hit the maximum amount.
Set your limit with FETCHOPT_MAXREDIRS(3).

## FETCHE_UNKNOWN_OPTION (48)

An option passed to libfetch is not recognized/known. Refer to the appropriate
documentation. This is most likely a problem in the program that uses
libfetch. The error buffer might contain more specific information about which
exact option it concerns.

## FETCHE_SETOPT_OPTION_SYNTAX (49)

An option passed in to a setopt was wrongly formatted. See error message for
details about what option.

## Obsolete errors (50-51)

Not used in modern versions.

## FETCHE_GOT_NOTHING (52)

Nothing was returned from the server, and under the circumstances, getting
nothing is considered an error.

## FETCHE_SSL_ENGINE_NOTFOUND (53)

The specified crypto engine was not found.

## FETCHE_SSL_ENGINE_SETFAILED (54)

Failed setting the selected SSL crypto engine as default.

## FETCHE_SEND_ERROR (55)

Failed sending network data.

## FETCHE_RECV_ERROR (56)

Failure with receiving network data.

## Obsolete error (57)

Not used in modern versions.

## FETCHE_SSL_CERTPROBLEM (58)

problem with the local client certificate.

## FETCHE_SSL_CIPHER (59)

Could not use specified cipher.

## FETCHE_PEER_FAILED_VERIFICATION (60)

The remote server's SSL certificate or SSH fingerprint was deemed not OK.
This error code has been unified with FETCHE_SSL_CACERT since 7.62.0. Its
previous value was 51.

## FETCHE_BAD_CONTENT_ENCODING (61)

Unrecognized transfer encoding.

## Obsolete error (62)

Not used in modern versions.

## FETCHE_FILESIZE_EXCEEDED (63)

Maximum file size exceeded.

## FETCHE_USE_SSL_FAILED (64)

Requested FTP SSL level failed.

## FETCHE_SEND_FAIL_REWIND (65)

When doing a send operation fetch had to rewind the data to retransmit, but the
rewinding operation failed.

## FETCHE_SSL_ENGINE_INITFAILED (66)

Initiating the SSL Engine failed.

## FETCHE_LOGIN_DENIED (67)

The remote server denied fetch to login (Added in 7.13.1)

## FETCHE_TFTP_NOTFOUND (68)

File not found on TFTP server.

## FETCHE_TFTP_PERM (69)

Permission problem on TFTP server.

## FETCHE_REMOTE_DISK_FULL (70)

Out of disk space on the server.

## FETCHE_TFTP_ILLEGAL (71)

Illegal TFTP operation.

## FETCHE_TFTP_UNKNOWNID (72)

Unknown TFTP transfer ID.

## FETCHE_REMOTE_FILE_EXISTS (73)

File already exists and is not overwritten.

## FETCHE_TFTP_NOSUCHUSER (74)

This error should never be returned by a properly functioning TFTP server.

## Obsolete error (75-76)

Not used in modern versions.

## FETCHE_SSL_CACERT_BADFILE (77)

Problem with reading the SSL CA cert (path? access rights?)

## FETCHE_REMOTE_FILE_NOT_FOUND (78)

The resource referenced in the URL does not exist.

## FETCHE_SSH (79)

An unspecified error occurred during the SSH session.

## FETCHE_SSL_SHUTDOWN_FAILED (80)

Failed to shut down the SSL connection.

## FETCHE_AGAIN (81)

Socket is not ready for send/recv. Wait until it is ready and try again. This
return code is only returned from fetch_easy_recv(3) and fetch_easy_send(3)
(Added in 7.18.2)

## FETCHE_SSL_CRL_BADFILE (82)

Failed to load CRL file (Added in 7.19.0)

## FETCHE_SSL_ISSUER_ERROR (83)

Issuer check failed (Added in 7.19.0)

## FETCHE_FTP_PRET_FAILED (84)

The FTP server does not understand the PRET command at all or does not support
the given argument. Be careful when using FETCHOPT_CUSTOMREQUEST(3), a
custom LIST command is sent with the PRET command before PASV as well. (Added
in 7.20.0)

## FETCHE_RTSP_CSEQ_ERROR (85)

Mismatch of RTSP CSeq numbers.

## FETCHE_RTSP_SESSION_ERROR (86)

Mismatch of RTSP Session Identifiers.

## FETCHE_FTP_BAD_FILE_LIST (87)

Unable to parse FTP file list (during FTP wildcard downloading).

## FETCHE_CHUNK_FAILED (88)

Chunk callback reported error.

## FETCHE_NO_CONNECTION_AVAILABLE (89)

(For internal use only, is never returned by libfetch) No connection available,
the session is queued. (added in 7.30.0)

## FETCHE_SSL_PINNEDPUBKEYNOTMATCH (90)

Failed to match the pinned key specified with FETCHOPT_PINNEDPUBLICKEY(3).

## FETCHE_SSL_INVALIDCERTSTATUS (91)

Status returned failure when asked with FETCHOPT_SSL_VERIFYSTATUS(3).

## FETCHE_HTTP2_STREAM (92)

Stream error in the HTTP/2 framing layer.

## FETCHE_RECURSIVE_API_CALL (93)

An API function was called from inside a callback.

## FETCHE_AUTH_ERROR (94)

An authentication function returned an error.

## FETCHE_HTTP3 (95)

A problem was detected in the HTTP/3 layer. This is somewhat generic and can
be one out of several problems, see the error buffer for details.

## FETCHE_QUIC_CONNECT_ERROR (96)

QUIC connection error. This error may be caused by an SSL library error. QUIC
is the protocol used for HTTP/3 transfers.

## FETCHE_PROXY (97)

Proxy handshake error. FETCHINFO_PROXY_ERROR(3) provides extra details on
the specific problem.

## FETCHE_SSL_CLIENTCERT (98)

SSL Client Certificate required.

## FETCHE_UNRECOVERABLE_POLL (99)

An internal call to poll() or select() returned error that is not recoverable.

## FETCHE_TOO_LARGE (100)

A value or data field grew larger than allowed.

## FETCHE_ECH_REQUIRED (101)"

ECH was attempted but failed.

# FETCHMcode

This is the generic return code used by functions in the libfetch multi
interface. Also consider fetch_multi_strerror(3).

## FETCHM_CALL_MULTI_PERFORM (-1)

This is not really an error. It means you should call
fetch_multi_perform(3) again without doing select() or similar in
between. Before version 7.20.0 (released on February 9 2010) this could be returned by
fetch_multi_perform(3), but in later versions this return code is never
used.

## FETCHM_OK (0)

Things are fine.

## FETCHM_BAD_HANDLE (1)

The passed-in handle is not a valid *FETCHM* handle.

## FETCHM_BAD_EASY_HANDLE (2)

An easy handle was not good/valid. It could mean that it is not an easy handle
at all, or possibly that the handle already is in use by this or another multi
handle.

## FETCHM_OUT_OF_MEMORY (3)

You are doomed.

## FETCHM_INTERNAL_ERROR (4)

This can only be returned if libfetch bugs. Please report it to us.

## FETCHM_BAD_SOCKET (5)

The passed-in socket is not a valid one that libfetch already knows about.
(Added in 7.15.4)

## FETCHM_UNKNOWN_OPTION (6)

fetch_multi_setopt() with unsupported option
(Added in 7.15.4)

## FETCHM_ADDED_ALREADY (7)

An easy handle already added to a multi handle was attempted to get added a
second time. (Added in 7.32.1)

## FETCHM_RECURSIVE_API_CALL (8)

An API function was called from inside a callback.

## FETCHM_WAKEUP_FAILURE (9)

Wake up is unavailable or failed.

## FETCHM_BAD_FUNCTION_ARGUMENT (10)

A function was called with a bad parameter.

## FETCHM_ABORTED_BY_CALLBACK (11)

A multi handle callback returned error.

## FETCHM_UNRECOVERABLE_POLL (12)

An internal call to poll() or select() returned error that is not recoverable.

# FETCHSHcode

The "share" interface returns a **FETCHSHcode** to indicate when an error has
occurred. Also consider fetch_share_strerror(3).

## FETCHSHE_OK (0)

All fine. Proceed as usual.

## FETCHSHE_BAD_OPTION (1)

An invalid option was passed to the function.

## FETCHSHE_IN_USE (2)

The share object is currently in use.

## FETCHSHE_INVALID (3)

An invalid share object was passed to the function.

## FETCHSHE_NOMEM (4)

Not enough memory was available.
(Added in 7.12.0)

## FETCHSHE_NOT_BUILT_IN (5)

The requested sharing could not be done because the library you use do not have
that particular feature enabled. (Added in 7.23.0)

# FETCHUcode

The URL interface returns a *FETCHUcode* to indicate when an error has
occurred. Also consider fetch_url_strerror(3).

## FETCHUE_OK (0)

All fine. Proceed as usual.

## FETCHUE_BAD_HANDLE (1)

An invalid URL handle was passed as argument.

## FETCHUE_BAD_PARTPOINTER (2)

An invalid 'part' argument was passed as argument.

## FETCHUE_MALFORMED_INPUT (3)

A malformed input was passed to a URL API function.

## FETCHUE_BAD_PORT_NUMBER (4)

The port number was not a decimal number between 0 and 65535.

## FETCHUE_UNSUPPORTED_SCHEME (5)

This libfetch build does not support the given URL scheme.

## FETCHUE_URLDECODE (6)

URL decode error, most likely because of rubbish in the input.

## FETCHUE_OUT_OF_MEMORY (7)

A memory function failed.

## FETCHUE_USER_NOT_ALLOWED (8)

Credentials was passed in the URL when prohibited.

## FETCHUE_UNKNOWN_PART (9)

An unknown part ID was passed to a URL API function.

## FETCHUE_NO_SCHEME (10)

There is no scheme part in the URL.

## FETCHUE_NO_USER (11)

There is no user part in the URL.

## FETCHUE_NO_PASSWORD (12)

There is no password part in the URL.

## FETCHUE_NO_OPTIONS (13)

There is no options part in the URL.

## FETCHUE_NO_HOST (14)

There is no host part in the URL.

## FETCHUE_NO_PORT (15)

There is no port part in the URL.

## FETCHUE_NO_QUERY (16)

There is no query part in the URL.

## FETCHUE_NO_FRAGMENT (17)

There is no fragment part in the URL.

## FETCHUE_NO_ZONEID (18)

There is no zone id set in the URL.

## FETCHUE_BAD_FILE_URL (19)

The file:// URL is invalid.

## FETCHUE_BAD_FRAGMENT (20)

The fragment part of the URL contained bad or invalid characters.

## FETCHUE_BAD_HOSTNAME (21)

The hostname contained bad or invalid characters.

## FETCHUE_BAD_IPV6 (22)

The IPv6 address hostname contained bad or invalid characters.

## FETCHUE_BAD_LOGIN (23)

The login part of the URL contained bad or invalid characters.

## FETCHUE_BAD_PASSWORD (24)

The password part of the URL contained bad or invalid characters.

## FETCHUE_BAD_PATH (25)

The path part of the URL contained bad or invalid characters.

## FETCHUE_BAD_QUERY (26)

The query part of the URL contained bad or invalid characters.

## FETCHUE_BAD_SCHEME (27)

The scheme part of the URL contained bad or invalid characters.

## FETCHUE_BAD_SLASHES (28)

The URL contained an invalid number of slashes.

## FETCHUE_BAD_USER (29)

The user part of the URL contained bad or invalid characters.

## FETCHUE_LACKS_IDN (30)

libfetch lacks IDN support.

## FETCHUE_TOO_LARGE (31)

A value or data field is larger than allowed.

# FETCHHcode

The header interface returns a *FETCHHcode* to indicate when an error has
occurred.

## FETCHHE_OK (0)

All fine. Proceed as usual.

## FETCHHE_BADINDEX (1)

There is no header with the requested index.

## FETCHHE_MISSING (2)

No such header exists.

## FETCHHE_NOHEADERS (3)

No headers at all have been recorded.

## FETCHHE_NOREQUEST (4)

There was no such request number.

## FETCHHE_OUT_OF_MEMORY (5)

Out of resources

## FETCHHE_BAD_ARGUMENT (6)

One or more of the given arguments are bad.

## FETCHHE_NOT_BUILT_IN (7)

HTTP support or the header API has been disabled in the build.
