Long: write-out
Short: w
Arg: <format>
Help: Use output FORMAT after completion
---
Make curl display information on stdout after a completed transfer. The format
is a string that may contain plain text mixed with any number of
variables. The format can be specified as a literal "string", or you can have
curl read the format from a file with "@filename" and to tell curl to read the
format from stdin you write "@-".

The variables present in the output format will be substituted by the value or
text that curl thinks fit, as described below. All variables are specified as
%{variable_name} and to output a normal % you just write them as %%. You can
output a newline by using \\n, a carriage return with \\r and a tab space with
\\t.

The output will be written to standard output, but this can be switched to
standard error by using %{stderr}.

.B NOTE:
The %-symbol is a special symbol in the win32-environment, where all
occurrences of % must be doubled when using this option.

The variables available are:
.RS
.TP 15
.B content_type
The Content-Type of the requested document, if there was any.
.TP
.B filename_effective
The ultimate filename that curl writes out to. This is only meaningful if curl
is told to write to a file with the --remote-name or --output
option. It's most useful in combination with the --remote-header-name
option. (Added in 7.26.0)
.TP
.B ftp_entry_path
The initial path curl ended up in when logging on to the remote FTP
server. (Added in 7.15.4)
.TP
.B http_code
The numerical response code that was found in the last retrieved HTTP(S) or
FTP(s) transfer. In 7.18.2 the alias \fBresponse_code\fP was added to show the
same info.
.TP
.B http_connect
The numerical code that was found in the last response (from a proxy) to a
curl CONNECT request. (Added in 7.12.4)
.TP
.B http_version
The http version that was effectively used. (Added in 7.50.0)
.TP
.B local_ip
The IP address of the local end of the most recently done connection - can be
either IPv4 or IPv6 (Added in 7.29.0)
.TP
.B local_port
The local port number of the most recently done connection (Added in 7.29.0)
.TP
.B num_connects
Number of new connects made in the recent transfer. (Added in 7.12.3)
.TP
.B num_redirects
Number of redirects that were followed in the request. (Added in 7.12.3)
.TP
.B proxy_ssl_verify_result
The result of the HTTPS proxy's SSL peer certificate verification that was
requested. 0 means the verification was successful. (Added in 7.52.0)
.TP
.B redirect_url
When an HTTP request was made without --location to follow redirects (or when
--max-redir is met), this variable will show the actual URL a redirect
\fIwould\fP have gone to. (Added in 7.18.2)
.TP
.B remote_ip
The remote IP address of the most recently done connection - can be either
IPv4 or IPv6 (Added in 7.29.0)
.TP
.B remote_port
The remote port number of the most recently done connection (Added in 7.29.0)
.TP
.B scheme
The URL scheme (sometimes called protocol) that was effectively used (Added in 7.52.0)
.TP
.B size_download
The total amount of bytes that were downloaded.
.TP
.B size_header
The total amount of bytes of the downloaded headers.
.TP
.B size_request
The total amount of bytes that were sent in the HTTP request.
.TP
.B size_upload
The total amount of bytes that were uploaded.
.TP
.B speed_download
The average download speed that curl measured for the complete download. Bytes
per second.
.TP
.B speed_upload
The average upload speed that curl measured for the complete upload. Bytes per
second.
.TP
.B ssl_verify_result
The result of the SSL peer certificate verification that was requested. 0
means the verification was successful. (Added in 7.19.0)
.TP
.B stderr
From this point on, the --write-out output will be written to standard
error. (Added in 7.63.0)
.TP
.B stdout
From this point on, the --write-out output will be written to standard output.
This is the default, but can be used to switch back after switching to stderr.
(Added in 7.63.0)
.TP
.B time_appconnect
The time, in seconds, it took from the start until the SSL/SSH/etc
connect/handshake to the remote host was completed. (Added in 7.19.0)
.TP
.B time_connect
The time, in seconds, it took from the start until the TCP connect to the
remote host (or proxy) was completed.
.TP
.B time_namelookup
The time, in seconds, it took from the start until the name resolving was
completed.
.TP
.B time_pretransfer
The time, in seconds, it took from the start until the file transfer was just
about to begin. This includes all pre-transfer commands and negotiations that
are specific to the particular protocol(s) involved.
.TP
.B time_redirect
The time, in seconds, it took for all redirection steps including name lookup,
connect, pretransfer and transfer before the final transaction was
started. time_redirect shows the complete execution time for multiple
redirections. (Added in 7.12.3)
.TP
.B time_starttransfer
The time, in seconds, it took from the start until the first byte was just
about to be transferred. This includes time_pretransfer and also the time the
server needed to calculate the result.
.TP
.B time_total
The total time, in seconds, that the full operation lasted.
.TP
.B url_effective
The URL that was fetched last. This is most meaningful if you've told curl
to follow location: headers.
.RE
.IP
If this option is used several times, the last one will be used.
