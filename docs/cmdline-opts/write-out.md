---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Long: write-out
Short: w
Arg: <format>
Help: Output FORMAT after completion
Category: verbose
Added: 6.5
Multi: single
See-also:
  - verbose
  - head
Example:
  - -w '%{response_code}\n' $URL
---

# `--write-out`

Make curl display information on stdout after a completed transfer. The format
is a string that may contain plain text mixed with any number of variables.
The format can be specified as a literal "string", or you can have curl read
the format from a file with "@filename" and to tell curl to read the format
from stdin you write "@-".

The variables present in the output format are substituted by the value or
text that curl thinks fit, as described below. All variables are specified as
%{variable_name} and to output a normal % you just write them as %%. You can
output a newline by using \n, a carriage return with \r and a tab space with
\t.

The output is by default written to standard output, but can be changed with
%{stderr} and %output{}.

Output HTTP header values from the transfer's most recent server response by
using *%header{name}* where *name* is the case insensitive name of the header
(without the trailing colon). The header contents are exactly as delivered over
the network but with leading and trailing whitespace and newlines stripped off
(added in 7.84.0).

Select a specific target destination file to write the output to, by using
*%output{name}* (added in curl 8.3.0) where *name* is the full filename. The
output following that instruction is then written to that file. More than one
*%output{}* instruction can be specified in the same write-out argument. If
the filename cannot be created, curl leaves the output destination to the one
used prior to the *%output{}* instruction. Use *%output{\>\>name}* to append
data to an existing file.

This output is done independently of if the file transfer was successful or
not.

If the specified action or output specified with this option fails in any way,
it does not make curl return a (different) error.

**NOTE:** On Windows, the %-symbol is a special symbol used to expand
environment variables. In batch files, all occurrences of % must be doubled
when using this option to properly escape. If this option is used at the
command prompt then the % cannot be escaped and unintended expansion is
possible.

The variables available are:

## `certs`
Output the certificate chain with details. Supported only by the OpenSSL,
GnuTLS, Schannel and Rustls backends. (Added in 7.88.0)

## `conn_id`
The connection identifier last used by the transfer. The connection id is
unique number among all connections using the same connection cache.
(Added in 8.2.0)

## `content_type`
The Content-Type of the requested document, if there was any.

## `errormsg`
The error message. (Added in 7.75.0)

## `exitcode`
The numerical exit code of the transfer. (Added in 7.75.0)

## `filename_effective`
The ultimate filename that curl writes out to. This is only meaningful if curl
is told to write to a file with the --remote-name or --output option. It is
most useful in combination with the --remote-header-name option.
(Added in 7.26.0)

## `ftp_entry_path`
The initial path curl ended up in when logging on to the remote FTP
server. (Added in 7.15.4)

## `header{name}`
The value of header `name` from the transfer's most recent server response.
Unlike other variables, the variable name `header` is not in braces. For
example `%header{date}`. Refer to --write-out remarks. (Added in 7.84.0)

## `header_json`
A JSON object with all HTTP response headers from the recent transfer. Values
are provided as arrays, since in the case of multiple headers there can be
multiple values. (Added in 7.83.0)

The header names provided in lowercase, listed in order of appearance over the
wire. Except for duplicated headers. They are grouped on the first occurrence
of that header, each value is presented in the JSON array.

## `http_code`
The numerical response code that was found in the last retrieved HTTP(S) or
FTP(s) transfer.

## `http_connect`
The numerical code that was found in the last response (from a proxy) to a
curl CONNECT request. (Added in 7.12.4)

## `http_version`
The http version that was effectively used. (Added in 7.50.0)

## `json`
A JSON object with all available keys except `header_json`. (Added in 7.70.0)

## `local_ip`
The IP address of the local end of the most recently done connection - can be
either IPv4 or IPv6. (Added in 7.29.0)

## `local_port`
The local port number of the most recently done connection. (Added in 7.29.0)

## `method`
The http method used in the most recent HTTP request. (Added in 7.72.0)

## `num_certs`
Number of server certificates received in the TLS handshake. Supported only by
the OpenSSL, GnuTLS, Schannel and Rustls backends. (Added in 7.88.0)

## `num_connects`
Number of new connects made in the recent transfer. (Added in 7.12.3)

## `num_headers`
The number of response headers in the most recent request (restarted at each
redirect). Note that the status line IS NOT a header. (Added in 7.73.0)

## `num_redirects`
Number of redirects that were followed in the request. (Added in 7.12.3)

## `num_retries`
Number of retries actually performed when `--retry` has been used.
(Added in 8.9.0)

## `onerror`
The rest of the output is only shown if the transfer returned a non-zero error.
(Added in 7.75.0)

## `output{filename}`
From this point on, the --write-out output is written to the filename specified
in braces. The filename can be prefixed with `>>` to append to the file. Unlike
other variables, the variable name `output` is not in braces. For example
`%output{>>stats.txt}`. Refer to --write-out remarks. (Added in 8.3.0)

## `proxy_ssl_verify_result`
The result of the HTTPS proxy's SSL peer certificate verification that was
requested. 0 means the verification was successful. (Added in 7.52.0)

## `proxy_used`
Returns 1 if the previous transfer used a proxy, otherwise 0. Useful to for
example determine if a `NOPROXY` pattern matched the hostname or not. (Added
in 8.7.0)

## `redirect_url`
When an HTTP request was made without --location to follow redirects (or when
--max-redirs is met), this variable shows the actual URL a redirect
*would* have gone to. (Added in 7.18.2)

## `referer`
The Referer: header, if there was any. (Added in 7.76.0)

## `remote_ip`
The remote IP address of the most recently done connection - can be either
IPv4 or IPv6. (Added in 7.29.0)

## `remote_port`
The remote port number of the most recently done connection. (Added in 7.29.0)

## `response_code`
The numerical response code that was found in the last transfer (formerly
known as "http_code"). (Added in 7.18.2)

## `scheme`
The URL scheme (sometimes called protocol) that was effectively used. (Added in 7.52.0)

## `size_download`
The total amount of bytes that were downloaded. This is the size of the
body/data that was transferred, excluding headers.

## `size_header`
The total amount of bytes of the downloaded headers.

## `size_request`
The total amount of bytes that were sent in the HTTP request.

## `size_upload`
The total amount of bytes that were uploaded. This is the size of the
body/data that was transferred, excluding headers.

## `speed_download`
The average download speed that curl measured for the complete download. Bytes
per second.

## `speed_upload`
The average upload speed that curl measured for the complete upload. Bytes per
second.

## `ssl_verify_result`
The result of the SSL peer certificate verification that was requested. 0
means the verification was successful. (Added in 7.19.0)

## `stderr`
From this point on, the --write-out output is written to standard
error. (Added in 7.63.0)

## `stdout`
From this point on, the --write-out output is written to standard output.
This is the default, but can be used to switch back after switching to stderr.
(Added in 7.63.0)

## `time{format}`
Output the current UTC time using `strftime()` format. See TIME OUTPUT FORMAT
below for details. (Added in 8.16.0)

## `time_appconnect`
The time, in seconds, it took from the start until the SSL/SSH/etc
connect/handshake to the remote host was completed. (Added in 7.19.0)

## `time_connect`
The time, in seconds, it took from the start until the TCP connect to the
remote host (or proxy) was completed.

## `time_namelookup`
The time, in seconds, it took from the start until the name resolving was
completed.

## `time_posttransfer`
The time it took from the start until the last byte is sent by libcurl.
In microseconds. (Added in 8.10.0)

## `time_pretransfer`
The time, in seconds, it took from the start until the file transfer was just
about to begin. This includes all pre-transfer commands and negotiations that
are specific to the particular protocol(s) involved.

## `time_queue`
The time, in seconds, the transfer was queued during its run. This adds
the queue time for each redirect step that may have happened. Transfers
may be queued for significant amounts of time when connection or parallel
limits are in place. (Added in 8.12.0)

## `time_redirect`
The time, in seconds, it took for all redirection steps including name lookup,
connect, pretransfer and transfer before the final transaction was
started. `time_redirect` shows the complete execution time for multiple
redirections. (Added in 7.12.3)

## `time_starttransfer`
The time, in seconds, it took from the start until the first byte was received.
This includes time_pretransfer and also the time the server needed to calculate
the result.

## `time_total`
The total time, in seconds, that the full operation lasted.

## `tls_earlydata`
The amount of bytes that were sent as TLSv1.3 early data. This is 0
if this TLS feature was not used and negative if the data sent had
been rejected by the server. The use of early data is enabled via
the command line option `--tls-earlydata`. (Added in 8.12.0)

## `url`
The URL that was fetched. (Added in 7.75.0)

## `url.scheme`
The scheme part of the URL that was fetched. (Added in 8.1.0)

## `url.user`
The user part of the URL that was fetched. (Added in 8.1.0)

## `url.password`
The password part of the URL that was fetched. (Added in 8.1.0)

## `url.options`
The options part of the URL that was fetched. (Added in 8.1.0)

## `url.host`
The host part of the URL that was fetched. (Added in 8.1.0)

## `url.port`
The port number of the URL that was fetched. If no port number was specified
and the URL scheme is known, that scheme's default port number is
shown. (Added in 8.1.0)

## `url.path`
The path part of the URL that was fetched. (Added in 8.1.0)

## `url.query`
The query part of the URL that was fetched. (Added in 8.1.0)

## `url.fragment`
The fragment part of the URL that was fetched. (Added in 8.1.0)

## `url.zoneid`
The zone id part of the URL that was fetched. (Added in 8.1.0)

## `urle.scheme`
The scheme part of the effective (last) URL that was fetched. (Added in 8.1.0)

## `urle.user`
The user part of the effective (last) URL that was fetched. (Added in 8.1.0)

## `urle.password`
The password part of the effective (last) URL that was fetched. (Added in 8.1.0)

## `urle.options`
The options part of the effective (last) URL that was fetched. (Added in 8.1.0)

## `urle.host`
The host part of the effective (last) URL that was fetched. (Added in 8.1.0)

## `urle.port`
The port number of the effective (last) URL that was fetched. If no port
number was specified, but the URL scheme is known, that scheme's default port
number is shown. (Added in 8.1.0)

## `urle.path`
The path part of the effective (last) URL that was fetched. (Added in 8.1.0)

## `urle.query`
The query part of the effective (last) URL that was fetched. (Added in 8.1.0)

## `urle.fragment`
The fragment part of the effective (last) URL that was fetched. (Added in 8.1.0)

## `urle.zoneid`
The zone id part of the effective (last) URL that was fetched. (Added in 8.1.0)

## `urlnum`
The URL index number of this transfer, 0-indexed. Unglobbed URLs share the
same index number as the origin globbed URL. (Added in 7.75.0)

## `url_effective`
The URL that was fetched last. This is most meaningful if you have told curl
to follow location: headers.

## `xfer_id`
The numerical identifier of the last transfer done. -1 if no transfer has been
started yet for the handle. The transfer id is unique among all transfers
performed using the same connection cache.
(Added in 8.2.0)

##

TIME OUTPUT FORMAT

To show time with `%time{}` the characters within `{}` creates a special
format string that may contain special character sequences called conversion
specifications. Each conversion specification starts with `%` and is followed
by a character that instructs curl to output a particular time detail. All
other characters used are displayed as-is and-

The following conversion specification are available:

## `%a`

The abbreviated name of the day of the week according to the current locale.

## `%A`

The full name of the day of the week according to the current locale.

## `%b`

The abbreviated month name according to the current locale.

## `%B`

The full month name according to the current locale.

## `%c`

The preferred date and time representation for the current locale. (In the
POSIX locale this is equivalent to `%a %b %e %H:%M:%S %Y`.)

## `%C`

The century number (year/100) as a 2-digit integer.

## `%d`

The day of the month as a decimal number (range 01 to 31).

## `%D`

Equivalent to `%m/%d/%y`. In international contexts, this format is ambiguous
and should be avoided.)

## `%e`

Like `%d`, the day of the month as a decimal number, but a leading zero is
replaced by a space.

## `%f`

The number of microseconds elapsed of the current second. (This a curl special
code and not a standard one.)

## `%F`

Equivalent to `%Y-%m-%d` (the ISO 8601 date format).

## `%G`

The ISO 8601 week-based year with century as a decimal number. The 4-digit
year corresponding to the ISO week number (see `%V`). This has the same format
and value as `%Y`, except that if the ISO week number belongs to the previous
or next year, that year is used instead.

## `%g`

Like `%G`, but without century, that is, with a 2-digit year (00-99).

## `%h`

Equivalent to `%b`.

## `%H`

The hour as a decimal number using a 24-hour clock (range 00 to 23).

## `%I`

The hour as a decimal number using a 12-hour clock (range 01 to 12).

## `%j`

The day of the year as a decimal number (range 001 to 366).

## `%k`

The hour (24-hour clock) as a decimal number (range 0 to 23); single digits
are preceded by a blank.

## `%l`

The hour (12-hour clock) as a decimal number (range 1 to 12); single digits
are preceded by a blank.

## `%m`

The month as a decimal number (range 01 to 12).

## `%M`

The minute as a decimal number (range 00 to 59).

## `%p`

Either "AM" or "PM" according to the given time value, or the corresponding
strings for the current locale. Noon is treated as "PM" and midnight as "AM".

## `%P`

Like `%p` but in lowercase: "am" or "pm" or a corresponding string for the
current locale.

## `%r`

The time in am or pm notation.

## `%R`

The time in 24-hour notation (`%H:%M`). For a version including the seconds,
see `%T` below.

## `%s`

The number of seconds since the Epoch, 1970-01-01 00:00:00 +0000 (UTC).

## `%S`

The second as a decimal number (range 00 to 60). (The range is up to 60 to
allow for occasional leap seconds.) See `%f` for microseconds.

## `%T`

The time in 24-hour notation (`%H:%M:%S`).

## `%u`

The day of the week as a decimal, range 1 to 7, Monday being 1.

## `%U`

The week number of the current year as a decimal number, range 00 to 53,
starting with the first Sunday as the first day of week 01. See also `%V` and
`%W`.

## `%V`

The ISO 8601 week number (see NOTES) of the current year as a decimal number,
range 01 to 53, where week 1 is the first week that has at least 4 days in the
new year. See also `%U` and `%W`.

## `%w`

The day of the week as a decimal, range 0 to 6, Sunday being 0. See also `%u`.

## `%W`

The week number of the current year as a decimal number, range 00 to 53,
starting with the first Monday as the first day of week 01.

## `%x`

The preferred date representation for the current locale without the time.

## `%X`

The preferred time representation for the current locale without the date.

## `%y`

The year as a decimal number without a century (range 00 to 99).

## `%Y`

The year as a decimal number including the century.

## `%z`

The `+hhmm` or `-hhmm` numeric timezone (that is, the hour and minute offset
from UTC). As time is always UTC, this outputs `+0000`.

## `%Z`

The timezone name. For some reason `GMT`.

## `%%`

A literal `%` character.
