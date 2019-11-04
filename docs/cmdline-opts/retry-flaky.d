Long: retry-flaky
Help: Retry on partial transfer errors (heed warnings; use with --retry)
Added: 7.68.0
---
In addition to the other conditions, consider partial transfer errors as
transient errors too for --retry. This option is used together with --retry.

For server compatibility curl attempts to retry failed flaky transfers as
close as possible to how they were stated. It removes output data from a
failed partial transfer that was written to an output file. However this is not
true of data redirected to a | pipe or > file, which are not reset. We suggest
don't parse or record output via redirect in combination with this option,
since you may receive duplicate data. Furthermore don't use this option as a
default option (eg in curlrc) for that reason.

Partial transfer errors are CURLE_COULDNT_RESOLVE_HOST (6),
CURLE_FTP_CANT_GET_HOST (15), CURLE_HTTP2 (16), CURLE_PARTIAL_FILE (18),
CURLE_SSL_CONNECT_ERROR (35), CURLE_GOT_NOTHING (52), CURLE_SEND_ERROR (55),
CURLE_RECV_ERROR (56), CURLE_HTTP2_STREAM (92). More may be added as needed.
