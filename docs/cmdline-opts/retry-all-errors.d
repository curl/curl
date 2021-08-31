Long: retry-all-errors
Help: Retry all errors (use with --retry)
Added: 7.71.0
Category: curl
Example: --retry-all-errors $URL
---
Retry on any error. This option is used together with --retry.

This option is the "sledgehammer" of retrying. Do not use this option by
default (eg in curlrc), there may be unintended consequences such as sending or
receiving duplicate data. Do not use with redirected input or output. You'd be
much better off handling your unique problems in shell script. Please read the
example below.

**WARNING**: For server compatibility curl attempts to retry failed flaky
transfers as close as possible to how they were started, but this is not
possible with redirected input or output. For example, before retrying it
removes output data from a failed partial transfer that was written to an
output file. However this is not true of data redirected to a | pipe or >
file, which are not reset. We strongly suggest don't parse or record output
via redirect in combination with this option, since you may receive duplicate
data.

By default curl will not error on an HTTP response code that indicates an HTTP
error, if the transfer was successful. For example, if a server replies 404
Not Found and the reply is fully received then that is not an error. When
--retry is used then curl will retry on some HTTP response codes that indicate
transient HTTP errors, but that does not include most 4xx response codes such
as 404. If you want to retry on all response codes that indicate HTTP errors
(4xx and 5xx) then combine with --fail.
