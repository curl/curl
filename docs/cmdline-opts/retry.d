Long: retry
Arg: <num>
Added: 7.12.3
Help: Retry request if transient problems occur
---
If a transient error is returned when curl tries to perform a transfer, it
will retry this number of times before giving up. Setting the number to 0
makes curl do no retries (which is the default). Transient error means either:
a timeout, an FTP 4xx response code or an HTTP 5xx response code.

When curl is about to retry a transfer, it will first wait one second and then
for all forthcoming retries it will double the waiting time until it reaches
10 minutes which then will be the delay between the rest of the retries.  By
using --retry-delay you disable this exponential backoff algorithm. See also
--retry-max-time to limit the total time allowed for retries.

If this option is used several times, the last one will be used.
