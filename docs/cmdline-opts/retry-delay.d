long: retry-delay
arg: <seconds>
Help: Wait time between retries
Added: 7.12.3
---
Make curl sleep this amount of time before each retry when a transfer has
failed with a transient error (it changes the default backoff time algorithm
between retries). This option is only interesting if --retry is also
used. Setting this delay to zero will make curl use the default backoff time.

If this option is used several times, the last one will be used.
