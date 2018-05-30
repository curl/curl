Long: retry-max-time
Arg: <seconds>
Help: Retry only within this period
Added: 7.12.3
---
The retry timer is reset before the first transfer attempt. Retries will be
done as usual (see --retry) as long as the timer hasn't reached this given
limit. Notice that if the timer hasn't reached the limit, the request will be
made and while performing, it may take longer than this given time period. To
limit a single request\'s maximum time, use --max-time.  Set this option to
zero to not timeout retries.

If this option is used several times, the last one will be used.
