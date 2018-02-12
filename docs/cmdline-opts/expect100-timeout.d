Long: expect100-timeout
Arg: <seconds>
Help: How long to wait for 100-continue
Protocols: HTTP
Added: 7.47.0
See-also: connect-timeout
---
Maximum time in seconds that you allow curl to wait for a 100-continue
response when curl emits an Expects: 100-continue header in its request. By
default curl will wait one second. This option accepts decimal values! When
curl stops waiting, it will continue as if the response has been received.
