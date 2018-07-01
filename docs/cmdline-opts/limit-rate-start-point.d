Long: limit-rate-start-point
Arg: <starting point>
Help: Control where the speed limit begins
---
Control where the speed limit begins - for both downloads and uploads.
When you do not set this parameter, the starting point for limiting 
the speed is before dns parsing.When you set the starting point does 
not exist, the default starting point will be used (For example: HTTP
without 'appok' starting point).This parameter is executed only when 
the '--limit-rate' parameter setting is in effect.

The 'starting point' argument should be one of the following 
alternatives:
.RS
.IP dnsok 
Speed limit starting point - DNS resolution is completed.
.IP tcpok
Speed limit starting point - TCP connect is completed.
.IP appok
Speed limit starting point - SSL/SSH/etc connect/handshake 
to the remote host was completed.
.IP ttfb
Speed limit starting point - Time To First Byte.
.RE
