Long: referer
Short: e
Arg: <URL>
Protocols: HTTP
Help: Referrer URL
See-also: user-agent header
Category: http
Example: --referer "https://fake.example" $URL
Example: --referer "https://fake.example;auto" -L $URL
Example: --referer ";auto" -L $URL
Added: 4.0
---
Sends the "Referrer Page" information to the HTTP server. This can also be set
with the --header flag of course. When used with --location you can append
";auto" to the --referer URL to make curl automatically set the previous URL
when it follows a Location: header. The \&";auto" string can be used alone,
even if you do not set an initial --referer.

If this option is used several times, the last one will be used.
