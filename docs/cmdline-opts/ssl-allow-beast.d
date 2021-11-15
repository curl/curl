Long: ssl-allow-beast
Help: Allow security flaw to improve interop
Added: 7.25.0
Category: tls
Example: --ssl-allow-beast $URL
See-also: proxy-ssl-allow-beast insecure
---
This option tells curl to not work around a security flaw in the SSL3 and
TLS1.0 protocols known as BEAST.  If this option is not used, the SSL layer
may use workarounds known to cause interoperability problems with some older
SSL implementations.

**WARNING**: this option loosens the SSL security, and by using this flag you
ask for exactly that.
