Long: proxy-crlfile
Arg: <file>
Help: Set a CRL list for proxy
Added: 7.52.0
---
Same as --crlfile but used in HTTPS proxy context.

If --crlfile is set but this option is not then curl will use the --crlfile
value for this option.
