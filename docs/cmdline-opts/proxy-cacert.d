Long: proxy-cacert
Help: CA certificate to verify peer against for proxy
Arg: <file>
Added: 7.52.0
See-also: proxy-capath cacert capath proxy
---
Same as --cacert but used in HTTPS proxy context.

If --cacert is set but this option is not then curl will use the --cacert value
for this option.
