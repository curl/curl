Long: proxy-capath
Help: CA directory to verify peer against for proxy
Arg: <dir>
Added: 7.52.0
See-also: proxy-cacert proxy capath
---
Same as --capath but used in HTTPS proxy context.

If --capath is set but this option is not then curl will use the --capath value
for this option.
