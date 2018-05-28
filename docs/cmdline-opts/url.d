Long: url
Arg: <url>
Help: URL to work with
---
Specify a URL to fetch. This option is mostly handy when you want to specify
URL(s) in a config file.

If the given URL is missing a scheme name (such as "http://" or "ftp://" etc)
then curl will make a guess based on the host. If the outermost sub-domain
name matches DICT, FTP, IMAP, LDAP, POP3 or SMTP then that protocol will be
used, otherwise HTTP will be used. Since 7.45.0 guessing can be disabled by
setting a default protocol, see --proto-default for details.

This option may be used any number of times. To control where this URL is
written, use the --output or the --remote-name options.
