Short: :
Long: next
Tags:
Protocols:
Added: 7.36.0
Magic: divider
Help: Make next URL use its separate set of options
Category: curl
Example: $URL --next -d postthis www2.example.com
Example: -I $URL --next https://example.net/
See-also: parallel config
---
Tells curl to use a separate operation for the following URL and associated
options. This allows you to send several URL requests, each with their own
specific options, for example, such as different user names or custom requests
for each.

--next will reset all local options and only global ones will have their
values survive over to the operation following the --next instruction. Global
options include --verbose, --trace, --trace-ascii and --fail-early.

For example, you can do both a GET and a POST in a single command line:

 curl www1.example.com --next -d postthis www2.example.com
