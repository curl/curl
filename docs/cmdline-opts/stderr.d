Long: stderr
Arg: <file>
Help: Where to redirect stderr
See-also: verbose silent
Category: verbose
Example: --stderr output.txt $URL
Added: 6.2
---
Redirect all writes to stderr to the specified file instead. If the file name
is a plain '-', it is instead written to stdout.

This option is global and does not need to be specified for each use of
--next.

If this option is used several times, the last one will be used.
