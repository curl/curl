Long: remote-header-name
Short: J
Protocols: HTTP
Help: Use the header-provided filename
Category: output
---
This option tells the --remote-name option to use the server-specified
Content-Disposition filename instead of extracting a filename from the URL.

If the server specifies a file name and a file with that name already exists
in the current working directory it will not be overwritten and an error will
occur. If the server doesn't specify a file name then this option has no
effect.

There's no attempt to decode %-sequences (yet) in the provided file name, so
this option may provide you with rather unexpected file names.

**WARNING**: Exercise judicious use of this option, especially on Windows. A
rogue server could send you the name of a DLL or other file that could possibly
be loaded automatically by Windows or some third party software.
