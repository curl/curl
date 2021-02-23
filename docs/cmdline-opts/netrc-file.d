Long: netrc-file
Help: Specify FILE for netrc
Arg: <filename>
Added: 7.21.5
Mutexed: netrc
Category: curl
---
This option is similar to --netrc, except that you provide the path (absolute
or relative) to the netrc file that curl should use.  You can only specify one
netrc file per invocation. If several --netrc-file options are provided,
the last one will be used.

It will abide by --netrc-optional if specified.
