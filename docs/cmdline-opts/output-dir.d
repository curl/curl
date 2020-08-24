Long: output-dir
Arg: <dir>
Help: Directory to save files in
Added: 7.73.0
See-also: remote-name remote-header-name
---

This option specifies the directory in which files should be stored, when
--remote-name or --output are used.

The given output directory is used for all URLs and output options on the
command line, up until the first --next.

If the specified target directory doesn't exist, the operation will fail
unless --create-dirs is also used.

If this option is used multiple times, the last specified directory will be
used.
