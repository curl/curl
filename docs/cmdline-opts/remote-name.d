Long: remote-name
Short: O
Help: Write output to a file named as the remote file
Category: important output
Example: -O https://example.com/filename
Added: 4.0
---
Write output to a local file named like the remote file we get. (Only the file
part of the remote file is used, the path is cut off.)

The file will be saved in the current working directory. If you want the file
saved in a different directory, make sure you change the current working
directory before invoking curl with this option.

The remote file name to use for saving is extracted from the given URL,
nothing else, and if it already exists it will be overwritten. If you want the
server to be able to choose the file name refer to --remote-header-name which
can be used in addition to this option. If the server chooses a file name and
that name already exists it will not be overwritten.

There is no URL decoding done on the file name. If it has %20 or other URL
encoded parts of the name, they will end up as-is as file name.

You may use this option as many times as the number of URLs you have.
