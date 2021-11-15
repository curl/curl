Long: remote-time
Short: R
Help: Set the remote file's time on the local output
Category: output
Example: --remote-time -o foo $URL
Added: 7.9
See-also: remote-name time-cond
---
When used, this will make curl attempt to figure out the timestamp of the
remote file, and if that is available make the local file get that same
timestamp.
