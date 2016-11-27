Long: remote-name-all
Help: Use the remote file name for all URLs
Added: 7.19.0
---
This option changes the default action for all given URLs to be dealt with as
if --remote-name were used for each one. So if you want to disable that for a
specific URL after --remote-name-all has been used, you must use "-o -" or
--no-remote-name.
