Long: fail-early
Help: Fail on first transfer error, do not continue
Added: 7.52.0
Category: curl
Example: --fail-early $URL https://two.example
See-also: fail fail-with-body
---
Fail and exit on the first detected transfer error.

When curl is used to do multiple transfers on the command line, it will
attempt to operate on each given URL, one by one. By default, it will ignore
errors if there are more URLs given and the last URL's success will determine
the error code curl returns. So early failures will be "hidden" by subsequent
successful transfers.

Using this option, curl will instead return an error on the first transfer
that fails, independent of the amount of URLs that are given on the command
line. This way, no transfer failures go undetected by scripts and similar.

This option is global and does not need to be specified for each use of --next.

This option does not imply --fail, which causes transfers to fail due to the
server's HTTP status code. You can combine the two options, however note --fail
is not global and is therefore contained by --next.
