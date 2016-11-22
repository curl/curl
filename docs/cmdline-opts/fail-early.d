Long: fail-early
Help: Fail on first transfer error, do not continue
Added: 7.52.0
---
Fail and exit on first detected error.

When curl is used to do multiple transfers on the command line, it will
attempt to operate on each given URL, one by one. By default, it will ignore
errors if there are more URLs given and the last URL's success will determine
the error code curl returns. So early failures will be "hidden" by subsequent
successful transfers.

Using this option, curl will instead return an error on the first transfers
that fails, independent on the amount of more URLs that are given on the
command line. This way, no transfer failures go undetected by scripts and
similar.

This option will apply for all given URLs even if you use --next.
