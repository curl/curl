Long: time-cond
Short: z
Arg: <time>
Help: Transfer based on a time condition
Protocols: HTTP FTP
Category: http ftp
---
Request a file that has been modified later than the given time and date, or
one that has been modified before that time. The <date expression> can be all
sorts of date strings or if it doesn't match any internal ones, it is taken as
a filename and tries to get the modification date (mtime) from <file>
instead. See the *curl_getdate(3)* man pages for date expression details.

Start the date expression with a dash (-) to make it request for a document
that is older than the given date/time, default is a document that is newer
than the specified date/time.

If this option is used several times, the last one will be used.
