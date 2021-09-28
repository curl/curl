Long: upload-file
Short: T
Arg: <file>
Help: Transfer local FILE to destination
Category: important upload
Example: -T file $URL
Example: -T "img[1-1000].png" ftp://ftp.example.com/
Example: --upload-file "{file1,file2}" $URL
Added: 4.0
---
This transfers the specified local file to the remote URL. If there is no file
part in the specified URL, curl will append the local file name. NOTE that you
must use a trailing / on the last directory to really prove to Curl that there
is no file name or curl will think that your last directory name is the remote
file name to use. That will most likely cause the upload operation to fail. If
this is used on an HTTP(S) server, the PUT command will be used.

Use the file name "-" (a single dash) to use stdin instead of a given file.
Alternately, the file name "." (a single period) may be specified instead of
"-" to use stdin in non-blocking mode to allow reading server output while
stdin is being uploaded.

You can specify one --upload-file for each URL on the command line. Each
--upload-file + URL pair specifies what to upload and to where. curl also
supports "globbing" of the --upload-file argument, meaning that you can upload
multiple files to a single URL by using the same URL globbing style supported
in the URL.

When uploading to an SMTP server: the uploaded data is assumed to be RFC 5322
formatted. It has to feature the necessary set of headers and mail body
formatted correctly by the user as curl will not transcode nor encode it
further in any way.
