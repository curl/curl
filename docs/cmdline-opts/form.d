Long: form
Short: F
Arg: <name=content>
Help: Specify HTTP multipart POST data
Protocols: HTTP
Mutexed: data head upload
---
This lets curl emulate a filled-in form in which a user has pressed the submit
button. This causes curl to POST data using the Content-Type
multipart/form-data according to RFC 2388. This enables uploading of binary
files etc. To force the 'content' part to be a file, prefix the file name with
an @ sign. To just get the content part from a file, prefix the file name with
the symbol <. The difference between @ and < is then that @ makes a file get
attached in the post as a file upload, while the < makes a text field and just
get the contents for that text field from a file.

Example: to send an image to a server, where \&'profile' is the name of the
form-field to which portrait.jpg will be the input:

 curl -F profile=@portrait.jpg https://example.com/upload.cgi

To read content from stdin instead of a file, use - as the filename. This goes
for both @ and < constructs. Unfortunately it does not support reading the
file from a named pipe or similar, as it needs the full size before the
transfer starts.

You can also tell curl what Content-Type to use by using 'type=', in a manner
similar to:

 curl -F "web=@index.html;type=text/html" example.com

or

 curl -F "name=daniel;type=text/foo" example.com

You can also explicitly change the name field of a file upload part by setting
filename=, like this:

 curl -F "file=@localfile;filename=nameinpost" example.com

If filename/path contains ',' or ';', it must be quoted by double-quotes like:

 curl -F "file=@\\"localfile\\";filename=\\"nameinpost\\"" example.com

or

 curl -F 'file=@"localfile";filename="nameinpost"' example.com

Note that if a filename/path is quoted by double-quotes, any double-quote
or backslash within the filename must be escaped by backslash.

See further examples and details in the MANUAL.

This option can be used multiple times.
