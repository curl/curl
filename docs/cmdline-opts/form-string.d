Long: form-string
Help: Specify multipart MIME data
Protocols: HTTP SMTP IMAP
Arg: <name=string>
See-also: form
Category: http upload
---
Similar to --form except that the value string for the named parameter is used
literally. Leading \&'@' and \&'<' characters, and the \&';type=' string in
the value have no special meaning. Use this in preference to --form if
there's any possibility that the string value may accidentally trigger the
\&'@' or \&'<' features of --form.
