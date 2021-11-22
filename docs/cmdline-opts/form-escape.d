Long: form-escape
Help: Escape multipart form field/file names using backslash
Protocols: HTTP
See-also: form
Added: 7.81.0
Category: http post
Example: --form-escape --form 'field\\name=curl' 'file=@load"this' $URL
---
Tells curl to pass on names of multipart form fields and files using
backslash-escaping instead of percent-encoding.
