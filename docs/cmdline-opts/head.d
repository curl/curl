Long: head
Short: I
Help: Show document info only
Protocols: HTTP FTP FILE
Category: http ftp file
Example: -I $URL
Added: 4.0
---
Fetch the headers only! HTTP-servers feature the command HEAD which this uses
to get nothing but the header of a document. When used on an FTP or FILE file,
curl displays the file size and last modification time only.
