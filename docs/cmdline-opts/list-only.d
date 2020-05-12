Long: list-only
Short: l
Protocols: FTP POP3
Help: List only mode
Added: 4.0
---
(FTP)
When listing an FTP directory, this switch forces a name-only view. This is
especially useful if the user wants to machine-parse the contents of an FTP
directory since the normal directory view doesn't use a standard look or
format. When used like this, the option causes a NLST command to be sent to
the server instead of LIST.

Note: Some FTP servers list only files in their response to NLST; they do not
include sub-directories and symbolic links.

(POP3)
When retrieving a specific email from POP3, this switch forces a LIST command
to be performed instead of RETR. This is particularly useful if the user wants
to see if a specific message id exists on the server and what size it is.

Note: When combined with --request, this option can be used to send an UIDL
command instead, so the user may use the email's unique identifier rather than
it's message id to make the request.
