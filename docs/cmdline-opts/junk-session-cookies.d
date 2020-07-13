Long: junk-session-cookies
Short: j
Help: Ignore session cookies read from file
Protocols: HTTP
See-also: cookie cookie-jar
Category: http
---
When curl is told to read cookies from a given file, this option will make it
discard all "session cookies". This will basically have the same effect as if
a new session is started. Typical browsers always discard session cookies when
they're closed down.
