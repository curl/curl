Long: ssl-session-file
Arg: <file>
Help: File to read SSL session from, or file to write SSL session to
Protocols: TLS
---
Before SSL handshake, if the specified file contains the available session, then use this session.
When the SSL handshake is complete, this SSL session is written to the specified file.

for example:
 curl https://www.example.com/ -v --ssl-session-file /tmp/sess.pem

