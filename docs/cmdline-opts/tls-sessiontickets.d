Long: tls-session-tickets
Arg:
Help: Enable TLS session tickets
Added: 7.6x.0
---

Set TLS Session Tickets for Session Resumption without Server-Side State (RFC
5077)

This TLS setting allow the server to resume TLS sessions and avoid keeping
per-client session state. The TLS server encapsulates the session state into a
ticket and forwards it to the client. The client can subsequently resume a
session using the obtained ticket.
