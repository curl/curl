Long: mail-rcpt-allowfails
Help: Allow RCPT TO command to fail for some recipients
Protocols: SMTP
Added: 7.69.0
---
When sending data to multiple recipients, by default curl will abort SMTP
conversation if at least one of the recipients causes RCPT TO command to
return an error.

The default behavior can be changed by passing --mail-rcpt-allowfails
command-line option which will make curl ignore errors and proceed with the
remaining valid recipients.

In case when all recipients cause RCPT TO command to fail, curl will abort SMTP
conversation and return the error received from to the last RCPT TO command.