c: Copyright (C) 1998 - 2022, Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Long: mail-rcpt-allowfails
Help: Allow RCPT TO command to fail for some recipients
Protocols: SMTP
Added: 7.69.0
Category: smtp
Example: --mail-rcpt-allowfails --mail-rcpt dest@example.com smtp://example.com
See-also: mail-rcpt
Multi: boolean
---
When sending data to multiple recipients, by default curl will abort SMTP
conversation if at least one of the recipients causes RCPT TO command to
return an error.

The default behavior can be changed by passing --mail-rcpt-allowfails
command-line option which will make curl ignore errors and proceed with the
remaining valid recipients.

If all recipients trigger RCPT TO failures and this flag is specified, curl
will still abort the SMTP conversation and return the error received from to
the last RCPT TO command.
