Long: ssl-no-verify-subject-name
Help: Disable subject name and SAN checks
Added: 7.77.0
Category: tls
---
This option tells curl to disable verification of Subject Name and Subject
Alternative Name.
WARNING: this option loosens the SSL security, and by using this flag you ask
for exactly that.
