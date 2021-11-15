Long: ssl-revoke-best-effort
Help: Ignore missing/offline cert CRL dist points
Added: 7.70.0
Category: tls
Example: --ssl-revoke-best-effort $URL
See-also: crlfile insecure
---
(Schannel) This option tells curl to ignore certificate revocation checks when
they failed due to missing/offline distribution points for the revocation check
lists.
