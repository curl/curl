Long: esni
Help: Use encrypted SNI
Protocols: TLS
---
Forces curl to attempt to use encrypted SNI or, as --no-esni,
to avoid using encrypted SNI.

Implied by use of either --esni-cover or --esni-load options.

If --esni and --no-esni are both specified, only the first one
has effect.

This description of the --esni option is PROVISIONAL, as
ESNI support is work in progress.
