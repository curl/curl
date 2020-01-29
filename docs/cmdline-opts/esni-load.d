Long: esni-load
Help: File to load ESNIKeys data from
Arg: <string/@file>
Protocols: TLS
---

Specify ESNIkeys data as a string using hexadecimal or base-64
encoding for use (eg. for privacy reasons, or prior to data being
available in DNS) instead of fetching these data from the DNS.

The value used on the command line may be either the encoded string
itself or the '@'-escaped name of a text file containing the string.

Multiple ESNIkeys data structures may be specified using hexadecimal
encoding by simply concatenating the individual encoded strings, or
using base-64 encoding by using a semicolon between each individual
encoded string and the following one.

Implies --esni.

If specified more than once, or together with --no-esni, only the
first specification has effect.

This description of the --esni-load option is PROVISIONAL, as
ESNI support is work in progress.
