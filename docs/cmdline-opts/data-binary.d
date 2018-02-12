Long: data-binary
Arg: <data>
Help: HTTP POST binary data
Protocols: HTTP
---
This posts data exactly as specified with no extra processing whatsoever.

If you start the data with the letter @, the rest should be a filename.  Data
is posted in a similar manner as --data does, except that newlines and
carriage returns are preserved and conversions are never done.

If this option is used several times, the ones following the first will append
data as described in --data.
