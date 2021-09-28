Long: no-buffer
Short: N
Help: Disable buffering of the output stream
Category: curl
Example: --no-buffer $URL
Added: 6.5
---
Disables the buffering of the output stream. In normal work situations, curl
will use a standard buffered output stream that will have the effect that it
will output the data in chunks, not necessarily exactly when the data arrives.
Using this option will disable that buffering.

Note that this is the negated option name documented. You can thus use
--buffer to enforce the buffering.
