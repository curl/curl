Long: tcp-maxseg
Added: XXX
Help: Set TCP maximum segment size (MSS)
Category: connection
Example: --tcp-maxseg 536
Arg: <MSS>
---
Set the maximum segment size for outgoing TCP packets.
Values greater than the (eventual) interface MTU have no effect.
TCP will also impose its minimum and maximum bounds over the value provided.
