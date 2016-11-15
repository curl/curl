Short: v
Long: verbose
Mutexed: trace trace-ascii
Help: Make the operation more talkative
See-also: include
---
Makes curl verbose during the operation. Useful for debugging and seeing
what's going on "under the hood". A line starting with '>' means "header data"
sent by curl, '<' means "header data" received by curl that is hidden in
normal cases, and a line starting with '*' means additional info provided by
curl.

If you only want HTTP headers in the output, --include might be the option
you're looking for.

If you think this option still doesn't give you enough details, consider using
--trace or --trace-ascii instead.

Use --silent to make curl really quiet.
