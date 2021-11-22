Short: v
Long: verbose
Mutexed: trace trace-ascii
Help: Make the operation more talkative
See-also: include
Category: important verbose
Example: --verbose $URL
Added: 4.0
---
Makes curl verbose during the operation. Useful for debugging and seeing
what's going on "under the hood". A line starting with '>' means "header data"
sent by curl, '<' means "header data" received by curl that is hidden in
normal cases, and a line starting with '*' means additional info provided by
curl.

If you only want HTTP headers in the output, --include might be the option
you are looking for.

If you think this option still does not give you enough details, consider using
--trace or --trace-ascii instead.

This option is global and does not need to be specified for each use of
--next.

Use --silent to make curl really quiet.
