Long: aws-sigv4-nb-encoding
Arg: <0|1>
Help: Use AWS V4 signature authentication
Category: auth http
Added: 7.82.0
See-also: aws-sigv4
Example: --aws-sigv4 "aws:amz:east-2:es" --aws-sigv4-nb-encoding 1 --user "key:secret" $URL
---
Number of URL encoding to be done while processing AWS V4 signature.

0 is the default Value, and will tell curl to not URL encode anything.
1 mean there is one encoding pass to be made.
