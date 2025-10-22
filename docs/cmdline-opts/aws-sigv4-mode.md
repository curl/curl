---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Long: aws-sigv4-mode
Protocols: HTTP
Arg: <mode>
Help: AWS V4 signature mode
Category: auth http
Added: 8.17.0
Multi: single
See-also:
  - aws-sigv4
  - user
Example:
  - --aws-sigv4 "aws:amz:us-east-2:es" --aws-sigv4-mode querystring --user "key:secret" $URL
  - --aws-sigv4 "aws:amz:us-east-2:es" --aws-sigv4-mode querystring --user "key:secret:token" $URL
---

## --aws-sigv4-mode

Specify the AWS SIGV4 signing mode. Valid values are "header" (default) and "querystring".

When set to "header" (which is the default), AWS SIGV4 authentication parameters are added as HTTP headers instead of query string parameters. This
is the standard method for AWS API requests.

When set to "querystring", AWS SIGV4 authentication parameters are added to the URL query string instead of HTTP headers. This is useful for creating pre-signed URLs that
can be shared or used without additional authentication headers, such as when calling VPC Lattice services.

Example:
- --aws-sigv4 "aws:amz:us-east-1:vpc-lattice-svcs" --aws-sigv4-mode "querystring" --user "keyId:secretKey" -G -d "X-Amz-Expires=3600" $URL

For more information about AWS SIGV4 authentication methods, see:
https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_sigv-authentication-methods.html
