---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Long: aws-sigv4-algorithm
Protocols: HTTP
Arg: <algorithm>
Help: AWS V4 signature algorithm
Category: auth http
Added: 8.17.0
Multi: single
See-also:
  - aws-sigv4
  - aws-sigv4-mode
  - user
Example:
  - --aws-sigv4 "aws:amz:us-east-1:vpc-lattice" --aws-sigv4-algorithm "ECDSA-P256-SHA256" --user "key:secret" $URL
  - --aws-sigv4 "aws:amz:us-east-1:vpc-lattice" --aws-sigv4-algorithm "ECDSA-P256-SHA256" --user "key:secret:token" $URL
---

# `--aws-sigv4-algorithm`

Specify the AWS SIGV4 signing algorithm. Valid values are "HMAC-SHA256" (default) and "ECDSA-P256-SHA256".

When set to "HMAC-SHA256" (which is the default), uses the standard AWS Signature Version 4 algorithm based on HMAC-SHA256 signing. This supports single region signing.

When set to "ECDSA-P256-SHA256", uses AWS Signature Version 4A (SIGV4A) based on ECDSA P-256 signing. This supports multi-region/cross-region signing.

For more details on AWS signature algorithms, see the [AWS documentation](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_sigv-create-signed-request.html).

## Example

Standard SIGV4 signing:
~~~
curl \
  --user "keyId:secretKey:sessionToken" \
  --aws-sigv4 "aws:amz:us-east-1:vpc-lattice-svcs" \
  --aws-sigv4-algorithm "HMAC-SHA256" \
  "https://some-host.amazonaws.com/api/data"
~~~

SIGV4A multi-region signing usable in specific regions:
~~~
curl \
  --user "keyId:secretKey:sessionToken" \
  --aws-sigv4 "aws:amz:us-east-1,us-west-2:another-svc" \
  --aws-sigv4-algorithm "ECDSA-P256-SHA256" \
  "https://some-host.amazonaws.com/api/data"
~~~

SIGV4A multi-region signing usable in any region:
~~~
curl \
  --user "keyId:secretKey:sessionToken" \
  --aws-sigv4 "aws:amz:*:vpc-lattice" \
  --aws-sigv4-algorithm "ECDSA-P256-SHA256" \
  "https://some-host.amazonaws.com/api/data"
~~~
