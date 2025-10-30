---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Long: aws-sigv4
Protocols: HTTP
Arg: <provider1[:prvdr2[:reg[:srv]]]>
Help: AWS V4 signature auth
Category: auth http
Added: 7.75.0
Multi: single
See-also:
  - basic
  - user
Example:
  - --aws-sigv4 "aws:amz:us-east-2:es" --user "access-key-id:secret-key" $URL
  - --aws-sigv4 "aws:amz:us-east-2:es" --user "access-key-id:secret-key:security-token" $URL
---

# `--aws-sigv4`

Use AWS V4 signature authentication in the transfer.

The provider argument is a string that is used by the algorithm when creating
outgoing authentication headers.

The region argument is a string that points to a geographic area of
a resources collection (region-code) when the region name is omitted from
the endpoint.

The service argument is a string that points to a function provided by a cloud
(service-code) when the service name is omitted from the endpoint.

## X-Amz-Date Override

By default, curl generates the current timestamp for AWS signature calculation.
You can override this by providing your own X-Amz-Date value:

- **Header mode**: Use `-H "X-Amz-Date: 20231024T120000Z"`
- **Query parameter mode**: Include `X-Amz-Date=20231024T120000Z` in the URL

The timestamp must be in ISO8601 format (YYYYMMDDTHHMMSSZ).
Invalid formats are ignored and curl uses the generated timestamp instead.

## X-Amz-Security-Token Override

By default, curl uses the security token from the `--user` parameter if provided.
You can override this by providing your own X-Amz-Security-Token value:

- **Header mode**: Use `-H "X-Amz-Security-Token: your-session-token"`

The header value takes precedence over the `--user` parameter token.
Override only works in header mode; in query parameter mode, the `--user` parameter token is always used.

## SignedHeaders Override

By default, curl automatically determines which headers to include in the AWS signature calculation based on the request. You can override this using the `--aws-sigv4-signedheaders` option:

~~~
curl \
  --user "keyId:secretKey" \
  --aws-sigv4 "aws:vpc-lattice:us-east-1:vpc-lattice" \
  --aws-sigv4-signedheaders \
  "host;x-amz-content-sha256;x-amz-date" \
  "https://svc.vpc-lattice-svcs.us-east-1.on.aws/api"
~~~

The header names must be lowercase, semicolon-separated, and sorted alphabetically.
