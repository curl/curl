c: Copyright (C) 1998 - 2022, Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Long: aws-sigv4
Arg: <provider1[:provider2[:region[:service]]]>
Help: Use AWS V4 signature authentication
Category: auth http
Added: 7.75.0
See-also: basic user
Example: --aws-sigv4 "aws:amz:east-2:es" --user "key:secret" $URL
Multi: single
---
Use AWS V4 signature authentication in the transfer.

The provider argument is a string that is used by the algorithm when creating
outgoing authentication headers.

The region argument is a string that points to a geographic area of
a resources collection (region-code) when the region name is omitted from
the endpoint.

The service argument is a string that points to a function provided by a cloud
(service-code) when the service name is omitted from the endpoint.
