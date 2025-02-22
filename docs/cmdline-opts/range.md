---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Long: range
Short: r
Help: Retrieve only the bytes within RANGE
Arg: <range>
Protocols: HTTP FTP SFTP FILE
Category: http ftp sftp file
Added: 4.0
Multi: single
See-also:
  - continue-at
  - append
Example:
  - --range 22-44 $URL
---

# `--range`

Retrieve a byte range (i.e. a partial document) from an HTTP/1.1, FTP or SFTP
server or a local FILE. Ranges can be specified in a number of ways.

## 0-499
specifies the first 500 bytes

## 500-999
specifies the second 500 bytes

## -500
specifies the last 500 bytes

## 9500-
specifies the bytes from offset 9500 and forward

## 0-0,-1
specifies the first and last byte only(*)(HTTP)

## 100-199,500-599
specifies two separate 100-byte ranges(*) (HTTP)

##

(*) = NOTE that if specifying multiple ranges and the server supports it then
it replies with a multiple part response that curl returns as-is. It
contains meta information in addition to the requested bytes. Parsing or
otherwise transforming this response is the responsibility of the caller.

Only digit characters (0-9) are valid in the 'start' and 'stop' fields of the
'start-stop' range syntax. If a non-digit character is given in the range, the
server's response is unspecified, depending on the server's configuration.

Many HTTP/1.1 servers do not have this feature enabled, so that when you
attempt to get a range, curl instead gets the whole document.

FTP and SFTP range downloads only support the simple 'start-stop' syntax
(optionally with one of the numbers omitted). FTP use depends on the extended
FTP command SIZE.

This command line option is mutually exclusive with --continue-at: you can only
use one of them for a single transfer.
