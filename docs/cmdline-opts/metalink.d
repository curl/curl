Long: metalink
Help: Process given URLs as metalink XML file
Added: 7.27.0
Requires: metalink
---
This option can tell curl to parse and process a given URI as Metalink file
(both version 3 and 4 (RFC 5854) are supported) and make use of the mirrors
listed within for failover if there are errors (such as the file or server not
being available). It will also verify the hash of the file after the download
completes. The Metalink file itself is downloaded and processed in memory and
not stored in the local file system.

Example to use a remote Metalink file:

 curl --metalink http://www.example.com/example.metalink

To use a Metalink file in the local file system, use FILE protocol (file://):

 curl --metalink file://example.metalink

Please note that if FILE protocol is disabled, there is no way to use a local
Metalink file at the time of this writing. Also note that if --metalink and
--include are used together, --include will be ignored. This is because
including headers in the response will break Metalink parser and if the
headers are included in the file described in Metalink file, hash check will
fail.
