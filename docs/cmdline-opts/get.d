Long: get
Short: G
Help: Put the post data in the URL and use GET
Category: http upload
Example: --get $URL
Example: --get -d "tool=curl" -d "age=old" $URL
Example: --get -I -d "tool=curl" $URL
Added: 7.8.1
See-also: data request
---
When used, this option will make all data specified with --data, --data-binary
or --data-urlencode to be used in an HTTP GET request instead of the POST
request that otherwise would be used. The data will be appended to the URL
with a '?' separator.

If used in combination with --head, the POST data will instead be appended to
the URL with a HEAD request.

If this option is used several times, only the first one is used. This is
because undoing a GET does not make sense, but you should then instead enforce
the alternative method you prefer.
