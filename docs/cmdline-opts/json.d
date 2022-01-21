Long: json
Arg: <data>
Help: HTTP POST JSON
Protocols: HTTP
See-also: data-binary data-raw
Mutexed: form head upload-file
Category: http post upload
Example: --json '{ "drink": "coffe" }' $URL
Example: --json '{ "drink":' --json ' "coffe" }' $URL
Example: --json @prepared $URL
Example: --json @- $URL < json.txt
Added: 7.82.0
---
Sends the specified JSON data in a POST request to the HTTP server. --json
works as a shortcut for passing on these three options:

 --data [arg]
 --header "Content-Type: application/json"
 --header "Accept: application/json"

There is **no verification** that the passed in data is actual JSON or that
the syntax is correct.

If you start the data with the letter @, the rest should be a file name to
read the data from, or a single dash (-) if you want curl to read the data
from stdin. Posting data from a file named \&'foobar' would thus be done with
--json @foobar and to instead read the data from stdin, use --json @-.

If this option is used more than once on the same command line, the additional
data pieces will be concatenated to the previous before sending.

The headers this option sets can be overriden with --header as usual.
