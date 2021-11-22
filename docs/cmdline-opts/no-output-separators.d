Long: no-output-separators
Help: Do not insert separators between files on stdout
Category: curl
See-also: silent write-out
Example: --no-output-separators $URL/split-file.part[001-099] > original-file
Added: 7.82.0
---
Disables output separators on stdout. By default, when downloading multiple
files to stdout, curl will insert separators of the form --_curl_--<URL>
before the response to each request.

Output separators are also disabled by --silent.
