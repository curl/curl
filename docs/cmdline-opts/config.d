Long: config
Arg: <file>
Help: Read config from a file
Short: K
Category: curl
Example: --config file.txt $URL
Added: 4.10
See-also: disable
---
Specify a text file to read curl arguments from. The command line arguments
found in the text file will be used as if they were provided on the command
line.

Options and their parameters must be specified on the same line in the file,
separated by whitespace, colon, or the equals sign. Long option names can
optionally be given in the config file without the initial double dashes and
if so, the colon or equals characters can be used as separators. If the option
is specified with one or two dashes, there can be no colon or equals character
between the option and its parameter.

If the parameter contains whitespace (or starts with : or =), the parameter
must be enclosed within quotes. Within double quotes, the following escape
sequences are available: \\\\, \\", \\t, \\n, \\r and \\v. A backslash
preceding any other letter is ignored.

If the first column of a config line is a '#' character, the rest of the line
will be treated as a comment.

Only write one option per physical line in the config file.

Specify the filename to --config as '-' to make curl read the file from stdin.

Note that to be able to specify a URL in the config file, you need to specify
it using the --url option, and not by simply writing the URL on its own
line. So, it could look similar to this:

url = "https://curl.se/docs/"

 # --- Example file ---
 # this is a comment
 url = "example.com"
 output = "curlhere.html"
 user-agent = "superagent/1.0"

 # and fetch another URL too
 url = "example.com/docs/manpage.html"
 -O
 referer = "http://nowhereatall.example.com/"
 # --- End of example file ---

When curl is invoked, it (unless --disable is used) checks for a default
config file and uses it if found, even when --config is used. The default
config file is checked for in the following places in this order:

1) "$CURL_HOME/.curlrc"

2) "$XDG_CONFIG_HOME/.curlrc" (Added in 7.73.0)

3) "$HOME/.curlrc"

4) Windows: "%USERPROFILE%\\.curlrc"

5) Windows: "%APPDATA%\\.curlrc"

6) Windows: "%USERPROFILE%\\Application Data\\.curlrc"

7) Non-Windows: use getpwuid to find the home directory

8) On Windows, if it finds no .curlrc file in the sequence described above, it
checks for one in the same dir the curl executable is placed.

On Windows two filenames are checked per location: .curlrc and _curlrc,
preferring the former. Older versions on Windows checked for _curlrc only.

This option can be used multiple times to load multiple config files.
