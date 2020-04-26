# curl test suite file format

The curl test suite's file format is very simple and extensible, closely
resembling XML. All data for a single test case resides in a single ASCII
file. Labels mark the beginning and the end of all sections, and each label
must be written in its own line.  Comments are either XML-style (enclosed with
`<!--` and `-->`) or shell script style (beginning with `#`) and must appear
on their own lines and not alongside actual test data.  Most test data files
are syntactically valid XML, although a few files are not (lack of support for
character entities and the preservation of CR/LF characters at the end of
lines are the biggest differences).

Each test case exists as a file matching the format `tests/data/testNUM`,
where NUM is considered the unique test number.

The file begins with a 'testcase' tag, which encompasses the remainder of the
file.

# `<testcase>`

Each test is always within the testcase tag. Each test case is split up in
four main sections: `info`, `reply`, `client` and `verify`.

- **info** provides information about the test case

- **reply** is used for the server to know what to send as a reply for the
requests curl sends

- **client** defines how the client should behave

- **verify** defines how to verify that the data stored after a command has
been run ended up correctly

Each main section has a number of available subsections that can be specified,
that will be checked/used if specified.

## `<info>`

### `<keywords>`
A newline-separated list of keywords describing what this test case uses and
tests. Try to use an already used keyword.  These keywords will be used for
statistical/informational purposes and for choosing or skipping classes
of tests.  "Keywords" must begin with an alphabetic character, "-", "["
or "{" and may actually consist of multiple words separated by spaces
which are treated together as a single identifier.

## `<reply>`

### `<data [nocheck="yes"] [sendzero="yes"] [base64="yes"] [hex="yes"]>`

data to be sent to the client on its request and later verified that it
arrived safely. Set `nocheck="yes"` to prevent the test script from verifying
the arrival of this data.

If the data contains `swsclose` anywhere within the start and end tag, and
this is a HTTP test, then the connection will be closed by the server after
this response is sent. If not, the connection will be kept persistent.

If the data contains `swsbounce` anywhere within the start and end tag, the
HTTP server will detect if this is a second request using the same test and
part number and will then increase the part number with one. This is useful
for auth tests and similar.

`sendzero=yes` means that the (FTP) server will "send" the data even if the
size is zero bytes. Used to verify curl's behaviour on zero bytes transfers.

`base64=yes` means that the data provided in the test-file is a chunk of data
encoded with base64. It is the only way a test case can contain binary
data. (This attribute can in fact be used on any section, but it doesn't make
much sense for other sections than "data").

`hex=yes` means that the data is a sequence of hex pairs. It will get decoded
and used as "raw" data.

For FTP file listings, the `<data>` section will be used *only* if you make
sure that there has been a CWD done first to a directory named `test-[num]`
where [num] is the test case number. Otherwise the ftp server can't know from
which test file to load the list content.

### `<dataNUM>`

Send back this contents instead of the <data> one. The num is set by:

 - The test number in the request line is >10000 and this is the remainder
   of [test case number]%10000.
 - The request was HTTP and included digest details, which adds 1000 to NUM
 - If a HTTP request is NTLM type-1, it adds 1001 to num
 - If a HTTP request is NTLM type-3, it adds 1002 to num
 - If a HTTP request is Basic and num is already >=1000, it adds 1 to num
 - If a HTTP request is Negotiate, num gets incremented by one for each
   request with Negotiate authorization header on the same test case.

Dynamically changing num in this way allows the test harness to be used to
test authentication negotiation where several different requests must be sent
to complete a transfer. The response to each request is found in its own data
section.  Validating the entire negotiation sequence can be done by specifying
a datacheck section.

### `<connect>`
The connect section is used instead of the 'data' for all CONNECT
requests. The remainder of the rules for the data section then apply but with
a connect prefix.

### `<datacheck [mode="text"] [nonewline="yes"]>`
if the data is sent but this is what should be checked afterwards. If
`nonewline=yes` is set, runtests will cut off the trailing newline from the
data before comparing with the one actually received by the client.

Use the `mode="text"` attribute if the output is in text mode on platforms
that have a text/binary difference.

### `<datacheckNUM [nonewline="yes"] [mode="text"]>`
The contents of numbered datacheck sections are appended to the non-numbered
one.

### `<size>`
number to return on a ftp SIZE command (set to -1 to make this command fail)

### `<mdtm>`
what to send back if the client sends a (FTP) MDTM command, set to -1 to
have it return that the file doesn't exist

### `<postcmd>`
special purpose server-command to control its behavior *after* the
reply is sent
For HTTP/HTTPS, these are supported:

`wait [secs]` - Pause for the given time

### `<servercmd>`
Special-commands for the server.

The first line of this file will always be set to `Testnum [number]` by the
test script, to allow servers to read that to know what test the client is
about to issue.

#### For FTP/SMTP/POP/IMAP

- `REPLY [command] [return value] [response string]` - Changes how the server
  responds to the [command]. [response string] is evaluated as a perl string,
  so it can contain embedded \r\n, for example. There's a special [command]
  named "welcome" (without quotes) which is the string sent immediately on
  connect as a welcome.
- `REPLYLF` (like above but sends the response terminated with LF-only and not
   CRLF)
- `COUNT [command] [num]` - Do the `REPLY` change for `[command]` only `[num]`
  times and then go back to the built-in approach
- `DELAY [command] [secs]` - Delay responding to this command for the given
  time
- `RETRWEIRDO` - Enable the "weirdo" RETR case when multiple response lines
   appear at once when a file is transferred
- `RETRNOSIZE` - Make sure the RETR response doesn't contain the size of the
  file
- `NOSAVE` - Don't actually save what is received
- `SLOWDOWN` - Send FTP responses with 0.01 sec delay between each byte
- `PASVBADIP` - makes PASV send back an illegal IP in its 227 response
- `CAPA [capabilities]` - Enables support for and specifies a list of space
   separated capabilities to return to the client for the IMAP `CAPABILITY`,
   POP3 `CAPA` and SMTP `EHLO` commands
- `AUTH [mechanisms]` - Enables support for SASL authentication and specifies
   a list of space separated mechanisms for IMAP, POP3 and SMTP

#### For HTTP/HTTPS

- `auth_required` if this is set and a POST/PUT is made without auth, the
  server will NOT wait for the full request body to get sent
- `idle` - do nothing after receiving the request, just "sit idle"
- `stream` - continuously send data to the client, never-ending
- `writedelay: [secs]` delay this amount between reply packets
- `skip: [num]` - instructs the server to ignore reading this many bytes from
  a PUT or POST request
- `rtp: part [num] channel [num] size [num]` - stream a fake RTP packet for
  the given part on a chosen channel with the given payload size
- `connection-monitor` - When used, this will log `[DISCONNECT]` to the
  `server.input` log when the connection is disconnected.
- `upgrade` - when an HTTP upgrade header is found, the server will upgrade to
  http2
- `swsclose` - instruct server to close connection after response
- `no-expect` - don't read the request body if Expect: is present

#### For TFTP
`writedelay: [secs]` delay this amount between reply packets (each packet
  being 512 bytes payload)

## `<client>`

### `<server>`
What server(s) this test case requires/uses. Available servers:

- `file`
- `ftp-ipv6`
- `ftp`
- `ftps`
- `http-ipv6`
- `http-proxy`
- `http-unix`
- `http/2`
- `http`
- `https`
- `httptls+srp-ipv6`
- `httptls+srp`
- `imap`
- `mqtt`
- `none`
- `pop3`
- `rtsp-ipv6`
- `rtsp`
- `scp`
- `sftp`
- `smtp`
- `socks4`
- `socks5`

Give only one per line.  This subsection is mandatory.

### `<features>`
A list of features that MUST be present in the client/library for this test to
be able to run. If a required feature is not present then the test will be
SKIPPED.

Alternatively a feature can be prefixed with an exclamation mark to indicate a
feature is NOT required. If the feature is present then the test will be
SKIPPED.

Features testable here are:

- `alt-svc`
- `crypto`
- `debug`
- `getrlimit`
- `GnuTLS`
- `GSS-API`
- `http/2`
- `idn`
- `ipv6`
- `Kerberos`
- `large_file`
- `ld_preload`
- `libz`
- `manual`
- `Metalink`
- `NSS`
- `NTLM`
- `OpenSSL`
- `PSL`
- `socks`
- `SPNEGO`
- `SSL`
- `SSLpinning`
- `SSPI`
- `threaded-resolver`
- `TLS-SRP`
- `TrackMemory`
- `unittest`
- `unix-sockets`
- `win32`
- `WinSSL`

as well as each protocol that curl supports.  A protocol only needs to be
specified if it is different from the server (useful when the server
is `none`).

### `<killserver>`
Using the same syntax as in `<server>` but when mentioned here these servers
are explicitly KILLED when this test case is completed. Only use this if there
is no other alternatives. Using this of course requires subsequent tests to
restart servers.

### `<precheck>`
A command line that if set gets run by the test script before the test. If an
output is displayed by the command or if the return code is non-zero, the test
will be skipped and the (single-line) output will be displayed as reason for
not running the test.  Variables are substituted as in the `<command>`
  section.

### `<postcheck>`
A command line that if set gets run by the test script after the test. If
the command exists with a non-zero status code, the test will be considered
to have failed. Variables are substituted as in the `<command>` section.

### `<tool>`
Name of tool to invoke instead of "curl". This tool must be built and exist
either in the libtest/ directory (if the tool name starts with 'lib') or in
the unit/ directory (if the tool name starts with 'unit').

### `<name>`
Brief test case description, shown when the test runs.

### `<setenv>`
    variable1=contents1
    variable2=contents2

Set the given environment variables to the specified value before the actual
command is run. They are cleared again after the command has been run.
Variables are first substituted as in the `<command>` section.
### `<command [option="no-output/no-include/force-output/binary-trace"] [timeout="secs"][delay="secs"][type="perl"]>`
Command line to run. There's a bunch of %variables that get replaced
accordingly.

Note that the URL that gets passed to the server actually controls what data
that is returned. The last slash in the URL must be followed by a number. That
number (N) will be used by the test-server to load test case N and return the
data that is defined within the `<reply><data></data></reply>` section.

If there's no test number found above, the HTTP test server will use the
number following the last dot in the given hostname (made so that a CONNECT
can still pass on test number) so that "foo.bar.123" gets treated as test case
123. Alternatively, if an IPv6 address is provided to CONNECT, the last
hexadecimal group in the address will be used as the test number! For example
the address "[1234::ff]" would be treated as test case 255.

Set `type="perl"` to write the test case as a perl script. It implies that
there's no memory debugging and valgrind gets shut off for this test.

Set `option="no-output"` to prevent the test script to slap on the `--output`
argument that directs the output to a file. The `--output` is also not added
if the verify/stdout section is used.

Set `option="force-output"` to make use of `--output` even when the test is
otherwise written to verify stdout.

Set `option="no-include"` to prevent the test script to slap on the
`--include` argument.

Set `option="binary-trace"` to use `--trace` instead of `--trace-ascii` for
tracing.  Suitable for binary-oriented protocols such as MQTT.

Set `timeout="secs"` to override default server logs advisor read lock
timeout.  This timeout is used by the test harness, once that the command has
completed execution, to wait for the test server to write out server side log
files and remove the lock that advised not to read them. The "secs" parameter
is the not negative integer number of seconds for the timeout. This `timeout`
attribute is documented for completeness sake, but is deep test harness stuff
and only needed for very singular and specific test cases. Avoid using it.

Set `delay="secs"` to introduce a time delay once that the command has
completed execution and before the `<postcheck>` section runs. The "secs"
parameter is the not negative integer number of seconds for the delay. This
'delay' attribute is intended for very specific test cases, and normally not
needed.

Available substitute variables include:

- `%CLIENT6IP` - IPv6 address of the client running curl
- `%CLIENTIP` - IPv4 address of the client running curl
- `%CURL` - Path to the curl executable
- `%FILE_PWD` - Current directory, on windows prefixed with a slash
- `%FTP2PORT` - Port number of the FTP server 2
- `%FTP6PORT` - IPv6 port number of the FTP server
- `%FTPPORT` - Port number of the FTP server
- `%FTPSPORT` - Port number of the FTPS server
- `%FTPTIME2` - Timeout in seconds that should be just sufficient to receive a response from the test FTP server
- `%FTPTIME3` - Even longer than %FTPTIME2
- `%GOPHER6PORT` - IPv6 port number of the Gopher server
- `%GOPHERPORT` - Port number of the Gopher server
- `%HOST6IP` - IPv6 address of the host running this test
- `%HOSTIP` - IPv4 address of the host running this test
- `%HTTP6PORT` - IPv6 port number of the HTTP server
- `%HTTPPORT` - Port number of the HTTP server
- `%HTTPSPORT` - Port number of the HTTPS server
- `%HTTPTLS6PORT` - IPv6 port number of the HTTP TLS server
- `%HTTPTLSPORT` - Port number of the HTTP TLS server
- `%HTTPUNIXPATH` - Path to the Unix socket of the HTTP server
- `%IMAP6PORT` - IPv6 port number of the IMAP server
- `%IMAPPORT` - Port number of the IMAP server
- `%MQTTPORT` - Port number of the MQTT server
- `%NEGTELNETPORT` - Port number of the telnet server
- `%NOLISTENPORT` - Port number where no service is listening
- `%POP36PORT` - IPv6 port number of the POP3 server
- `%POP3PORT` - Port number of the POP3 server
- `%POSIX_PWD` - Current directory somewhat mingw friendly
- `%PROXYPORT` - Port number of the HTTP proxy
- `%PWD` - Current directory
- `%RTSP6PORT` - IPv6 port number of the RTSP server
- `%RTSPPORT` - Port number of the RTSP server
- `%SMBPORT` - Port number of the SMB server
- `%SMBSPORT` - Port number of the SMBS server
- `%SMTP6PORT` - IPv6 port number of the SMTP server
- `%SMTPPORT` - Port number of the SMTP server
- `%SOCKSPORT` - Port number of the SOCKS4/5 server
- `%SRCDIR` - Full path to the source dir
- `%SSHPORT` - Port number of the SCP/SFTP server
- `%SSHSRVMD5` - MD5 of SSH server's public key
- `%SSH_PWD` - Current directory friendly for the SSH server
- `%TFTP6PORT` - IPv6 port number of the TFTP server
- `%TFTPPORT` - Port number of the TFTP server
- `%USER` - Login ID of the user running the test

### `<file name="log/filename">`
This creates the named file with this content before the test case is run,
which is useful if the test case needs a file to act on.  Variables are
substituted on the contents of the file as in the `<command>` section.

### `<stdin [nonewline="yes"]>`
Pass this given data on stdin to the tool.

If 'nonewline' is set, we will cut off the trailing newline of this given data
before comparing with the one actually received by the client

## `<verify>`
### `<errorcode>`
numerical error code curl is supposed to return. Specify a list of accepted
error codes by separating multiple numbers with comma. See test 237 for an
example.

### `<strip>`
One regex per line that is removed from the protocol dumps before the
comparison is made. This is very useful to remove dependencies on dynamically
changing protocol data such as port numbers or user-agent strings.

### `<strippart>`
One perl op per line that operates on the protocol dump. This is pretty
advanced. Example: `s/^EPRT .*/EPRT stripped/`.

### `<protocol [nonewline="yes"]>`

the protocol dump curl should transmit, if 'nonewline' is set, we will cut off
the trailing newline of this given data before comparing with the one actually
sent by the client Variables are substituted as in the `<command>` section.
The `<strip>` and `<strippart>` rules are applied before comparisons are made.

### `<proxy [nonewline="yes"]>`

The protocol dump curl should transmit to a HTTP proxy (when the http-proxy
server is used), if 'nonewline' is set, we will cut off the trailing newline
of this given data before comparing with the one actually sent by the client
Variables are substituted as in the `<command>` section. The `<strip>` and
`<strippart>` rules are applied before comparisons are made.

### `<stdout [mode="text"] [nonewline="yes"]>`
This verifies that this data was passed to stdout.  Variables are
substituted as in the `<command>` section.

Use the mode="text" attribute if the output is in text mode on platforms that
have a text/binary difference.

If 'nonewline' is set, we will cut off the trailing newline of this given data
before comparing with the one actually received by the client

### `<file name="log/filename" [mode="text"]>`
The file's contents must be identical to this after the test is complete.  Use
the mode="text" attribute if the output is in text mode on platforms that have
a text/binary difference.  Variables are substituted as in the `<command>`
section.

### `<file1>`
1 to 4 can be appended to 'file' to compare more files.

### `<file2>`

### `<file3>`

### `<file4>`

### `<stripfile>`
One perl op per line that operates on the output file or stdout before being
compared with what is stored in the test file. This is pretty
advanced. Example: "s/^EPRT .*/EPRT stripped/"

### `<stripfile1>`
1 to 4 can be appended to 'stripfile' to strip the corresponding <fileN>
content

### `<stripfile2>`

### `<stripfile3>`

### `<stripfile4>`

### `<upload>`
the contents of the upload data curl should have sent

### `<valgrind>`
disable - disables the valgrind log check for this test
