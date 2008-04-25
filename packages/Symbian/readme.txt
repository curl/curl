Curl on Symbian OS
==================
This is a basic port of curl and libcurl to Symbian OS.  The port is
a straightforward one using Symbian's P.I.P.S. POSIX compatibility
layer. A more complete port would involve writing a Symbian C++ binding,
or wrapping libcurl as a Symbian application server with a C++ API to
handle requests from client applications and creating a GUI application
to allow file transfers.  The author has no current plans to do so.

This means that integration with standard Symbian OS programs can be
tricky, since libcurl isn't designed with Symbian's native asynchronous 
message passing idioms in mind. However, it may be possible to use libcurl
in an active object-based application through libcurl's multi interface.
The port is most easily used when porting POSIX applications to Symbian
OS using P.I.P.S.

libcurl is built as a standard Symbian ordinal-linked DLL, and curl is
built as a text mode EXE application.  They have not been Symbian
Signed, which is required in order to install them on most phones.

Following are some things to keep in mind when using this port.

curl notes
----------
When starting curl in the Windows emulator from the Windows command-line,
place a double-dash -- before the first curl command-line option.
e.g. \epoc32\release\winscw\udeb\curl -- -v http://localhost/
Failure to do so may mean that some of your options won't be correctly
processed.

Symbian OS does not provide for redirecting the standard I/O streams, so
stdin always comes from the keyboard, stdout always goes to the
console, and stderr goes to the epocwind.out file (on the emulator).
The standard curl options -o, --stderr and --trace-ascii can be used to
redirect output to a file (or stdout) instead.

P.I.P.S. doesn't inherit the current working directory at startup, so you
may need to use the -o option to specify a specific location to store a
downloaded file.

P.I.P.S. provides no way to disable echoing of characters as they are
entered, so passwords typed in on the console will be visible.

All screen output disappears after curl exits, so after a transfer completes,
curl waits by default for Enter to pressed before exiting.  This behaviour
is suppressed when the -s option is given.

The "home directory" in Symbian is C:\Private\f0206442\. The .curlrc is read
from this directory on startup.

libcurl notes
-------------
libcurl uses writeable static data, so the EPOCALLOWDLLDATA option is
used in its MMP file, with the corresponding additional memory usage
and limitations on the Windows emulator.

curl_global_init() *must* be called before any libcurl functions that could
allocate memory (like curl_getenv()).

P.I.P.S. doesn't support signals or the alarm() call, so some timeouts
(such as the connect timeout) are not honoured.

P.I.P.S. causes a USER:87 panic if a timeout much longer than half an hour
is selected. 

SSL/TLS encryption is not supported.


Dan Fandrich
dan@coneharvesters.com
April 2008
