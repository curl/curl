Curl on Symbian OS
==================
This is a basic port of curl and libcurl to Symbian OS.  The port is
a straightforward one using Symbian's P.I.P.S. POSIX compatibility
layer, which was first available for OS version 9.1. A more complete
port would involve writing a Symbian C++ binding, or wrapping libcurl
as a Symbian application server with a C++ API to handle requests
from client applications as well as creating a GUI application to allow
file transfers.  The author has no current plans to do so.

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

Symbian's ESHELL allows for redirecting stdin and stdout to files, but
stderr goes to the epocwind.out file (on the emulator).  The standard
curl options -o, --stderr and --trace-ascii can be used to
redirect output to a file (or stdout) instead.

P.I.P.S. doesn't inherit the current working directory at startup from
the shell, so relative path names are always relative to
C:\Private\f0206442\.

P.I.P.S. provides no way to disable echoing of characters as they are
entered, so passwords typed in on the console will be visible.  It also
line buffers keyboard input so interactive telnet sessions are not very
feasible.

All screen output disappears after curl exits, so after a command completes,
curl waits by default for Enter to be pressed before exiting.  This behaviour
is suppressed when the -s option is given.

curl's "home directory" in Symbian is C:\Private\f0206442\. The .curlrc file
is read from this directory on startup.


libcurl notes
-------------
libcurl uses writable static data, so the EPOCALLOWDLLDATA option is
used in its MMP file, with the corresponding additional memory usage
and limitations on the Windows emulator.

curl_global_init() *must* be called (either explicitly or implicitly through
calling certain other libcurl functions) before any libcurl functions
that could allocate memory (like curl_getenv()).

P.I.P.S. doesn't support signals or the alarm() call, so some timeouts
(such as the connect timeout) are not honoured.

P.I.P.S. causes a USER:87 panic if certain timeouts much longer than
half an hour are selected.

LDAP, SCP or SFTP methods are not supported.

gzip and deflate decompression is supported when enabled in the libcurl.mmp
file.

SSL/TLS encryption is not supported by default, but it has been reported
to be made working with macros similar to the ones in config-symbian.h
and libcurl.mmp. This requires the OpenSSL libraries included in the S60
Open C SDK.

Debug builds are not supported (i.e. --enable-debug) because they cause
additional symbol exports in the library which are not frozen in the .def
files.


Dan Fandrich
dan@coneharvesters.com
October 2008
