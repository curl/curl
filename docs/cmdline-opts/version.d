Long: version
Short: V
Help: Show version number and quit
Category: important curl
Example: --version
Added: 4.0
See-also: help manual
---
Displays information about curl and the libcurl version it uses.

The first line includes the full version of curl, libcurl and other 3rd party
libraries linked with the executable.

The second line (starts with "Protocols:") shows all protocols that libcurl
reports to support.

The third line (starts with "Features:") shows specific features libcurl
reports to offer. Available features include:
.RS
.IP "alt-svc"
Support for the Alt-Svc: header is provided.
.IP "AsynchDNS"
This curl uses asynchronous name resolves. Asynchronous name resolves can be
done using either the c-ares or the threaded resolver backends.
.IP "brotli"
Support for automatic brotli compression over HTTP(S).
.IP "CharConv"
curl was built with support for character set conversions (like EBCDIC)
.IP "Debug"
This curl uses a libcurl built with Debug. This enables more error-tracking
and memory debugging etc. For curl-developers only!
.IP "gsasl"
The built-in SASL authentication includes extensions to support SCRAM because
libcurl was built with libgsasl.
.IP "GSS-API"
GSS-API is supported.
.IP "HSTS"
HSTS support is present.
.IP "HTTP2"
HTTP/2 support has been built-in.
.IP "HTTP3"
HTTP/3 support has been built-in.
.IP "HTTPS-proxy"
This curl is built to support HTTPS proxy.
.IP "IDN"
This curl supports IDN - international domain names.
.IP "IPv6"
You can use IPv6 with this.
.IP "Kerberos"
Kerberos V5 authentication is supported.
.IP "Largefile"
This curl supports transfers of large files, files larger than 2GB.
.IP "libz"
Automatic decompression (via gzip, deflate) of compressed files over HTTP is
supported.
.IP "MultiSSL"
This curl supports multiple TLS backends.
.IP "NTLM"
NTLM authentication is supported.
.IP "NTLM_WB"
NTLM delegation to winbind helper is supported.
.IP "PSL"
PSL is short for Public Suffix List and means that this curl has been built
with knowledge about "public suffixes".
.IP "SPNEGO"
SPNEGO authentication is supported.
.IP "SSL"
SSL versions of various protocols are supported, such as HTTPS, FTPS, POP3S
and so on.
.IP "SSPI"
SSPI is supported.
.IP "TLS-SRP"
SRP (Secure Remote Password) authentication is supported for TLS.
.IP "TrackMemory"
Debug memory tracking is supported.
.IP "Unicode"
Unicode support on Windows.
.IP "UnixSockets"
Unix sockets support is provided.
.IP "zstd"
Automatic decompression (via zstd) of compressed files over HTTP is supported.
.RE
