---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: fetch
Title: fetch_easy_setopt
Section: 3
Source: libfetch
See-also:
  - fetch_easy_cleanup (3)
  - fetch_easy_getinfo (3)
  - fetch_easy_init (3)
  - fetch_easy_option_by_id (3)
  - fetch_easy_option_by_name (3)
  - fetch_easy_option_next (3)
  - fetch_easy_reset (3)
  - fetch_multi_setopt (3)
Protocol:
  - All
Added-in: 7.1
---

# NAME

fetch_easy_setopt - set options for a fetch easy handle

# SYNOPSIS

~~~c
#include <fetch/fetch.h>

FETCHcode fetch_easy_setopt(FETCH *handle, FETCHoption option, parameter);
~~~

# DESCRIPTION

fetch_easy_setopt(3) is used to tell libfetch how to behave. By setting the
appropriate options, the application can change libfetch's behavior. All
options are set with an *option* followed by a *parameter*. That parameter can
be a **long**, a **function pointer**, an **object pointer** or a
**fetch_off_t**, depending on what the specific option expects. Read this
manual carefully as bad input values may cause libfetch to behave badly. You
can only set one option in each function call. A typical application uses many
fetch_easy_setopt(3) calls in the setup phase.

Options set with this function call are valid for all forthcoming transfers
performed using this *handle*. The options are not in any way reset between
transfers, so if you want subsequent transfers with different options, you
must change them between the transfers. You can optionally reset all options
back to internal default with fetch_easy_reset(3).

Strings passed to libfetch as 'char *' arguments, are copied by the library;
the string storage associated to the pointer argument may be discarded or
reused after fetch_easy_setopt(3) returns. The only exception to this rule is
really FETCHOPT_POSTFIELDS(3), but the alternative that copies the string
FETCHOPT_COPYPOSTFIELDS(3) has some usage characteristics you need to read up
on. This function does not accept input strings longer than
**FETCH_MAX_INPUT_LENGTH** (8 MB).

The order in which the options are set does not matter.

Before version 7.17.0, strings were not copied. Instead the user was forced
keep them available until libfetch no longer needed them.

The *handle* is the return code from a fetch_easy_init(3) or
fetch_easy_duphandle(3) call.

# OPTIONS

## FETCHOPT_ABSTRACT_UNIX_SOCKET

Path to an abstract Unix domain socket. See FETCHOPT_ABSTRACT_UNIX_SOCKET(3)

## FETCHOPT_ACCEPTTIMEOUT_MS

Timeout for waiting for the server's connect back to be accepted. See
FETCHOPT_ACCEPTTIMEOUT_MS(3)

## FETCHOPT_ACCEPT_ENCODING

Accept-Encoding and automatic decompressing data. See
FETCHOPT_ACCEPT_ENCODING(3)

## FETCHOPT_ADDRESS_SCOPE

IPv6 scope for local addresses. See FETCHOPT_ADDRESS_SCOPE(3)

## FETCHOPT_ALTSVC

Specify the Alt-Svc: cache filename. See FETCHOPT_ALTSVC(3)

## FETCHOPT_ALTSVC_CTRL

Enable and configure Alt-Svc: treatment. See FETCHOPT_ALTSVC_CTRL(3)

## FETCHOPT_APPEND

Append to remote file. See FETCHOPT_APPEND(3)

## FETCHOPT_AUTOREFERER

Automatically set Referer: header. See FETCHOPT_AUTOREFERER(3)

## FETCHOPT_AWS_SIGV4

AWS HTTP V4 Signature. See FETCHOPT_AWS_SIGV4(3)

## FETCHOPT_BUFFERSIZE

Ask for alternate buffer size. See FETCHOPT_BUFFERSIZE(3)

## FETCHOPT_CAINFO

CA cert bundle. See FETCHOPT_CAINFO(3)

## FETCHOPT_CAINFO_BLOB

CA cert bundle memory buffer. See FETCHOPT_CAINFO_BLOB(3)

## FETCHOPT_CAPATH

Path to CA cert bundle. See FETCHOPT_CAPATH(3)

## FETCHOPT_CA_CACHE_TIMEOUT

Timeout for CA cache. See FETCHOPT_CA_CACHE_TIMEOUT(3)

## FETCHOPT_CERTINFO

Extract certificate info. See FETCHOPT_CERTINFO(3)

## FETCHOPT_CHUNK_BGN_FUNCTION

Callback for wildcard download start of chunk. See
FETCHOPT_CHUNK_BGN_FUNCTION(3)

## FETCHOPT_CHUNK_DATA

Data pointer to pass to the chunk callbacks. See FETCHOPT_CHUNK_DATA(3)

## FETCHOPT_CHUNK_END_FUNCTION

Callback for wildcard download end of chunk. See FETCHOPT_CHUNK_END_FUNCTION(3)

## FETCHOPT_CLOSESOCKETDATA

Data pointer to pass to the close socket callback. See
FETCHOPT_CLOSESOCKETDATA(3)

## FETCHOPT_CLOSESOCKETFUNCTION

Callback for closing socket. See FETCHOPT_CLOSESOCKETFUNCTION(3)

## FETCHOPT_CONNECTTIMEOUT

Timeout for the connection phase. See FETCHOPT_CONNECTTIMEOUT(3)

## FETCHOPT_CONNECTTIMEOUT_MS

Millisecond timeout for the connection phase. See FETCHOPT_CONNECTTIMEOUT_MS(3)

## FETCHOPT_CONNECT_ONLY

Only connect, nothing else. See FETCHOPT_CONNECT_ONLY(3)

## FETCHOPT_CONNECT_TO

Connect to a specific host and port. See FETCHOPT_CONNECT_TO(3)

## FETCHOPT_CONV_FROM_NETWORK_FUNCTION

**OBSOLETE** Callback for code base conversion.
See FETCHOPT_CONV_FROM_NETWORK_FUNCTION(3)

## FETCHOPT_CONV_FROM_UTF8_FUNCTION

**OBSOLETE** Callback for code base conversion.
See FETCHOPT_CONV_FROM_UTF8_FUNCTION(3)

## FETCHOPT_CONV_TO_NETWORK_FUNCTION

**OBSOLETE** Callback for code base conversion.
See FETCHOPT_CONV_TO_NETWORK_FUNCTION(3)

## FETCHOPT_COOKIE

Cookie(s) to send. See FETCHOPT_COOKIE(3)

## FETCHOPT_COOKIEFILE

File to read cookies from. See FETCHOPT_COOKIEFILE(3)

## FETCHOPT_COOKIEJAR

File to write cookies to. See FETCHOPT_COOKIEJAR(3)

## FETCHOPT_COOKIELIST

Add or control cookies. See FETCHOPT_COOKIELIST(3)

## FETCHOPT_COOKIESESSION

Start a new cookie session. See FETCHOPT_COOKIESESSION(3)

## FETCHOPT_COPYPOSTFIELDS

Send a POST with this data - and copy it. See FETCHOPT_COPYPOSTFIELDS(3)

## FETCHOPT_CRLF

Convert newlines. See FETCHOPT_CRLF(3)

## FETCHOPT_CRLFILE

Certificate Revocation List. See FETCHOPT_CRLFILE(3)

## FETCHOPT_FETCHU

Set URL to work on with a URL handle. See FETCHOPT_FETCHU(3)

## FETCHOPT_CUSTOMREQUEST

Custom request/method. See FETCHOPT_CUSTOMREQUEST(3)

## FETCHOPT_DEBUGDATA

Data pointer to pass to the debug callback. See FETCHOPT_DEBUGDATA(3)

## FETCHOPT_DEBUGFUNCTION

Callback for debug information. See FETCHOPT_DEBUGFUNCTION(3)

## FETCHOPT_DEFAULT_PROTOCOL

Default protocol. See FETCHOPT_DEFAULT_PROTOCOL(3)

## FETCHOPT_DIRLISTONLY

List only. See FETCHOPT_DIRLISTONLY(3)

## FETCHOPT_DISALLOW_USERNAME_IN_URL

Do not allow username in URL. See FETCHOPT_DISALLOW_USERNAME_IN_URL(3)

## FETCHOPT_DNS_CACHE_TIMEOUT

Timeout for DNS cache. See FETCHOPT_DNS_CACHE_TIMEOUT(3)

## FETCHOPT_DNS_INTERFACE

Bind name resolves to this interface. See FETCHOPT_DNS_INTERFACE(3)

## FETCHOPT_DNS_LOCAL_IP4

Bind name resolves to this IP4 address. See FETCHOPT_DNS_LOCAL_IP4(3)

## FETCHOPT_DNS_LOCAL_IP6

Bind name resolves to this IP6 address. See FETCHOPT_DNS_LOCAL_IP6(3)

## FETCHOPT_DNS_SERVERS

Preferred DNS servers. See FETCHOPT_DNS_SERVERS(3)

## FETCHOPT_DNS_SHUFFLE_ADDRESSES

Shuffle addresses before use. See FETCHOPT_DNS_SHUFFLE_ADDRESSES(3)

## FETCHOPT_DNS_USE_GLOBAL_CACHE

**OBSOLETE** Enable global DNS cache. See FETCHOPT_DNS_USE_GLOBAL_CACHE(3)

## FETCHOPT_DOH_SSL_VERIFYHOST

Verify the hostname in the DoH (DNS-over-HTTPS) SSL certificate. See
FETCHOPT_DOH_SSL_VERIFYHOST(3)

## FETCHOPT_DOH_SSL_VERIFYPEER

Verify the DoH (DNS-over-HTTPS) SSL certificate. See
FETCHOPT_DOH_SSL_VERIFYPEER(3)

## FETCHOPT_DOH_SSL_VERIFYSTATUS

Verify the DoH (DNS-over-HTTPS) SSL certificate's status. See
FETCHOPT_DOH_SSL_VERIFYSTATUS(3)

## FETCHOPT_DOH_URL

Use this DoH server for name resolves. See FETCHOPT_DOH_URL(3)

## FETCHOPT_ECH

Set the configuration for ECH. See FETCHOPT_ECH(3)

## FETCHOPT_EGDSOCKET

**OBSOLETE** Identify EGD socket for entropy. See FETCHOPT_EGDSOCKET(3)

## FETCHOPT_ERRORBUFFER

Error message buffer. See FETCHOPT_ERRORBUFFER(3)

## FETCHOPT_EXPECT_100_TIMEOUT_MS

100-continue timeout. See FETCHOPT_EXPECT_100_TIMEOUT_MS(3)

## FETCHOPT_FAILONERROR

Fail on HTTP 4xx errors. FETCHOPT_FAILONERROR(3)

## FETCHOPT_FILETIME

Request file modification date and time. See FETCHOPT_FILETIME(3)

## FETCHOPT_FNMATCH_DATA

Data pointer to pass to the wildcard matching callback. See
FETCHOPT_FNMATCH_DATA(3)

## FETCHOPT_FNMATCH_FUNCTION

Callback for wildcard matching. See FETCHOPT_FNMATCH_FUNCTION(3)

## FETCHOPT_FOLLOWLOCATION

Follow HTTP redirects. See FETCHOPT_FOLLOWLOCATION(3)

## FETCHOPT_FORBID_REUSE

Prevent subsequent connections from reusing this. See FETCHOPT_FORBID_REUSE(3)

## FETCHOPT_FRESH_CONNECT

Use a new connection. FETCHOPT_FRESH_CONNECT(3)

## FETCHOPT_FTPPORT

Use active FTP. See FETCHOPT_FTPPORT(3)

## FETCHOPT_FTPSSLAUTH

Control how to do TLS. See FETCHOPT_FTPSSLAUTH(3)

## FETCHOPT_FTP_ACCOUNT

Send ACCT command. See FETCHOPT_FTP_ACCOUNT(3)

## FETCHOPT_FTP_ALTERNATIVE_TO_USER

Alternative to USER. See FETCHOPT_FTP_ALTERNATIVE_TO_USER(3)

## FETCHOPT_FTP_CREATE_MISSING_DIRS

Create missing directories on the remote server. See
FETCHOPT_FTP_CREATE_MISSING_DIRS(3)

## FETCHOPT_FTP_FILEMETHOD

Specify how to reach files. See FETCHOPT_FTP_FILEMETHOD(3)

## FETCHOPT_FTP_SKIP_PASV_IP

Ignore the IP address in the PASV response. See FETCHOPT_FTP_SKIP_PASV_IP(3)

## FETCHOPT_FTP_SSL_CCC

Back to non-TLS again after authentication. See FETCHOPT_FTP_SSL_CCC(3)

## FETCHOPT_FTP_USE_EPRT

Use EPRT. See FETCHOPT_FTP_USE_EPRT(3)

## FETCHOPT_FTP_USE_EPSV

Use EPSV. See FETCHOPT_FTP_USE_EPSV(3)

## FETCHOPT_FTP_USE_PRET

Use PRET. See FETCHOPT_FTP_USE_PRET(3)

## FETCHOPT_GSSAPI_DELEGATION

Disable GSS-API delegation. See FETCHOPT_GSSAPI_DELEGATION(3)

## FETCHOPT_HAPPY_EYEBALLS_TIMEOUT_MS

Timeout for happy eyeballs. See FETCHOPT_HAPPY_EYEBALLS_TIMEOUT_MS(3)

## FETCHOPT_HAPROXYPROTOCOL

Send an HAProxy PROXY protocol v1 header. See FETCHOPT_HAPROXYPROTOCOL(3)

## FETCHOPT_HAPROXY_CLIENT_IP

Spoof the client IP in an HAProxy PROXY protocol v1 header. See
FETCHOPT_HAPROXY_CLIENT_IP(3)

## FETCHOPT_HEADER

Include the header in the body output. See FETCHOPT_HEADER(3)

## FETCHOPT_HEADERDATA

Data pointer to pass to the header callback. See FETCHOPT_HEADERDATA(3)

## FETCHOPT_HEADERFUNCTION

Callback for writing received headers. See FETCHOPT_HEADERFUNCTION(3)

## FETCHOPT_HEADEROPT

Control custom headers. See FETCHOPT_HEADEROPT(3)

## FETCHOPT_HSTS

Set HSTS cache file. See FETCHOPT_HSTS(3)

## FETCHOPT_HSTSREADDATA

Pass pointer to the HSTS read callback. See FETCHOPT_HSTSREADDATA(3)

## FETCHOPT_HSTSREADFUNCTION

Set HSTS read callback. See FETCHOPT_HSTSREADFUNCTION(3)

## FETCHOPT_HSTSWRITEDATA

Pass pointer to the HSTS write callback. See FETCHOPT_HSTSWRITEDATA(3)

## FETCHOPT_HSTSWRITEFUNCTION

Set HSTS write callback. See FETCHOPT_HSTSWRITEFUNCTION(3)

## FETCHOPT_HSTS_CTRL

Enable HSTS. See FETCHOPT_HSTS_CTRL(3)

## FETCHOPT_HTTP09_ALLOWED

Allow HTTP/0.9 responses. FETCHOPT_HTTP09_ALLOWED(3)

## FETCHOPT_HTTP200ALIASES

Alternative versions of 200 OK. See FETCHOPT_HTTP200ALIASES(3)

## FETCHOPT_HTTPAUTH

HTTP server authentication methods. See FETCHOPT_HTTPAUTH(3)

## FETCHOPT_HTTPGET

Do an HTTP GET request. See FETCHOPT_HTTPGET(3)

## FETCHOPT_HTTPHEADER

Custom HTTP headers. See FETCHOPT_HTTPHEADER(3)

## FETCHOPT_HTTPPOST

**Deprecated option** Multipart formpost HTTP POST.
See FETCHOPT_HTTPPOST(3)

## FETCHOPT_HTTPPROXYTUNNEL

Tunnel through the HTTP proxy. FETCHOPT_HTTPPROXYTUNNEL(3)

## FETCHOPT_HTTP_CONTENT_DECODING

Disable Content decoding. See FETCHOPT_HTTP_CONTENT_DECODING(3)

## FETCHOPT_HTTP_TRANSFER_DECODING

Disable Transfer decoding. See FETCHOPT_HTTP_TRANSFER_DECODING(3)

## FETCHOPT_HTTP_VERSION

HTTP version to use. FETCHOPT_HTTP_VERSION(3)

## FETCHOPT_IGNORE_CONTENT_LENGTH

Ignore Content-Length. See FETCHOPT_IGNORE_CONTENT_LENGTH(3)

## FETCHOPT_INFILESIZE

Size of file to send. FETCHOPT_INFILESIZE(3)

## FETCHOPT_INFILESIZE_LARGE

Size of file to send. FETCHOPT_INFILESIZE_LARGE(3)

## FETCHOPT_INTERFACE

Bind connection locally to this. See FETCHOPT_INTERFACE(3)

## FETCHOPT_INTERLEAVEDATA

Data pointer to pass to the RTSP interleave callback. See
FETCHOPT_INTERLEAVEDATA(3)

## FETCHOPT_INTERLEAVEFUNCTION

Callback for RTSP interleaved data. See FETCHOPT_INTERLEAVEFUNCTION(3)

## FETCHOPT_IOCTLDATA

**Deprecated option** Data pointer to pass to the I/O callback.
See FETCHOPT_IOCTLDATA(3)

## FETCHOPT_IOCTLFUNCTION

**Deprecated option** Callback for I/O operations.
See FETCHOPT_IOCTLFUNCTION(3)

## FETCHOPT_IPRESOLVE

IP version to use. See FETCHOPT_IPRESOLVE(3)

## FETCHOPT_ISSUERCERT

Issuer certificate. See FETCHOPT_ISSUERCERT(3)

## FETCHOPT_ISSUERCERT_BLOB

Issuer certificate memory buffer. See FETCHOPT_ISSUERCERT_BLOB(3)

## FETCHOPT_KEEP_SENDING_ON_ERROR

Keep sending on HTTP \>= 300 errors. FETCHOPT_KEEP_SENDING_ON_ERROR(3)

## FETCHOPT_KEYPASSWD

Client key password. See FETCHOPT_KEYPASSWD(3)

## FETCHOPT_KRBLEVEL

Kerberos security level. See FETCHOPT_KRBLEVEL(3)

## FETCHOPT_LOCALPORT

Bind connection locally to this port. See FETCHOPT_LOCALPORT(3)

## FETCHOPT_LOCALPORTRANGE

Bind connection locally to port range. See FETCHOPT_LOCALPORTRANGE(3)

## FETCHOPT_LOGIN_OPTIONS

Login options. See FETCHOPT_LOGIN_OPTIONS(3)

## FETCHOPT_LOW_SPEED_LIMIT

Low speed limit to abort transfer. See FETCHOPT_LOW_SPEED_LIMIT(3)

## FETCHOPT_LOW_SPEED_TIME

Time to be below the speed to trigger low speed abort. See
FETCHOPT_LOW_SPEED_TIME(3)

## FETCHOPT_MAIL_AUTH

Authentication address. See FETCHOPT_MAIL_AUTH(3)

## FETCHOPT_MAIL_FROM

Address of the sender. See FETCHOPT_MAIL_FROM(3)

## FETCHOPT_MAIL_RCPT

Address of the recipients. See FETCHOPT_MAIL_RCPT(3)

## FETCHOPT_MAIL_RCPT_ALLOWFAILS

Allow RCPT TO command to fail for some recipients. See
FETCHOPT_MAIL_RCPT_ALLOWFAILS(3)

## FETCHOPT_MAXAGE_CONN

Limit the age (idle time) of connections for reuse. See FETCHOPT_MAXAGE_CONN(3)

## FETCHOPT_MAXCONNECTS

Maximum number of connections in the connection pool. See
FETCHOPT_MAXCONNECTS(3)

## FETCHOPT_MAXFILESIZE

Maximum file size to get. See FETCHOPT_MAXFILESIZE(3)

## FETCHOPT_MAXFILESIZE_LARGE

Maximum file size to get. See FETCHOPT_MAXFILESIZE_LARGE(3)

## FETCHOPT_MAXLIFETIME_CONN

Limit the age (since creation) of connections for reuse. See
FETCHOPT_MAXLIFETIME_CONN(3)

## FETCHOPT_MAXREDIRS

Maximum number of redirects to follow. See FETCHOPT_MAXREDIRS(3)

## FETCHOPT_MAX_RECV_SPEED_LARGE

Cap the download speed to this. See FETCHOPT_MAX_RECV_SPEED_LARGE(3)

## FETCHOPT_MAX_SEND_SPEED_LARGE

Cap the upload speed to this. See FETCHOPT_MAX_SEND_SPEED_LARGE(3)

## FETCHOPT_MIMEPOST

Post/send MIME data. See FETCHOPT_MIMEPOST(3)

## FETCHOPT_MIME_OPTIONS

Set MIME option flags. See FETCHOPT_MIME_OPTIONS(3)

## FETCHOPT_NETRC

Enable .netrc parsing. See FETCHOPT_NETRC(3)

## FETCHOPT_NETRC_FILE

.netrc filename. See FETCHOPT_NETRC_FILE(3)

## FETCHOPT_NEW_DIRECTORY_PERMS

Mode for creating new remote directories. See FETCHOPT_NEW_DIRECTORY_PERMS(3)

## FETCHOPT_NEW_FILE_PERMS

Mode for creating new remote files. See FETCHOPT_NEW_FILE_PERMS(3)

## FETCHOPT_NOBODY

Do not get the body contents. See FETCHOPT_NOBODY(3)

## FETCHOPT_NOPROGRESS

Shut off the progress meter. See FETCHOPT_NOPROGRESS(3)

## FETCHOPT_NOPROXY

Filter out hosts from proxy use. FETCHOPT_NOPROXY(3)

## FETCHOPT_NOSIGNAL

Do not install signal handlers. See FETCHOPT_NOSIGNAL(3)

## FETCHOPT_OPENSOCKETDATA

Data pointer to pass to the open socket callback. See FETCHOPT_OPENSOCKETDATA(3)

## FETCHOPT_OPENSOCKETFUNCTION

Callback for socket creation. See FETCHOPT_OPENSOCKETFUNCTION(3)

## FETCHOPT_PASSWORD

Password. See FETCHOPT_PASSWORD(3)

## FETCHOPT_PATH_AS_IS

Disable squashing /../ and /./ sequences in the path. See FETCHOPT_PATH_AS_IS(3)

## FETCHOPT_PINNEDPUBLICKEY

Set pinned SSL public key . See FETCHOPT_PINNEDPUBLICKEY(3)

## FETCHOPT_PIPEWAIT

Wait on connection to pipeline on it. See FETCHOPT_PIPEWAIT(3)

## FETCHOPT_PORT

Port number to connect to. See FETCHOPT_PORT(3)

## FETCHOPT_POST

Make an HTTP POST. See FETCHOPT_POST(3)

## FETCHOPT_POSTFIELDSIZE

The POST data is this big. See FETCHOPT_POSTFIELDSIZE(3)

## FETCHOPT_POSTFIELDSIZE_LARGE

The POST data is this big. See FETCHOPT_POSTFIELDSIZE_LARGE(3)

## FETCHOPT_POSTQUOTE

Commands to run after transfer. See FETCHOPT_POSTQUOTE(3)

## FETCHOPT_POSTREDIR

How to act on redirects after POST. See FETCHOPT_POSTREDIR(3)

## FETCHOPT_PREQUOTE

Commands to run just before transfer. See FETCHOPT_PREQUOTE(3)

## FETCHOPT_PREREQDATA

Data pointer to pass to the FETCHOPT_PREREQFUNCTION callback. See
FETCHOPT_PREREQDATA(3)

## FETCHOPT_PREREQFUNCTION

Callback to be called after a connection is established but before a request
is made on that connection. See FETCHOPT_PREREQFUNCTION(3)

## FETCHOPT_PRE_PROXY

Socks proxy to use. See FETCHOPT_PRE_PROXY(3)

## FETCHOPT_PRIVATE

Private pointer to store. See FETCHOPT_PRIVATE(3)

## FETCHOPT_PROGRESSDATA

Data pointer to pass to the progress meter callback. See
FETCHOPT_PROGRESSDATA(3)

## FETCHOPT_PROGRESSFUNCTION

**OBSOLETE** callback for progress meter. See FETCHOPT_PROGRESSFUNCTION(3)

## FETCHOPT_PROTOCOLS

**Deprecated option** Allowed protocols. See FETCHOPT_PROTOCOLS(3)

## FETCHOPT_PROTOCOLS_STR

Allowed protocols. See FETCHOPT_PROTOCOLS_STR(3)

## FETCHOPT_PROXY

Proxy to use. See FETCHOPT_PROXY(3)

## FETCHOPT_PROXYAUTH

HTTP proxy authentication methods. See FETCHOPT_PROXYAUTH(3)

## FETCHOPT_PROXYHEADER

Custom HTTP headers sent to proxy. See FETCHOPT_PROXYHEADER(3)

## FETCHOPT_PROXYPASSWORD

Proxy password. See FETCHOPT_PROXYPASSWORD(3)

## FETCHOPT_PROXYPORT

Proxy port to use. See FETCHOPT_PROXYPORT(3)

## FETCHOPT_PROXYTYPE

Proxy type. See FETCHOPT_PROXYTYPE(3)

## FETCHOPT_PROXYUSERNAME
Proxy username. See FETCHOPT_PROXYUSERNAME(3)

## FETCHOPT_PROXYUSERPWD

Proxy username and password. See FETCHOPT_PROXYUSERPWD(3)

## FETCHOPT_PROXY_CAINFO

Proxy CA cert bundle. See FETCHOPT_PROXY_CAINFO(3)

## FETCHOPT_PROXY_CAINFO_BLOB

Proxy CA cert bundle memory buffer. See FETCHOPT_PROXY_CAINFO_BLOB(3)

## FETCHOPT_PROXY_CAPATH

Path to proxy CA cert bundle. See FETCHOPT_PROXY_CAPATH(3)

## FETCHOPT_PROXY_CRLFILE

Proxy Certificate Revocation List. See FETCHOPT_PROXY_CRLFILE(3)

## FETCHOPT_PROXY_ISSUERCERT

Proxy issuer certificate. See FETCHOPT_PROXY_ISSUERCERT(3)

## FETCHOPT_PROXY_ISSUERCERT_BLOB

Proxy issuer certificate memory buffer. See FETCHOPT_PROXY_ISSUERCERT_BLOB(3)

## FETCHOPT_PROXY_KEYPASSWD

Proxy client key password. See FETCHOPT_PROXY_KEYPASSWD(3)

## FETCHOPT_PROXY_PINNEDPUBLICKEY

Set the proxy's pinned SSL public key. See
FETCHOPT_PROXY_PINNEDPUBLICKEY(3)

## FETCHOPT_PROXY_SERVICE_NAME

Proxy authentication service name. FETCHOPT_PROXY_SERVICE_NAME(3)

## FETCHOPT_PROXY_SSLCERT

Proxy client cert. See FETCHOPT_PROXY_SSLCERT(3)

## FETCHOPT_PROXY_SSLCERTTYPE

Proxy client cert type. See FETCHOPT_PROXY_SSLCERTTYPE(3)

## FETCHOPT_PROXY_SSLCERT_BLOB

Proxy client cert memory buffer. See FETCHOPT_PROXY_SSLCERT_BLOB(3)

## FETCHOPT_PROXY_SSLKEY

Proxy client key. See FETCHOPT_PROXY_SSLKEY(3)

## FETCHOPT_PROXY_SSLKEYTYPE

Proxy client key type. See FETCHOPT_PROXY_SSLKEYTYPE(3)

## FETCHOPT_PROXY_SSLKEY_BLOB

Proxy client key. See FETCHOPT_PROXY_SSLKEY_BLOB(3)

## FETCHOPT_PROXY_SSLVERSION

Proxy SSL version to use. See FETCHOPT_PROXY_SSLVERSION(3)

## FETCHOPT_PROXY_SSL_CIPHER_LIST

Proxy ciphers to use. See FETCHOPT_PROXY_SSL_CIPHER_LIST(3)

## FETCHOPT_PROXY_SSL_OPTIONS

Control proxy SSL behavior. See FETCHOPT_PROXY_SSL_OPTIONS(3)

## FETCHOPT_PROXY_SSL_VERIFYHOST

Verify the hostname in the proxy SSL certificate. See
FETCHOPT_PROXY_SSL_VERIFYHOST(3)

## FETCHOPT_PROXY_SSL_VERIFYPEER

Verify the proxy SSL certificate. See FETCHOPT_PROXY_SSL_VERIFYPEER(3)

## FETCHOPT_PROXY_TLS13_CIPHERS

Proxy TLS 1.3 cipher suites to use. See FETCHOPT_PROXY_TLS13_CIPHERS(3)

## FETCHOPT_PROXY_TLSAUTH_PASSWORD

Proxy TLS authentication password. See FETCHOPT_PROXY_TLSAUTH_PASSWORD(3)

## FETCHOPT_PROXY_TLSAUTH_TYPE

Proxy TLS authentication methods. See FETCHOPT_PROXY_TLSAUTH_TYPE(3)

## FETCHOPT_PROXY_TLSAUTH_USERNAME

Proxy TLS authentication username. See FETCHOPT_PROXY_TLSAUTH_USERNAME(3)

## FETCHOPT_PROXY_TRANSFER_MODE

Add transfer mode to URL over proxy. See FETCHOPT_PROXY_TRANSFER_MODE(3)

## FETCHOPT_PUT

**Deprecated option** Issue an HTTP PUT request. See FETCHOPT_PUT(3)

## FETCHOPT_QUICK_EXIT

To be set by toplevel tools like "fetch" to skip lengthy cleanups when they are
about to call exit() anyway. See FETCHOPT_QUICK_EXIT(3)

## FETCHOPT_QUOTE

Commands to run before transfer. See FETCHOPT_QUOTE(3)

## FETCHOPT_RANDOM_FILE

**OBSOLETE** Provide source for entropy random data.
See FETCHOPT_RANDOM_FILE(3)

## FETCHOPT_RANGE

Range requests. See FETCHOPT_RANGE(3)

## FETCHOPT_READDATA

Data pointer to pass to the read callback. See FETCHOPT_READDATA(3)

## FETCHOPT_READFUNCTION

Callback for reading data. See FETCHOPT_READFUNCTION(3)

## FETCHOPT_REDIR_PROTOCOLS

**Deprecated option** Protocols to allow redirects to. See
FETCHOPT_REDIR_PROTOCOLS(3)

## FETCHOPT_REDIR_PROTOCOLS_STR

Protocols to allow redirects to. See FETCHOPT_REDIR_PROTOCOLS_STR(3)

## FETCHOPT_REFERER

Referer: header. See FETCHOPT_REFERER(3)

## FETCHOPT_REQUEST_TARGET

Set the request target. FETCHOPT_REQUEST_TARGET(3)

## FETCHOPT_RESOLVE

Provide fixed/fake name resolves. See FETCHOPT_RESOLVE(3)

## FETCHOPT_RESOLVER_START_DATA

Data pointer to pass to resolver start callback. See
FETCHOPT_RESOLVER_START_DATA(3)

## FETCHOPT_RESOLVER_START_FUNCTION

Callback to be called before a new resolve request is started. See
FETCHOPT_RESOLVER_START_FUNCTION(3)

## FETCHOPT_RESUME_FROM

Resume a transfer. See FETCHOPT_RESUME_FROM(3)

## FETCHOPT_RESUME_FROM_LARGE

Resume a transfer. See FETCHOPT_RESUME_FROM_LARGE(3)

## FETCHOPT_RTSP_CLIENT_CSEQ

Client CSEQ number. See FETCHOPT_RTSP_CLIENT_CSEQ(3)

## FETCHOPT_RTSP_REQUEST

RTSP request. See FETCHOPT_RTSP_REQUEST(3)

## FETCHOPT_RTSP_SERVER_CSEQ

CSEQ number for RTSP Server-\>Client request. See FETCHOPT_RTSP_SERVER_CSEQ(3)

## FETCHOPT_RTSP_SESSION_ID

RTSP session-id. See FETCHOPT_RTSP_SESSION_ID(3)

## FETCHOPT_RTSP_STREAM_URI

RTSP stream URI. See FETCHOPT_RTSP_STREAM_URI(3)

## FETCHOPT_RTSP_TRANSPORT

RTSP Transport: header. See FETCHOPT_RTSP_TRANSPORT(3)

## FETCHOPT_SASL_AUTHZID

SASL authorization identity (identity to act as). See FETCHOPT_SASL_AUTHZID(3)

## FETCHOPT_SASL_IR

Enable SASL initial response. See FETCHOPT_SASL_IR(3)

## FETCHOPT_SEEKDATA

Data pointer to pass to the seek callback. See FETCHOPT_SEEKDATA(3)

## FETCHOPT_SEEKFUNCTION

Callback for seek operations. See FETCHOPT_SEEKFUNCTION(3)

## FETCHOPT_SERVER_RESPONSE_TIMEOUT

Timeout for server responses. See FETCHOPT_SERVER_RESPONSE_TIMEOUT(3)

## FETCHOPT_SERVER_RESPONSE_TIMEOUT_MS

Timeout for server responses. See FETCHOPT_SERVER_RESPONSE_TIMEOUT_MS(3)

## FETCHOPT_SERVICE_NAME

Authentication service name. FETCHOPT_SERVICE_NAME(3)

## FETCHOPT_SHARE

Share object to use. See FETCHOPT_SHARE(3)

## FETCHOPT_SOCKOPTDATA

Data pointer to pass to the sockopt callback. See FETCHOPT_SOCKOPTDATA(3)

## FETCHOPT_SOCKOPTFUNCTION

Callback for sockopt operations. See FETCHOPT_SOCKOPTFUNCTION(3)

## FETCHOPT_SOCKS5_AUTH

Socks5 authentication methods. See FETCHOPT_SOCKS5_AUTH(3)

## FETCHOPT_SOCKS5_GSSAPI_NEC

Socks5 GSSAPI NEC mode. See FETCHOPT_SOCKS5_GSSAPI_NEC(3)

## FETCHOPT_SOCKS5_GSSAPI_SERVICE

**Deprecated option** Socks5 GSSAPI service name.
See FETCHOPT_SOCKS5_GSSAPI_SERVICE(3)

## FETCHOPT_SSH_AUTH_TYPES

SSH authentication types. See FETCHOPT_SSH_AUTH_TYPES(3)

## FETCHOPT_SSH_COMPRESSION

Enable SSH compression. See FETCHOPT_SSH_COMPRESSION(3)

## FETCHOPT_SSH_HOSTKEYDATA

Custom pointer to pass to ssh host key callback. See FETCHOPT_SSH_HOSTKEYDATA(3)

## FETCHOPT_SSH_HOSTKEYFUNCTION

Callback for checking host key handling. See FETCHOPT_SSH_HOSTKEYFUNCTION(3)

## FETCHOPT_SSH_HOST_PUBLIC_KEY_MD5

MD5 of host's public key. See FETCHOPT_SSH_HOST_PUBLIC_KEY_MD5(3)

## FETCHOPT_SSH_HOST_PUBLIC_KEY_SHA256

SHA256 of host's public key. See FETCHOPT_SSH_HOST_PUBLIC_KEY_SHA256(3)

## FETCHOPT_SSH_KEYDATA

Custom pointer to pass to ssh key callback. See FETCHOPT_SSH_KEYDATA(3)

## FETCHOPT_SSH_KEYFUNCTION

Callback for known hosts handling. See FETCHOPT_SSH_KEYFUNCTION(3)

## FETCHOPT_SSH_KNOWNHOSTS

Filename with known hosts. See FETCHOPT_SSH_KNOWNHOSTS(3)

## FETCHOPT_SSH_PRIVATE_KEYFILE

Filename of the private key. See FETCHOPT_SSH_PRIVATE_KEYFILE(3)

## FETCHOPT_SSH_PUBLIC_KEYFILE

Filename of the public key. See FETCHOPT_SSH_PUBLIC_KEYFILE(3)

## FETCHOPT_SSLCERT

Client cert. See FETCHOPT_SSLCERT(3)

## FETCHOPT_SSLCERTTYPE

Client cert type. See FETCHOPT_SSLCERTTYPE(3)

## FETCHOPT_SSLCERT_BLOB

Client cert memory buffer. See FETCHOPT_SSLCERT_BLOB(3)

## FETCHOPT_SSLENGINE

Use identifier with SSL engine. See FETCHOPT_SSLENGINE(3)

## FETCHOPT_SSLENGINE_DEFAULT

Default SSL engine. See FETCHOPT_SSLENGINE_DEFAULT(3)

## FETCHOPT_SSLKEY

Client key. See FETCHOPT_SSLKEY(3)

## FETCHOPT_SSLKEYTYPE

Client key type. See FETCHOPT_SSLKEYTYPE(3)

## FETCHOPT_SSLKEY_BLOB

Client key memory buffer. See FETCHOPT_SSLKEY_BLOB(3)

## FETCHOPT_SSLVERSION

SSL version to use. See FETCHOPT_SSLVERSION(3)

## FETCHOPT_SSL_CIPHER_LIST

Ciphers to use. See FETCHOPT_SSL_CIPHER_LIST(3)

## FETCHOPT_SSL_CTX_DATA

Data pointer to pass to the SSL context callback. See FETCHOPT_SSL_CTX_DATA(3)

## FETCHOPT_SSL_CTX_FUNCTION

Callback for SSL context logic. See FETCHOPT_SSL_CTX_FUNCTION(3)

## FETCHOPT_SSL_EC_CURVES

Set key exchange curves. See FETCHOPT_SSL_EC_CURVES(3)

## FETCHOPT_SSL_ENABLE_ALPN

Enable use of ALPN. See FETCHOPT_SSL_ENABLE_ALPN(3)

## FETCHOPT_SSL_ENABLE_NPN

**OBSOLETE** Enable use of NPN. See FETCHOPT_SSL_ENABLE_NPN(3)

## FETCHOPT_SSL_FALSESTART

Enable TLS False Start. See FETCHOPT_SSL_FALSESTART(3)

## FETCHOPT_SSL_OPTIONS

Control SSL behavior. See FETCHOPT_SSL_OPTIONS(3)

## FETCHOPT_SSL_SESSIONID_CACHE

Disable SSL session-id cache. See FETCHOPT_SSL_SESSIONID_CACHE(3)

## FETCHOPT_SSL_VERIFYHOST

Verify the hostname in the SSL certificate. See FETCHOPT_SSL_VERIFYHOST(3)

## FETCHOPT_SSL_VERIFYPEER

Verify the SSL certificate. See FETCHOPT_SSL_VERIFYPEER(3)

## FETCHOPT_SSL_VERIFYSTATUS

Verify the SSL certificate's status. See FETCHOPT_SSL_VERIFYSTATUS(3)

## FETCHOPT_STDERR

Redirect stderr to another stream. See FETCHOPT_STDERR(3)

## FETCHOPT_STREAM_DEPENDS

This HTTP/2 stream depends on another. See FETCHOPT_STREAM_DEPENDS(3)

## FETCHOPT_STREAM_DEPENDS_E

This HTTP/2 stream depends on another exclusively. See
FETCHOPT_STREAM_DEPENDS_E(3)

## FETCHOPT_STREAM_WEIGHT

Set this HTTP/2 stream's weight. See FETCHOPT_STREAM_WEIGHT(3)

## FETCHOPT_SUPPRESS_CONNECT_HEADERS

Suppress proxy CONNECT response headers from user callbacks. See
FETCHOPT_SUPPRESS_CONNECT_HEADERS(3)

## FETCHOPT_TCP_FASTOPEN

Enable TCP Fast Open. See FETCHOPT_TCP_FASTOPEN(3)

## FETCHOPT_TCP_KEEPALIVE

Enable TCP keep-alive. See FETCHOPT_TCP_KEEPALIVE(3)

## FETCHOPT_TCP_KEEPCNT

Maximum number of keep-alive probes. See FETCHOPT_TCP_KEEPCNT(3)

## FETCHOPT_TCP_KEEPIDLE

Idle time before sending keep-alive. See FETCHOPT_TCP_KEEPIDLE(3)

## FETCHOPT_TCP_KEEPINTVL

Interval between keep-alive probes. See FETCHOPT_TCP_KEEPINTVL(3)

## FETCHOPT_TCP_NODELAY

Disable the Nagle algorithm. See FETCHOPT_TCP_NODELAY(3)

## FETCHOPT_TELNETOPTIONS

TELNET options. See FETCHOPT_TELNETOPTIONS(3)

## FETCHOPT_TFTP_BLKSIZE

TFTP block size. See FETCHOPT_TFTP_BLKSIZE(3)

## FETCHOPT_TFTP_NO_OPTIONS

Do not send TFTP options requests. See FETCHOPT_TFTP_NO_OPTIONS(3)

## FETCHOPT_TIMECONDITION

Make a time conditional request. See FETCHOPT_TIMECONDITION(3)

## FETCHOPT_TIMEOUT

Timeout for the entire request. See FETCHOPT_TIMEOUT(3)

## FETCHOPT_TIMEOUT_MS

Millisecond timeout for the entire request. See FETCHOPT_TIMEOUT_MS(3)

## FETCHOPT_TIMEVALUE

Time value for the time conditional request. See FETCHOPT_TIMEVALUE(3)

## FETCHOPT_TIMEVALUE_LARGE

Time value for the time conditional request. See FETCHOPT_TIMEVALUE_LARGE(3)

## FETCHOPT_TLS13_CIPHERS

TLS 1.3 cipher suites to use. See FETCHOPT_TLS13_CIPHERS(3)

## FETCHOPT_TLSAUTH_PASSWORD

TLS authentication password. See FETCHOPT_TLSAUTH_PASSWORD(3)

## FETCHOPT_TLSAUTH_TYPE

TLS authentication methods. See FETCHOPT_TLSAUTH_TYPE(3)

## FETCHOPT_TLSAUTH_USERNAME

TLS authentication username. See FETCHOPT_TLSAUTH_USERNAME(3)

## FETCHOPT_TRAILERDATA

Custom pointer passed to the trailing headers callback. See
FETCHOPT_TRAILERDATA(3)

## FETCHOPT_TRAILERFUNCTION

Set callback for sending trailing headers. See
FETCHOPT_TRAILERFUNCTION(3)

## FETCHOPT_TRANSFERTEXT

Use text transfer. See FETCHOPT_TRANSFERTEXT(3)

## FETCHOPT_TRANSFER_ENCODING

Request Transfer-Encoding. See FETCHOPT_TRANSFER_ENCODING(3)

## FETCHOPT_UNIX_SOCKET_PATH

Path to a Unix domain socket. See FETCHOPT_UNIX_SOCKET_PATH(3)

## FETCHOPT_UNRESTRICTED_AUTH

Do not restrict authentication to original host. FETCHOPT_UNRESTRICTED_AUTH(3)

## FETCHOPT_UPKEEP_INTERVAL_MS

Sets the interval at which connection upkeep are performed. See
FETCHOPT_UPKEEP_INTERVAL_MS(3)

## FETCHOPT_UPLOAD

Upload data. See FETCHOPT_UPLOAD(3)

## FETCHOPT_UPLOAD_BUFFERSIZE

Set upload buffer size. See FETCHOPT_UPLOAD_BUFFERSIZE(3)

## FETCHOPT_URL

URL to work on. See FETCHOPT_URL(3)

## FETCHOPT_USERAGENT

User-Agent: header. See FETCHOPT_USERAGENT(3)

## FETCHOPT_USERNAME

Username. See FETCHOPT_USERNAME(3)

## FETCHOPT_USERPWD

Username and password. See FETCHOPT_USERPWD(3)

## FETCHOPT_USE_SSL

Use TLS/SSL. See FETCHOPT_USE_SSL(3)

## FETCHOPT_VERBOSE

Display verbose information. See FETCHOPT_VERBOSE(3)

## FETCHOPT_WILDCARDMATCH

Transfer multiple files according to a filename pattern. See
FETCHOPT_WILDCARDMATCH(3)

## FETCHOPT_WRITEDATA

Data pointer to pass to the write callback. See FETCHOPT_WRITEDATA(3)

## FETCHOPT_WRITEFUNCTION

Callback for writing data. See FETCHOPT_WRITEFUNCTION(3)

## FETCHOPT_WS_OPTIONS

Set WebSocket options. See FETCHOPT_WS_OPTIONS(3)

## FETCHOPT_XFERINFODATA

Data pointer to pass to the progress meter callback. See
FETCHOPT_XFERINFODATA(3)

## FETCHOPT_XFERINFOFUNCTION

Callback for progress meter. See FETCHOPT_XFERINFOFUNCTION(3)

## FETCHOPT_XOAUTH2_BEARER

OAuth2 bearer token. See FETCHOPT_XOAUTH2_BEARER(3)

# %PROTOCOLS%

# EXAMPLE

~~~c
int main(void)
{
  FETCH *fetch = fetch_easy_init();
  if(fetch) {
    FETCHcode res;
    fetch_easy_setopt(fetch, FETCHOPT_URL, "https://example.com");
    res = fetch_easy_perform(fetch);
    fetch_easy_cleanup(fetch);
  }
}
~~~

# %AVAILABILITY%

# RETURN VALUE

This function returns a FETCHcode indicating success or error.

FETCHE_OK (0) means everything was OK, non-zero means an error occurred, see
libfetch-errors(3). If FETCHOPT_ERRORBUFFER(3) was set with fetch_easy_setopt(3)
there can be an error message stored in the error buffer when non-zero is
returned.

Strings passed on to libfetch must be shorter than 8000000 bytes, otherwise
fetch_easy_setopt(3) returns **FETCHE_BAD_FUNCTION_ARGUMENT** (added in 7.65.0).

**FETCHE_BAD_FUNCTION_ARGUMENT** is returned when the argument to an option is
invalid, like perhaps out of range.

If you try to set an option that libfetch does not know about, perhaps because
the library is too old to support it or the option was removed in a recent
version, this function returns *FETCHE_UNKNOWN_OPTION*. If support for the
option was disabled at compile-time, it returns *FETCHE_NOT_BUILT_IN*.
