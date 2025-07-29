---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Title: curl_easy_setopt
Section: 3
Source: libcurl
See-also:
  - curl_easy_cleanup (3)
  - curl_easy_getinfo (3)
  - curl_easy_init (3)
  - curl_easy_option_by_id (3)
  - curl_easy_option_by_name (3)
  - curl_easy_option_next (3)
  - curl_easy_reset (3)
  - curl_multi_setopt (3)
Protocol:
  - All
Added-in: 7.1
---

# NAME

curl_easy_setopt - set options for a curl easy handle

# SYNOPSIS

~~~c
#include <curl/curl.h>

CURLcode curl_easy_setopt(CURL *handle, CURLoption option, parameter);
~~~

# DESCRIPTION

curl_easy_setopt(3) is used to tell libcurl how to behave. By setting the
appropriate options, the application can change libcurl's behavior. All
options are set with an *option* followed by a *parameter*. That parameter can
be a **long**, a **function pointer**, an **object pointer** or a
**curl_off_t**, depending on what the specific option expects. Read this
manual carefully as bad input values may cause libcurl to behave badly. You
can only set one option in each function call. A typical application uses many
curl_easy_setopt(3) calls in the setup phase.

The *handle* argument is the return code from a curl_easy_init(3) or
curl_easy_duphandle(3) call.

Options set with this function call are sticky. They remain set for all
forthcoming transfers performed using this *handle*. The options are not in
any way reset between transfers, so if you want subsequent transfers with
different options, you must change them between the transfers. You can
optionally reset all options back to internal default with curl_easy_reset(3).

The order in which the options are set does not matter.

# STRINGS

Strings passed to libcurl as 'char *' arguments, are copied by the library;
the string storage associated to the pointer argument may be discarded or
reused after curl_easy_setopt(3) returns. The only exception to this rule is
really CURLOPT_POSTFIELDS(3), but the alternative that copies the string
CURLOPT_COPYPOSTFIELDS(3) has some usage characteristics you need to read up
on.

This function does not accept input strings longer than
**CURL_MAX_INPUT_LENGTH** (8 MB).

libcurl does little to no verification of the contents of provided strings.
Passing in "creative octets" like newlines where they are not expected might
trigger unexpected results.

Before version 7.17.0, strings were not copied. Instead the user was forced
keep them available until libcurl no longer needed them.

# OPTIONS

## CURLOPT_ABSTRACT_UNIX_SOCKET

Path to an abstract Unix domain socket. See CURLOPT_ABSTRACT_UNIX_SOCKET(3)

## CURLOPT_ACCEPTTIMEOUT_MS

Timeout for waiting for the server's connect back to be accepted. See
CURLOPT_ACCEPTTIMEOUT_MS(3)

## CURLOPT_ACCEPT_ENCODING

Accept-Encoding and automatic decompressing data. See
CURLOPT_ACCEPT_ENCODING(3)

## CURLOPT_ADDRESS_SCOPE

IPv6 scope for local addresses. See CURLOPT_ADDRESS_SCOPE(3)

## CURLOPT_ALTSVC

Specify the Alt-Svc: cache filename. See CURLOPT_ALTSVC(3)

## CURLOPT_ALTSVC_CTRL

Enable and configure Alt-Svc: treatment. See CURLOPT_ALTSVC_CTRL(3)

## CURLOPT_APPEND

Append to remote file. See CURLOPT_APPEND(3)

## CURLOPT_AUTOREFERER

Automatically set Referer: header. See CURLOPT_AUTOREFERER(3)

## CURLOPT_AWS_SIGV4

AWS HTTP V4 Signature. See CURLOPT_AWS_SIGV4(3)

## CURLOPT_BUFFERSIZE

Ask for alternate buffer size. See CURLOPT_BUFFERSIZE(3)

## CURLOPT_CAINFO

CA cert bundle. See CURLOPT_CAINFO(3)

## CURLOPT_CAINFO_BLOB

CA cert bundle memory buffer. See CURLOPT_CAINFO_BLOB(3)

## CURLOPT_CAPATH

Path to CA cert bundle. See CURLOPT_CAPATH(3)

## CURLOPT_CA_CACHE_TIMEOUT

Timeout for CA cache. See CURLOPT_CA_CACHE_TIMEOUT(3)

## CURLOPT_CERTINFO

Extract certificate info. See CURLOPT_CERTINFO(3)

## CURLOPT_CHUNK_BGN_FUNCTION

Callback for wildcard download start of chunk. See
CURLOPT_CHUNK_BGN_FUNCTION(3)

## CURLOPT_CHUNK_DATA

Data pointer to pass to the chunk callbacks. See CURLOPT_CHUNK_DATA(3)

## CURLOPT_CHUNK_END_FUNCTION

Callback for wildcard download end of chunk. See CURLOPT_CHUNK_END_FUNCTION(3)

## CURLOPT_CLOSESOCKETDATA

Data pointer to pass to the close socket callback. See
CURLOPT_CLOSESOCKETDATA(3)

## CURLOPT_CLOSESOCKETFUNCTION

Callback for closing socket. See CURLOPT_CLOSESOCKETFUNCTION(3)

## CURLOPT_CONNECTTIMEOUT

Timeout for the connection phase. See CURLOPT_CONNECTTIMEOUT(3)

## CURLOPT_CONNECTTIMEOUT_MS

Millisecond timeout for the connection phase. See CURLOPT_CONNECTTIMEOUT_MS(3)

## CURLOPT_CONNECT_ONLY

Only connect, nothing else. See CURLOPT_CONNECT_ONLY(3)

## CURLOPT_CONNECT_TO

Connect to a specific host and port. See CURLOPT_CONNECT_TO(3)

## CURLOPT_CONV_FROM_NETWORK_FUNCTION

**OBSOLETE** Callback for code base conversion.
See CURLOPT_CONV_FROM_NETWORK_FUNCTION(3)

## CURLOPT_CONV_FROM_UTF8_FUNCTION

**OBSOLETE** Callback for code base conversion.
See CURLOPT_CONV_FROM_UTF8_FUNCTION(3)

## CURLOPT_CONV_TO_NETWORK_FUNCTION

**OBSOLETE** Callback for code base conversion.
See CURLOPT_CONV_TO_NETWORK_FUNCTION(3)

## CURLOPT_COOKIE

Cookie(s) to send. See CURLOPT_COOKIE(3)

## CURLOPT_COOKIEFILE

File to read cookies from. See CURLOPT_COOKIEFILE(3)

## CURLOPT_COOKIEJAR

File to write cookies to. See CURLOPT_COOKIEJAR(3)

## CURLOPT_COOKIELIST

Add or control cookies. See CURLOPT_COOKIELIST(3)

## CURLOPT_COOKIESESSION

Start a new cookie session. See CURLOPT_COOKIESESSION(3)

## CURLOPT_COPYPOSTFIELDS

Send a POST with this data - and copy it. See CURLOPT_COPYPOSTFIELDS(3)

## CURLOPT_CRLF

Convert newlines. See CURLOPT_CRLF(3)

## CURLOPT_CRLFILE

Certificate Revocation List. See CURLOPT_CRLFILE(3)

## CURLOPT_CURLU

Set URL to work on with a URL handle. See CURLOPT_CURLU(3)

## CURLOPT_CUSTOMREQUEST

Custom request/method. See CURLOPT_CUSTOMREQUEST(3)

## CURLOPT_DEBUGDATA

Data pointer to pass to the debug callback. See CURLOPT_DEBUGDATA(3)

## CURLOPT_DEBUGFUNCTION

Callback for debug information. See CURLOPT_DEBUGFUNCTION(3)

## CURLOPT_DEFAULT_PROTOCOL

Default protocol. See CURLOPT_DEFAULT_PROTOCOL(3)

## CURLOPT_DIRLISTONLY

List only. See CURLOPT_DIRLISTONLY(3)

## CURLOPT_DISALLOW_USERNAME_IN_URL

Do not allow username in URL. See CURLOPT_DISALLOW_USERNAME_IN_URL(3)

## CURLOPT_DNS_CACHE_TIMEOUT

Timeout for DNS cache. See CURLOPT_DNS_CACHE_TIMEOUT(3)

## CURLOPT_DNS_INTERFACE

Bind name resolves to this interface. See CURLOPT_DNS_INTERFACE(3)

## CURLOPT_DNS_LOCAL_IP4

Bind name resolves to this IP4 address. See CURLOPT_DNS_LOCAL_IP4(3)

## CURLOPT_DNS_LOCAL_IP6

Bind name resolves to this IP6 address. See CURLOPT_DNS_LOCAL_IP6(3)

## CURLOPT_DNS_SERVERS

Preferred DNS servers. See CURLOPT_DNS_SERVERS(3)

## CURLOPT_DNS_SHUFFLE_ADDRESSES

Shuffle addresses before use. See CURLOPT_DNS_SHUFFLE_ADDRESSES(3)

## CURLOPT_DNS_USE_GLOBAL_CACHE

**OBSOLETE** Enable global DNS cache. See CURLOPT_DNS_USE_GLOBAL_CACHE(3)

## CURLOPT_DOH_SSL_VERIFYHOST

Verify the hostname in the DoH (DNS-over-HTTPS) SSL certificate. See
CURLOPT_DOH_SSL_VERIFYHOST(3)

## CURLOPT_DOH_SSL_VERIFYPEER

Verify the DoH (DNS-over-HTTPS) SSL certificate. See
CURLOPT_DOH_SSL_VERIFYPEER(3)

## CURLOPT_DOH_SSL_VERIFYSTATUS

Verify the DoH (DNS-over-HTTPS) SSL certificate's status. See
CURLOPT_DOH_SSL_VERIFYSTATUS(3)

## CURLOPT_DOH_URL

Use this DoH server for name resolves. See CURLOPT_DOH_URL(3)

## CURLOPT_ECH

Set the configuration for ECH. See CURLOPT_ECH(3)

## CURLOPT_EGDSOCKET

**OBSOLETE** Identify EGD socket for entropy. See CURLOPT_EGDSOCKET(3)

## CURLOPT_ERRORBUFFER

Error message buffer. See CURLOPT_ERRORBUFFER(3)

## CURLOPT_EXPECT_100_TIMEOUT_MS

100-continue timeout. See CURLOPT_EXPECT_100_TIMEOUT_MS(3)

## CURLOPT_FAILONERROR

Fail on HTTP 4xx errors. CURLOPT_FAILONERROR(3)

## CURLOPT_FILETIME

Request file modification date and time. See CURLOPT_FILETIME(3)

## CURLOPT_FNMATCH_DATA

Data pointer to pass to the wildcard matching callback. See
CURLOPT_FNMATCH_DATA(3)

## CURLOPT_FNMATCH_FUNCTION

Callback for wildcard matching. See CURLOPT_FNMATCH_FUNCTION(3)

## CURLOPT_FOLLOWLOCATION

Follow HTTP redirects. See CURLOPT_FOLLOWLOCATION(3)

## CURLOPT_FORBID_REUSE

Prevent subsequent connections from reusing this. See CURLOPT_FORBID_REUSE(3)

## CURLOPT_FRESH_CONNECT

Use a new connection. CURLOPT_FRESH_CONNECT(3)

## CURLOPT_FTPPORT

Use active FTP. See CURLOPT_FTPPORT(3)

## CURLOPT_FTPSSLAUTH

Control how to do TLS. See CURLOPT_FTPSSLAUTH(3)

## CURLOPT_FTP_ACCOUNT

Send ACCT command. See CURLOPT_FTP_ACCOUNT(3)

## CURLOPT_FTP_ALTERNATIVE_TO_USER

Alternative to USER. See CURLOPT_FTP_ALTERNATIVE_TO_USER(3)

## CURLOPT_FTP_CREATE_MISSING_DIRS

Create missing directories on the remote server. See
CURLOPT_FTP_CREATE_MISSING_DIRS(3)

## CURLOPT_FTP_FILEMETHOD

Specify how to reach files. See CURLOPT_FTP_FILEMETHOD(3)

## CURLOPT_FTP_SKIP_PASV_IP

Ignore the IP address in the PASV response. See CURLOPT_FTP_SKIP_PASV_IP(3)

## CURLOPT_FTP_SSL_CCC

Back to non-TLS again after authentication. See CURLOPT_FTP_SSL_CCC(3)

## CURLOPT_FTP_USE_EPRT

Use EPRT. See CURLOPT_FTP_USE_EPRT(3)

## CURLOPT_FTP_USE_EPSV

Use EPSV. See CURLOPT_FTP_USE_EPSV(3)

## CURLOPT_FTP_USE_PRET

Use PRET. See CURLOPT_FTP_USE_PRET(3)

## CURLOPT_GSSAPI_DELEGATION

Disable GSS-API delegation. See CURLOPT_GSSAPI_DELEGATION(3)

## CURLOPT_HAPPY_EYEBALLS_TIMEOUT_MS

Timeout for happy eyeballs. See CURLOPT_HAPPY_EYEBALLS_TIMEOUT_MS(3)

## CURLOPT_HAPROXYPROTOCOL

Send an HAProxy PROXY protocol v1 header. See CURLOPT_HAPROXYPROTOCOL(3)

## CURLOPT_HAPROXY_CLIENT_IP

Spoof the client IP in an HAProxy PROXY protocol v1 header. See
CURLOPT_HAPROXY_CLIENT_IP(3)

## CURLOPT_HEADER

Include the header in the body output. See CURLOPT_HEADER(3)

## CURLOPT_HEADERDATA

Data pointer to pass to the header callback. See CURLOPT_HEADERDATA(3)

## CURLOPT_HEADERFUNCTION

Callback for writing received headers. See CURLOPT_HEADERFUNCTION(3)

## CURLOPT_HEADEROPT

Control custom headers. See CURLOPT_HEADEROPT(3)

## CURLOPT_HSTS

Set HSTS cache file. See CURLOPT_HSTS(3)

## CURLOPT_HSTSREADDATA

Pass pointer to the HSTS read callback. See CURLOPT_HSTSREADDATA(3)

## CURLOPT_HSTSREADFUNCTION

Set HSTS read callback. See CURLOPT_HSTSREADFUNCTION(3)

## CURLOPT_HSTSWRITEDATA

Pass pointer to the HSTS write callback. See CURLOPT_HSTSWRITEDATA(3)

## CURLOPT_HSTSWRITEFUNCTION

Set HSTS write callback. See CURLOPT_HSTSWRITEFUNCTION(3)

## CURLOPT_HSTS_CTRL

Enable HSTS. See CURLOPT_HSTS_CTRL(3)

## CURLOPT_HTTP09_ALLOWED

Allow HTTP/0.9 responses. CURLOPT_HTTP09_ALLOWED(3)

## CURLOPT_HTTP200ALIASES

Alternative versions of 200 OK. See CURLOPT_HTTP200ALIASES(3)

## CURLOPT_HTTPAUTH

HTTP server authentication methods. See CURLOPT_HTTPAUTH(3)

## CURLOPT_HTTPGET

Do an HTTP GET request. See CURLOPT_HTTPGET(3)

## CURLOPT_HTTPHEADER

Custom HTTP headers. See CURLOPT_HTTPHEADER(3)

## CURLOPT_HTTPPOST

**Deprecated option** Multipart formpost HTTP POST.
See CURLOPT_HTTPPOST(3)

## CURLOPT_HTTPPROXYTUNNEL

Tunnel through the HTTP proxy. CURLOPT_HTTPPROXYTUNNEL(3)

## CURLOPT_HTTP_CONTENT_DECODING

Disable Content decoding. See CURLOPT_HTTP_CONTENT_DECODING(3)

## CURLOPT_HTTP_TRANSFER_DECODING

Disable Transfer decoding. See CURLOPT_HTTP_TRANSFER_DECODING(3)

## CURLOPT_HTTP_VERSION

HTTP version to use. CURLOPT_HTTP_VERSION(3)

## CURLOPT_IGNORE_CONTENT_LENGTH

Ignore Content-Length. See CURLOPT_IGNORE_CONTENT_LENGTH(3)

## CURLOPT_INFILESIZE

Size of file to send. CURLOPT_INFILESIZE(3)

## CURLOPT_INFILESIZE_LARGE

Size of file to send. CURLOPT_INFILESIZE_LARGE(3)

## CURLOPT_INTERFACE

Bind connection locally to this. See CURLOPT_INTERFACE(3)

## CURLOPT_INTERLEAVEDATA

Data pointer to pass to the RTSP interleave callback. See
CURLOPT_INTERLEAVEDATA(3)

## CURLOPT_INTERLEAVEFUNCTION

Callback for RTSP interleaved data. See CURLOPT_INTERLEAVEFUNCTION(3)

## CURLOPT_IOCTLDATA

**Deprecated option** Data pointer to pass to the I/O callback.
See CURLOPT_IOCTLDATA(3)

## CURLOPT_IOCTLFUNCTION

**Deprecated option** Callback for I/O operations.
See CURLOPT_IOCTLFUNCTION(3)

## CURLOPT_IPRESOLVE

IP version to use. See CURLOPT_IPRESOLVE(3)

## CURLOPT_ISSUERCERT

Issuer certificate. See CURLOPT_ISSUERCERT(3)

## CURLOPT_ISSUERCERT_BLOB

Issuer certificate memory buffer. See CURLOPT_ISSUERCERT_BLOB(3)

## CURLOPT_KEEP_SENDING_ON_ERROR

Keep sending on HTTP \>= 300 errors. CURLOPT_KEEP_SENDING_ON_ERROR(3)

## CURLOPT_KEYPASSWD

Client key password. See CURLOPT_KEYPASSWD(3)

## CURLOPT_KRBLEVEL

Kerberos security level. See CURLOPT_KRBLEVEL(3)

## CURLOPT_LOCALPORT

Bind connection locally to this port. See CURLOPT_LOCALPORT(3)

## CURLOPT_LOCALPORTRANGE

Bind connection locally to port range. See CURLOPT_LOCALPORTRANGE(3)

## CURLOPT_LOGIN_OPTIONS

Login options. See CURLOPT_LOGIN_OPTIONS(3)

## CURLOPT_LOW_SPEED_LIMIT

Low speed limit to abort transfer. See CURLOPT_LOW_SPEED_LIMIT(3)

## CURLOPT_LOW_SPEED_TIME

Time to be below the speed to trigger low speed abort. See
CURLOPT_LOW_SPEED_TIME(3)

## CURLOPT_MAIL_AUTH

Authentication address. See CURLOPT_MAIL_AUTH(3)

## CURLOPT_MAIL_FROM

Address of the sender. See CURLOPT_MAIL_FROM(3)

## CURLOPT_MAIL_RCPT

Address of the recipients. See CURLOPT_MAIL_RCPT(3)

## CURLOPT_MAIL_RCPT_ALLOWFAILS

Allow RCPT TO command to fail for some recipients. See
CURLOPT_MAIL_RCPT_ALLOWFAILS(3)

## CURLOPT_MAXAGE_CONN

Limit the age (idle time) of connections for reuse. See CURLOPT_MAXAGE_CONN(3)

## CURLOPT_MAXCONNECTS

Maximum number of connections in the connection pool. See
CURLOPT_MAXCONNECTS(3)

## CURLOPT_MAXFILESIZE

Maximum file size to get. See CURLOPT_MAXFILESIZE(3)

## CURLOPT_MAXFILESIZE_LARGE

Maximum file size to get. See CURLOPT_MAXFILESIZE_LARGE(3)

## CURLOPT_MAXLIFETIME_CONN

Limit the age (since creation) of connections for reuse. See
CURLOPT_MAXLIFETIME_CONN(3)

## CURLOPT_MAXREDIRS

Maximum number of redirects to follow. See CURLOPT_MAXREDIRS(3)

## CURLOPT_MAX_RECV_SPEED_LARGE

Cap the download speed to this. See CURLOPT_MAX_RECV_SPEED_LARGE(3)

## CURLOPT_MAX_SEND_SPEED_LARGE

Cap the upload speed to this. See CURLOPT_MAX_SEND_SPEED_LARGE(3)

## CURLOPT_MIMEPOST

Post/send MIME data. See CURLOPT_MIMEPOST(3)

## CURLOPT_MIME_OPTIONS

Set MIME option flags. See CURLOPT_MIME_OPTIONS(3)

## CURLOPT_NETRC

Enable .netrc parsing. See CURLOPT_NETRC(3)

## CURLOPT_NETRC_FILE

.netrc filename. See CURLOPT_NETRC_FILE(3)

## CURLOPT_NEW_DIRECTORY_PERMS

Mode for creating new remote directories. See CURLOPT_NEW_DIRECTORY_PERMS(3)

## CURLOPT_NEW_FILE_PERMS

Mode for creating new remote files. See CURLOPT_NEW_FILE_PERMS(3)

## CURLOPT_NOBODY

Do not get the body contents. See CURLOPT_NOBODY(3)

## CURLOPT_NOPROGRESS

Shut off the progress meter. See CURLOPT_NOPROGRESS(3)

## CURLOPT_NOPROXY

Filter out hosts from proxy use. CURLOPT_NOPROXY(3)

## CURLOPT_NOSIGNAL

Do not install signal handlers. See CURLOPT_NOSIGNAL(3)

## CURLOPT_OPENSOCKETDATA

Data pointer to pass to the open socket callback. See CURLOPT_OPENSOCKETDATA(3)

## CURLOPT_OPENSOCKETFUNCTION

Callback for socket creation. See CURLOPT_OPENSOCKETFUNCTION(3)

## CURLOPT_PASSWORD

Password. See CURLOPT_PASSWORD(3)

## CURLOPT_PATH_AS_IS

Disable squashing /../ and /./ sequences in the path. See CURLOPT_PATH_AS_IS(3)

## CURLOPT_PINNEDPUBLICKEY

Set pinned SSL public key . See CURLOPT_PINNEDPUBLICKEY(3)

## CURLOPT_PIPEWAIT

Wait on connection to pipeline on it. See CURLOPT_PIPEWAIT(3)

## CURLOPT_PORT

Port number to connect to. See CURLOPT_PORT(3)

## CURLOPT_POST

Make an HTTP POST. See CURLOPT_POST(3)

## CURLOPT_POSTFIELDSIZE

The POST data is this big. See CURLOPT_POSTFIELDSIZE(3)

## CURLOPT_POSTFIELDSIZE_LARGE

The POST data is this big. See CURLOPT_POSTFIELDSIZE_LARGE(3)

## CURLOPT_POSTQUOTE

Commands to run after transfer. See CURLOPT_POSTQUOTE(3)

## CURLOPT_POSTREDIR

How to act on redirects after POST. See CURLOPT_POSTREDIR(3)

## CURLOPT_PREQUOTE

Commands to run just before transfer. See CURLOPT_PREQUOTE(3)

## CURLOPT_PREREQDATA

Data pointer to pass to the CURLOPT_PREREQFUNCTION callback. See
CURLOPT_PREREQDATA(3)

## CURLOPT_PREREQFUNCTION

Callback to be called after a connection is established but before a request
is made on that connection. See CURLOPT_PREREQFUNCTION(3)

## CURLOPT_PRE_PROXY

Socks proxy to use. See CURLOPT_PRE_PROXY(3)

## CURLOPT_PRIVATE

Private pointer to store. See CURLOPT_PRIVATE(3)

## CURLOPT_PROGRESSDATA

Data pointer to pass to the progress meter callback. See
CURLOPT_PROGRESSDATA(3)

## CURLOPT_PROGRESSFUNCTION

**OBSOLETE** callback for progress meter. See CURLOPT_PROGRESSFUNCTION(3)

## CURLOPT_PROTOCOLS

**Deprecated option** Allowed protocols. See CURLOPT_PROTOCOLS(3)

## CURLOPT_PROTOCOLS_STR

Allowed protocols. See CURLOPT_PROTOCOLS_STR(3)

## CURLOPT_PROXY

Proxy to use. See CURLOPT_PROXY(3)

## CURLOPT_PROXYAUTH

HTTP proxy authentication methods. See CURLOPT_PROXYAUTH(3)

## CURLOPT_PROXYHEADER

Custom HTTP headers sent to proxy. See CURLOPT_PROXYHEADER(3)

## CURLOPT_PROXYPASSWORD

Proxy password. See CURLOPT_PROXYPASSWORD(3)

## CURLOPT_PROXYPORT

Proxy port to use. See CURLOPT_PROXYPORT(3)

## CURLOPT_PROXYTYPE

Proxy type. See CURLOPT_PROXYTYPE(3)

## CURLOPT_PROXYUSERNAME
Proxy username. See CURLOPT_PROXYUSERNAME(3)

## CURLOPT_PROXYUSERPWD

Proxy username and password. See CURLOPT_PROXYUSERPWD(3)

## CURLOPT_PROXY_CAINFO

Proxy CA cert bundle. See CURLOPT_PROXY_CAINFO(3)

## CURLOPT_PROXY_CAINFO_BLOB

Proxy CA cert bundle memory buffer. See CURLOPT_PROXY_CAINFO_BLOB(3)

## CURLOPT_PROXY_CAPATH

Path to proxy CA cert bundle. See CURLOPT_PROXY_CAPATH(3)

## CURLOPT_PROXY_CRLFILE

Proxy Certificate Revocation List. See CURLOPT_PROXY_CRLFILE(3)

## CURLOPT_PROXY_ISSUERCERT

Proxy issuer certificate. See CURLOPT_PROXY_ISSUERCERT(3)

## CURLOPT_PROXY_ISSUERCERT_BLOB

Proxy issuer certificate memory buffer. See CURLOPT_PROXY_ISSUERCERT_BLOB(3)

## CURLOPT_PROXY_KEYPASSWD

Proxy client key password. See CURLOPT_PROXY_KEYPASSWD(3)

## CURLOPT_PROXY_PINNEDPUBLICKEY

Set the proxy's pinned SSL public key. See
CURLOPT_PROXY_PINNEDPUBLICKEY(3)

## CURLOPT_PROXY_SERVICE_NAME

Proxy authentication service name. CURLOPT_PROXY_SERVICE_NAME(3)

## CURLOPT_PROXY_SSLCERT

Proxy client cert. See CURLOPT_PROXY_SSLCERT(3)

## CURLOPT_PROXY_SSLCERTTYPE

Proxy client cert type. See CURLOPT_PROXY_SSLCERTTYPE(3)

## CURLOPT_PROXY_SSLCERT_BLOB

Proxy client cert memory buffer. See CURLOPT_PROXY_SSLCERT_BLOB(3)

## CURLOPT_PROXY_SSLKEY

Proxy client key. See CURLOPT_PROXY_SSLKEY(3)

## CURLOPT_PROXY_SSLKEYTYPE

Proxy client key type. See CURLOPT_PROXY_SSLKEYTYPE(3)

## CURLOPT_PROXY_SSLKEY_BLOB

Proxy client key. See CURLOPT_PROXY_SSLKEY_BLOB(3)

## CURLOPT_PROXY_SSLVERSION

Proxy SSL version to use. See CURLOPT_PROXY_SSLVERSION(3)

## CURLOPT_PROXY_SSL_CIPHER_LIST

Proxy ciphers to use. See CURLOPT_PROXY_SSL_CIPHER_LIST(3)

## CURLOPT_PROXY_SSL_OPTIONS

Control proxy SSL behavior. See CURLOPT_PROXY_SSL_OPTIONS(3)

## CURLOPT_PROXY_SSL_VERIFYHOST

Verify the hostname in the proxy SSL certificate. See
CURLOPT_PROXY_SSL_VERIFYHOST(3)

## CURLOPT_PROXY_SSL_VERIFYPEER

Verify the proxy SSL certificate. See CURLOPT_PROXY_SSL_VERIFYPEER(3)

## CURLOPT_PROXY_TLS13_CIPHERS

Proxy TLS 1.3 cipher suites to use. See CURLOPT_PROXY_TLS13_CIPHERS(3)

## CURLOPT_PROXY_TLSAUTH_PASSWORD

Proxy TLS authentication password. See CURLOPT_PROXY_TLSAUTH_PASSWORD(3)

## CURLOPT_PROXY_TLSAUTH_TYPE

Proxy TLS authentication methods. See CURLOPT_PROXY_TLSAUTH_TYPE(3)

## CURLOPT_PROXY_TLSAUTH_USERNAME

Proxy TLS authentication username. See CURLOPT_PROXY_TLSAUTH_USERNAME(3)

## CURLOPT_PROXY_TRANSFER_MODE

Add transfer mode to URL over proxy. See CURLOPT_PROXY_TRANSFER_MODE(3)

## CURLOPT_PUT

**Deprecated option** Issue an HTTP PUT request. See CURLOPT_PUT(3)

## CURLOPT_QUICK_EXIT

To be set by toplevel tools like "curl" to skip lengthy cleanups when they are
about to call exit() anyway. See CURLOPT_QUICK_EXIT(3)

## CURLOPT_QUOTE

Commands to run before transfer. See CURLOPT_QUOTE(3)

## CURLOPT_RANDOM_FILE

**OBSOLETE** Provide source for entropy random data.
See CURLOPT_RANDOM_FILE(3)

## CURLOPT_RANGE

Range requests. See CURLOPT_RANGE(3)

## CURLOPT_READDATA

Data pointer to pass to the read callback. See CURLOPT_READDATA(3)

## CURLOPT_READFUNCTION

Callback for reading data. See CURLOPT_READFUNCTION(3)

## CURLOPT_REDIR_PROTOCOLS

**Deprecated option** Protocols to allow redirects to. See
CURLOPT_REDIR_PROTOCOLS(3)

## CURLOPT_REDIR_PROTOCOLS_STR

Protocols to allow redirects to. See CURLOPT_REDIR_PROTOCOLS_STR(3)

## CURLOPT_REFERER

Referer: header. See CURLOPT_REFERER(3)

## CURLOPT_REQUEST_TARGET

Set the request target. CURLOPT_REQUEST_TARGET(3)

## CURLOPT_RESOLVE

Provide fixed/fake name resolves. See CURLOPT_RESOLVE(3)

## CURLOPT_RESOLVER_START_DATA

Data pointer to pass to resolver start callback. See
CURLOPT_RESOLVER_START_DATA(3)

## CURLOPT_RESOLVER_START_FUNCTION

Callback to be called before a new resolve request is started. See
CURLOPT_RESOLVER_START_FUNCTION(3)

## CURLOPT_RESUME_FROM

Resume a transfer. See CURLOPT_RESUME_FROM(3)

## CURLOPT_RESUME_FROM_LARGE

Resume a transfer. See CURLOPT_RESUME_FROM_LARGE(3)

## CURLOPT_RTSP_CLIENT_CSEQ

Client CSEQ number. See CURLOPT_RTSP_CLIENT_CSEQ(3)

## CURLOPT_RTSP_REQUEST

RTSP request. See CURLOPT_RTSP_REQUEST(3)

## CURLOPT_RTSP_SERVER_CSEQ

CSEQ number for RTSP Server-\>Client request. See CURLOPT_RTSP_SERVER_CSEQ(3)

## CURLOPT_RTSP_SESSION_ID

RTSP session-id. See CURLOPT_RTSP_SESSION_ID(3)

## CURLOPT_RTSP_STREAM_URI

RTSP stream URI. See CURLOPT_RTSP_STREAM_URI(3)

## CURLOPT_RTSP_TRANSPORT

RTSP Transport: header. See CURLOPT_RTSP_TRANSPORT(3)

## CURLOPT_SASL_AUTHZID

SASL authorization identity (identity to act as). See CURLOPT_SASL_AUTHZID(3)

## CURLOPT_SASL_IR

Enable SASL initial response. See CURLOPT_SASL_IR(3)

## CURLOPT_SEEKDATA

Data pointer to pass to the seek callback. See CURLOPT_SEEKDATA(3)

## CURLOPT_SEEKFUNCTION

Callback for seek operations. See CURLOPT_SEEKFUNCTION(3)

## CURLOPT_SERVER_RESPONSE_TIMEOUT

Timeout for server responses. See CURLOPT_SERVER_RESPONSE_TIMEOUT(3)

## CURLOPT_SERVER_RESPONSE_TIMEOUT_MS

Timeout for server responses. See CURLOPT_SERVER_RESPONSE_TIMEOUT_MS(3)

## CURLOPT_SERVICE_NAME

Authentication service name. CURLOPT_SERVICE_NAME(3)

## CURLOPT_SHARE

Share object to use. See CURLOPT_SHARE(3)

## CURLOPT_SOCKOPTDATA

Data pointer to pass to the sockopt callback. See CURLOPT_SOCKOPTDATA(3)

## CURLOPT_SOCKOPTFUNCTION

Callback for sockopt operations. See CURLOPT_SOCKOPTFUNCTION(3)

## CURLOPT_SOCKS5_AUTH

Socks5 authentication methods. See CURLOPT_SOCKS5_AUTH(3)

## CURLOPT_SOCKS5_GSSAPI_NEC

Socks5 GSSAPI NEC mode. See CURLOPT_SOCKS5_GSSAPI_NEC(3)

## CURLOPT_SOCKS5_GSSAPI_SERVICE

**Deprecated option** Socks5 GSSAPI service name.
See CURLOPT_SOCKS5_GSSAPI_SERVICE(3)

## CURLOPT_SSH_AUTH_TYPES

SSH authentication types. See CURLOPT_SSH_AUTH_TYPES(3)

## CURLOPT_SSH_COMPRESSION

Enable SSH compression. See CURLOPT_SSH_COMPRESSION(3)

## CURLOPT_SSH_HOSTKEYDATA

Custom pointer to pass to ssh host key callback. See CURLOPT_SSH_HOSTKEYDATA(3)

## CURLOPT_SSH_HOSTKEYFUNCTION

Callback for checking host key handling. See CURLOPT_SSH_HOSTKEYFUNCTION(3)

## CURLOPT_SSH_HOST_PUBLIC_KEY_MD5

MD5 of host's public key. See CURLOPT_SSH_HOST_PUBLIC_KEY_MD5(3)

## CURLOPT_SSH_HOST_PUBLIC_KEY_SHA256

SHA256 of host's public key. See CURLOPT_SSH_HOST_PUBLIC_KEY_SHA256(3)

## CURLOPT_SSH_KEYDATA

Custom pointer to pass to ssh key callback. See CURLOPT_SSH_KEYDATA(3)

## CURLOPT_SSH_KEYFUNCTION

Callback for known hosts handling. See CURLOPT_SSH_KEYFUNCTION(3)

## CURLOPT_SSH_KNOWNHOSTS

Filename with known hosts. See CURLOPT_SSH_KNOWNHOSTS(3)

## CURLOPT_SSH_PRIVATE_KEYFILE

Filename of the private key. See CURLOPT_SSH_PRIVATE_KEYFILE(3)

## CURLOPT_SSH_PUBLIC_KEYFILE

Filename of the public key. See CURLOPT_SSH_PUBLIC_KEYFILE(3)

## CURLOPT_SSLCERT

Client cert. See CURLOPT_SSLCERT(3)

## CURLOPT_SSLCERTTYPE

Client cert type. See CURLOPT_SSLCERTTYPE(3)

## CURLOPT_SSLCERT_BLOB

Client cert memory buffer. See CURLOPT_SSLCERT_BLOB(3)

## CURLOPT_SSLENGINE

Use identifier with SSL engine. See CURLOPT_SSLENGINE(3)

## CURLOPT_SSLENGINE_DEFAULT

Default SSL engine. See CURLOPT_SSLENGINE_DEFAULT(3)

## CURLOPT_SSLKEY

Client key. See CURLOPT_SSLKEY(3)

## CURLOPT_SSLKEYTYPE

Client key type. See CURLOPT_SSLKEYTYPE(3)

## CURLOPT_SSLKEY_BLOB

Client key memory buffer. See CURLOPT_SSLKEY_BLOB(3)

## CURLOPT_SSLVERSION

SSL version to use. See CURLOPT_SSLVERSION(3)

## CURLOPT_SSL_CIPHER_LIST

Ciphers to use. See CURLOPT_SSL_CIPHER_LIST(3)

## CURLOPT_SSL_CTX_DATA

Data pointer to pass to the SSL context callback. See CURLOPT_SSL_CTX_DATA(3)

## CURLOPT_SSL_CTX_FUNCTION

Callback for SSL context logic. See CURLOPT_SSL_CTX_FUNCTION(3)

## CURLOPT_SSL_EC_CURVES

Set key exchange curves. See CURLOPT_SSL_EC_CURVES(3)

## CURLOPT_SSL_ENABLE_ALPN

Enable use of ALPN. See CURLOPT_SSL_ENABLE_ALPN(3)

## CURLOPT_SSL_ENABLE_NPN

**OBSOLETE** Enable use of NPN. See CURLOPT_SSL_ENABLE_NPN(3)

## CURLOPT_SSL_FALSESTART

**Deprecated option** Enable TLS False Start. See CURLOPT_SSL_FALSESTART(3)

## CURLOPT_SSL_OPTIONS

Control SSL behavior. See CURLOPT_SSL_OPTIONS(3)

## CURLOPT_SSL_SESSIONID_CACHE

Disable SSL session-id cache. See CURLOPT_SSL_SESSIONID_CACHE(3)

## CURLOPT_SSL_SIGNATURE_ALGORITHMS

TLS signature algorithms to use. See CURLOPT_SSL_SIGNATURE_ALGORITHMS(3)

## CURLOPT_SSL_VERIFYHOST

Verify the hostname in the SSL certificate. See CURLOPT_SSL_VERIFYHOST(3)

## CURLOPT_SSL_VERIFYPEER

Verify the SSL certificate. See CURLOPT_SSL_VERIFYPEER(3)

## CURLOPT_SSL_VERIFYSTATUS

Verify the SSL certificate's status. See CURLOPT_SSL_VERIFYSTATUS(3)

## CURLOPT_STDERR

Redirect stderr to another stream. See CURLOPT_STDERR(3)

## CURLOPT_STREAM_DEPENDS

This HTTP/2 stream depends on another. See CURLOPT_STREAM_DEPENDS(3)

## CURLOPT_STREAM_DEPENDS_E

This HTTP/2 stream depends on another exclusively. See
CURLOPT_STREAM_DEPENDS_E(3)

## CURLOPT_STREAM_WEIGHT

Set this HTTP/2 stream's weight. See CURLOPT_STREAM_WEIGHT(3)

## CURLOPT_SUPPRESS_CONNECT_HEADERS

Suppress proxy CONNECT response headers from user callbacks. See
CURLOPT_SUPPRESS_CONNECT_HEADERS(3)

## CURLOPT_TCP_FASTOPEN

Enable TCP Fast Open. See CURLOPT_TCP_FASTOPEN(3)

## CURLOPT_TCP_KEEPALIVE

Enable TCP keep-alive. See CURLOPT_TCP_KEEPALIVE(3)

## CURLOPT_TCP_KEEPCNT

Maximum number of keep-alive probes. See CURLOPT_TCP_KEEPCNT(3)

## CURLOPT_TCP_KEEPIDLE

Idle time before sending keep-alive. See CURLOPT_TCP_KEEPIDLE(3)

## CURLOPT_TCP_KEEPINTVL

Interval between keep-alive probes. See CURLOPT_TCP_KEEPINTVL(3)

## CURLOPT_TCP_NODELAY

Disable the Nagle algorithm. See CURLOPT_TCP_NODELAY(3)

## CURLOPT_TELNETOPTIONS

TELNET options. See CURLOPT_TELNETOPTIONS(3)

## CURLOPT_TFTP_BLKSIZE

TFTP block size. See CURLOPT_TFTP_BLKSIZE(3)

## CURLOPT_TFTP_NO_OPTIONS

Do not send TFTP options requests. See CURLOPT_TFTP_NO_OPTIONS(3)

## CURLOPT_TIMECONDITION

Make a time conditional request. See CURLOPT_TIMECONDITION(3)

## CURLOPT_TIMEOUT

Timeout for the entire request. See CURLOPT_TIMEOUT(3)

## CURLOPT_TIMEOUT_MS

Millisecond timeout for the entire request. See CURLOPT_TIMEOUT_MS(3)

## CURLOPT_TIMEVALUE

Time value for the time conditional request. See CURLOPT_TIMEVALUE(3)

## CURLOPT_TIMEVALUE_LARGE

Time value for the time conditional request. See CURLOPT_TIMEVALUE_LARGE(3)

## CURLOPT_TLS13_CIPHERS

TLS 1.3 cipher suites to use. See CURLOPT_TLS13_CIPHERS(3)

## CURLOPT_TLSAUTH_PASSWORD

TLS authentication password. See CURLOPT_TLSAUTH_PASSWORD(3)

## CURLOPT_TLSAUTH_TYPE

TLS authentication methods. See CURLOPT_TLSAUTH_TYPE(3)

## CURLOPT_TLSAUTH_USERNAME

TLS authentication username. See CURLOPT_TLSAUTH_USERNAME(3)

## CURLOPT_TRAILERDATA

Custom pointer passed to the trailing headers callback. See
CURLOPT_TRAILERDATA(3)

## CURLOPT_TRAILERFUNCTION

Set callback for sending trailing headers. See
CURLOPT_TRAILERFUNCTION(3)

## CURLOPT_TRANSFERTEXT

Use text transfer. See CURLOPT_TRANSFERTEXT(3)

## CURLOPT_TRANSFER_ENCODING

Request Transfer-Encoding. See CURLOPT_TRANSFER_ENCODING(3)

## CURLOPT_UNIX_SOCKET_PATH

Path to a Unix domain socket. See CURLOPT_UNIX_SOCKET_PATH(3)

## CURLOPT_UNRESTRICTED_AUTH

Do not restrict authentication to original host. CURLOPT_UNRESTRICTED_AUTH(3)

## CURLOPT_UPKEEP_INTERVAL_MS

Sets the interval at which connection upkeep are performed. See
CURLOPT_UPKEEP_INTERVAL_MS(3)

## CURLOPT_UPLOAD

Upload data. See CURLOPT_UPLOAD(3)

## CURLOPT_UPLOAD_BUFFERSIZE

Set upload buffer size. See CURLOPT_UPLOAD_BUFFERSIZE(3)

## CURLOPT_UPLOAD_FLAGS

Set upload flags. See CURLOPT_UPLOAD_FLAGS(3)

## CURLOPT_URL

URL to work on. See CURLOPT_URL(3)

## CURLOPT_USERAGENT

User-Agent: header. See CURLOPT_USERAGENT(3)

## CURLOPT_USERNAME

Username. See CURLOPT_USERNAME(3)

## CURLOPT_USERPWD

Username and password. See CURLOPT_USERPWD(3)

## CURLOPT_USE_SSL

Use TLS/SSL. See CURLOPT_USE_SSL(3)

## CURLOPT_VERBOSE

Display verbose information. See CURLOPT_VERBOSE(3)

## CURLOPT_WILDCARDMATCH

Transfer multiple files according to a filename pattern. See
CURLOPT_WILDCARDMATCH(3)

## CURLOPT_WRITEDATA

Data pointer to pass to the write callback. See CURLOPT_WRITEDATA(3)

## CURLOPT_WRITEFUNCTION

Callback for writing data. See CURLOPT_WRITEFUNCTION(3)

## CURLOPT_WS_OPTIONS

Set WebSocket options. See CURLOPT_WS_OPTIONS(3)

## CURLOPT_XFERINFODATA

Data pointer to pass to the progress meter callback. See
CURLOPT_XFERINFODATA(3)

## CURLOPT_XFERINFOFUNCTION

Callback for progress meter. See CURLOPT_XFERINFOFUNCTION(3)

## CURLOPT_XOAUTH2_BEARER

OAuth2 bearer token. See CURLOPT_XOAUTH2_BEARER(3)

# %PROTOCOLS%

# EXAMPLE

~~~c
int main(void)
{
  CURL *curl = curl_easy_init();
  if(curl) {
    CURLcode res;
    curl_easy_setopt(curl, CURLOPT_URL, "https://example.com");
    res = curl_easy_perform(curl);
    curl_easy_cleanup(curl);
  }
}
~~~

# %AVAILABILITY%

# RETURN VALUE

This function returns a CURLcode indicating success or error.

CURLE_OK (0) means everything was OK, non-zero means an error occurred, see
libcurl-errors(3). If CURLOPT_ERRORBUFFER(3) was set with curl_easy_setopt(3)
there can be an error message stored in the error buffer when non-zero is
returned.

Strings passed on to libcurl must be shorter than 8000000 bytes, otherwise
curl_easy_setopt(3) returns **CURLE_BAD_FUNCTION_ARGUMENT** (added in 7.65.0).

**CURLE_BAD_FUNCTION_ARGUMENT** is returned when the argument to an option is
invalid, like perhaps out of range.

If you try to set an option that libcurl does not know about, perhaps because
the library is too old to support it or the option was removed in a recent
version, this function returns *CURLE_UNKNOWN_OPTION*. If support for the
option was disabled at compile-time, it returns *CURLE_NOT_BUILT_IN*.
