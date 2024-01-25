---
c: Copyright (C) Daniel Stenberg, <daniel.se>, et al.
SPDX-License-Identifier: curl
Title: libcurl-symbols
Section: 3
Source: libcurl
See-also:
  - libcurl (3)
  - libcurl-easy (3)
  - libcurl-multi (3)
  - libcurl-security (3)
  - libcurl-thread (3)
---
# libcurl symbols

This man page details version information for public symbols provided in the
libcurl header files. This lists the first version in which the symbol was
introduced and for some symbols two additional information pieces:

The first version in which the symbol is marked "deprecated" - meaning that
since that version no new code should be written to use the symbol as it is
marked for getting removed in a future.

The last version that featured the specific symbol. Using the symbol in source
code will make it no longer compile error-free after that specified version.

This man page is automatically generated from the symbols-in-versions file.

## CURL_AT_LEAST_VERSION
Introduced in 7.43.0.

## CURL_BLOB_COPY
Introduced in 7.71.0.

## CURL_BLOB_NOCOPY
Introduced in 7.71.0.

## CURL_CHUNK_BGN_FUNC_FAIL
Introduced in 7.21.0. See CURLOPT_CHUNK_BGN_FUNCTION(3).

## CURL_CHUNK_BGN_FUNC_OK
Introduced in 7.21.0. See CURLOPT_CHUNK_BGN_FUNCTION(3).

## CURL_CHUNK_BGN_FUNC_SKIP
Introduced in 7.21.0. See CURLOPT_CHUNK_BGN_FUNCTION(3).

## CURL_CHUNK_END_FUNC_FAIL
Introduced in 7.21.0. See CURLOPT_CHUNK_END_FUNCTION(3).

## CURL_CHUNK_END_FUNC_OK
Introduced in 7.21.0. See CURLOPT_CHUNK_END_FUNCTION(3).

## CURL_CSELECT_ERR
Introduced in 7.16.3. See curl_multi_socket_action(3).

## CURL_CSELECT_IN
Introduced in 7.16.3. See curl_multi_socket_action(3).

## CURL_CSELECT_OUT
Introduced in 7.16.3. See curl_multi_socket_action(3).

## CURL_DEPRECATED
Introduced in 7.87.0.

## CURL_DID_MEMORY_FUNC_TYPEDEFS
Introduced in 7.49.0.

## CURL_EASY_NONE
Introduced in 7.14.0. Last used in 7.15.4.

## CURL_EASY_TIMEOUT
Introduced in 7.14.0. Last used in 7.15.4.

## CURL_ERROR_SIZE
Introduced in 7.1.

## CURL_FNMATCHFUNC_FAIL
Introduced in 7.21.0. See CURLOPT_FNMATCH_FUNCTION(3).

## CURL_FNMATCHFUNC_MATCH
Introduced in 7.21.0. See CURLOPT_FNMATCH_FUNCTION(3).

## CURL_FNMATCHFUNC_NOMATCH
Introduced in 7.21.0. See CURLOPT_FNMATCH_FUNCTION(3).

## CURL_FORMADD_DISABLED
Introduced in 7.12.1. Deprecated since 7.56.0.

## CURL_FORMADD_ILLEGAL_ARRAY
Introduced in 7.9.8. Deprecated since 7.56.0.

## CURL_FORMADD_INCOMPLETE
Introduced in 7.9.8. Deprecated since 7.56.0.

## CURL_FORMADD_MEMORY
Introduced in 7.9.8. Deprecated since 7.56.0.

## CURL_FORMADD_NULL
Introduced in 7.9.8. Deprecated since 7.56.0.

## CURL_FORMADD_OK
Introduced in 7.9.8. Deprecated since 7.56.0.

## CURL_FORMADD_OPTION_TWICE
Introduced in 7.9.8. Deprecated since 7.56.0.

## CURL_FORMADD_UNKNOWN_OPTION
Introduced in 7.9.8. Deprecated since 7.56.0.

## CURL_GLOBAL_ACK_EINTR
Introduced in 7.30.0. See curl_global_init(3).

## CURL_GLOBAL_ALL
Introduced in 7.8. See curl_global_init(3).

## CURL_GLOBAL_DEFAULT
Introduced in 7.8. See curl_global_init(3).

## CURL_GLOBAL_NOTHING
Introduced in 7.8. See curl_global_init(3).

## CURL_GLOBAL_SSL
Introduced in 7.8. See curl_global_init(3).

## CURL_GLOBAL_WIN32
Introduced in 7.8.1. See curl_global_init(3).

## CURL_HET_DEFAULT
Introduced in 7.59.0. See CURLOPT_HAPPY_EYEBALLS_TIMEOUT_MS(3).

## CURL_HTTP_VERSION_1_0
Introduced in 7.9.1. See CURLOPT_HTTP_VERSION(3).

## CURL_HTTP_VERSION_1_1
Introduced in 7.9.1. See CURLOPT_HTTP_VERSION(3).

## CURL_HTTP_VERSION_2
Introduced in 7.43.0. See CURLOPT_HTTP_VERSION(3).

## CURL_HTTP_VERSION_2_0
Introduced in 7.33.0. See CURLOPT_HTTP_VERSION(3).

## CURL_HTTP_VERSION_2_PRIOR_KNOWLEDGE
Introduced in 7.49.0. See CURLOPT_HTTP_VERSION(3).

## CURL_HTTP_VERSION_2TLS
Introduced in 7.47.0. See CURLOPT_HTTP_VERSION(3).

## CURL_HTTP_VERSION_3
Introduced in 7.66.0. See CURLOPT_HTTP_VERSION(3).

## CURL_HTTP_VERSION_3ONLY
Introduced in 7.88.0. See CURLOPT_HTTP_VERSION(3).

## CURL_HTTP_VERSION_NONE
Introduced in 7.9.1. See CURLOPT_HTTP_VERSION(3).

## CURL_HTTPPOST_BUFFER
Introduced in 7.46.0. See curl_formadd(3).

## CURL_HTTPPOST_CALLBACK
Introduced in 7.46.0. See curl_formadd(3).

## CURL_HTTPPOST_FILENAME
Introduced in 7.46.0. See curl_formadd(3).

## CURL_HTTPPOST_LARGE
Introduced in 7.46.0. See curl_formadd(3).

## CURL_HTTPPOST_PTRBUFFER
Introduced in 7.46.0. See curl_formadd(3).

## CURL_HTTPPOST_PTRCONTENTS
Introduced in 7.46.0. See curl_formadd(3).

## CURL_HTTPPOST_PTRNAME
Introduced in 7.46.0. See curl_formadd(3).

## CURL_HTTPPOST_READFILE
Introduced in 7.46.0. See curl_formadd(3).

## CURL_IGNORE_DEPRECATION
Introduced in 7.87.0.

## CURL_IPRESOLVE_V4
Introduced in 7.10.8. See CURLOPT_IPRESOLVE(3).

## CURL_IPRESOLVE_V6
Introduced in 7.10.8. See CURLOPT_IPRESOLVE(3).

## CURL_IPRESOLVE_WHATEVER
Introduced in 7.10.8. See CURLOPT_IPRESOLVE(3).

## CURL_ISOCPP
Introduced in 7.10.2.

## CURL_LOCK_ACCESS_NONE
Introduced in 7.10.3. See CURLSHOPT_SHARE(3).

## CURL_LOCK_ACCESS_SHARED
Introduced in 7.10.3. See CURLSHOPT_SHARE(3).

## CURL_LOCK_ACCESS_SINGLE
Introduced in 7.10.3. See CURLSHOPT_SHARE(3).

## CURL_LOCK_DATA_CONNECT
Introduced in 7.10.3. See CURLSHOPT_SHARE(3).

## CURL_LOCK_DATA_COOKIE
Introduced in 7.10.3. See CURLSHOPT_SHARE(3).

## CURL_LOCK_DATA_DNS
Introduced in 7.10.3. See CURLSHOPT_SHARE(3).

## CURL_LOCK_DATA_HSTS
Introduced in 7.88.0. See CURLSHOPT_SHARE(3).

## CURL_LOCK_DATA_NONE
Introduced in 7.10.3. See CURLSHOPT_SHARE(3).

## CURL_LOCK_DATA_PSL
Introduced in 7.61.0. See CURLSHOPT_SHARE(3).

## CURL_LOCK_DATA_SHARE
Introduced in 7.10.4. See CURLSHOPT_SHARE(3).

## CURL_LOCK_DATA_SSL_SESSION
Introduced in 7.10.3. See CURLSHOPT_SHARE(3).

## CURL_LOCK_TYPE_CONNECT
Introduced in 7.10. Last used in 7.10.2.

## CURL_LOCK_TYPE_COOKIE
Introduced in 7.10. Last used in 7.10.2.

## CURL_LOCK_TYPE_DNS
Introduced in 7.10. Last used in 7.10.2.

## CURL_LOCK_TYPE_NONE
Introduced in 7.10. Last used in 7.10.2.

## CURL_LOCK_TYPE_SSL_SESSION
Introduced in 7.10. Last used in 7.10.2.

## CURL_MAX_HTTP_HEADER
Introduced in 7.19.7.

## CURL_MAX_READ_SIZE
Introduced in 7.53.0.

## CURL_MAX_WRITE_SIZE
Introduced in 7.9.7.

## CURL_NETRC_IGNORED
Introduced in 7.9.8.

## CURL_NETRC_OPTIONAL
Introduced in 7.9.8.

## CURL_NETRC_REQUIRED
Introduced in 7.9.8.

## CURL_POLL_IN
Introduced in 7.14.0. See CURLMOPT_SOCKETFUNCTION(3).

## CURL_POLL_INOUT
Introduced in 7.14.0. See CURLMOPT_SOCKETFUNCTION(3).

## CURL_POLL_NONE
Introduced in 7.14.0. See CURLMOPT_SOCKETFUNCTION(3).

## CURL_POLL_OUT
Introduced in 7.14.0. See CURLMOPT_SOCKETFUNCTION(3).

## CURL_POLL_REMOVE
Introduced in 7.14.0. See CURLMOPT_SOCKETFUNCTION(3).

## CURL_PREREQFUNC_ABORT
Introduced in 7.79.0.

## CURL_PREREQFUNC_OK
Introduced in 7.79.0.

## CURL_PROGRESS_BAR
Introduced in 7.1.1. Last used in 7.4.1.

## CURL_PROGRESS_STATS
Introduced in 7.1.1. Last used in 7.4.1.

## CURL_PROGRESSFUNC_CONTINUE
Introduced in 7.68.0.

## CURL_PULL_SYS_POLL_H
Introduced in 7.56.0.

## CURL_PUSH_DENY
Introduced in 7.44.0.

## CURL_PUSH_ERROROUT
Introduced in 7.72.0.

## CURL_PUSH_OK
Introduced in 7.44.0.

## CURL_READFUNC_ABORT
Introduced in 7.12.1.

## CURL_READFUNC_PAUSE
Introduced in 7.18.0.

## CURL_REDIR_GET_ALL
Introduced in 7.19.1.

## CURL_REDIR_POST_301
Introduced in 7.19.1. See CURLOPT_POSTREDIR(3).

## CURL_REDIR_POST_302
Introduced in 7.19.1. See CURLOPT_POSTREDIR(3).

## CURL_REDIR_POST_303
Introduced in 7.25.1. See CURLOPT_POSTREDIR(3).

## CURL_REDIR_POST_ALL
Introduced in 7.19.1. See CURLOPT_POSTREDIR(3).

## CURL_RTSPREQ_ANNOUNCE
Introduced in 7.20.0. See CURLOPT_RTSP_REQUEST(3).

## CURL_RTSPREQ_DESCRIBE
Introduced in 7.20.0. See CURLOPT_RTSP_REQUEST(3).

## CURL_RTSPREQ_GET_PARAMETER
Introduced in 7.20.0. See CURLOPT_RTSP_REQUEST(3).

## CURL_RTSPREQ_NONE
Introduced in 7.20.0. See CURLOPT_RTSP_REQUEST(3).

## CURL_RTSPREQ_OPTIONS
Introduced in 7.20.0. See CURLOPT_RTSP_REQUEST(3).

## CURL_RTSPREQ_PAUSE
Introduced in 7.20.0. See CURLOPT_RTSP_REQUEST(3).

## CURL_RTSPREQ_PLAY
Introduced in 7.20.0. See CURLOPT_RTSP_REQUEST(3).

## CURL_RTSPREQ_RECEIVE
Introduced in 7.20.0. See CURLOPT_RTSP_REQUEST(3).

## CURL_RTSPREQ_RECORD
Introduced in 7.20.0. See CURLOPT_RTSP_REQUEST(3).

## CURL_RTSPREQ_SET_PARAMETER
Introduced in 7.20.0. See CURLOPT_RTSP_REQUEST(3).

## CURL_RTSPREQ_SETUP
Introduced in 7.20.0. See CURLOPT_RTSP_REQUEST(3).

## CURL_RTSPREQ_TEARDOWN
Introduced in 7.20.0. See CURLOPT_RTSP_REQUEST(3).

## CURL_SEEKFUNC_CANTSEEK
Introduced in 7.19.5. See CURLOPT_SEEKFUNCTION(3).

## CURL_SEEKFUNC_FAIL
Introduced in 7.19.5. See CURLOPT_SEEKFUNCTION(3).

## CURL_SEEKFUNC_OK
Introduced in 7.19.5. See CURLOPT_SEEKFUNCTION(3).

## CURL_SOCKET_BAD
Introduced in 7.14.0.

## CURL_SOCKET_TIMEOUT
Introduced in 7.14.0.

## CURL_SOCKOPT_ALREADY_CONNECTED
Introduced in 7.21.5.

## CURL_SOCKOPT_ERROR
Introduced in 7.21.5.

## CURL_SOCKOPT_OK
Introduced in 7.21.5.

## CURL_SSLVERSION_DEFAULT
Introduced in 7.9.2. See CURLOPT_SSLVERSION(3).

## CURL_SSLVERSION_MAX_DEFAULT
Introduced in 7.54.0. See CURLOPT_SSLVERSION(3).

## CURL_SSLVERSION_MAX_NONE
Introduced in 7.54.0. See CURLOPT_SSLVERSION(3).

## CURL_SSLVERSION_MAX_TLSv1_0
Introduced in 7.54.0. See CURLOPT_SSLVERSION(3).

## CURL_SSLVERSION_MAX_TLSv1_1
Introduced in 7.54.0. See CURLOPT_SSLVERSION(3).

## CURL_SSLVERSION_MAX_TLSv1_2
Introduced in 7.54.0. See CURLOPT_SSLVERSION(3).

## CURL_SSLVERSION_MAX_TLSv1_3
Introduced in 7.54.0. See CURLOPT_SSLVERSION(3).

## CURL_SSLVERSION_SSLv2
Introduced in 7.9.2. See CURLOPT_SSLVERSION(3).

## CURL_SSLVERSION_SSLv3
Introduced in 7.9.2. See CURLOPT_SSLVERSION(3).

## CURL_SSLVERSION_TLSv1
Introduced in 7.9.2. See CURLOPT_SSLVERSION(3).

## CURL_SSLVERSION_TLSv1_0
Introduced in 7.34.0. See CURLOPT_SSLVERSION(3).

## CURL_SSLVERSION_TLSv1_1
Introduced in 7.34.0. See CURLOPT_SSLVERSION(3).

## CURL_SSLVERSION_TLSv1_2
Introduced in 7.34.0. See CURLOPT_SSLVERSION(3).

## CURL_SSLVERSION_TLSv1_3
Introduced in 7.52.0. See CURLOPT_SSLVERSION(3).

## CURL_STRICTER
Introduced in 7.50.2.

## CURL_TIMECOND_IFMODSINCE
Introduced in 7.9.7. See CURLOPT_TIMECONDITION(3).

## CURL_TIMECOND_IFUNMODSINCE
Introduced in 7.9.7. See CURLOPT_TIMECONDITION(3).

## CURL_TIMECOND_LASTMOD
Introduced in 7.9.7. See CURLOPT_TIMECONDITION(3).

## CURL_TIMECOND_NONE
Introduced in 7.9.7. See CURLOPT_TIMECONDITION(3).

## CURL_TLSAUTH_NONE
Introduced in 7.21.4.

## CURL_TLSAUTH_SRP
Introduced in 7.21.4.

## CURL_TRAILERFUNC_ABORT
Introduced in 7.64.0. See CURLOPT_TRAILERFUNCTION(3).

## CURL_TRAILERFUNC_OK
Introduced in 7.64.0. See CURLOPT_TRAILERFUNCTION(3).

## CURL_UPKEEP_INTERVAL_DEFAULT
Introduced in 7.62.0.

## CURL_VERSION_ALTSVC
Introduced in 7.64.1. See curl_version_info(3).

## CURL_VERSION_ASYNCHDNS
Introduced in 7.10.7. See curl_version_info(3).

## CURL_VERSION_BITS
Introduced in 7.43.0. See curl_version_info(3).

## CURL_VERSION_BROTLI
Introduced in 7.57.0. See curl_version_info(3).

## CURL_VERSION_CONV
Introduced in 7.15.4. See curl_version_info(3).

## CURL_VERSION_CURLDEBUG
Introduced in 7.19.6. See curl_version_info(3).

## CURL_VERSION_DEBUG
Introduced in 7.10.6. See curl_version_info(3).

## CURL_VERSION_GSASL
Introduced in 7.76.0. See curl_version_info(3).

## CURL_VERSION_GSSAPI
Introduced in 7.38.0. See curl_version_info(3).

## CURL_VERSION_GSSNEGOTIATE
Introduced in 7.10.6. Deprecated since 7.38.0.

## CURL_VERSION_HSTS
Introduced in 7.74.0. See curl_version_info(3).

## CURL_VERSION_HTTP2
Introduced in 7.33.0. See curl_version_info(3).

## CURL_VERSION_HTTP3
Introduced in 7.66.0. See curl_version_info(3).

## CURL_VERSION_HTTPS_PROXY
Introduced in 7.52.0. See curl_version_info(3).

## CURL_VERSION_IDN
Introduced in 7.12.0. See curl_version_info(3).

## CURL_VERSION_IPV6
Introduced in 7.10. See curl_version_info(3).

## CURL_VERSION_KERBEROS4
Introduced in 7.10. Deprecated since 7.33.0.

## CURL_VERSION_KERBEROS5
Introduced in 7.40.0. See curl_version_info(3).

## CURL_VERSION_LARGEFILE
Introduced in 7.11.1. See curl_version_info(3).

## CURL_VERSION_LIBZ
Introduced in 7.10. See curl_version_info(3).

## CURL_VERSION_MULTI_SSL
Introduced in 7.56.0. See curl_version_info(3).

## CURL_VERSION_NTLM
Introduced in 7.10.6. See curl_version_info(3).

## CURL_VERSION_NTLM_WB
Introduced in 7.22.0. See curl_version_info(3).

## CURL_VERSION_PSL
Introduced in 7.47.0. See curl_version_info(3).

## CURL_VERSION_SPNEGO
Introduced in 7.10.8. See curl_version_info(3).

## CURL_VERSION_SSL
Introduced in 7.10. See curl_version_info(3).

## CURL_VERSION_SSPI
Introduced in 7.13.2. See curl_version_info(3).

## CURL_VERSION_THREADSAFE
Introduced in 7.84.0. See curl_version_info(3).

## CURL_VERSION_TLSAUTH_SRP
Introduced in 7.21.4. See curl_version_info(3).

## CURL_VERSION_UNICODE
Introduced in 7.72.0. See curl_version_info(3).

## CURL_VERSION_UNIX_SOCKETS
Introduced in 7.40.0. See curl_version_info(3).

## CURL_VERSION_ZSTD
Introduced in 7.72.0. See curl_version_info(3).

## CURL_WAIT_POLLIN
Introduced in 7.28.0.

## CURL_WAIT_POLLOUT
Introduced in 7.28.0.

## CURL_WAIT_POLLPRI
Introduced in 7.28.0.

## CURL_WIN32
Introduced in 7.69.0. Last used in 8.5.0.

## CURL_WRITEFUNC_ERROR
Introduced in 7.87.0.

## CURL_WRITEFUNC_PAUSE
Introduced in 7.18.0.

## CURL_ZERO_TERMINATED
Introduced in 7.56.0.

## CURLALTSVC_H1
Introduced in 7.64.1. See CURLOPT_ALTSVC_CTRL(3).

## CURLALTSVC_H2
Introduced in 7.64.1. See CURLOPT_ALTSVC_CTRL(3).

## CURLALTSVC_H3
Introduced in 7.64.1. See CURLOPT_ALTSVC_CTRL(3).

## CURLALTSVC_READONLYFILE
Introduced in 7.64.1. See CURLOPT_ALTSVC_CTRL(3).

## CURLAUTH_ANY
Introduced in 7.10.6. See CURLOPT_HTTPAUTH(3).

## CURLAUTH_ANYSAFE
Introduced in 7.10.6. See CURLOPT_HTTPAUTH(3).

## CURLAUTH_AWS_SIGV4
Introduced in 7.75.0. See CURLOPT_HTTPAUTH(3).

## CURLAUTH_BASIC
Introduced in 7.10.6. See CURLOPT_HTTPAUTH(3).

## CURLAUTH_BEARER
Introduced in 7.61.0. See CURLOPT_HTTPAUTH(3).

## CURLAUTH_DIGEST
Introduced in 7.10.6. See CURLOPT_HTTPAUTH(3).

## CURLAUTH_DIGEST_IE
Introduced in 7.19.3. See CURLOPT_HTTPAUTH(3).

## CURLAUTH_GSSAPI
Introduced in 7.55.0. See CURLOPT_HTTPAUTH(3).

## CURLAUTH_GSSNEGOTIATE
Introduced in 7.10.6. Deprecated since 7.38.0.

## CURLAUTH_NEGOTIATE
Introduced in 7.38.0. See CURLOPT_HTTPAUTH(3).

## CURLAUTH_NONE
Introduced in 7.10.6. See CURLOPT_HTTPAUTH(3).

## CURLAUTH_NTLM
Introduced in 7.10.6. See CURLOPT_HTTPAUTH(3).

## CURLAUTH_NTLM_WB
Introduced in 7.22.0. See CURLOPT_HTTPAUTH(3).

## CURLAUTH_ONLY
Introduced in 7.21.3. See CURLOPT_HTTPAUTH(3).

## CURLCLOSEPOLICY_CALLBACK
Introduced in 7.7. Deprecated since 7.16.1.

## CURLCLOSEPOLICY_LEAST_RECENTLY_USED
Introduced in 7.7. Deprecated since 7.16.1.

## CURLCLOSEPOLICY_LEAST_TRAFFIC
Introduced in 7.7. Deprecated since 7.16.1.

## CURLCLOSEPOLICY_NONE
Introduced in 7.7. Deprecated since 7.16.1.

## CURLCLOSEPOLICY_OLDEST
Introduced in 7.7. Deprecated since 7.16.1.

## CURLCLOSEPOLICY_SLOWEST
Introduced in 7.7. Deprecated since 7.16.1.

## CURLE_ABORTED_BY_CALLBACK
Introduced in 7.1. See libcurl-errors(3).

## CURLE_AGAIN
Introduced in 7.18.2. See libcurl-errors(3).

## CURLE_ALREADY_COMPLETE
Introduced in 7.7.2. Deprecated since 7.8.

## CURLE_AUTH_ERROR
Introduced in 7.66.0. See libcurl-errors(3).

## CURLE_BAD_CALLING_ORDER
Introduced in 7.1. Deprecated since 7.17.0.

## CURLE_BAD_CONTENT_ENCODING
Introduced in 7.10. See libcurl-errors(3).

## CURLE_BAD_DOWNLOAD_RESUME
Introduced in 7.10. See libcurl-errors(3).

## CURLE_BAD_FUNCTION_ARGUMENT
Introduced in 7.1. See libcurl-errors(3).

## CURLE_BAD_PASSWORD_ENTERED
Introduced in 7.4.2. Deprecated since 7.17.0.

## CURLE_CHUNK_FAILED
Introduced in 7.21.0. See libcurl-errors(3).

## CURLE_CONV_FAILED
Introduced in 7.15.4. Deprecated since 7.82.0.

## CURLE_CONV_REQD
Introduced in 7.15.4. Deprecated since 7.82.0.

## CURLE_COULDNT_CONNECT
Introduced in 7.1. See libcurl-errors(3).

## CURLE_COULDNT_RESOLVE_HOST
Introduced in 7.1. See libcurl-errors(3).

## CURLE_COULDNT_RESOLVE_PROXY
Introduced in 7.1. See libcurl-errors(3).

## CURLE_FAILED_INIT
Introduced in 7.1. See libcurl-errors(3).

## CURLE_FILE_COULDNT_READ_FILE
Introduced in 7.1. See libcurl-errors(3).

## CURLE_FILESIZE_EXCEEDED
Introduced in 7.10.8. See libcurl-errors(3).

## CURLE_FTP_ACCEPT_FAILED
Introduced in 7.24.0. See libcurl-errors(3).

## CURLE_FTP_ACCEPT_TIMEOUT
Introduced in 7.24.0. See libcurl-errors(3).

## CURLE_FTP_ACCESS_DENIED
Introduced in 7.1. Deprecated since 7.17.0.

## CURLE_FTP_BAD_DOWNLOAD_RESUME
Introduced in 7.1. Deprecated since 7.1.

## CURLE_FTP_BAD_FILE_LIST
Introduced in 7.21.0. See libcurl-errors(3).

## CURLE_FTP_CANT_GET_HOST
Introduced in 7.1. See libcurl-errors(3).

## CURLE_FTP_CANT_RECONNECT
Introduced in 7.1. Deprecated since 7.17.0.

## CURLE_FTP_COULDNT_GET_SIZE
Introduced in 7.1. Deprecated since 7.17.0.

## CURLE_FTP_COULDNT_RETR_FILE
Introduced in 7.1. See libcurl-errors(3).

## CURLE_FTP_COULDNT_SET_ASCII
Introduced in 7.1. Deprecated since 7.17.0.

## CURLE_FTP_COULDNT_SET_BINARY
Introduced in 7.1. Deprecated since 7.17.0.

## CURLE_FTP_COULDNT_SET_TYPE
Introduced in 7.17.0. See libcurl-errors(3).

## CURLE_FTP_COULDNT_STOR_FILE
Introduced in 7.1. Deprecated since 7.16.3.

## CURLE_FTP_COULDNT_USE_REST
Introduced in 7.1. See libcurl-errors(3).

## CURLE_FTP_PARTIAL_FILE
Introduced in 7.1. Deprecated since 7.1.

## CURLE_FTP_PORT_FAILED
Introduced in 7.1. See libcurl-errors(3).

## CURLE_FTP_PRET_FAILED
Introduced in 7.20.0. See libcurl-errors(3).

## CURLE_FTP_QUOTE_ERROR
Introduced in 7.1. Deprecated since 7.17.0.

## CURLE_FTP_SSL_FAILED
Introduced in 7.11.0. Deprecated since 7.17.0.

## CURLE_FTP_USER_PASSWORD_INCORRECT
Introduced in 7.1. Deprecated since 7.17.0.

## CURLE_FTP_WEIRD_227_FORMAT
Introduced in 7.1. See libcurl-errors(3).

## CURLE_FTP_WEIRD_PASS_REPLY
Introduced in 7.1. See libcurl-errors(3).

## CURLE_FTP_WEIRD_PASV_REPLY
Introduced in 7.1. See libcurl-errors(3).

## CURLE_FTP_WEIRD_SERVER_REPLY
Introduced in 7.1. Deprecated since 7.51.0.

## CURLE_FTP_WEIRD_USER_REPLY
Introduced in 7.1. Deprecated since 7.17.0.

## CURLE_FTP_WRITE_ERROR
Introduced in 7.1. Deprecated since 7.17.0.

## CURLE_FUNCTION_NOT_FOUND
Introduced in 7.1. See libcurl-errors(3).

## CURLE_GOT_NOTHING
Introduced in 7.9.1. See libcurl-errors(3).

## CURLE_HTTP2
Introduced in 7.38.0. See libcurl-errors(3).

## CURLE_HTTP2_STREAM
Introduced in 7.49.0. See libcurl-errors(3).

## CURLE_HTTP3
Introduced in 7.68.0. See libcurl-errors(3).

## CURLE_HTTP_NOT_FOUND
Introduced in 7.1. Deprecated since 7.10.3.

## CURLE_HTTP_PORT_FAILED
Introduced in 7.3. Deprecated since 7.12.0.

## CURLE_HTTP_POST_ERROR
Introduced in 7.1. See libcurl-errors(3).

## CURLE_HTTP_RANGE_ERROR
Introduced in 7.1. Deprecated since 7.17.0.

## CURLE_HTTP_RETURNED_ERROR
Introduced in 7.10.3. See libcurl-errors(3).

## CURLE_INTERFACE_FAILED
Introduced in 7.12.0. See libcurl-errors(3).

## CURLE_LDAP_CANNOT_BIND
Introduced in 7.1. See libcurl-errors(3).

## CURLE_LDAP_INVALID_URL
Introduced in 7.10.8. Deprecated since 7.82.0.

## CURLE_LDAP_SEARCH_FAILED
Introduced in 7.1. See libcurl-errors(3).

## CURLE_LIBRARY_NOT_FOUND
Introduced in 7.1. Deprecated since 7.17.0.

## CURLE_LOGIN_DENIED
Introduced in 7.13.1. See libcurl-errors(3).

## CURLE_MALFORMAT_USER
Introduced in 7.1. Deprecated since 7.17.0.

## CURLE_NO_CONNECTION_AVAILABLE
Introduced in 7.30.0. See libcurl-errors(3).

## CURLE_NOT_BUILT_IN
Introduced in 7.21.5. See libcurl-errors(3).

## CURLE_OK
Introduced in 7.1. See libcurl-errors(3).

## CURLE_OPERATION_TIMEDOUT
Introduced in 7.10.2. See libcurl-errors(3).

## CURLE_OPERATION_TIMEOUTED
Introduced in 7.1. Deprecated since 7.17.0.

## CURLE_OUT_OF_MEMORY
Introduced in 7.1. See libcurl-errors(3).

## CURLE_PARTIAL_FILE
Introduced in 7.1. See libcurl-errors(3).

## CURLE_PEER_FAILED_VERIFICATION
Introduced in 7.17.1. See libcurl-errors(3).

## CURLE_PROXY
Introduced in 7.73.0. See libcurl-errors(3).

## CURLE_QUIC_CONNECT_ERROR
Introduced in 7.69.0. See libcurl-errors(3).

## CURLE_QUOTE_ERROR
Introduced in 7.17.0. See libcurl-errors(3).

## CURLE_RANGE_ERROR
Introduced in 7.17.0. See libcurl-errors(3).

## CURLE_READ_ERROR
Introduced in 7.1. See libcurl-errors(3).

## CURLE_RECURSIVE_API_CALL
Introduced in 7.59.0. See libcurl-errors(3).

## CURLE_RECV_ERROR
Introduced in 7.10. See libcurl-errors(3).

## CURLE_REMOTE_ACCESS_DENIED
Introduced in 7.17.0. See libcurl-errors(3).

## CURLE_REMOTE_DISK_FULL
Introduced in 7.17.0. See libcurl-errors(3).

## CURLE_REMOTE_FILE_EXISTS
Introduced in 7.17.0. See libcurl-errors(3).

## CURLE_REMOTE_FILE_NOT_FOUND
Introduced in 7.16.1. See libcurl-errors(3).

## CURLE_RTSP_CSEQ_ERROR
Introduced in 7.20.0. See libcurl-errors(3).

## CURLE_RTSP_SESSION_ERROR
Introduced in 7.20.0. See libcurl-errors(3).

## CURLE_SEND_ERROR
Introduced in 7.10. See libcurl-errors(3).

## CURLE_SEND_FAIL_REWIND
Introduced in 7.12.3. See libcurl-errors(3).

## CURLE_SETOPT_OPTION_SYNTAX
Introduced in 7.78.0. See libcurl-errors(3).

## CURLE_SHARE_IN_USE
Introduced in 7.9.6. Deprecated since 7.17.0.

## CURLE_SSH
Introduced in 7.16.1. See libcurl-errors(3).

## CURLE_SSL_CACERT
Introduced in 7.10. Deprecated since 7.62.0.

## CURLE_SSL_CACERT_BADFILE
Introduced in 7.16.0. See libcurl-errors(3).

## CURLE_SSL_CERTPROBLEM
Introduced in 7.10. See libcurl-errors(3).

## CURLE_SSL_CIPHER
Introduced in 7.10. See libcurl-errors(3).

## CURLE_SSL_CLIENTCERT
Introduced in 7.77.0. See libcurl-errors(3).

## CURLE_SSL_CONNECT_ERROR
Introduced in 7.1. See libcurl-errors(3).

## CURLE_SSL_CRL_BADFILE
Introduced in 7.19.0. See libcurl-errors(3).

## CURLE_SSL_ENGINE_INITFAILED
Introduced in 7.12.3. See libcurl-errors(3).

## CURLE_SSL_ENGINE_NOTFOUND
Introduced in 7.9.3. See libcurl-errors(3).

## CURLE_SSL_ENGINE_SETFAILED
Introduced in 7.9.3. See libcurl-errors(3).

## CURLE_SSL_INVALIDCERTSTATUS
Introduced in 7.41.0. See libcurl-errors(3).

## CURLE_SSL_ISSUER_ERROR
Introduced in 7.19.0. See libcurl-errors(3).

## CURLE_SSL_PEER_CERTIFICATE
Introduced in 7.8. Deprecated since 7.17.1.

## CURLE_SSL_PINNEDPUBKEYNOTMATCH
Introduced in 7.39.0. See libcurl-errors(3).

## CURLE_SSL_SHUTDOWN_FAILED
Introduced in 7.16.1. See libcurl-errors(3).

## CURLE_TELNET_OPTION_SYNTAX
Introduced in 7.7. See libcurl-errors(3).

## CURLE_TFTP_DISKFULL
Introduced in 7.15.0. Deprecated since 7.17.0.

## CURLE_TFTP_EXISTS
Introduced in 7.15.0. Deprecated since 7.17.0.

## CURLE_TFTP_ILLEGAL
Introduced in 7.15.0. See libcurl-errors(3).

## CURLE_TFTP_NOSUCHUSER
Introduced in 7.15.0. See libcurl-errors(3).

## CURLE_TFTP_NOTFOUND
Introduced in 7.15.0. See libcurl-errors(3).

## CURLE_TFTP_PERM
Introduced in 7.15.0. See libcurl-errors(3).

## CURLE_TFTP_UNKNOWNID
Introduced in 7.15.0. See libcurl-errors(3).

## CURLE_TOO_LARGE
Introduced in 8.6.0. See libcurl-errors(3).

## CURLE_TOO_MANY_REDIRECTS
Introduced in 7.5. See libcurl-errors(3).

## CURLE_UNKNOWN_OPTION
Introduced in 7.21.5. See libcurl-errors(3).

## CURLE_UNKNOWN_TELNET_OPTION
Introduced in 7.7. Deprecated since 7.21.5.

## CURLE_UNRECOVERABLE_POLL
Introduced in 7.84.0. See libcurl-errors(3).

## CURLE_UNSUPPORTED_PROTOCOL
Introduced in 7.1. See libcurl-errors(3).

## CURLE_UPLOAD_FAILED
Introduced in 7.16.3. See libcurl-errors(3).

## CURLE_URL_MALFORMAT
Introduced in 7.1. See libcurl-errors(3).

## CURLE_URL_MALFORMAT_USER
Introduced in 7.1. Deprecated since 7.17.0.

## CURLE_USE_SSL_FAILED
Introduced in 7.17.0. See libcurl-errors(3).

## CURLE_WEIRD_SERVER_REPLY
Introduced in 7.51.0. See libcurl-errors(3).

## CURLE_WRITE_ERROR
Introduced in 7.1. See libcurl-errors(3).

## CURLFILETYPE_DEVICE_BLOCK
Introduced in 7.21.0. See CURLOPT_CHUNK_BGN_FUNCTION(3).

## CURLFILETYPE_DEVICE_CHAR
Introduced in 7.21.0. See CURLOPT_CHUNK_BGN_FUNCTION(3).

## CURLFILETYPE_DIRECTORY
Introduced in 7.21.0. See CURLOPT_CHUNK_BGN_FUNCTION(3).

## CURLFILETYPE_DOOR
Introduced in 7.21.0. See CURLOPT_CHUNK_BGN_FUNCTION(3).

## CURLFILETYPE_FILE
Introduced in 7.21.0. See CURLOPT_CHUNK_BGN_FUNCTION(3).

## CURLFILETYPE_NAMEDPIPE
Introduced in 7.21.0. See CURLOPT_CHUNK_BGN_FUNCTION(3).

## CURLFILETYPE_SOCKET
Introduced in 7.21.0. See CURLOPT_CHUNK_BGN_FUNCTION(3).

## CURLFILETYPE_SYMLINK
Introduced in 7.21.0. See CURLOPT_CHUNK_BGN_FUNCTION(3).

## CURLFILETYPE_UNKNOWN
Introduced in 7.21.0. See CURLOPT_CHUNK_BGN_FUNCTION(3).

## CURLFINFOFLAG_KNOWN_FILENAME
Introduced in 7.21.0. See CURLOPT_CHUNK_BGN_FUNCTION(3).

## CURLFINFOFLAG_KNOWN_FILETYPE
Introduced in 7.21.0. See CURLOPT_CHUNK_BGN_FUNCTION(3).

## CURLFINFOFLAG_KNOWN_GID
Introduced in 7.21.0. See CURLOPT_CHUNK_BGN_FUNCTION(3).

## CURLFINFOFLAG_KNOWN_HLINKCOUNT
Introduced in 7.21.0. See CURLOPT_CHUNK_BGN_FUNCTION(3).

## CURLFINFOFLAG_KNOWN_PERM
Introduced in 7.21.0. See CURLOPT_CHUNK_BGN_FUNCTION(3).

## CURLFINFOFLAG_KNOWN_SIZE
Introduced in 7.21.0. See CURLOPT_CHUNK_BGN_FUNCTION(3).

## CURLFINFOFLAG_KNOWN_TIME
Introduced in 7.21.0. See CURLOPT_CHUNK_BGN_FUNCTION(3).

## CURLFINFOFLAG_KNOWN_UID
Introduced in 7.21.0. See CURLOPT_CHUNK_BGN_FUNCTION(3).

## CURLFORM_ARRAY
Introduced in 7.9.1. Deprecated since 7.56.0.

## CURLFORM_ARRAY_END
Introduced in 7.9.1. Deprecated since 7.9.5.

## CURLFORM_ARRAY_START
Introduced in 7.9.1. Deprecated since 7.9.5.

## CURLFORM_BUFFER
Introduced in 7.9.8. Deprecated since 7.56.0.

## CURLFORM_BUFFERLENGTH
Introduced in 7.9.8. Deprecated since 7.56.0.

## CURLFORM_BUFFERPTR
Introduced in 7.9.8. Deprecated since 7.56.0.

## CURLFORM_CONTENTHEADER
Introduced in 7.9.3. Deprecated since 7.56.0.

## CURLFORM_CONTENTLEN
Introduced in 7.46.0. Deprecated since 7.56.0.

## CURLFORM_CONTENTSLENGTH
Introduced in 7.9. Deprecated since 7.56.0.

## CURLFORM_CONTENTTYPE
Introduced in 7.9. Deprecated since 7.56.0.

## CURLFORM_COPYCONTENTS
Introduced in 7.9. Deprecated since 7.56.0.

## CURLFORM_COPYNAME
Introduced in 7.9. Deprecated since 7.56.0.

## CURLFORM_END
Introduced in 7.9. Deprecated since 7.56.0.

## CURLFORM_FILE
Introduced in 7.9. Deprecated since 7.56.0.

## CURLFORM_FILECONTENT
Introduced in 7.9.1. Deprecated since 7.56.0.

## CURLFORM_FILENAME
Introduced in 7.9.6. Deprecated since 7.56.0.

## CURLFORM_NAMELENGTH
Introduced in 7.9. Deprecated since 7.56.0.

## CURLFORM_NOTHING
Introduced in 7.9. Deprecated since 7.56.0.

## CURLFORM_PTRCONTENTS
Introduced in 7.9. Deprecated since 7.56.0.

## CURLFORM_PTRNAME
Introduced in 7.9. Deprecated since 7.56.0.

## CURLFORM_STREAM
Introduced in 7.18.2. Deprecated since 7.56.0.

## CURLFTP_CREATE_DIR
Introduced in 7.19.4. See CURLOPT_FTP_CREATE_MISSING_DIRS(3).

## CURLFTP_CREATE_DIR_NONE
Introduced in 7.19.4. See CURLOPT_FTP_CREATE_MISSING_DIRS(3).

## CURLFTP_CREATE_DIR_RETRY
Introduced in 7.19.4. See CURLOPT_FTP_CREATE_MISSING_DIRS(3).

## CURLFTPAUTH_DEFAULT
Introduced in 7.12.2. See CURLOPT_FTPSSLAUTH(3).

## CURLFTPAUTH_SSL
Introduced in 7.12.2. See CURLOPT_FTPSSLAUTH(3).

## CURLFTPAUTH_TLS
Introduced in 7.12.2. See CURLOPT_FTPSSLAUTH(3).

## CURLFTPMETHOD_DEFAULT
Introduced in 7.15.3. See CURLOPT_FTP_FILEMETHOD(3).

## CURLFTPMETHOD_MULTICWD
Introduced in 7.15.3. See CURLOPT_FTP_FILEMETHOD(3).

## CURLFTPMETHOD_NOCWD
Introduced in 7.15.3. See CURLOPT_FTP_FILEMETHOD(3).

## CURLFTPMETHOD_SINGLECWD
Introduced in 7.15.3. See CURLOPT_FTP_FILEMETHOD(3).

## CURLFTPSSL_ALL
Introduced in 7.11.0. Deprecated since 7.17.0.

## CURLFTPSSL_CCC_ACTIVE
Introduced in 7.16.2. See CURLOPT_USE_SSL(3).

## CURLFTPSSL_CCC_NONE
Introduced in 7.16.2. See CURLOPT_USE_SSL(3).

## CURLFTPSSL_CCC_PASSIVE
Introduced in 7.16.1. See CURLOPT_USE_SSL(3).

## CURLFTPSSL_CONTROL
Introduced in 7.11.0. Deprecated since 7.17.0.

## CURLFTPSSL_NONE
Introduced in 7.11.0. Deprecated since 7.17.0.

## CURLFTPSSL_TRY
Introduced in 7.11.0. Deprecated since 7.17.0.

## CURLGSSAPI_DELEGATION_FLAG
Introduced in 7.22.0. See CURLOPT_GSSAPI_DELEGATION(3).

## CURLGSSAPI_DELEGATION_NONE
Introduced in 7.22.0. See CURLOPT_GSSAPI_DELEGATION(3).

## CURLGSSAPI_DELEGATION_POLICY_FLAG
Introduced in 7.22.0. See CURLOPT_GSSAPI_DELEGATION(3).

## CURLH_1XX
Introduced in 7.83.0. See curl_easy_header(3).

## CURLH_CONNECT
Introduced in 7.83.0. See curl_easy_header(3).

## CURLH_HEADER
Introduced in 7.83.0. See curl_easy_header(3).

## CURLH_PSEUDO
Introduced in 7.83.0. See curl_easy_header(3).

## CURLH_TRAILER
Introduced in 7.83.0. See curl_easy_header(3).

## CURLHE_BAD_ARGUMENT
Introduced in 7.83.0. See libcurl-errors(3).

## CURLHE_BADINDEX
Introduced in 7.83.0. See libcurl-errors(3).

## CURLHE_MISSING
Introduced in 7.83.0. See libcurl-errors(3).

## CURLHE_NOHEADERS
Introduced in 7.83.0. See libcurl-errors(3).

## CURLHE_NOREQUEST
Introduced in 7.83.0. See libcurl-errors(3).

## CURLHE_NOT_BUILT_IN
Introduced in 7.83.0. See libcurl-errors(3).

## CURLHE_OK
Introduced in 7.83.0. See libcurl-errors(3).

## CURLHE_OUT_OF_MEMORY
Introduced in 7.83.0. See libcurl-errors(3).

## CURLHEADER_SEPARATE
Introduced in 7.37.0. See CURLOPT_HEADEROPT(3).

## CURLHEADER_UNIFIED
Introduced in 7.37.0. See CURLOPT_HEADEROPT(3).

## CURLHSTS_ENABLE
Introduced in 7.74.0. See CURLOPT_HSTS_CTRL(3).

## CURLHSTS_READONLYFILE
Introduced in 7.74.0. See CURLOPT_HSTS_CTRL(3).

## CURLINFO_ACTIVESOCKET
Introduced in 7.45.0.

## CURLINFO_APPCONNECT_TIME
Introduced in 7.19.0.

## CURLINFO_APPCONNECT_TIME_T
Introduced in 7.61.0.

## CURLINFO_CAINFO
Introduced in 7.84.0.

## CURLINFO_CAPATH
Introduced in 7.84.0.

## CURLINFO_CERTINFO
Introduced in 7.19.1.

## CURLINFO_CONDITION_UNMET
Introduced in 7.19.4.

## CURLINFO_CONN_ID
Introduced in 8.2.0.

## CURLINFO_CONNECT_TIME
Introduced in 7.4.1.

## CURLINFO_CONNECT_TIME_T
Introduced in 7.61.0.

## CURLINFO_CONTENT_LENGTH_DOWNLOAD
Introduced in 7.6.1. Deprecated since 7.55.0.

## CURLINFO_CONTENT_LENGTH_DOWNLOAD_T
Introduced in 7.55.0.

## CURLINFO_CONTENT_LENGTH_UPLOAD
Introduced in 7.6.1. Deprecated since 7.55.0.

## CURLINFO_CONTENT_LENGTH_UPLOAD_T
Introduced in 7.55.0.

## CURLINFO_CONTENT_TYPE
Introduced in 7.9.4.

## CURLINFO_COOKIELIST
Introduced in 7.14.1.

## CURLINFO_DATA_IN
Introduced in 7.9.6. See CURLOPT_DEBUGFUNCTION(3).

## CURLINFO_DATA_OUT
Introduced in 7.9.6. See CURLOPT_DEBUGFUNCTION(3).

## CURLINFO_DOUBLE
Introduced in 7.4.1.

## CURLINFO_EFFECTIVE_METHOD
Introduced in 7.72.0.

## CURLINFO_EFFECTIVE_URL
Introduced in 7.4.

## CURLINFO_END
Introduced in 7.9.6.

## CURLINFO_FILETIME
Introduced in 7.5.

## CURLINFO_FILETIME_T
Introduced in 7.59.0.

## CURLINFO_FTP_ENTRY_PATH
Introduced in 7.15.4.

## CURLINFO_HEADER_IN
Introduced in 7.9.6. See CURLOPT_DEBUGFUNCTION(3).

## CURLINFO_HEADER_OUT
Introduced in 7.9.6. See CURLOPT_DEBUGFUNCTION(3).

## CURLINFO_HEADER_SIZE
Introduced in 7.4.1.

## CURLINFO_HTTP_CODE
Introduced in 7.4.1. Deprecated since 7.10.8.

## CURLINFO_HTTP_CONNECTCODE
Introduced in 7.10.7.

## CURLINFO_HTTP_VERSION
Introduced in 7.50.0.

## CURLINFO_HTTPAUTH_AVAIL
Introduced in 7.10.8.

## CURLINFO_LASTONE
Introduced in 7.4.1.

## CURLINFO_LASTSOCKET
Introduced in 7.15.2. Deprecated since 7.45.0.

## CURLINFO_LOCAL_IP
Introduced in 7.21.0.

## CURLINFO_LOCAL_PORT
Introduced in 7.21.0.

## CURLINFO_LONG
Introduced in 7.4.1.

## CURLINFO_MASK
Introduced in 7.4.1.

## CURLINFO_NAMELOOKUP_TIME
Introduced in 7.4.1.

## CURLINFO_NAMELOOKUP_TIME_T
Introduced in 7.61.0.

## CURLINFO_NONE
Introduced in 7.4.1.

## CURLINFO_NUM_CONNECTS
Introduced in 7.12.3.

## CURLINFO_OFF_T
Introduced in 7.55.0.

## CURLINFO_OS_ERRNO
Introduced in 7.12.2.

## CURLINFO_PRETRANSFER_TIME
Introduced in 7.4.1.

## CURLINFO_PRETRANSFER_TIME_T
Introduced in 7.61.0.

## CURLINFO_PRIMARY_IP
Introduced in 7.19.0.

## CURLINFO_PRIMARY_PORT
Introduced in 7.21.0.

## CURLINFO_PRIVATE
Introduced in 7.10.3.

## CURLINFO_PROTOCOL
Introduced in 7.52.0. Deprecated since 7.85.0.

## CURLINFO_PROXY_ERROR
Introduced in 7.73.0.

## CURLINFO_PROXY_SSL_VERIFYRESULT
Introduced in 7.52.0.

## CURLINFO_PROXYAUTH_AVAIL
Introduced in 7.10.8.

## CURLINFO_PTR
Introduced in 7.54.1.

## CURLINFO_QUEUE_TIME_T
Introduced in 8.6.0.

## CURLINFO_REDIRECT_COUNT
Introduced in 7.9.7.

## CURLINFO_REDIRECT_TIME
Introduced in 7.9.7.

## CURLINFO_REDIRECT_TIME_T
Introduced in 7.61.0.

## CURLINFO_REDIRECT_URL
Introduced in 7.18.2.

## CURLINFO_REFERER
Introduced in 7.76.0.

## CURLINFO_REQUEST_SIZE
Introduced in 7.4.1.

## CURLINFO_RESPONSE_CODE
Introduced in 7.10.8.

## CURLINFO_RETRY_AFTER
Introduced in 7.66.0.

## CURLINFO_RTSP_CLIENT_CSEQ
Introduced in 7.20.0.

## CURLINFO_RTSP_CSEQ_RECV
Introduced in 7.20.0.

## CURLINFO_RTSP_SERVER_CSEQ
Introduced in 7.20.0.

## CURLINFO_RTSP_SESSION_ID
Introduced in 7.20.0.

## CURLINFO_SCHEME
Introduced in 7.52.0.

## CURLINFO_SIZE_DOWNLOAD
Introduced in 7.4.1. Deprecated since 7.55.0.

## CURLINFO_SIZE_DOWNLOAD_T
Introduced in 7.55.0.

## CURLINFO_SIZE_UPLOAD
Introduced in 7.4.1. Deprecated since 7.55.0.

## CURLINFO_SIZE_UPLOAD_T
Introduced in 7.55.0.

## CURLINFO_SLIST
Introduced in 7.12.3.

## CURLINFO_SOCKET
Introduced in 7.45.0.

## CURLINFO_SPEED_DOWNLOAD
Introduced in 7.4.1. Deprecated since 7.55.0.

## CURLINFO_SPEED_DOWNLOAD_T
Introduced in 7.55.0.

## CURLINFO_SPEED_UPLOAD
Introduced in 7.4.1. Deprecated since 7.55.0.

## CURLINFO_SPEED_UPLOAD_T
Introduced in 7.55.0.

## CURLINFO_SSL_DATA_IN
Introduced in 7.12.1. See CURLOPT_DEBUGFUNCTION(3).

## CURLINFO_SSL_DATA_OUT
Introduced in 7.12.1. See CURLOPT_DEBUGFUNCTION(3).

## CURLINFO_SSL_ENGINES
Introduced in 7.12.3.

## CURLINFO_SSL_VERIFYRESULT
Introduced in 7.5.

## CURLINFO_STARTTRANSFER_TIME
Introduced in 7.9.2.

## CURLINFO_STARTTRANSFER_TIME_T
Introduced in 7.61.0.

## CURLINFO_STRING
Introduced in 7.4.1.

## CURLINFO_TEXT
Introduced in 7.9.6. See CURLOPT_DEBUGFUNCTION(3).

## CURLINFO_TLS_SESSION
Introduced in 7.34.0. Deprecated since 7.48.0.

## CURLINFO_TLS_SSL_PTR
Introduced in 7.48.0.

## CURLINFO_TOTAL_TIME
Introduced in 7.4.1.

## CURLINFO_TOTAL_TIME_T
Introduced in 7.61.0.

## CURLINFO_TYPEMASK
Introduced in 7.4.1.

## CURLINFO_XFER_ID
Introduced in 8.2.0.

## CURLIOCMD_NOP
Introduced in 7.12.3. See CURLOPT_IOCTLFUNCTION(3).

## CURLIOCMD_RESTARTREAD
Introduced in 7.12.3. See CURLOPT_IOCTLFUNCTION(3).

## CURLIOE_FAILRESTART
Introduced in 7.12.3. See CURLOPT_IOCTLFUNCTION(3).

## CURLIOE_OK
Introduced in 7.12.3. See CURLOPT_IOCTLFUNCTION(3).

## CURLIOE_UNKNOWNCMD
Introduced in 7.12.3. See CURLOPT_IOCTLFUNCTION(3).

## CURLKHMATCH_MISMATCH
Introduced in 7.19.6. See CURLOPT_SSH_KEYFUNCTION(3).

## CURLKHMATCH_MISSING
Introduced in 7.19.6. See CURLOPT_SSH_KEYFUNCTION(3).

## CURLKHMATCH_OK
Introduced in 7.19.6. See CURLOPT_SSH_KEYFUNCTION(3).

## CURLKHSTAT_DEFER
Introduced in 7.19.6. See CURLOPT_SSH_KEYFUNCTION(3).

## CURLKHSTAT_FINE
Introduced in 7.19.6. See CURLOPT_SSH_KEYFUNCTION(3).

## CURLKHSTAT_FINE_ADD_TO_FILE
Introduced in 7.19.6. See CURLOPT_SSH_KEYFUNCTION(3).

## CURLKHSTAT_FINE_REPLACE
Introduced in 7.73.0. See CURLOPT_SSH_KEYFUNCTION(3).

## CURLKHSTAT_REJECT
Introduced in 7.19.6. See CURLOPT_SSH_KEYFUNCTION(3).

## CURLKHTYPE_DSS
Introduced in 7.19.6. See CURLOPT_SSH_KEYFUNCTION(3).

## CURLKHTYPE_ECDSA
Introduced in 7.58.0. See CURLOPT_SSH_KEYFUNCTION(3).

## CURLKHTYPE_ED25519
Introduced in 7.58.0. See CURLOPT_SSH_KEYFUNCTION(3).

## CURLKHTYPE_RSA
Introduced in 7.19.6. See CURLOPT_SSH_KEYFUNCTION(3).

## CURLKHTYPE_RSA1
Introduced in 7.19.6. See CURLOPT_SSH_KEYFUNCTION(3).

## CURLKHTYPE_UNKNOWN
Introduced in 7.19.6. See CURLOPT_SSH_KEYFUNCTION(3).

## CURLM_ABORTED_BY_CALLBACK
Introduced in 7.81.0. See libcurl-errors(3).

## CURLM_ADDED_ALREADY
Introduced in 7.32.1. See libcurl-errors(3).

## CURLM_BAD_EASY_HANDLE
Introduced in 7.9.6. See libcurl-errors(3).

## CURLM_BAD_FUNCTION_ARGUMENT
Introduced in 7.69.0. See libcurl-errors(3).

## CURLM_BAD_HANDLE
Introduced in 7.9.6. See libcurl-errors(3).

## CURLM_BAD_SOCKET
Introduced in 7.15.4. See libcurl-errors(3).

## CURLM_CALL_MULTI_PERFORM
Introduced in 7.9.6. See libcurl-errors(3).

## CURLM_CALL_MULTI_SOCKET
Introduced in 7.15.5. See libcurl-errors(3).

## CURLM_INTERNAL_ERROR
Introduced in 7.9.6. See libcurl-errors(3).

## CURLM_OK
Introduced in 7.9.6. See libcurl-errors(3).

## CURLM_OUT_OF_MEMORY
Introduced in 7.9.6. See libcurl-errors(3).

## CURLM_RECURSIVE_API_CALL
Introduced in 7.59.0. See libcurl-errors(3).

## CURLM_UNKNOWN_OPTION
Introduced in 7.15.4. See libcurl-errors(3).

## CURLM_UNRECOVERABLE_POLL
Introduced in 7.84.0. See libcurl-errors(3).

## CURLM_WAKEUP_FAILURE
Introduced in 7.68.0. See libcurl-errors(3).

## CURLMIMEOPT_FORMESCAPE
Introduced in 7.81.0. See CURLOPT_MIME_OPTIONS(3).

## CURLMOPT_CHUNK_LENGTH_PENALTY_SIZE
Introduced in 7.30.0. See CURLMOPT_CHUNK_LENGTH_PENALTY_SIZE(3).

## CURLMOPT_CONTENT_LENGTH_PENALTY_SIZE
Introduced in 7.30.0. See CURLMOPT_CONTENT_LENGTH_PENALTY_SIZE(3).

## CURLMOPT_MAX_CONCURRENT_STREAMS
Introduced in 7.67.0. See CURLMOPT_MAX_CONCURRENT_STREAMS(3).

## CURLMOPT_MAX_HOST_CONNECTIONS
Introduced in 7.30.0. See CURLMOPT_MAX_HOST_CONNECTIONS(3).

## CURLMOPT_MAX_PIPELINE_LENGTH
Introduced in 7.30.0. See CURLMOPT_MAX_PIPELINE_LENGTH(3).

## CURLMOPT_MAX_TOTAL_CONNECTIONS
Introduced in 7.30.0. See CURLMOPT_MAX_TOTAL_CONNECTIONS(3).

## CURLMOPT_MAXCONNECTS
Introduced in 7.16.3. See CURLMOPT_MAXCONNECTS(3).

## CURLMOPT_PIPELINING
Introduced in 7.16.0. See CURLMOPT_PIPELINING(3).

## CURLMOPT_PIPELINING_SERVER_BL
Introduced in 7.30.0. See CURLMOPT_PIPELINING_SERVER_BL(3).

## CURLMOPT_PIPELINING_SITE_BL
Introduced in 7.30.0. See CURLMOPT_PIPELINING_SITE_BL(3).

## CURLMOPT_PUSHDATA
Introduced in 7.44.0. See CURLMOPT_PUSHDATA(3).

## CURLMOPT_PUSHFUNCTION
Introduced in 7.44.0. See CURLMOPT_PUSHFUNCTION(3).

## CURLMOPT_SOCKETDATA
Introduced in 7.15.4. See CURLMOPT_SOCKETDATA(3).

## CURLMOPT_SOCKETFUNCTION
Introduced in 7.15.4. See CURLMOPT_SOCKETFUNCTION(3).

## CURLMOPT_TIMERDATA
Introduced in 7.16.0. See CURLMOPT_TIMERDATA(3).

## CURLMOPT_TIMERFUNCTION
Introduced in 7.16.0. See CURLMOPT_TIMERFUNCTION(3).

## CURLMSG_DONE
Introduced in 7.9.6. See curl_multi_info_read(3).

## CURLMSG_NONE
Introduced in 7.9.6. See curl_multi_info_read(3).

## CURLOPT
Introduced in 7.69.0.

## CURLOPT_ABSTRACT_UNIX_SOCKET
Introduced in 7.53.0. See CURLOPT_ABSTRACT_UNIX_SOCKET(3).

## CURLOPT_ACCEPT_ENCODING
Introduced in 7.21.6. See CURLOPT_ACCEPT_ENCODING(3).

## CURLOPT_ACCEPTTIMEOUT_MS
Introduced in 7.24.0. See CURLOPT_ACCEPTTIMEOUT_MS(3).

## CURLOPT_ADDRESS_SCOPE
Introduced in 7.19.0. See CURLOPT_ADDRESS_SCOPE(3).

## CURLOPT_ALTSVC
Introduced in 7.64.1. See CURLOPT_ALTSVC(3).

## CURLOPT_ALTSVC_CTRL
Introduced in 7.64.1. See CURLOPT_ALTSVC_CTRL(3).

## CURLOPT_APPEND
Introduced in 7.17.0. See CURLOPT_APPEND(3).

## CURLOPT_AUTOREFERER
Introduced in 7.1. See CURLOPT_AUTOREFERER(3).

## CURLOPT_AWS_SIGV4
Introduced in 7.75.0. See CURLOPT_AWS_SIGV4(3).

## CURLOPT_BUFFERSIZE
Introduced in 7.10. See CURLOPT_BUFFERSIZE(3).

## CURLOPT_CAINFO
Introduced in 7.4.2. See CURLOPT_CAINFO(3).

## CURLOPT_CAINFO_BLOB
Introduced in 7.77.0. See CURLOPT_CAINFO_BLOB(3).

## CURLOPT_CAPATH
Introduced in 7.9.8. See CURLOPT_CAPATH(3).

## CURLOPT_CA_CACHE_TIMEOUT
Introduced in 7.87.0. See CURLOPT_CA_CACHE_TIMEOUT(3).

## CURLOPT_CERTINFO
Introduced in 7.19.1. See CURLOPT_CERTINFO(3).

## CURLOPT_CHUNK_BGN_FUNCTION
Introduced in 7.21.0. See CURLOPT_CHUNK_BGN_FUNCTION(3).

## CURLOPT_CHUNK_DATA
Introduced in 7.21.0. See CURLOPT_CHUNK_DATA(3).

## CURLOPT_CHUNK_END_FUNCTION
Introduced in 7.21.0. See CURLOPT_CHUNK_END_FUNCTION(3).

## CURLOPT_CLOSEFUNCTION
Introduced in 7.7. Deprecated since 7.11.1.

## CURLOPT_CLOSEPOLICY
Introduced in 7.7. Deprecated since 7.16.1.

## CURLOPT_CLOSESOCKETDATA
Introduced in 7.21.7. See CURLOPT_CLOSESOCKETDATA(3).

## CURLOPT_CLOSESOCKETFUNCTION
Introduced in 7.21.7. See CURLOPT_CLOSESOCKETFUNCTION(3).

## CURLOPT_CONNECT_ONLY
Introduced in 7.15.2. See CURLOPT_CONNECT_ONLY(3).

## CURLOPT_CONNECT_TO
Introduced in 7.49.0. See CURLOPT_CONNECT_TO(3).

## CURLOPT_CONNECTTIMEOUT
Introduced in 7.7. See CURLOPT_CONNECTTIMEOUT(3).

## CURLOPT_CONNECTTIMEOUT_MS
Introduced in 7.16.2. See CURLOPT_CONNECTTIMEOUT_MS(3).

## CURLOPT_CONV_FROM_NETWORK_FUNCTION
Introduced in 7.15.4. Deprecated since 7.82.0.

## CURLOPT_CONV_FROM_UTF8_FUNCTION
Introduced in 7.15.4. Deprecated since 7.82.0.

## CURLOPT_CONV_TO_NETWORK_FUNCTION
Introduced in 7.15.4. Deprecated since 7.82.0.

## CURLOPT_COOKIE
Introduced in 7.1. See CURLOPT_COOKIE(3).

## CURLOPT_COOKIEFILE
Introduced in 7.1. See CURLOPT_COOKIEFILE(3).

## CURLOPT_COOKIEJAR
Introduced in 7.9. See CURLOPT_COOKIEJAR(3).

## CURLOPT_COOKIELIST
Introduced in 7.14.1. See CURLOPT_COOKIELIST(3).

## CURLOPT_COOKIESESSION
Introduced in 7.9.7. See CURLOPT_COOKIESESSION(3).

## CURLOPT_COPYPOSTFIELDS
Introduced in 7.17.1. See CURLOPT_COPYPOSTFIELDS(3).

## CURLOPT_CRLF
Introduced in 7.1. See CURLOPT_CRLF(3).

## CURLOPT_CRLFILE
Introduced in 7.19.0. See CURLOPT_CRLFILE(3).

## CURLOPT_CURLU
Introduced in 7.63.0. See CURLOPT_CURLU(3).

## CURLOPT_CUSTOMREQUEST
Introduced in 7.1. See CURLOPT_CUSTOMREQUEST(3).

## CURLOPT_DEBUGDATA
Introduced in 7.9.6. See CURLOPT_DEBUGDATA(3).

## CURLOPT_DEBUGFUNCTION
Introduced in 7.9.6. See CURLOPT_DEBUGFUNCTION(3).

## CURLOPT_DEFAULT_PROTOCOL
Introduced in 7.45.0. See CURLOPT_DEFAULT_PROTOCOL(3).

## CURLOPT_DIRLISTONLY
Introduced in 7.17.0. See CURLOPT_DIRLISTONLY(3).

## CURLOPT_DISALLOW_USERNAME_IN_URL
Introduced in 7.61.0. See CURLOPT_DISALLOW_USERNAME_IN_URL(3).

## CURLOPT_DNS_CACHE_TIMEOUT
Introduced in 7.9.3. See CURLOPT_DNS_CACHE_TIMEOUT(3).

## CURLOPT_DNS_INTERFACE
Introduced in 7.33.0. See CURLOPT_DNS_INTERFACE(3).

## CURLOPT_DNS_LOCAL_IP4
Introduced in 7.33.0. See CURLOPT_DNS_LOCAL_IP4(3).

## CURLOPT_DNS_LOCAL_IP6
Introduced in 7.33.0. See CURLOPT_DNS_LOCAL_IP6(3).

## CURLOPT_DNS_SERVERS
Introduced in 7.24.0. See CURLOPT_DNS_SERVERS(3).

## CURLOPT_DNS_SHUFFLE_ADDRESSES
Introduced in 7.60.0. See CURLOPT_DNS_SHUFFLE_ADDRESSES(3).

## CURLOPT_DNS_USE_GLOBAL_CACHE
Introduced in 7.9.3. Deprecated since 7.11.1.

## CURLOPT_DOH_SSL_VERIFYHOST
Introduced in 7.76.0. See CURLOPT_DOH_SSL_VERIFYHOST(3).

## CURLOPT_DOH_SSL_VERIFYPEER
Introduced in 7.76.0. See CURLOPT_DOH_SSL_VERIFYPEER(3).

## CURLOPT_DOH_SSL_VERIFYSTATUS
Introduced in 7.76.0. See CURLOPT_DOH_SSL_VERIFYSTATUS(3).

## CURLOPT_DOH_URL
Introduced in 7.62.0. See CURLOPT_DOH_URL(3).

## CURLOPT_EGDSOCKET
Introduced in 7.7. Deprecated since 7.84.0.

## CURLOPT_ENCODING
Introduced in 7.10. Deprecated since 7.21.6.

## CURLOPT_ERRORBUFFER
Introduced in 7.1. See CURLOPT_ERRORBUFFER(3).

## CURLOPT_EXPECT_100_TIMEOUT_MS
Introduced in 7.36.0. See CURLOPT_EXPECT_100_TIMEOUT_MS(3).

## CURLOPT_FAILONERROR
Introduced in 7.1. See CURLOPT_FAILONERROR(3).

## CURLOPT_FILE
Introduced in 7.1. Deprecated since 7.9.7.

## CURLOPT_FILETIME
Introduced in 7.5. See CURLOPT_FILETIME(3).

## CURLOPT_FNMATCH_DATA
Introduced in 7.21.0. See CURLOPT_FNMATCH_DATA(3).

## CURLOPT_FNMATCH_FUNCTION
Introduced in 7.21.0. See CURLOPT_FNMATCH_FUNCTION(3).

## CURLOPT_FOLLOWLOCATION
Introduced in 7.1. See CURLOPT_FOLLOWLOCATION(3).

## CURLOPT_FORBID_REUSE
Introduced in 7.7. See CURLOPT_FORBID_REUSE(3).

## CURLOPT_FRESH_CONNECT
Introduced in 7.7. See CURLOPT_FRESH_CONNECT(3).

## CURLOPT_FTP_ACCOUNT
Introduced in 7.13.0. See CURLOPT_FTP_ACCOUNT(3).

## CURLOPT_FTP_ALTERNATIVE_TO_USER
Introduced in 7.15.5. See CURLOPT_FTP_ALTERNATIVE_TO_USER(3).

## CURLOPT_FTP_CREATE_MISSING_DIRS
Introduced in 7.10.7. See CURLOPT_FTP_CREATE_MISSING_DIRS(3).

## CURLOPT_FTP_FILEMETHOD
Introduced in 7.15.1. See CURLOPT_FTP_FILEMETHOD(3).

## CURLOPT_FTP_RESPONSE_TIMEOUT
Introduced in 7.10.8. Deprecated since 7.85.0.

## CURLOPT_FTP_SKIP_PASV_IP
Introduced in 7.15.0. See CURLOPT_FTP_SKIP_PASV_IP(3).

## CURLOPT_FTP_SSL
Introduced in 7.11.0. Deprecated since 7.16.4.

## CURLOPT_FTP_SSL_CCC
Introduced in 7.16.1. See CURLOPT_FTP_SSL_CCC(3).

## CURLOPT_FTP_USE_EPRT
Introduced in 7.10.5. See CURLOPT_FTP_USE_EPRT(3).

## CURLOPT_FTP_USE_EPSV
Introduced in 7.9.2. See CURLOPT_FTP_USE_EPSV(3).

## CURLOPT_FTP_USE_PRET
Introduced in 7.20.0. See CURLOPT_FTP_USE_PRET(3).

## CURLOPT_FTPAPPEND
Introduced in 7.1. Deprecated since 7.16.4.

## CURLOPT_FTPASCII
Introduced in 7.1. Deprecated since 7.11.1.

## CURLOPT_FTPLISTONLY
Introduced in 7.1. Deprecated since 7.16.4.

## CURLOPT_FTPPORT
Introduced in 7.1. See CURLOPT_FTPPORT(3).

## CURLOPT_FTPSSLAUTH
Introduced in 7.12.2. See CURLOPT_FTPSSLAUTH(3).

## CURLOPT_GSSAPI_DELEGATION
Introduced in 7.22.0. See CURLOPT_GSSAPI_DELEGATION(3).

## CURLOPT_HAPPY_EYEBALLS_TIMEOUT_MS
Introduced in 7.59.0. See CURLOPT_HAPPY_EYEBALLS_TIMEOUT_MS(3).

## CURLOPT_HAPROXYPROTOCOL
Introduced in 7.60.0. See CURLOPT_HAPROXYPROTOCOL(3).

## CURLOPT_HAPROXY_CLIENT_IP
Introduced in 8.2.0. See CURLOPT_HAPROXY_CLIENT_IP(3).

## CURLOPT_HEADER
Introduced in 7.1. See CURLOPT_HEADER(3).

## CURLOPT_HEADERDATA
Introduced in 7.10. See CURLOPT_HEADERDATA(3).

## CURLOPT_HEADERFUNCTION
Introduced in 7.7.2. See CURLOPT_HEADERFUNCTION(3).

## CURLOPT_HEADEROPT
Introduced in 7.37.0. See CURLOPT_HEADEROPT(3).

## CURLOPT_HSTS
Introduced in 7.74.0. See CURLOPT_HSTS(3).

## CURLOPT_HSTS_CTRL
Introduced in 7.74.0. See CURLOPT_HSTS_CTRL(3).

## CURLOPT_HSTSREADDATA
Introduced in 7.74.0. See CURLOPT_HSTSREADDATA(3).

## CURLOPT_HSTSREADFUNCTION
Introduced in 7.74.0. See CURLOPT_HSTSREADFUNCTION(3).

## CURLOPT_HSTSWRITEDATA
Introduced in 7.74.0. See CURLOPT_HSTSWRITEDATA(3).

## CURLOPT_HSTSWRITEFUNCTION
Introduced in 7.74.0. See CURLOPT_HSTSWRITEFUNCTION(3).

## CURLOPT_HTTP09_ALLOWED
Introduced in 7.64.0. See CURLOPT_HTTP09_ALLOWED(3).

## CURLOPT_HTTP200ALIASES
Introduced in 7.10.3. See CURLOPT_HTTP200ALIASES(3).

## CURLOPT_HTTP_CONTENT_DECODING
Introduced in 7.16.2. See CURLOPT_HTTP_CONTENT_DECODING(3).

## CURLOPT_HTTP_TRANSFER_DECODING
Introduced in 7.16.2. See CURLOPT_HTTP_TRANSFER_DECODING(3).

## CURLOPT_HTTP_VERSION
Introduced in 7.9.1. See CURLOPT_HTTP_VERSION(3).

## CURLOPT_HTTPAUTH
Introduced in 7.10.6. See CURLOPT_HTTPAUTH(3).

## CURLOPT_HTTPGET
Introduced in 7.8.1. See CURLOPT_HTTPGET(3).

## CURLOPT_HTTPHEADER
Introduced in 7.1. See CURLOPT_HTTPHEADER(3).

## CURLOPT_HTTPPOST
Introduced in 7.1. Deprecated since 7.56.0.

## CURLOPT_HTTPPROXYTUNNEL
Introduced in 7.3. See CURLOPT_HTTPPROXYTUNNEL(3).

## CURLOPT_HTTPREQUEST
Introduced in 7.1. Last used in 7.15.5.

## CURLOPT_IGNORE_CONTENT_LENGTH
Introduced in 7.14.1. See CURLOPT_IGNORE_CONTENT_LENGTH(3).

## CURLOPT_INFILE
Introduced in 7.1. Deprecated since 7.9.7.

## CURLOPT_INFILESIZE
Introduced in 7.1. See CURLOPT_INFILESIZE(3).

## CURLOPT_INFILESIZE_LARGE
Introduced in 7.11.0. See CURLOPT_INFILESIZE_LARGE(3).

## CURLOPT_INTERFACE
Introduced in 7.3. See CURLOPT_INTERFACE(3).

## CURLOPT_INTERLEAVEDATA
Introduced in 7.20.0. See CURLOPT_INTERLEAVEDATA(3).

## CURLOPT_INTERLEAVEFUNCTION
Introduced in 7.20.0. See CURLOPT_INTERLEAVEFUNCTION(3).

## CURLOPT_IOCTLDATA
Introduced in 7.12.3. Deprecated since 7.18.0.

## CURLOPT_IOCTLFUNCTION
Introduced in 7.12.3. Deprecated since 7.18.0.

## CURLOPT_IPRESOLVE
Introduced in 7.10.8. See CURLOPT_IPRESOLVE(3).

## CURLOPT_ISSUERCERT
Introduced in 7.19.0. See CURLOPT_ISSUERCERT(3).

## CURLOPT_ISSUERCERT_BLOB
Introduced in 7.71.0. See CURLOPT_ISSUERCERT_BLOB(3).

## CURLOPT_KEEP_SENDING_ON_ERROR
Introduced in 7.51.0. See CURLOPT_KEEP_SENDING_ON_ERROR(3).

## CURLOPT_KEYPASSWD
Introduced in 7.17.0. See CURLOPT_KEYPASSWD(3).

## CURLOPT_KRB4LEVEL
Introduced in 7.3. Deprecated since 7.17.0.

## CURLOPT_KRBLEVEL
Introduced in 7.16.4. See CURLOPT_KRBLEVEL(3).

## CURLOPT_LOCALPORT
Introduced in 7.15.2. See CURLOPT_LOCALPORT(3).

## CURLOPT_LOCALPORTRANGE
Introduced in 7.15.2. See CURLOPT_LOCALPORTRANGE(3).

## CURLOPT_LOGIN_OPTIONS
Introduced in 7.34.0. See CURLOPT_LOGIN_OPTIONS(3).

## CURLOPT_LOW_SPEED_LIMIT
Introduced in 7.1. See CURLOPT_LOW_SPEED_LIMIT(3).

## CURLOPT_LOW_SPEED_TIME
Introduced in 7.1. See CURLOPT_LOW_SPEED_TIME(3).

## CURLOPT_MAIL_AUTH
Introduced in 7.25.0. See CURLOPT_MAIL_AUTH(3).

## CURLOPT_MAIL_FROM
Introduced in 7.20.0. See CURLOPT_MAIL_FROM(3).

## CURLOPT_MAIL_RCPT
Introduced in 7.20.0. See CURLOPT_MAIL_RCPT(3).

## CURLOPT_MAIL_RCPT_ALLLOWFAILS
Introduced in 7.69.0. Deprecated since 8.2.0.

## CURLOPT_MAIL_RCPT_ALLOWFAILS
Introduced in 8.2.0. See CURLOPT_MAIL_RCPT_ALLOWFAILS(3).

## CURLOPT_QUICK_EXIT
Introduced in 7.87.0. See CURLOPT_QUICK_EXIT(3).

## CURLOPT_MAX_RECV_SPEED_LARGE
Introduced in 7.15.5. See CURLOPT_MAX_RECV_SPEED_LARGE(3).

## CURLOPT_MAX_SEND_SPEED_LARGE
Introduced in 7.15.5. See CURLOPT_MAX_SEND_SPEED_LARGE(3).

## CURLOPT_MAXAGE_CONN
Introduced in 7.65.0. See CURLOPT_MAXAGE_CONN(3).

## CURLOPT_MAXCONNECTS
Introduced in 7.7. See CURLOPT_MAXCONNECTS(3).

## CURLOPT_MAXFILESIZE
Introduced in 7.10.8. See CURLOPT_MAXFILESIZE(3).

## CURLOPT_MAXFILESIZE_LARGE
Introduced in 7.11.0. See CURLOPT_MAXFILESIZE_LARGE(3).

## CURLOPT_MAXLIFETIME_CONN
Introduced in 7.80.0. See CURLOPT_MAXLIFETIME_CONN(3).

## CURLOPT_MAXREDIRS
Introduced in 7.5. See CURLOPT_MAXREDIRS(3).

## CURLOPT_MIME_OPTIONS
Introduced in 7.81.0. See CURLOPT_MIME_OPTIONS(3).

## CURLOPT_MIMEPOST
Introduced in 7.56.0. See CURLOPT_MIMEPOST(3).

## CURLOPT_MUTE
Introduced in 7.1. Deprecated since 7.8.

## CURLOPT_NETRC
Introduced in 7.1. See CURLOPT_NETRC(3).

## CURLOPT_NETRC_FILE
Introduced in 7.11.0. See CURLOPT_NETRC_FILE(3).

## CURLOPT_NEW_DIRECTORY_PERMS
Introduced in 7.16.4. See CURLOPT_NEW_DIRECTORY_PERMS(3).

## CURLOPT_NEW_FILE_PERMS
Introduced in 7.16.4. See CURLOPT_NEW_FILE_PERMS(3).

## CURLOPT_NOBODY
Introduced in 7.1. See CURLOPT_NOBODY(3).

## CURLOPT_NOPROGRESS
Introduced in 7.1. See CURLOPT_NOPROGRESS(3).

## CURLOPT_NOPROXY
Introduced in 7.19.4. See CURLOPT_NOPROXY(3).

## CURLOPT_NOSIGNAL
Introduced in 7.10. See CURLOPT_NOSIGNAL(3).

## CURLOPT_NOTHING
Introduced in 7.1.1. Deprecated since 7.11.1.

## CURLOPT_OPENSOCKETDATA
Introduced in 7.17.1. See CURLOPT_OPENSOCKETDATA(3).

## CURLOPT_OPENSOCKETFUNCTION
Introduced in 7.17.1. See CURLOPT_OPENSOCKETFUNCTION(3).

## CURLOPT_PASSWDDATA
Introduced in 7.4.2. Deprecated since 7.11.1.

## CURLOPT_PASSWDFUNCTION
Introduced in 7.4.2. Deprecated since 7.11.1.

## CURLOPT_PASSWORD
Introduced in 7.19.1. See CURLOPT_PASSWORD(3).

## CURLOPT_PASV_HOST
Introduced in 7.12.1. Deprecated since 7.16.0.

## CURLOPT_PATH_AS_IS
Introduced in 7.42.0. See CURLOPT_PATH_AS_IS(3).

## CURLOPT_PINNEDPUBLICKEY
Introduced in 7.39.0. See CURLOPT_PINNEDPUBLICKEY(3).

## CURLOPT_PIPEWAIT
Introduced in 7.43.0. See CURLOPT_PIPEWAIT(3).

## CURLOPT_PORT
Introduced in 7.1. See CURLOPT_PORT(3).

## CURLOPT_POST
Introduced in 7.1. See CURLOPT_POST(3).

## CURLOPT_POST301
Introduced in 7.17.1. Deprecated since 7.19.1.

## CURLOPT_POSTFIELDS
Introduced in 7.1. See CURLOPT_POSTFIELDS(3).

## CURLOPT_POSTFIELDSIZE
Introduced in 7.2. See CURLOPT_POSTFIELDSIZE(3).

## CURLOPT_POSTFIELDSIZE_LARGE
Introduced in 7.11.1. See CURLOPT_POSTFIELDSIZE_LARGE(3).

## CURLOPT_POSTQUOTE
Introduced in 7.1. See CURLOPT_POSTQUOTE(3).

## CURLOPT_POSTREDIR
Introduced in 7.19.1. See CURLOPT_POSTREDIR(3).

## CURLOPT_PRE_PROXY
Introduced in 7.52.0. See CURLOPT_PRE_PROXY(3).

## CURLOPT_PREQUOTE
Introduced in 7.9.5. See CURLOPT_PREQUOTE(3).

## CURLOPT_PREREQDATA
Introduced in 7.80.0. See CURLOPT_PREREQDATA(3).

## CURLOPT_PREREQFUNCTION
Introduced in 7.80.0. See CURLOPT_PREREQFUNCTION(3).

## CURLOPT_PRIVATE
Introduced in 7.10.3. See CURLOPT_PRIVATE(3).

## CURLOPT_PROGRESSDATA
Introduced in 7.1. See CURLOPT_PROGRESSDATA(3).

## CURLOPT_PROGRESSFUNCTION
Introduced in 7.1. Deprecated since 7.32.0.

## CURLOPT_PROTOCOLS
Introduced in 7.19.4. Deprecated since 7.85.0.

## CURLOPT_PROTOCOLS_STR
Introduced in 7.85.0. See CURLOPT_PROTOCOLS_STR(3).

## CURLOPT_PROXY
Introduced in 7.1. See CURLOPT_PROXY(3).

## CURLOPT_PROXY_CAINFO
Introduced in 7.52.0. See CURLOPT_PROXY_CAINFO(3).

## CURLOPT_PROXY_CAINFO_BLOB
Introduced in 7.77.0. See CURLOPT_PROXY_CAINFO_BLOB(3).

## CURLOPT_PROXY_CAPATH
Introduced in 7.52.0. See CURLOPT_PROXY_CAPATH(3).

## CURLOPT_PROXY_CRLFILE
Introduced in 7.52.0. See CURLOPT_PROXY_CRLFILE(3).

## CURLOPT_PROXY_ISSUERCERT
Introduced in 7.71.0. See CURLOPT_PROXY_ISSUERCERT(3).

## CURLOPT_PROXY_ISSUERCERT_BLOB
Introduced in 7.71.0. See CURLOPT_PROXY_ISSUERCERT_BLOB(3).

## CURLOPT_PROXY_KEYPASSWD
Introduced in 7.52.0. See CURLOPT_PROXY_KEYPASSWD(3).

## CURLOPT_PROXY_PINNEDPUBLICKEY
Introduced in 7.52.0. See CURLOPT_PROXY_PINNEDPUBLICKEY(3).

## CURLOPT_PROXY_SERVICE_NAME
Introduced in 7.43.0. See CURLOPT_PROXY_SERVICE_NAME(3).

## CURLOPT_PROXY_SSL_CIPHER_LIST
Introduced in 7.52.0. See CURLOPT_PROXY_SSL_CIPHER_LIST(3).

## CURLOPT_PROXY_SSL_OPTIONS
Introduced in 7.52.0. See CURLOPT_PROXY_SSL_OPTIONS(3).

## CURLOPT_PROXY_SSL_VERIFYHOST
Introduced in 7.52.0. See CURLOPT_PROXY_SSL_VERIFYHOST(3).

## CURLOPT_PROXY_SSL_VERIFYPEER
Introduced in 7.52.0. See CURLOPT_PROXY_SSL_VERIFYPEER(3).

## CURLOPT_PROXY_SSLCERT
Introduced in 7.52.0. See CURLOPT_PROXY_SSLCERT(3).

## CURLOPT_PROXY_SSLCERT_BLOB
Introduced in 7.71.0. See CURLOPT_PROXY_SSLCERT_BLOB(3).

## CURLOPT_PROXY_SSLCERTTYPE
Introduced in 7.52.0. See CURLOPT_PROXY_SSLCERTTYPE(3).

## CURLOPT_PROXY_SSLKEY
Introduced in 7.52.0. See CURLOPT_PROXY_SSLKEY(3).

## CURLOPT_PROXY_SSLKEY_BLOB
Introduced in 7.71.0. See CURLOPT_PROXY_SSLKEY_BLOB(3).

## CURLOPT_PROXY_SSLKEYTYPE
Introduced in 7.52.0. See CURLOPT_PROXY_SSLKEYTYPE(3).

## CURLOPT_PROXY_SSLVERSION
Introduced in 7.52.0. See CURLOPT_PROXY_SSLVERSION(3).

## CURLOPT_PROXY_TLS13_CIPHERS
Introduced in 7.61.0. See CURLOPT_PROXY_TLS13_CIPHERS(3).

## CURLOPT_PROXY_TLSAUTH_PASSWORD
Introduced in 7.52.0. See CURLOPT_PROXY_TLSAUTH_PASSWORD(3).

## CURLOPT_PROXY_TLSAUTH_TYPE
Introduced in 7.52.0. See CURLOPT_PROXY_TLSAUTH_TYPE(3).

## CURLOPT_PROXY_TLSAUTH_USERNAME
Introduced in 7.52.0. See CURLOPT_PROXY_TLSAUTH_USERNAME(3).

## CURLOPT_PROXY_TRANSFER_MODE
Introduced in 7.18.0. See CURLOPT_PROXY_TRANSFER_MODE(3).

## CURLOPT_PROXYAUTH
Introduced in 7.10.7. See CURLOPT_PROXYAUTH(3).

## CURLOPT_PROXYHEADER
Introduced in 7.37.0. See CURLOPT_PROXYHEADER(3).

## CURLOPT_PROXYPASSWORD
Introduced in 7.19.1. See CURLOPT_PROXYPASSWORD(3).

## CURLOPT_PROXYPORT
Introduced in 7.1. See CURLOPT_PROXYPORT(3).

## CURLOPT_PROXYTYPE
Introduced in 7.10. See CURLOPT_PROXYTYPE(3).

## CURLOPT_PROXYUSERNAME
Introduced in 7.19.1. See CURLOPT_PROXYUSERNAME(3).

## CURLOPT_PROXYUSERPWD
Introduced in 7.1. See CURLOPT_PROXYUSERPWD(3).

## CURLOPT_PUT
Introduced in 7.1. Deprecated since 7.12.1.

## CURLOPT_QUOTE
Introduced in 7.1. See CURLOPT_QUOTE(3).

## CURLOPT_RANDOM_FILE
Introduced in 7.7. Deprecated since 7.84.0.

## CURLOPT_RANGE
Introduced in 7.1. See CURLOPT_RANGE(3).

## CURLOPT_READDATA
Introduced in 7.9.7. See CURLOPT_READDATA(3).

## CURLOPT_READFUNCTION
Introduced in 7.1. See CURLOPT_READFUNCTION(3).

## CURLOPT_REDIR_PROTOCOLS
Introduced in 7.19.4. Deprecated since 7.85.0.

## CURLOPT_REDIR_PROTOCOLS_STR
Introduced in 7.85.0. See CURLOPT_REDIR_PROTOCOLS_STR(3).

## CURLOPT_REFERER
Introduced in 7.1. See CURLOPT_REFERER(3).

## CURLOPT_REQUEST_TARGET
Introduced in 7.55.0. See CURLOPT_REQUEST_TARGET(3).

## CURLOPT_RESOLVE
Introduced in 7.21.3. See CURLOPT_RESOLVE(3).

## CURLOPT_RESOLVER_START_DATA
Introduced in 7.59.0. See CURLOPT_RESOLVER_START_DATA(3).

## CURLOPT_RESOLVER_START_FUNCTION
Introduced in 7.59.0. See CURLOPT_RESOLVER_START_FUNCTION(3).

## CURLOPT_RESUME_FROM
Introduced in 7.1. See CURLOPT_RESUME_FROM(3).

## CURLOPT_RESUME_FROM_LARGE
Introduced in 7.11.0. See CURLOPT_RESUME_FROM_LARGE(3).

## CURLOPT_RTSP_CLIENT_CSEQ
Introduced in 7.20.0. See CURLOPT_RTSP_CLIENT_CSEQ(3).

## CURLOPT_RTSP_REQUEST
Introduced in 7.20.0. See CURLOPT_RTSP_REQUEST(3).

## CURLOPT_RTSP_SERVER_CSEQ
Introduced in 7.20.0. See CURLOPT_RTSP_SERVER_CSEQ(3).

## CURLOPT_RTSP_SESSION_ID
Introduced in 7.20.0. See CURLOPT_RTSP_SESSION_ID(3).

## CURLOPT_RTSP_STREAM_URI
Introduced in 7.20.0. See CURLOPT_RTSP_STREAM_URI(3).

## CURLOPT_RTSP_TRANSPORT
Introduced in 7.20.0. See CURLOPT_RTSP_TRANSPORT(3).

## CURLOPT_RTSPHEADER
Introduced in 7.20.0. See CURLOPT_HTTPHEADER.

## CURLOPT_SASL_AUTHZID
Introduced in 7.66.0. See CURLOPT_SASL_AUTHZID(3).

## CURLOPT_SASL_IR
Introduced in 7.31.0. See CURLOPT_SASL_IR(3).

## CURLOPT_SEEKDATA
Introduced in 7.18.0. See CURLOPT_SEEKDATA(3).

## CURLOPT_SEEKFUNCTION
Introduced in 7.18.0. See CURLOPT_SEEKFUNCTION(3).

## CURLOPT_SERVER_RESPONSE_TIMEOUT
Introduced in 7.20.0. See CURLOPT_SERVER_RESPONSE_TIMEOUT(3).

## CURLOPT_SERVER_RESPONSE_TIMEOUT_MS
Introduced in 8.6.0. See CURLOPT_SERVER_RESPONSE_TIMEOUT_MS(3).

## CURLOPT_SERVICE_NAME
Introduced in 7.43.0. See CURLOPT_SERVICE_NAME(3).

## CURLOPT_SHARE
Introduced in 7.10. See CURLOPT_SHARE(3).

## CURLOPT_SOCKOPTDATA
Introduced in 7.16.0. See CURLOPT_SOCKOPTDATA(3).

## CURLOPT_SOCKOPTFUNCTION
Introduced in 7.16.0. See CURLOPT_SOCKOPTFUNCTION(3).

## CURLOPT_SOCKS5_AUTH
Introduced in 7.55.0. See CURLOPT_SOCKS5_AUTH(3).

## CURLOPT_SOCKS5_GSSAPI_NEC
Introduced in 7.19.4. See CURLOPT_SOCKS5_GSSAPI_NEC(3).

## CURLOPT_SOCKS5_GSSAPI_SERVICE
Introduced in 7.19.4. Deprecated since 7.49.0.

## CURLOPT_SOURCE_HOST
Introduced in 7.12.1. Last used in 7.15.5.

## CURLOPT_SOURCE_PATH
Introduced in 7.12.1. Last used in 7.15.5.

## CURLOPT_SOURCE_PORT
Introduced in 7.12.1. Last used in 7.15.5.

## CURLOPT_SOURCE_POSTQUOTE
Introduced in 7.12.1. Last used in 7.15.5.

## CURLOPT_SOURCE_PREQUOTE
Introduced in 7.12.1. Last used in 7.15.5.

## CURLOPT_SOURCE_QUOTE
Introduced in 7.13.0. Last used in 7.15.5.

## CURLOPT_SOURCE_URL
Introduced in 7.13.0. Last used in 7.15.5.

## CURLOPT_SOURCE_USERPWD
Introduced in 7.12.1. Last used in 7.15.5.

## CURLOPT_SSH_AUTH_TYPES
Introduced in 7.16.1. See CURLOPT_SSH_AUTH_TYPES(3).

## CURLOPT_SSH_COMPRESSION
Introduced in 7.56.0. See CURLOPT_SSH_COMPRESSION(3).

## CURLOPT_SSH_HOST_PUBLIC_KEY_MD5
Introduced in 7.17.1. See CURLOPT_SSH_HOST_PUBLIC_KEY_MD5(3).

## CURLOPT_SSH_HOST_PUBLIC_KEY_SHA256
Introduced in 7.80.0. See CURLOPT_SSH_HOST_PUBLIC_KEY_SHA256(3).

## CURLOPT_SSH_HOSTKEYDATA
Introduced in 7.84.0. See CURLOPT_SSH_HOSTKEYDATA(3).

## CURLOPT_SSH_HOSTKEYFUNCTION
Introduced in 7.84.0. See CURLOPT_SSH_HOSTKEYFUNCTION(3).

## CURLOPT_SSH_KEYDATA
Introduced in 7.19.6. See CURLOPT_SSH_KEYDATA(3).

## CURLOPT_SSH_KEYFUNCTION
Introduced in 7.19.6. See CURLOPT_SSH_KEYFUNCTION(3).

## CURLOPT_SSH_KNOWNHOSTS
Introduced in 7.19.6. See CURLOPT_SSH_KNOWNHOSTS(3).

## CURLOPT_SSH_PRIVATE_KEYFILE
Introduced in 7.16.1. See CURLOPT_SSH_PRIVATE_KEYFILE(3).

## CURLOPT_SSH_PUBLIC_KEYFILE
Introduced in 7.16.1. See CURLOPT_SSH_PUBLIC_KEYFILE(3).

## CURLOPT_SSL_CIPHER_LIST
Introduced in 7.9. See CURLOPT_SSL_CIPHER_LIST(3).

## CURLOPT_SSL_CTX_DATA
Introduced in 7.10.6. See CURLOPT_SSL_CTX_DATA(3).

## CURLOPT_SSL_CTX_FUNCTION
Introduced in 7.10.6. See CURLOPT_SSL_CTX_FUNCTION(3).

## CURLOPT_SSL_EC_CURVES
Introduced in 7.73.0. See CURLOPT_SSL_EC_CURVES(3).

## CURLOPT_SSL_ENABLE_ALPN
Introduced in 7.36.0. See CURLOPT_SSL_ENABLE_ALPN(3).

## CURLOPT_SSL_ENABLE_NPN
Introduced in 7.36.0. Deprecated since 7.86.0.

## CURLOPT_SSL_FALSESTART
Introduced in 7.42.0. See CURLOPT_SSL_FALSESTART(3).

## CURLOPT_SSL_OPTIONS
Introduced in 7.25.0. See CURLOPT_SSL_OPTIONS(3).

## CURLOPT_SSL_SESSIONID_CACHE
Introduced in 7.16.0. See CURLOPT_SSL_SESSIONID_CACHE(3).

## CURLOPT_SSL_VERIFYHOST
Introduced in 7.8.1. See CURLOPT_SSL_VERIFYHOST(3).

## CURLOPT_SSL_VERIFYPEER
Introduced in 7.4.2. See CURLOPT_SSL_VERIFYPEER(3).

## CURLOPT_SSL_VERIFYSTATUS
Introduced in 7.41.0. See CURLOPT_SSL_VERIFYSTATUS(3).

## CURLOPT_SSLCERT
Introduced in 7.1. See CURLOPT_SSLCERT(3).

## CURLOPT_SSLCERT_BLOB
Introduced in 7.71.0. See CURLOPT_SSLCERT_BLOB(3).

## CURLOPT_SSLCERTPASSWD
Introduced in 7.1.1. Deprecated since 7.17.0.

## CURLOPT_SSLCERTTYPE
Introduced in 7.9.3. See CURLOPT_SSLCERTTYPE(3).

## CURLOPT_SSLENGINE
Introduced in 7.9.3. See CURLOPT_SSLENGINE(3).

## CURLOPT_SSLENGINE_DEFAULT
Introduced in 7.9.3. See CURLOPT_SSLENGINE_DEFAULT(3).

## CURLOPT_SSLKEY
Introduced in 7.9.3. See CURLOPT_SSLKEY(3).

## CURLOPT_SSLKEY_BLOB
Introduced in 7.71.0. See CURLOPT_SSLKEY_BLOB(3).

## CURLOPT_SSLKEYPASSWD
Introduced in 7.9.3. Deprecated since 7.17.0.

## CURLOPT_SSLKEYTYPE
Introduced in 7.9.3. See CURLOPT_SSLKEYTYPE(3).

## CURLOPT_SSLVERSION
Introduced in 7.1. See CURLOPT_SSLVERSION(3).

## CURLOPT_STDERR
Introduced in 7.1. See CURLOPT_STDERR(3).

## CURLOPT_STREAM_DEPENDS
Introduced in 7.46.0. See CURLOPT_STREAM_DEPENDS(3).

## CURLOPT_STREAM_DEPENDS_E
Introduced in 7.46.0. See CURLOPT_STREAM_DEPENDS_E(3).

## CURLOPT_STREAM_WEIGHT
Introduced in 7.46.0. See CURLOPT_STREAM_WEIGHT(3).

## CURLOPT_SUPPRESS_CONNECT_HEADERS
Introduced in 7.54.0. See CURLOPT_SUPPRESS_CONNECT_HEADERS(3).

## CURLOPT_TCP_FASTOPEN
Introduced in 7.49.0. See CURLOPT_TCP_FASTOPEN(3).

## CURLOPT_TCP_KEEPALIVE
Introduced in 7.25.0. See CURLOPT_TCP_KEEPALIVE(3).

## CURLOPT_TCP_KEEPIDLE
Introduced in 7.25.0. See CURLOPT_TCP_KEEPIDLE(3).

## CURLOPT_TCP_KEEPINTVL
Introduced in 7.25.0. See CURLOPT_TCP_KEEPINTVL(3).

## CURLOPT_TCP_NODELAY
Introduced in 7.11.2. See CURLOPT_TCP_NODELAY(3).

## CURLOPT_TELNETOPTIONS
Introduced in 7.7. See CURLOPT_TELNETOPTIONS(3).

## CURLOPT_TFTP_BLKSIZE
Introduced in 7.19.4. See CURLOPT_TFTP_BLKSIZE(3).

## CURLOPT_TFTP_NO_OPTIONS
Introduced in 7.48.0. See CURLOPT_TFTP_NO_OPTIONS(3).

## CURLOPT_TIMECONDITION
Introduced in 7.1. See CURLOPT_TIMECONDITION(3).

## CURLOPT_TIMEOUT
Introduced in 7.1. See CURLOPT_TIMEOUT(3).

## CURLOPT_TIMEOUT_MS
Introduced in 7.16.2. See CURLOPT_TIMEOUT_MS(3).

## CURLOPT_TIMEVALUE
Introduced in 7.1. See CURLOPT_TIMEVALUE(3).

## CURLOPT_TIMEVALUE_LARGE
Introduced in 7.59.0. See CURLOPT_TIMEVALUE_LARGE(3).

## CURLOPT_TLS13_CIPHERS
Introduced in 7.61.0. See CURLOPT_TLS13_CIPHERS(3).

## CURLOPT_TLSAUTH_PASSWORD
Introduced in 7.21.4. See CURLOPT_TLSAUTH_PASSWORD(3).

## CURLOPT_TLSAUTH_TYPE
Introduced in 7.21.4. See CURLOPT_TLSAUTH_TYPE(3).

## CURLOPT_TLSAUTH_USERNAME
Introduced in 7.21.4. See CURLOPT_TLSAUTH_USERNAME(3).

## CURLOPT_TRAILERDATA
Introduced in 7.64.0. See CURLOPT_TRAILERDATA(3).

## CURLOPT_TRAILERFUNCTION
Introduced in 7.64.0. See CURLOPT_TRAILERFUNCTION(3).

## CURLOPT_TRANSFER_ENCODING
Introduced in 7.21.6. See CURLOPT_TRANSFER_ENCODING(3).

## CURLOPT_TRANSFERTEXT
Introduced in 7.1.1. See CURLOPT_TRANSFERTEXT(3).

## CURLOPT_UNIX_SOCKET_PATH
Introduced in 7.40.0. See CURLOPT_UNIX_SOCKET_PATH(3).

## CURLOPT_UNRESTRICTED_AUTH
Introduced in 7.10.4. See CURLOPT_UNRESTRICTED_AUTH(3).

## CURLOPT_UPKEEP_INTERVAL_MS
Introduced in 7.62.0. See CURLOPT_UPKEEP_INTERVAL_MS(3).

## CURLOPT_UPLOAD
Introduced in 7.1. See CURLOPT_UPLOAD(3).

## CURLOPT_UPLOAD_BUFFERSIZE
Introduced in 7.62.0. See CURLOPT_UPLOAD_BUFFERSIZE(3).

## CURLOPT_URL
Introduced in 7.1. See CURLOPT_URL(3).

## CURLOPT_USE_SSL
Introduced in 7.17.0. See CURLOPT_USE_SSL(3).

## CURLOPT_USERAGENT
Introduced in 7.1. See CURLOPT_USERAGENT(3).

## CURLOPT_USERNAME
Introduced in 7.19.1. See CURLOPT_USERNAME(3).

## CURLOPT_USERPWD
Introduced in 7.1. See CURLOPT_USERPWD(3).

## CURLOPT_VERBOSE
Introduced in 7.1. See CURLOPT_VERBOSE(3).

## CURLOPT_WILDCARDMATCH
Introduced in 7.21.0. See CURLOPT_WILDCARDMATCH(3).

## CURLOPT_WRITEDATA
Introduced in 7.9.7. See CURLOPT_WRITEDATA(3).

## CURLOPT_WRITEFUNCTION
Introduced in 7.1. See CURLOPT_WRITEFUNCTION(3).

## CURLOPT_WRITEHEADER
Introduced in 7.1. See CURLOPT_HEADERDATA.

## CURLOPT_WRITEINFO
Introduced in 7.1.

## CURLOPT_WS_OPTIONS
Introduced in 7.86.0. See CURLOPT_WS_OPTIONS(3).

## CURLOPT_XFERINFODATA
Introduced in 7.32.0. See CURLOPT_XFERINFODATA(3).

## CURLOPT_XFERINFOFUNCTION
Introduced in 7.32.0. See CURLOPT_XFERINFOFUNCTION(3).

## CURLOPT_XOAUTH2_BEARER
Introduced in 7.33.0. See CURLOPT_XOAUTH2_BEARER(3).

## CURLOPTDEPRECATED
Introduced in 7.87.0.

## CURLOPTTYPE_BLOB
Introduced in 7.71.0.

## CURLOPTTYPE_CBPOINT
Introduced in 7.73.0.

## CURLOPTTYPE_FUNCTIONPOINT
Introduced in 7.1.

## CURLOPTTYPE_LONG
Introduced in 7.1.

## CURLOPTTYPE_OBJECTPOINT
Introduced in 7.1.

## CURLOPTTYPE_OFF_T
Introduced in 7.11.0.

## CURLOPTTYPE_SLISTPOINT
Introduced in 7.65.2.

## CURLOPTTYPE_STRINGPOINT
Introduced in 7.46.0.

## CURLOPTTYPE_VALUES
Introduced in 7.73.0.

## CURLOT_BLOB
Introduced in 7.73.0. See curl_easy_option_next(3).

## CURLOT_CBPTR
Introduced in 7.73.0. See curl_easy_option_next(3).

## CURLOT_FLAG_ALIAS
Introduced in 7.73.0. See curl_easy_option_next(3).

## CURLOT_FUNCTION
Introduced in 7.73.0. See curl_easy_option_next(3).

## CURLOT_LONG
Introduced in 7.73.0. See curl_easy_option_next(3).

## CURLOT_OBJECT
Introduced in 7.73.0. See curl_easy_option_next(3).

## CURLOT_OFF_T
Introduced in 7.73.0. See curl_easy_option_next(3).

## CURLOT_SLIST
Introduced in 7.73.0. See curl_easy_option_next(3).

## CURLOT_STRING
Introduced in 7.73.0. See curl_easy_option_next(3).

## CURLOT_VALUES
Introduced in 7.73.0. See curl_easy_option_next(3).

## CURLPAUSE_ALL
Introduced in 7.18.0. See curl_easy_pause(3).

## CURLPAUSE_CONT
Introduced in 7.18.0. See curl_easy_pause(3).

## CURLPAUSE_RECV
Introduced in 7.18.0. See curl_easy_pause(3).

## CURLPAUSE_RECV_CONT
Introduced in 7.18.0. See curl_easy_pause(3).

## CURLPAUSE_SEND
Introduced in 7.18.0. See curl_easy_pause(3).

## CURLPAUSE_SEND_CONT
Introduced in 7.18.0. See curl_easy_pause(3).

## CURLPIPE_HTTP1
Introduced in 7.43.0. See CURLMOPT_PIPELINING(3).

## CURLPIPE_MULTIPLEX
Introduced in 7.43.0. See CURLMOPT_PIPELINING(3).

## CURLPIPE_NOTHING
Introduced in 7.43.0. See CURLMOPT_PIPELINING(3).

## CURLPROTO_ALL
Introduced in 7.19.4. See CURLINFO_PROTOCOL(3).

## CURLPROTO_DICT
Introduced in 7.19.4. See CURLINFO_PROTOCOL(3).

## CURLPROTO_FILE
Introduced in 7.19.4. See CURLINFO_PROTOCOL(3).

## CURLPROTO_FTP
Introduced in 7.19.4. See CURLINFO_PROTOCOL(3).

## CURLPROTO_FTPS
Introduced in 7.19.4. See CURLINFO_PROTOCOL(3).

## CURLPROTO_GOPHER
Introduced in 7.21.2. See CURLINFO_PROTOCOL(3).

## CURLPROTO_GOPHERS
Introduced in 7.75.0. See CURLINFO_PROTOCOL(3).

## CURLPROTO_HTTP
Introduced in 7.19.4. See CURLINFO_PROTOCOL(3).

## CURLPROTO_HTTPS
Introduced in 7.19.4. See CURLINFO_PROTOCOL(3).

## CURLPROTO_IMAP
Introduced in 7.20.0. See CURLINFO_PROTOCOL(3).

## CURLPROTO_IMAPS
Introduced in 7.20.0. See CURLINFO_PROTOCOL(3).

## CURLPROTO_LDAP
Introduced in 7.19.4. See CURLINFO_PROTOCOL(3).

## CURLPROTO_LDAPS
Introduced in 7.19.4. See CURLINFO_PROTOCOL(3).

## CURLPROTO_MQTT
Introduced in 7.71.0. See CURLINFO_PROTOCOL(3).

## CURLPROTO_POP3
Introduced in 7.20.0. See CURLINFO_PROTOCOL(3).

## CURLPROTO_POP3S
Introduced in 7.20.0. See CURLINFO_PROTOCOL(3).

## CURLPROTO_RTMP
Introduced in 7.21.0. See CURLINFO_PROTOCOL(3).

## CURLPROTO_RTMPE
Introduced in 7.21.0. See CURLINFO_PROTOCOL(3).

## CURLPROTO_RTMPS
Introduced in 7.21.0. See CURLINFO_PROTOCOL(3).

## CURLPROTO_RTMPT
Introduced in 7.21.0. See CURLINFO_PROTOCOL(3).

## CURLPROTO_RTMPTE
Introduced in 7.21.0. See CURLINFO_PROTOCOL(3).

## CURLPROTO_RTMPTS
Introduced in 7.21.0. See CURLINFO_PROTOCOL(3).

## CURLPROTO_RTSP
Introduced in 7.20.0. See CURLINFO_PROTOCOL(3).

## CURLPROTO_SCP
Introduced in 7.19.4. See CURLINFO_PROTOCOL(3).

## CURLPROTO_SFTP
Introduced in 7.19.4. See CURLINFO_PROTOCOL(3).

## CURLPROTO_SMB
Introduced in 7.40.0. See CURLINFO_PROTOCOL(3).

## CURLPROTO_SMBS
Introduced in 7.40.0. See CURLINFO_PROTOCOL(3).

## CURLPROTO_SMTP
Introduced in 7.20.0. See CURLINFO_PROTOCOL(3).

## CURLPROTO_SMTPS
Introduced in 7.20.0. See CURLINFO_PROTOCOL(3).

## CURLPROTO_TELNET
Introduced in 7.19.4. See CURLINFO_PROTOCOL(3).

## CURLPROTO_TFTP
Introduced in 7.19.4. See CURLINFO_PROTOCOL(3).

## CURLPROXY_HTTP
Introduced in 7.10. See CURLOPT_PROXYTYPE(3).

## CURLPROXY_HTTP_1_0
Introduced in 7.19.4. See CURLOPT_PROXYTYPE(3).

## CURLPROXY_HTTPS
Introduced in 7.52.0. See CURLOPT_PROXYTYPE(3).

## CURLPROXY_HTTPS2
Introduced in 8.1.0. See CURLOPT_PROXYTYPE(3).

## CURLPROXY_SOCKS4
Introduced in 7.10. See CURLOPT_PROXYTYPE(3).

## CURLPROXY_SOCKS4A
Introduced in 7.18.0. See CURLOPT_PROXYTYPE(3).

## CURLPROXY_SOCKS5
Introduced in 7.10. See CURLOPT_PROXYTYPE(3).

## CURLPROXY_SOCKS5_HOSTNAME
Introduced in 7.18.0. See CURLOPT_PROXYTYPE(3).

## CURLPX_BAD_ADDRESS_TYPE
Introduced in 7.73.0. See CURLINFO_PROXY_ERROR(3).

## CURLPX_BAD_VERSION
Introduced in 7.73.0. See CURLINFO_PROXY_ERROR(3).

## CURLPX_CLOSED
Introduced in 7.73.0. See CURLINFO_PROXY_ERROR(3).

## CURLPX_GSSAPI
Introduced in 7.73.0. See CURLINFO_PROXY_ERROR(3).

## CURLPX_GSSAPI_PERMSG
Introduced in 7.73.0. See CURLINFO_PROXY_ERROR(3).

## CURLPX_GSSAPI_PROTECTION
Introduced in 7.73.0. See CURLINFO_PROXY_ERROR(3).

## CURLPX_IDENTD
Introduced in 7.73.0. See CURLINFO_PROXY_ERROR(3).

## CURLPX_IDENTD_DIFFER
Introduced in 7.73.0. See CURLINFO_PROXY_ERROR(3).

## CURLPX_LONG_HOSTNAME
Introduced in 7.73.0. See CURLINFO_PROXY_ERROR(3).

## CURLPX_LONG_PASSWD
Introduced in 7.73.0. See CURLINFO_PROXY_ERROR(3).

## CURLPX_LONG_USER
Introduced in 7.73.0. See CURLINFO_PROXY_ERROR(3).

## CURLPX_NO_AUTH
Introduced in 7.73.0. See CURLINFO_PROXY_ERROR(3).

## CURLPX_OK
Introduced in 7.73.0. See CURLINFO_PROXY_ERROR(3).

## CURLPX_RECV_ADDRESS
Introduced in 7.73.0. See CURLINFO_PROXY_ERROR(3).

## CURLPX_RECV_AUTH
Introduced in 7.73.0. See CURLINFO_PROXY_ERROR(3).

## CURLPX_RECV_CONNECT
Introduced in 7.73.0. See CURLINFO_PROXY_ERROR(3).

## CURLPX_RECV_REQACK
Introduced in 7.73.0. See CURLINFO_PROXY_ERROR(3).

## CURLPX_REPLY_ADDRESS_TYPE_NOT_SUPPORTED
Introduced in 7.73.0. See CURLINFO_PROXY_ERROR(3).

## CURLPX_REPLY_COMMAND_NOT_SUPPORTED
Introduced in 7.73.0. See CURLINFO_PROXY_ERROR(3).

## CURLPX_REPLY_CONNECTION_REFUSED
Introduced in 7.73.0. See CURLINFO_PROXY_ERROR(3).

## CURLPX_REPLY_GENERAL_SERVER_FAILURE
Introduced in 7.73.0. See CURLINFO_PROXY_ERROR(3).

## CURLPX_REPLY_HOST_UNREACHABLE
Introduced in 7.73.0. See CURLINFO_PROXY_ERROR(3).

## CURLPX_REPLY_NETWORK_UNREACHABLE
Introduced in 7.73.0. See CURLINFO_PROXY_ERROR(3).

## CURLPX_REPLY_NOT_ALLOWED
Introduced in 7.73.0. See CURLINFO_PROXY_ERROR(3).

## CURLPX_REPLY_TTL_EXPIRED
Introduced in 7.73.0. See CURLINFO_PROXY_ERROR(3).

## CURLPX_REPLY_UNASSIGNED
Introduced in 7.73.0. See CURLINFO_PROXY_ERROR(3).

## CURLPX_REQUEST_FAILED
Introduced in 7.73.0. See CURLINFO_PROXY_ERROR(3).

## CURLPX_RESOLVE_HOST
Introduced in 7.73.0. See CURLINFO_PROXY_ERROR(3).

## CURLPX_SEND_AUTH
Introduced in 7.73.0. See CURLINFO_PROXY_ERROR(3).

## CURLPX_SEND_CONNECT
Introduced in 7.73.0. See CURLINFO_PROXY_ERROR(3).

## CURLPX_SEND_REQUEST
Introduced in 7.73.0. See CURLINFO_PROXY_ERROR(3).

## CURLPX_UNKNOWN_FAIL
Introduced in 7.73.0. See CURLINFO_PROXY_ERROR(3).

## CURLPX_UNKNOWN_MODE
Introduced in 7.73.0. See CURLINFO_PROXY_ERROR(3).

## CURLPX_USER_REJECTED
Introduced in 7.73.0. See CURLINFO_PROXY_ERROR(3).

## CURLSHE_BAD_OPTION
Introduced in 7.10.3. See libcurl-errors(3).

## CURLSHE_IN_USE
Introduced in 7.10.3. See libcurl-errors(3).

## CURLSHE_INVALID
Introduced in 7.10.3. See libcurl-errors(3).

## CURLSHE_NOMEM
Introduced in 7.12.0. See libcurl-errors(3).

## CURLSHE_NOT_BUILT_IN
Introduced in 7.23.0. See libcurl-errors(3).

## CURLSHE_OK
Introduced in 7.10.3. See libcurl-errors(3).

## CURLSHOPT_LOCKFUNC
Introduced in 7.10.3. See CURLSHOPT_LOCKFUNC(3).

## CURLSHOPT_NONE
Introduced in 7.10.3. See curl_share_setopt(3).

## CURLSHOPT_SHARE
Introduced in 7.10.3. See CURLSHOPT_SHARE(3).

## CURLSHOPT_UNLOCKFUNC
Introduced in 7.10.3. See CURLSHOPT_UNLOCKFUNC(3).

## CURLSHOPT_UNSHARE
Introduced in 7.10.3. See CURLSHOPT_UNSHARE(3).

## CURLSHOPT_USERDATA
Introduced in 7.10.3. See CURLSHOPT_USERDATA(3).

## CURLSOCKTYPE_ACCEPT
Introduced in 7.28.0. See CURLOPT_SOCKOPTFUNCTION(3).

## CURLSOCKTYPE_IPCXN
Introduced in 7.16.0. See CURLOPT_SOCKOPTFUNCTION(3).

## CURLSSH_AUTH_AGENT
Introduced in 7.28.0. See CURLOPT_SSH_AUTH_TYPES(3).

## CURLSSH_AUTH_ANY
Introduced in 7.16.1. See CURLOPT_SSH_AUTH_TYPES(3).

## CURLSSH_AUTH_DEFAULT
Introduced in 7.16.1. See CURLOPT_SSH_AUTH_TYPES(3).

## CURLSSH_AUTH_GSSAPI
Introduced in 7.58.0. See CURLOPT_SSH_AUTH_TYPES(3).

## CURLSSH_AUTH_HOST
Introduced in 7.16.1. See CURLOPT_SSH_AUTH_TYPES(3).

## CURLSSH_AUTH_KEYBOARD
Introduced in 7.16.1. See CURLOPT_SSH_AUTH_TYPES(3).

## CURLSSH_AUTH_NONE
Introduced in 7.16.1. See CURLOPT_SSH_AUTH_TYPES(3).

## CURLSSH_AUTH_PASSWORD
Introduced in 7.16.1. See CURLOPT_SSH_AUTH_TYPES(3).

## CURLSSH_AUTH_PUBLICKEY
Introduced in 7.16.1. See CURLOPT_SSH_AUTH_TYPES(3).

## CURLSSLBACKEND_AWSLC
Introduced in 8.1.0. See curl_global_sslset(3).

## CURLSSLBACKEND_AXTLS
Introduced in 7.38.0. Deprecated since 7.61.0.

## CURLSSLBACKEND_BEARSSL
Introduced in 7.68.0. See curl_global_sslset(3).

## CURLSSLBACKEND_BORINGSSL
Introduced in 7.49.0. See curl_global_sslset(3).

## CURLSSLBACKEND_CYASSL
Introduced in 7.34.0. See curl_global_sslset(3).

## CURLSSLBACKEND_DARWINSSL
Introduced in 7.34.0. Deprecated since 7.64.1.

## CURLSSLBACKEND_GNUTLS
Introduced in 7.34.0. See curl_global_sslset(3).

## CURLSSLBACKEND_GSKIT
Introduced in 7.34.0. See curl_global_sslset(3).

## CURLSSLBACKEND_LIBRESSL
Introduced in 7.49.0. See curl_global_sslset(3).

## CURLSSLBACKEND_MBEDTLS
Introduced in 7.46.0. See curl_global_sslset(3).

## CURLSSLBACKEND_MESALINK
Introduced in 7.62.0. See curl_global_sslset(3).

## CURLSSLBACKEND_NONE
Introduced in 7.34.0. See curl_global_sslset(3).

## CURLSSLBACKEND_NSS
Introduced in 7.34.0. See curl_global_sslset(3).

## CURLSSLBACKEND_OPENSSL
Introduced in 7.34.0. See curl_global_sslset(3).

## CURLSSLBACKEND_POLARSSL
Introduced in 7.34.0. Deprecated since 7.69.0.

## CURLSSLBACKEND_QSOSSL
Introduced in 7.34.0. Last used in 7.38.0.

## CURLSSLBACKEND_RUSTLS
Introduced in 7.76.0. See curl_global_sslset(3).

## CURLSSLBACKEND_SCHANNEL
Introduced in 7.34.0. See curl_global_sslset(3).

## CURLSSLBACKEND_SECURETRANSPORT
Introduced in 7.64.1. See curl_global_sslset(3).

## CURLSSLBACKEND_WOLFSSL
Introduced in 7.49.0. See curl_global_sslset(3).

## CURLSSLOPT_ALLOW_BEAST
Introduced in 7.25.0. See CURLOPT_SSL_OPTIONS(3).

## CURLSSLOPT_AUTO_CLIENT_CERT
Introduced in 7.77.0. See CURLOPT_SSL_OPTIONS(3).

## CURLSSLOPT_NATIVE_CA
Introduced in 7.71.0. See CURLOPT_SSL_OPTIONS(3).

## CURLSSLOPT_NO_PARTIALCHAIN
Introduced in 7.68.0. See CURLOPT_SSL_OPTIONS(3).

## CURLSSLOPT_NO_REVOKE
Introduced in 7.44.0. See CURLOPT_SSL_OPTIONS(3).

## CURLSSLOPT_REVOKE_BEST_EFFORT
Introduced in 7.70.0. See CURLOPT_SSL_OPTIONS(3).

## CURLSSLSET_NO_BACKENDS
Introduced in 7.56.0. See curl_global_sslset(3).

## CURLSSLSET_OK
Introduced in 7.56.0. See curl_global_sslset(3).

## CURLSSLSET_TOO_LATE
Introduced in 7.56.0. See curl_global_sslset(3).

## CURLSSLSET_UNKNOWN_BACKEND
Introduced in 7.56.0. See curl_global_sslset(3).

## CURLSTS_DONE
Introduced in 7.74.0. See CURLOPT_HSTSREADFUNCTION(3).

## CURLSTS_FAIL
Introduced in 7.74.0. See CURLOPT_HSTSREADFUNCTION(3).

## CURLSTS_OK
Introduced in 7.74.0. See CURLOPT_HSTSREADFUNCTION(3).

## CURLU_ALLOW_SPACE
Introduced in 7.78.0. See curl_url_get(3).

## CURLU_APPENDQUERY
Introduced in 7.62.0. See curl_url_get(3).

## CURLU_DEFAULT_PORT
Introduced in 7.62.0. See curl_url_get(3).

## CURLU_DEFAULT_SCHEME
Introduced in 7.62.0. See curl_url_get(3).

## CURLU_DISALLOW_USER
Introduced in 7.62.0. See curl_url_get(3).

## CURLU_GUESS_SCHEME
Introduced in 7.62.0. See curl_url_get(3).

## CURLU_NO_AUTHORITY
Introduced in 7.67.0. See curl_url_get(3).

## CURLU_NO_DEFAULT_PORT
Introduced in 7.62.0. See curl_url_get(3).

## CURLU_NON_SUPPORT_SCHEME
Introduced in 7.62.0. See curl_url_get(3).

## CURLU_PATH_AS_IS
Introduced in 7.62.0. See curl_url_get(3).

## CURLU_PUNY2IDN
Introduced in 8.3.0. See curl_url_get(3).

## CURLU_PUNYCODE
Introduced in 7.88.0. See curl_url_get(3).

## CURLU_URLDECODE
Introduced in 7.62.0. See curl_url_get(3).

## CURLU_URLENCODE
Introduced in 7.62.0. See curl_url_get(3).

## CURLUE_BAD_FILE_URL
Introduced in 7.81.0. See libcurl-errors(3).

## CURLUE_BAD_FRAGMENT
Introduced in 7.81.0. See libcurl-errors(3).

## CURLUE_BAD_HANDLE
Introduced in 7.62.0. See libcurl-errors(3).

## CURLUE_BAD_HOSTNAME
Introduced in 7.81.0. See libcurl-errors(3).

## CURLUE_BAD_IPV6
Introduced in 7.81.0. See libcurl-errors(3).

## CURLUE_BAD_LOGIN
Introduced in 7.81.0. See libcurl-errors(3).

## CURLUE_BAD_PARTPOINTER
Introduced in 7.62.0. See libcurl-errors(3).

## CURLUE_BAD_PASSWORD
Introduced in 7.81.0. See libcurl-errors(3).

## CURLUE_BAD_PATH
Introduced in 7.81.0. See libcurl-errors(3).

## CURLUE_BAD_PORT_NUMBER
Introduced in 7.62.0. See libcurl-errors(3).

## CURLUE_BAD_QUERY
Introduced in 7.81.0. See libcurl-errors(3).

## CURLUE_BAD_SCHEME
Introduced in 7.81.0. See libcurl-errors(3).

## CURLUE_BAD_SLASHES
Introduced in 7.81.0. See libcurl-errors(3).

## CURLUE_BAD_USER
Introduced in 7.81.0. See libcurl-errors(3).

## CURLUE_LACKS_IDN
Introduced in 7.88.0. See libcurl-errors(3).

## CURLUE_MALFORMED_INPUT
Introduced in 7.62.0. See libcurl-errors(3).

## CURLUE_NO_FRAGMENT
Introduced in 7.62.0. See libcurl-errors(3).

## CURLUE_NO_HOST
Introduced in 7.62.0. See libcurl-errors(3).

## CURLUE_NO_OPTIONS
Introduced in 7.62.0. See libcurl-errors(3).

## CURLUE_NO_PASSWORD
Introduced in 7.62.0. See libcurl-errors(3).

## CURLUE_NO_PORT
Introduced in 7.62.0. See libcurl-errors(3).

## CURLUE_NO_QUERY
Introduced in 7.62.0. See libcurl-errors(3).

## CURLUE_NO_SCHEME
Introduced in 7.62.0. See libcurl-errors(3).

## CURLUE_NO_USER
Introduced in 7.62.0. See libcurl-errors(3).

## CURLUE_NO_ZONEID
Introduced in 7.81.0. See libcurl-errors(3).

## CURLUE_OK
Introduced in 7.62.0. See libcurl-errors(3).

## CURLUE_OUT_OF_MEMORY
Introduced in 7.62.0. See libcurl-errors(3).

## CURLUE_TOO_LARGE
Introduced in 8.6.0. See libcurl-errors(3).

## CURLUE_UNKNOWN_PART
Introduced in 7.62.0. See libcurl-errors(3).

## CURLUE_UNSUPPORTED_SCHEME
Introduced in 7.62.0. See libcurl-errors(3).

## CURLUE_URLDECODE
Introduced in 7.62.0. See libcurl-errors(3).

## CURLUE_USER_NOT_ALLOWED
Introduced in 7.62.0. See libcurl-errors(3).

## CURLUPART_FRAGMENT
Introduced in 7.62.0. See curl_url_get(3).

## CURLUPART_HOST
Introduced in 7.62.0. See curl_url_get(3).

## CURLUPART_OPTIONS
Introduced in 7.62.0. See curl_url_get(3).

## CURLUPART_PASSWORD
Introduced in 7.62.0. See curl_url_get(3).

## CURLUPART_PATH
Introduced in 7.62.0. See curl_url_get(3).

## CURLUPART_PORT
Introduced in 7.62.0. See curl_url_get(3).

## CURLUPART_QUERY
Introduced in 7.62.0. See curl_url_get(3).

## CURLUPART_SCHEME
Introduced in 7.62.0. See curl_url_get(3).

## CURLUPART_URL
Introduced in 7.62.0. See curl_url_get(3).

## CURLUPART_USER
Introduced in 7.62.0. See curl_url_get(3).

## CURLUPART_ZONEID
Introduced in 7.65.0. See curl_url_get(3).

## CURLUSESSL_ALL
Introduced in 7.17.0. See CURLOPT_USE_SSL(3).

## CURLUSESSL_CONTROL
Introduced in 7.17.0. See CURLOPT_USE_SSL(3).

## CURLUSESSL_NONE
Introduced in 7.17.0. See CURLOPT_USE_SSL(3).

## CURLUSESSL_TRY
Introduced in 7.17.0. See CURLOPT_USE_SSL(3).

## CURLVERSION_EIGHTH
Introduced in 7.72.0. See curl_version_info(3).

## CURLVERSION_ELEVENTH
Introduced in 7.87.0. See curl_version_info(3).

## CURLVERSION_FIFTH
Introduced in 7.57.0. See curl_version_info(3).

## CURLVERSION_FIRST
Introduced in 7.10. See curl_version_info(3).

## CURLVERSION_FOURTH
Introduced in 7.16.1. See curl_version_info(3).

## CURLVERSION_NINTH
Introduced in 7.75.0. See curl_version_info(3).

## CURLVERSION_NOW
Introduced in 7.10. See curl_version_info(3).

## CURLVERSION_SECOND
Introduced in 7.11.1. See curl_version_info(3).

## CURLVERSION_SEVENTH
Introduced in 7.70.0. See curl_version_info(3).

## CURLVERSION_SIXTH
Introduced in 7.66.0. See curl_version_info(3).

## CURLVERSION_TENTH
Introduced in 7.77.0. See curl_version_info(3).

## CURLVERSION_THIRD
Introduced in 7.12.0. See curl_version_info(3).

## CURLWARNING
Introduced in 7.66.0.

## CURLWS_BINARY
Introduced in 7.86.0. See curl_ws_send(3).

## CURLWS_CLOSE
Introduced in 7.86.0. See curl_ws_send(3).

## CURLWS_CONT
Introduced in 7.86.0. See curl_ws_send(3).

## CURLWS_OFFSET
Introduced in 7.86.0. See curl_ws_send(3).

## CURLWS_PING
Introduced in 7.86.0. See curl_ws_send(3).

## CURLWS_PONG
Introduced in 7.86.0. See curl_ws_send(3).

## CURLWS_RAW_MODE
Introduced in 7.86.0. See curl_ws_send(3).

## CURLWS_TEXT
Introduced in 7.86.0. See curl_ws_send(3).
