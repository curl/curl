#ifndef HEADER_CURL_FEAT_H
#define HEADER_CURL_FEAT_H
/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) 1998 - 2022, Daniel Stenberg, <daniel@haxx.se>, et al.
 *
 * This software is licensed as described in the file COPYING, which
 * you should have received as part of this distribution. The terms
 * are also available at https://curl.se/docs/copyright.html.
 *
 * You may opt to use, copy, modify, merge, publish, distribute and/or sell
 * copies of the Software, and permit persons to whom the Software is
 * furnished to do so, under the terms of the COPYING file.
 *
 * This software is distributed on an "AS IS" basis, WITHOUT WARRANTY OF ANY
 * KIND, either express or implied.
 *
 * SPDX-License-Identifier: curl
 *
 ***************************************************************************/
#ifndef CURL_DISABLE_ALTSVC
#ifndef CURL_DISABLE_HTTP
#define FEAT_ALTSVC
#endif
#endif
#ifndef CURL_DISABLE_COOKIES
#define FEAT_COOKIES
#endif
#ifndef CURL_DISABLE_CRYPTO_AUTH
#define FEAT_CRYPTO_AUTH
#endif
#ifndef CURL_DISABLE_DICT
#define FEAT_DICT /* protocol */
#endif
#ifndef CURL_DISABLE_DOH
#define FEAT_DOH
#endif
#ifndef CURL_DISABLE_FILE
#define FEAT_FILE /* protocol */
#endif
#ifndef CURL_DISABLE_FTP
#define FEAT_FTP /* protocol */
#endif
#ifndef CURL_DISABLE_GETOPTIONS
#define FEAT_GETOPTIONS
#endif
#ifndef CURL_DISABLE_GOPHER
#define FEAT_GOPHER /* protocol */
#endif
#ifndef CURL_DISABLE_HEADERS_API
#define FEAT_HEADERS_API
#endif
#ifndef CURL_DISABLE_HSTS
#define FEAT_HSTS
#endif
#ifndef CURL_DISABLE_HTTP
#define FEAT_HTTP /* protocol */
#endif
#ifndef CURL_DISABLE_HTTP_AUTH
#define FEAT_HTTP_AUTH
#endif
#ifndef CURL_DISABLE_IMAP
#define FEAT_IMAP /* protocol */
#endif
#ifndef CURL_DISABLE_LDAP
#define FEAT_LDAP /* protocol */
#endif
#ifndef CURL_DISABLE_LDAPS
#define FEAT_LDAPS /* protocol */
#endif
#ifndef CURL_DISABLE_LIBCURL_OPTION
#define FEAT_LIBCURL_OPTION
#endif
#ifndef CURL_DISABLE_MIME
#define FEAT_MIME
#endif
#ifndef CURL_DISABLE_MQTT
#define FEAT_MQTT /* protocol */
#endif
#ifndef CURL_DISABLE_NETRC
#define FEAT_NETRC
#endif
#ifndef CURL_DISABLE_NTLM
#define FEAT_NTLM
#endif
#ifndef CURL_DISABLE_OPENSSL_AUTO_LOAD_CONFIG
#define FEAT_OPENSSL_AUTO_LOAD_CONFIG
#endif
#ifndef CURL_DISABLE_PARSEDATE
#define FEAT_PARSEDATE
#endif
#ifndef CURL_DISABLE_POP3
#define FEAT_POP3 /* protocol */
#endif
#ifndef CURL_DISABLE_PROGRESS_METER
#define FEAT_PROGRESS_METER
#endif
#ifndef CURL_DISABLE_PROXY
#define FEAT_PROXY
#endif
#ifndef CURL_DISABLE_RTSP
#define FEAT_RTSP /* protocol */
#endif
#ifndef CURL_DISABLE_SHUFFLE_DNS
#define FEAT_SHUFFLE_DNS
#endif
#ifndef CURL_DISABLE_SMB
#define FEAT_SMB /* protocol */
#endif
#ifndef CURL_DISABLE_SMTP
#define FEAT_SMTP /* protocol */
#endif
#ifndef CURL_DISABLE_SOCKETPAIR
#define FEAT_SOCKETPAIR
#endif
#ifndef CURL_DISABLE_TELNET
#define FEAT_TELNET /* protocol */
#endif
#ifndef CURL_DISABLE_TFTP
#define FEAT_TFTP /* protocol */
#endif
#ifndef CURL_DISABLE_VERBOSE_STRINGS
#define FEAT_VERBOSE_STRINGS
#endif

#ifdef USE_WEBSOCKETS
#define FEAT_WS
#endif

/* Disable all other protocols when http is the only one desired. */
#ifdef HTTP_ONLY
  #undef FEAT_DICT
  #undef FEAT_FILE
  #undef FEAT_FTP
  #undef FEAT_GOPHER
  #undef FEAT_IMAP
  #undef FEAT_LDAP
  #undef FEAT_LDAPS
  #undef FEAT_MQTT
  #undef FEAT_POP3
  #undef FEAT_RTSP
  #undef FEAT_SMB
  #undef FEAT_SMTP
  #undef FEAT_TELNET
  #undef FEAT_TFTP
  #undef FEAT_WS
#endif

/* When HTTP is disabled, RTSP is not supported. */

#ifndef FEAT_HTTP
#undef FEAT_RTSP
#endif


#endif /* HEADER_CURL_FEAT_H */
