#ifndef FETCHINC_TYPECHECK_GCC_H
#define FETCHINC_TYPECHECK_GCC_H
/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
 *
 * This software is licensed as described in the file COPYING, which
 * you should have received as part of this distribution. The terms
 * are also available at https://fetch.se/docs/copyright.html.
 *
 * You may opt to use, copy, modify, merge, publish, distribute and/or sell
 * copies of the Software, and permit persons to whom the Software is
 * furnished to do so, under the terms of the COPYING file.
 *
 * This software is distributed on an "AS IS" basis, WITHOUT WARRANTY OF ANY
 * KIND, either express or implied.
 *
 * SPDX-License-Identifier: fetch
 *
 ***************************************************************************/

/* wraps fetch_easy_setopt() with typechecking */

/* To add a new kind of warning, add an
 *   if(fetchcheck_sometype_option(_fetch_opt))
 *     if(!fetchcheck_sometype(value))
 *       _fetch_easy_setopt_err_sometype();
 * block and define fetchcheck_sometype_option, fetchcheck_sometype and
 * _fetch_easy_setopt_err_sometype below
 *
 * NOTE: We use two nested 'if' statements here instead of the && operator, in
 *       order to work around gcc bug #32061. It affects only gcc 4.3.x/4.4.x
 *       when compiling with -Wlogical-op.
 *
 * To add an option that uses the same type as an existing option, you will
 * just need to extend the appropriate _fetch_*_option macro
 */
#define fetch_easy_setopt(handle, option, value)                         \
  __extension__({                                                       \
      FETCHoption _fetch_opt = (option);                                  \
      if(__builtin_constant_p(_fetch_opt)) {                             \
        FETCH_IGNORE_DEPRECATION(                                        \
          if(fetchcheck_long_option(_fetch_opt))                          \
            if(!fetchcheck_long(value))                                  \
              _fetch_easy_setopt_err_long();                             \
          if(fetchcheck_off_t_option(_fetch_opt))                         \
            if(!fetchcheck_off_t(value))                                 \
              _fetch_easy_setopt_err_fetch_off_t();                       \
          if(fetchcheck_string_option(_fetch_opt))                        \
            if(!fetchcheck_string(value))                                \
              _fetch_easy_setopt_err_string();                           \
          if(fetchcheck_write_cb_option(_fetch_opt))                      \
            if(!fetchcheck_write_cb(value))                              \
              _fetch_easy_setopt_err_write_callback();                   \
          if((_fetch_opt) == FETCHOPT_RESOLVER_START_FUNCTION)            \
            if(!fetchcheck_resolver_start_callback(value))               \
              _fetch_easy_setopt_err_resolver_start_callback();          \
          if((_fetch_opt) == FETCHOPT_READFUNCTION)                       \
            if(!fetchcheck_read_cb(value))                               \
              _fetch_easy_setopt_err_read_cb();                          \
          if((_fetch_opt) == FETCHOPT_IOCTLFUNCTION)                      \
            if(!fetchcheck_ioctl_cb(value))                              \
              _fetch_easy_setopt_err_ioctl_cb();                         \
          if((_fetch_opt) == FETCHOPT_SOCKOPTFUNCTION)                    \
            if(!fetchcheck_sockopt_cb(value))                            \
              _fetch_easy_setopt_err_sockopt_cb();                       \
          if((_fetch_opt) == FETCHOPT_OPENSOCKETFUNCTION)                 \
            if(!fetchcheck_opensocket_cb(value))                         \
              _fetch_easy_setopt_err_opensocket_cb();                    \
          if((_fetch_opt) == FETCHOPT_PROGRESSFUNCTION)                   \
            if(!fetchcheck_progress_cb(value))                           \
              _fetch_easy_setopt_err_progress_cb();                      \
          if((_fetch_opt) == FETCHOPT_DEBUGFUNCTION)                      \
            if(!fetchcheck_debug_cb(value))                              \
              _fetch_easy_setopt_err_debug_cb();                         \
          if((_fetch_opt) == FETCHOPT_SSL_CTX_FUNCTION)                   \
            if(!fetchcheck_ssl_ctx_cb(value))                            \
              _fetch_easy_setopt_err_ssl_ctx_cb();                       \
          if(fetchcheck_conv_cb_option(_fetch_opt))                       \
            if(!fetchcheck_conv_cb(value))                               \
              _fetch_easy_setopt_err_conv_cb();                          \
          if((_fetch_opt) == FETCHOPT_SEEKFUNCTION)                       \
            if(!fetchcheck_seek_cb(value))                               \
              _fetch_easy_setopt_err_seek_cb();                          \
          if(fetchcheck_cb_data_option(_fetch_opt))                       \
            if(!fetchcheck_cb_data(value))                               \
              _fetch_easy_setopt_err_cb_data();                          \
          if((_fetch_opt) == FETCHOPT_ERRORBUFFER)                        \
            if(!fetchcheck_error_buffer(value))                          \
              _fetch_easy_setopt_err_error_buffer();                     \
          if((_fetch_opt) == FETCHOPT_STDERR)                             \
            if(!fetchcheck_FILE(value))                                  \
              _fetch_easy_setopt_err_FILE();                             \
          if(fetchcheck_postfields_option(_fetch_opt))                    \
            if(!fetchcheck_postfields(value))                            \
              _fetch_easy_setopt_err_postfields();                       \
          if((_fetch_opt) == FETCHOPT_HTTPPOST)                           \
            if(!fetchcheck_arr((value), struct fetch_httppost))           \
              _fetch_easy_setopt_err_fetch_httpost();                     \
          if((_fetch_opt) == FETCHOPT_MIMEPOST)                           \
            if(!fetchcheck_ptr((value), fetch_mime))                      \
              _fetch_easy_setopt_err_fetch_mimepost();                    \
          if(fetchcheck_slist_option(_fetch_opt))                         \
            if(!fetchcheck_arr((value), struct fetch_slist))              \
              _fetch_easy_setopt_err_fetch_slist();                       \
          if((_fetch_opt) == FETCHOPT_SHARE)                              \
            if(!fetchcheck_ptr((value), FETCHSH))                         \
              _fetch_easy_setopt_err_FETCHSH();                           \
        )                                                               \
      }                                                                 \
      fetch_easy_setopt(handle, _fetch_opt, value);                       \
    })

/* wraps fetch_easy_getinfo() with typechecking */
#define fetch_easy_getinfo(handle, info, arg)                            \
  __extension__({                                                       \
      FETCHINFO _fetch_info = (info);                                     \
      if(__builtin_constant_p(_fetch_info)) {                            \
        FETCH_IGNORE_DEPRECATION(                                        \
          if(fetchcheck_string_info(_fetch_info))                         \
            if(!fetchcheck_arr((arg), char *))                           \
              _fetch_easy_getinfo_err_string();                          \
          if(fetchcheck_long_info(_fetch_info))                           \
            if(!fetchcheck_arr((arg), long))                             \
              _fetch_easy_getinfo_err_long();                            \
          if(fetchcheck_double_info(_fetch_info))                         \
            if(!fetchcheck_arr((arg), double))                           \
              _fetch_easy_getinfo_err_double();                          \
          if(fetchcheck_slist_info(_fetch_info))                          \
            if(!fetchcheck_arr((arg), struct fetch_slist *))              \
              _fetch_easy_getinfo_err_fetch_slist();                      \
          if(fetchcheck_tlssessioninfo_info(_fetch_info))                 \
            if(!fetchcheck_arr((arg), struct fetch_tlssessioninfo *))     \
              _fetch_easy_getinfo_err_fetch_tlssesssioninfo();            \
          if(fetchcheck_certinfo_info(_fetch_info))                       \
            if(!fetchcheck_arr((arg), struct fetch_certinfo *))           \
              _fetch_easy_getinfo_err_fetch_certinfo();                   \
          if(fetchcheck_socket_info(_fetch_info))                         \
            if(!fetchcheck_arr((arg), fetch_socket_t))                    \
              _fetch_easy_getinfo_err_fetch_socket();                     \
          if(fetchcheck_off_t_info(_fetch_info))                          \
            if(!fetchcheck_arr((arg), fetch_off_t))                       \
              _fetch_easy_getinfo_err_fetch_off_t();                      \
        )                                                               \
      }                                                                 \
      fetch_easy_getinfo(handle, _fetch_info, arg);                       \
    })

/*
 * For now, just make sure that the functions are called with three arguments
 */
#define fetch_share_setopt(share,opt,param) fetch_share_setopt(share,opt,param)
#define fetch_multi_setopt(handle,opt,param) fetch_multi_setopt(handle,opt,param)


/* the actual warnings, triggered by calling the _fetch_easy_setopt_err*
 * functions */

/* To define a new warning, use _FETCH_WARNING(identifier, "message") */
#define FETCHWARNING(id, message)                                        \
  static void __attribute__((__warning__(message)))                     \
  __attribute__((__unused__)) __attribute__((__noinline__))             \
  id(void) { __asm__(""); }

FETCHWARNING(_fetch_easy_setopt_err_long,
  "fetch_easy_setopt expects a long argument for this option")
FETCHWARNING(_fetch_easy_setopt_err_fetch_off_t,
  "fetch_easy_setopt expects a fetch_off_t argument for this option")
FETCHWARNING(_fetch_easy_setopt_err_string,
              "fetch_easy_setopt expects a "
              "string ('char *' or char[]) argument for this option"
  )
FETCHWARNING(_fetch_easy_setopt_err_write_callback,
  "fetch_easy_setopt expects a fetch_write_callback argument for this option")
FETCHWARNING(_fetch_easy_setopt_err_resolver_start_callback,
              "fetch_easy_setopt expects a "
              "fetch_resolver_start_callback argument for this option"
  )
FETCHWARNING(_fetch_easy_setopt_err_read_cb,
  "fetch_easy_setopt expects a fetch_read_callback argument for this option")
FETCHWARNING(_fetch_easy_setopt_err_ioctl_cb,
  "fetch_easy_setopt expects a fetch_ioctl_callback argument for this option")
FETCHWARNING(_fetch_easy_setopt_err_sockopt_cb,
  "fetch_easy_setopt expects a fetch_sockopt_callback argument for this option")
FETCHWARNING(_fetch_easy_setopt_err_opensocket_cb,
              "fetch_easy_setopt expects a "
              "fetch_opensocket_callback argument for this option"
  )
FETCHWARNING(_fetch_easy_setopt_err_progress_cb,
  "fetch_easy_setopt expects a fetch_progress_callback argument for this option")
FETCHWARNING(_fetch_easy_setopt_err_debug_cb,
  "fetch_easy_setopt expects a fetch_debug_callback argument for this option")
FETCHWARNING(_fetch_easy_setopt_err_ssl_ctx_cb,
  "fetch_easy_setopt expects a fetch_ssl_ctx_callback argument for this option")
FETCHWARNING(_fetch_easy_setopt_err_conv_cb,
  "fetch_easy_setopt expects a fetch_conv_callback argument for this option")
FETCHWARNING(_fetch_easy_setopt_err_seek_cb,
  "fetch_easy_setopt expects a fetch_seek_callback argument for this option")
FETCHWARNING(_fetch_easy_setopt_err_cb_data,
              "fetch_easy_setopt expects a "
              "private data pointer as argument for this option")
FETCHWARNING(_fetch_easy_setopt_err_error_buffer,
              "fetch_easy_setopt expects a "
              "char buffer of FETCH_ERROR_SIZE as argument for this option")
FETCHWARNING(_fetch_easy_setopt_err_FILE,
  "fetch_easy_setopt expects a 'FILE *' argument for this option")
FETCHWARNING(_fetch_easy_setopt_err_postfields,
  "fetch_easy_setopt expects a 'void *' or 'char *' argument for this option")
FETCHWARNING(_fetch_easy_setopt_err_fetch_httpost,
              "fetch_easy_setopt expects a 'struct fetch_httppost *' "
              "argument for this option")
FETCHWARNING(_fetch_easy_setopt_err_fetch_mimepost,
              "fetch_easy_setopt expects a 'fetch_mime *' "
              "argument for this option")
FETCHWARNING(_fetch_easy_setopt_err_fetch_slist,
  "fetch_easy_setopt expects a 'struct fetch_slist *' argument for this option")
FETCHWARNING(_fetch_easy_setopt_err_FETCHSH,
  "fetch_easy_setopt expects a FETCHSH* argument for this option")

FETCHWARNING(_fetch_easy_getinfo_err_string,
  "fetch_easy_getinfo expects a pointer to 'char *' for this info")
FETCHWARNING(_fetch_easy_getinfo_err_long,
  "fetch_easy_getinfo expects a pointer to long for this info")
FETCHWARNING(_fetch_easy_getinfo_err_double,
  "fetch_easy_getinfo expects a pointer to double for this info")
FETCHWARNING(_fetch_easy_getinfo_err_fetch_slist,
  "fetch_easy_getinfo expects a pointer to 'struct fetch_slist *' for this info")
FETCHWARNING(_fetch_easy_getinfo_err_fetch_tlssesssioninfo,
              "fetch_easy_getinfo expects a pointer to "
              "'struct fetch_tlssessioninfo *' for this info")
FETCHWARNING(_fetch_easy_getinfo_err_fetch_certinfo,
              "fetch_easy_getinfo expects a pointer to "
              "'struct fetch_certinfo *' for this info")
FETCHWARNING(_fetch_easy_getinfo_err_fetch_socket,
  "fetch_easy_getinfo expects a pointer to fetch_socket_t for this info")
FETCHWARNING(_fetch_easy_getinfo_err_fetch_off_t,
  "fetch_easy_getinfo expects a pointer to fetch_off_t for this info")

/* groups of fetch_easy_setops options that take the same type of argument */

/* To add a new option to one of the groups, just add
 *   (option) == FETCHOPT_SOMETHING
 * to the or-expression. If the option takes a long or fetch_off_t, you do not
 * have to do anything
 */

/* evaluates to true if option takes a long argument */
#define fetchcheck_long_option(option)                   \
  (0 < (option) && (option) < FETCHOPTTYPE_OBJECTPOINT)

#define fetchcheck_off_t_option(option)          \
  (((option) > FETCHOPTTYPE_OFF_T) && ((option) < FETCHOPTTYPE_BLOB))

/* evaluates to true if option takes a char* argument */
#define fetchcheck_string_option(option)                                       \
  ((option) == FETCHOPT_ABSTRACT_UNIX_SOCKET ||                                \
   (option) == FETCHOPT_ACCEPT_ENCODING ||                                     \
   (option) == FETCHOPT_ALTSVC ||                                              \
   (option) == FETCHOPT_CAINFO ||                                              \
   (option) == FETCHOPT_CAPATH ||                                              \
   (option) == FETCHOPT_COOKIE ||                                              \
   (option) == FETCHOPT_COOKIEFILE ||                                          \
   (option) == FETCHOPT_COOKIEJAR ||                                           \
   (option) == FETCHOPT_COOKIELIST ||                                          \
   (option) == FETCHOPT_CRLFILE ||                                             \
   (option) == FETCHOPT_CUSTOMREQUEST ||                                       \
   (option) == FETCHOPT_DEFAULT_PROTOCOL ||                                    \
   (option) == FETCHOPT_DNS_INTERFACE ||                                       \
   (option) == FETCHOPT_DNS_LOCAL_IP4 ||                                       \
   (option) == FETCHOPT_DNS_LOCAL_IP6 ||                                       \
   (option) == FETCHOPT_DNS_SERVERS ||                                         \
   (option) == FETCHOPT_DOH_URL ||                                             \
   (option) == FETCHOPT_ECH        ||                                          \
   (option) == FETCHOPT_EGDSOCKET ||                                           \
   (option) == FETCHOPT_FTP_ACCOUNT ||                                         \
   (option) == FETCHOPT_FTP_ALTERNATIVE_TO_USER ||                             \
   (option) == FETCHOPT_FTPPORT ||                                             \
   (option) == FETCHOPT_HSTS ||                                                \
   (option) == FETCHOPT_HAPROXY_CLIENT_IP ||                                   \
   (option) == FETCHOPT_INTERFACE ||                                           \
   (option) == FETCHOPT_ISSUERCERT ||                                          \
   (option) == FETCHOPT_KEYPASSWD ||                                           \
   (option) == FETCHOPT_KRBLEVEL ||                                            \
   (option) == FETCHOPT_LOGIN_OPTIONS ||                                       \
   (option) == FETCHOPT_MAIL_AUTH ||                                           \
   (option) == FETCHOPT_MAIL_FROM ||                                           \
   (option) == FETCHOPT_NETRC_FILE ||                                          \
   (option) == FETCHOPT_NOPROXY ||                                             \
   (option) == FETCHOPT_PASSWORD ||                                            \
   (option) == FETCHOPT_PINNEDPUBLICKEY ||                                     \
   (option) == FETCHOPT_PRE_PROXY ||                                           \
   (option) == FETCHOPT_PROTOCOLS_STR ||                                       \
   (option) == FETCHOPT_PROXY ||                                               \
   (option) == FETCHOPT_PROXY_CAINFO ||                                        \
   (option) == FETCHOPT_PROXY_CAPATH ||                                        \
   (option) == FETCHOPT_PROXY_CRLFILE ||                                       \
   (option) == FETCHOPT_PROXY_ISSUERCERT ||                                    \
   (option) == FETCHOPT_PROXY_KEYPASSWD ||                                     \
   (option) == FETCHOPT_PROXY_PINNEDPUBLICKEY ||                               \
   (option) == FETCHOPT_PROXY_SERVICE_NAME ||                                  \
   (option) == FETCHOPT_PROXY_SSL_CIPHER_LIST ||                               \
   (option) == FETCHOPT_PROXY_SSLCERT ||                                       \
   (option) == FETCHOPT_PROXY_SSLCERTTYPE ||                                   \
   (option) == FETCHOPT_PROXY_SSLKEY ||                                        \
   (option) == FETCHOPT_PROXY_SSLKEYTYPE ||                                    \
   (option) == FETCHOPT_PROXY_TLS13_CIPHERS ||                                 \
   (option) == FETCHOPT_PROXY_TLSAUTH_PASSWORD ||                              \
   (option) == FETCHOPT_PROXY_TLSAUTH_TYPE ||                                  \
   (option) == FETCHOPT_PROXY_TLSAUTH_USERNAME ||                              \
   (option) == FETCHOPT_PROXYPASSWORD ||                                       \
   (option) == FETCHOPT_PROXYUSERNAME ||                                       \
   (option) == FETCHOPT_PROXYUSERPWD ||                                        \
   (option) == FETCHOPT_RANDOM_FILE ||                                         \
   (option) == FETCHOPT_RANGE ||                                               \
   (option) == FETCHOPT_REDIR_PROTOCOLS_STR ||                                 \
   (option) == FETCHOPT_REFERER ||                                             \
   (option) == FETCHOPT_REQUEST_TARGET ||                                      \
   (option) == FETCHOPT_RTSP_SESSION_ID ||                                     \
   (option) == FETCHOPT_RTSP_STREAM_URI ||                                     \
   (option) == FETCHOPT_RTSP_TRANSPORT ||                                      \
   (option) == FETCHOPT_SASL_AUTHZID ||                                        \
   (option) == FETCHOPT_SERVICE_NAME ||                                        \
   (option) == FETCHOPT_SOCKS5_GSSAPI_SERVICE ||                               \
   (option) == FETCHOPT_SSH_HOST_PUBLIC_KEY_MD5 ||                             \
   (option) == FETCHOPT_SSH_HOST_PUBLIC_KEY_SHA256 ||                          \
   (option) == FETCHOPT_SSH_KNOWNHOSTS ||                                      \
   (option) == FETCHOPT_SSH_PRIVATE_KEYFILE ||                                 \
   (option) == FETCHOPT_SSH_PUBLIC_KEYFILE ||                                  \
   (option) == FETCHOPT_SSLCERT ||                                             \
   (option) == FETCHOPT_SSLCERTTYPE ||                                         \
   (option) == FETCHOPT_SSLENGINE ||                                           \
   (option) == FETCHOPT_SSLKEY ||                                              \
   (option) == FETCHOPT_SSLKEYTYPE ||                                          \
   (option) == FETCHOPT_SSL_CIPHER_LIST ||                                     \
   (option) == FETCHOPT_TLS13_CIPHERS ||                                       \
   (option) == FETCHOPT_TLSAUTH_PASSWORD ||                                    \
   (option) == FETCHOPT_TLSAUTH_TYPE ||                                        \
   (option) == FETCHOPT_TLSAUTH_USERNAME ||                                    \
   (option) == FETCHOPT_UNIX_SOCKET_PATH ||                                    \
   (option) == FETCHOPT_URL ||                                                 \
   (option) == FETCHOPT_USERAGENT ||                                           \
   (option) == FETCHOPT_USERNAME ||                                            \
   (option) == FETCHOPT_AWS_SIGV4 ||                                           \
   (option) == FETCHOPT_USERPWD ||                                             \
   (option) == FETCHOPT_XOAUTH2_BEARER ||                                      \
   (option) == FETCHOPT_SSL_EC_CURVES ||                                       \
   0)

/* evaluates to true if option takes a fetch_write_callback argument */
#define fetchcheck_write_cb_option(option)                               \
  ((option) == FETCHOPT_HEADERFUNCTION ||                                \
   (option) == FETCHOPT_WRITEFUNCTION)

/* evaluates to true if option takes a fetch_conv_callback argument */
#define fetchcheck_conv_cb_option(option)                                \
  ((option) == FETCHOPT_CONV_TO_NETWORK_FUNCTION ||                      \
   (option) == FETCHOPT_CONV_FROM_NETWORK_FUNCTION ||                    \
   (option) == FETCHOPT_CONV_FROM_UTF8_FUNCTION)

/* evaluates to true if option takes a data argument to pass to a callback */
#define fetchcheck_cb_data_option(option)                                      \
  ((option) == FETCHOPT_CHUNK_DATA ||                                          \
   (option) == FETCHOPT_CLOSESOCKETDATA ||                                     \
   (option) == FETCHOPT_DEBUGDATA ||                                           \
   (option) == FETCHOPT_FNMATCH_DATA ||                                        \
   (option) == FETCHOPT_HEADERDATA ||                                          \
   (option) == FETCHOPT_HSTSREADDATA ||                                        \
   (option) == FETCHOPT_HSTSWRITEDATA ||                                       \
   (option) == FETCHOPT_INTERLEAVEDATA ||                                      \
   (option) == FETCHOPT_IOCTLDATA ||                                           \
   (option) == FETCHOPT_OPENSOCKETDATA ||                                      \
   (option) == FETCHOPT_PREREQDATA ||                                          \
   (option) == FETCHOPT_PROGRESSDATA ||                                        \
   (option) == FETCHOPT_READDATA ||                                            \
   (option) == FETCHOPT_SEEKDATA ||                                            \
   (option) == FETCHOPT_SOCKOPTDATA ||                                         \
   (option) == FETCHOPT_SSH_KEYDATA ||                                         \
   (option) == FETCHOPT_SSL_CTX_DATA ||                                        \
   (option) == FETCHOPT_WRITEDATA ||                                           \
   (option) == FETCHOPT_RESOLVER_START_DATA ||                                 \
   (option) == FETCHOPT_TRAILERDATA ||                                         \
   (option) == FETCHOPT_SSH_HOSTKEYDATA ||                                     \
   0)

/* evaluates to true if option takes a POST data argument (void* or char*) */
#define fetchcheck_postfields_option(option)                                   \
  ((option) == FETCHOPT_POSTFIELDS ||                                          \
   (option) == FETCHOPT_COPYPOSTFIELDS ||                                      \
   0)

/* evaluates to true if option takes a struct fetch_slist * argument */
#define fetchcheck_slist_option(option)                                        \
  ((option) == FETCHOPT_HTTP200ALIASES ||                                      \
   (option) == FETCHOPT_HTTPHEADER ||                                          \
   (option) == FETCHOPT_MAIL_RCPT ||                                           \
   (option) == FETCHOPT_POSTQUOTE ||                                           \
   (option) == FETCHOPT_PREQUOTE ||                                            \
   (option) == FETCHOPT_PROXYHEADER ||                                         \
   (option) == FETCHOPT_QUOTE ||                                               \
   (option) == FETCHOPT_RESOLVE ||                                             \
   (option) == FETCHOPT_TELNETOPTIONS ||                                       \
   (option) == FETCHOPT_CONNECT_TO ||                                          \
   0)

/* groups of fetch_easy_getinfo infos that take the same type of argument */

/* evaluates to true if info expects a pointer to char * argument */
#define fetchcheck_string_info(info)                             \
  (FETCHINFO_STRING < (info) && (info) < FETCHINFO_LONG &&        \
   (info) != FETCHINFO_PRIVATE)

/* evaluates to true if info expects a pointer to long argument */
#define fetchcheck_long_info(info)                       \
  (FETCHINFO_LONG < (info) && (info) < FETCHINFO_DOUBLE)

/* evaluates to true if info expects a pointer to double argument */
#define fetchcheck_double_info(info)                     \
  (FETCHINFO_DOUBLE < (info) && (info) < FETCHINFO_SLIST)

/* true if info expects a pointer to struct fetch_slist * argument */
#define fetchcheck_slist_info(info)                                      \
  (((info) == FETCHINFO_SSL_ENGINES) || ((info) == FETCHINFO_COOKIELIST))

/* true if info expects a pointer to struct fetch_tlssessioninfo * argument */
#define fetchcheck_tlssessioninfo_info(info)                              \
  (((info) == FETCHINFO_TLS_SSL_PTR) || ((info) == FETCHINFO_TLS_SESSION))

/* true if info expects a pointer to struct fetch_certinfo * argument */
#define fetchcheck_certinfo_info(info) ((info) == FETCHINFO_CERTINFO)

/* true if info expects a pointer to struct fetch_socket_t argument */
#define fetchcheck_socket_info(info)                     \
  (FETCHINFO_SOCKET < (info) && (info) < FETCHINFO_OFF_T)

/* true if info expects a pointer to fetch_off_t argument */
#define fetchcheck_off_t_info(info)              \
  (FETCHINFO_OFF_T < (info))


/* typecheck helpers -- check whether given expression has requested type */

/* For pointers, you can use the fetchcheck_ptr/fetchcheck_arr macros,
 * otherwise define a new macro. Search for __builtin_types_compatible_p
 * in the GCC manual.
 * NOTE: these macros MUST NOT EVALUATE their arguments! The argument is
 * the actual expression passed to the fetch_easy_setopt macro. This
 * means that you can only apply the sizeof and __typeof__ operators, no
 * == or whatsoever.
 */

/* XXX: should evaluate to true if expr is a pointer */
#define fetchcheck_any_ptr(expr)                 \
  (sizeof(expr) == sizeof(void *))

/* evaluates to true if expr is NULL */
/* XXX: must not evaluate expr, so this check is not accurate */
#define fetchcheck_NULL(expr)                                            \
  (__builtin_types_compatible_p(__typeof__(expr), __typeof__(NULL)))

/* evaluates to true if expr is type*, const type* or NULL */
#define fetchcheck_ptr(expr, type)                                       \
  (fetchcheck_NULL(expr) ||                                              \
   __builtin_types_compatible_p(__typeof__(expr), type *) ||            \
   __builtin_types_compatible_p(__typeof__(expr), const type *))

/* evaluates to true if expr is one of type[], type*, NULL or const type* */
#define fetchcheck_arr(expr, type)                                       \
  (fetchcheck_ptr((expr), type) ||                                       \
   __builtin_types_compatible_p(__typeof__(expr), type []))

/* evaluates to true if expr is a string */
#define fetchcheck_string(expr)                                          \
  (fetchcheck_arr((expr), char) ||                                       \
   fetchcheck_arr((expr), signed char) ||                                \
   fetchcheck_arr((expr), unsigned char))

/* evaluates to true if expr is a long (no matter the signedness)
 * XXX: for now, int is also accepted (and therefore short and char, which
 * are promoted to int when passed to a variadic function) */
#define fetchcheck_long(expr)                                                  \
  (__builtin_types_compatible_p(__typeof__(expr), long) ||                    \
   __builtin_types_compatible_p(__typeof__(expr), signed long) ||             \
   __builtin_types_compatible_p(__typeof__(expr), unsigned long) ||           \
   __builtin_types_compatible_p(__typeof__(expr), int) ||                     \
   __builtin_types_compatible_p(__typeof__(expr), signed int) ||              \
   __builtin_types_compatible_p(__typeof__(expr), unsigned int) ||            \
   __builtin_types_compatible_p(__typeof__(expr), short) ||                   \
   __builtin_types_compatible_p(__typeof__(expr), signed short) ||            \
   __builtin_types_compatible_p(__typeof__(expr), unsigned short) ||          \
   __builtin_types_compatible_p(__typeof__(expr), char) ||                    \
   __builtin_types_compatible_p(__typeof__(expr), signed char) ||             \
   __builtin_types_compatible_p(__typeof__(expr), unsigned char))

/* evaluates to true if expr is of type fetch_off_t */
#define fetchcheck_off_t(expr)                                   \
  (__builtin_types_compatible_p(__typeof__(expr), fetch_off_t))

/* evaluates to true if expr is abuffer suitable for FETCHOPT_ERRORBUFFER */
/* XXX: also check size of an char[] array? */
#define fetchcheck_error_buffer(expr)                                    \
  (fetchcheck_NULL(expr) ||                                              \
   __builtin_types_compatible_p(__typeof__(expr), char *) ||            \
   __builtin_types_compatible_p(__typeof__(expr), char[]))

/* evaluates to true if expr is of type (const) void* or (const) FILE* */
#if 0
#define fetchcheck_cb_data(expr)                                         \
  (fetchcheck_ptr((expr), void) ||                                       \
   fetchcheck_ptr((expr), FILE))
#else /* be less strict */
#define fetchcheck_cb_data(expr)                 \
  fetchcheck_any_ptr(expr)
#endif

/* evaluates to true if expr is of type FILE* */
#define fetchcheck_FILE(expr)                                            \
  (fetchcheck_NULL(expr) ||                                              \
   (__builtin_types_compatible_p(__typeof__(expr), FILE *)))

/* evaluates to true if expr can be passed as POST data (void* or char*) */
#define fetchcheck_postfields(expr)                                      \
  (fetchcheck_ptr((expr), void) ||                                       \
   fetchcheck_arr((expr), char) ||                                       \
   fetchcheck_arr((expr), unsigned char))

/* helper: __builtin_types_compatible_p distinguishes between functions and
 * function pointers, hide it */
#define fetchcheck_cb_compatible(func, type)                             \
  (__builtin_types_compatible_p(__typeof__(func), type) ||              \
   __builtin_types_compatible_p(__typeof__(func) *, type))

/* evaluates to true if expr is of type fetch_resolver_start_callback */
#define fetchcheck_resolver_start_callback(expr)       \
  (fetchcheck_NULL(expr) || \
   fetchcheck_cb_compatible((expr), fetch_resolver_start_callback))

/* evaluates to true if expr is of type fetch_read_callback or "similar" */
#define fetchcheck_read_cb(expr)                                         \
  (fetchcheck_NULL(expr) ||                                              \
   fetchcheck_cb_compatible((expr), __typeof__(fread) *) ||              \
   fetchcheck_cb_compatible((expr), fetch_read_callback) ||               \
   fetchcheck_cb_compatible((expr), _fetch_read_callback1) ||             \
   fetchcheck_cb_compatible((expr), _fetch_read_callback2) ||             \
   fetchcheck_cb_compatible((expr), _fetch_read_callback3) ||             \
   fetchcheck_cb_compatible((expr), _fetch_read_callback4) ||             \
   fetchcheck_cb_compatible((expr), _fetch_read_callback5) ||             \
   fetchcheck_cb_compatible((expr), _fetch_read_callback6))
typedef size_t (*_fetch_read_callback1)(char *, size_t, size_t, void *);
typedef size_t (*_fetch_read_callback2)(char *, size_t, size_t, const void *);
typedef size_t (*_fetch_read_callback3)(char *, size_t, size_t, FILE *);
typedef size_t (*_fetch_read_callback4)(void *, size_t, size_t, void *);
typedef size_t (*_fetch_read_callback5)(void *, size_t, size_t, const void *);
typedef size_t (*_fetch_read_callback6)(void *, size_t, size_t, FILE *);

/* evaluates to true if expr is of type fetch_write_callback or "similar" */
#define fetchcheck_write_cb(expr)                                        \
  (fetchcheck_read_cb(expr) ||                                           \
   fetchcheck_cb_compatible((expr), __typeof__(fwrite) *) ||             \
   fetchcheck_cb_compatible((expr), fetch_write_callback) ||              \
   fetchcheck_cb_compatible((expr), _fetch_write_callback1) ||            \
   fetchcheck_cb_compatible((expr), _fetch_write_callback2) ||            \
   fetchcheck_cb_compatible((expr), _fetch_write_callback3) ||            \
   fetchcheck_cb_compatible((expr), _fetch_write_callback4) ||            \
   fetchcheck_cb_compatible((expr), _fetch_write_callback5) ||            \
   fetchcheck_cb_compatible((expr), _fetch_write_callback6))
typedef size_t (*_fetch_write_callback1)(const char *, size_t, size_t, void *);
typedef size_t (*_fetch_write_callback2)(const char *, size_t, size_t,
                                       const void *);
typedef size_t (*_fetch_write_callback3)(const char *, size_t, size_t, FILE *);
typedef size_t (*_fetch_write_callback4)(const void *, size_t, size_t, void *);
typedef size_t (*_fetch_write_callback5)(const void *, size_t, size_t,
                                       const void *);
typedef size_t (*_fetch_write_callback6)(const void *, size_t, size_t, FILE *);

/* evaluates to true if expr is of type fetch_ioctl_callback or "similar" */
#define fetchcheck_ioctl_cb(expr)                                        \
  (fetchcheck_NULL(expr) ||                                              \
   fetchcheck_cb_compatible((expr), fetch_ioctl_callback) ||              \
   fetchcheck_cb_compatible((expr), _fetch_ioctl_callback1) ||            \
   fetchcheck_cb_compatible((expr), _fetch_ioctl_callback2) ||            \
   fetchcheck_cb_compatible((expr), _fetch_ioctl_callback3) ||            \
   fetchcheck_cb_compatible((expr), _fetch_ioctl_callback4))
typedef fetchioerr (*_fetch_ioctl_callback1)(FETCH *, int, void *);
typedef fetchioerr (*_fetch_ioctl_callback2)(FETCH *, int, const void *);
typedef fetchioerr (*_fetch_ioctl_callback3)(FETCH *, fetchiocmd, void *);
typedef fetchioerr (*_fetch_ioctl_callback4)(FETCH *, fetchiocmd, const void *);

/* evaluates to true if expr is of type fetch_sockopt_callback or "similar" */
#define fetchcheck_sockopt_cb(expr)                                      \
  (fetchcheck_NULL(expr) ||                                              \
   fetchcheck_cb_compatible((expr), fetch_sockopt_callback) ||            \
   fetchcheck_cb_compatible((expr), _fetch_sockopt_callback1) ||          \
   fetchcheck_cb_compatible((expr), _fetch_sockopt_callback2))
typedef int (*_fetch_sockopt_callback1)(void *, fetch_socket_t, fetchsocktype);
typedef int (*_fetch_sockopt_callback2)(const void *, fetch_socket_t,
                                      fetchsocktype);

/* evaluates to true if expr is of type fetch_opensocket_callback or
   "similar" */
#define fetchcheck_opensocket_cb(expr)                                   \
  (fetchcheck_NULL(expr) ||                                              \
   fetchcheck_cb_compatible((expr), fetch_opensocket_callback) ||         \
   fetchcheck_cb_compatible((expr), _fetch_opensocket_callback1) ||       \
   fetchcheck_cb_compatible((expr), _fetch_opensocket_callback2) ||       \
   fetchcheck_cb_compatible((expr), _fetch_opensocket_callback3) ||       \
   fetchcheck_cb_compatible((expr), _fetch_opensocket_callback4))
typedef fetch_socket_t (*_fetch_opensocket_callback1)
  (void *, fetchsocktype, struct fetch_sockaddr *);
typedef fetch_socket_t (*_fetch_opensocket_callback2)
  (void *, fetchsocktype, const struct fetch_sockaddr *);
typedef fetch_socket_t (*_fetch_opensocket_callback3)
  (const void *, fetchsocktype, struct fetch_sockaddr *);
typedef fetch_socket_t (*_fetch_opensocket_callback4)
  (const void *, fetchsocktype, const struct fetch_sockaddr *);

/* evaluates to true if expr is of type fetch_progress_callback or "similar" */
#define fetchcheck_progress_cb(expr)                                     \
  (fetchcheck_NULL(expr) ||                                              \
   fetchcheck_cb_compatible((expr), fetch_progress_callback) ||           \
   fetchcheck_cb_compatible((expr), _fetch_progress_callback1) ||         \
   fetchcheck_cb_compatible((expr), _fetch_progress_callback2))
typedef int (*_fetch_progress_callback1)(void *,
    double, double, double, double);
typedef int (*_fetch_progress_callback2)(const void *,
    double, double, double, double);

/* evaluates to true if expr is of type fetch_debug_callback or "similar" */
#define fetchcheck_debug_cb(expr)                                        \
  (fetchcheck_NULL(expr) ||                                              \
   fetchcheck_cb_compatible((expr), fetch_debug_callback) ||              \
   fetchcheck_cb_compatible((expr), _fetch_debug_callback1) ||            \
   fetchcheck_cb_compatible((expr), _fetch_debug_callback2) ||            \
   fetchcheck_cb_compatible((expr), _fetch_debug_callback3) ||            \
   fetchcheck_cb_compatible((expr), _fetch_debug_callback4) ||            \
   fetchcheck_cb_compatible((expr), _fetch_debug_callback5) ||            \
   fetchcheck_cb_compatible((expr), _fetch_debug_callback6) ||            \
   fetchcheck_cb_compatible((expr), _fetch_debug_callback7) ||            \
   fetchcheck_cb_compatible((expr), _fetch_debug_callback8))
typedef int (*_fetch_debug_callback1) (FETCH *,
    fetch_infotype, char *, size_t, void *);
typedef int (*_fetch_debug_callback2) (FETCH *,
    fetch_infotype, char *, size_t, const void *);
typedef int (*_fetch_debug_callback3) (FETCH *,
    fetch_infotype, const char *, size_t, void *);
typedef int (*_fetch_debug_callback4) (FETCH *,
    fetch_infotype, const char *, size_t, const void *);
typedef int (*_fetch_debug_callback5) (FETCH *,
    fetch_infotype, unsigned char *, size_t, void *);
typedef int (*_fetch_debug_callback6) (FETCH *,
    fetch_infotype, unsigned char *, size_t, const void *);
typedef int (*_fetch_debug_callback7) (FETCH *,
    fetch_infotype, const unsigned char *, size_t, void *);
typedef int (*_fetch_debug_callback8) (FETCH *,
    fetch_infotype, const unsigned char *, size_t, const void *);

/* evaluates to true if expr is of type fetch_ssl_ctx_callback or "similar" */
/* this is getting even messier... */
#define fetchcheck_ssl_ctx_cb(expr)                                      \
  (fetchcheck_NULL(expr) ||                                              \
   fetchcheck_cb_compatible((expr), fetch_ssl_ctx_callback) ||            \
   fetchcheck_cb_compatible((expr), _fetch_ssl_ctx_callback1) ||          \
   fetchcheck_cb_compatible((expr), _fetch_ssl_ctx_callback2) ||          \
   fetchcheck_cb_compatible((expr), _fetch_ssl_ctx_callback3) ||          \
   fetchcheck_cb_compatible((expr), _fetch_ssl_ctx_callback4) ||          \
   fetchcheck_cb_compatible((expr), _fetch_ssl_ctx_callback5) ||          \
   fetchcheck_cb_compatible((expr), _fetch_ssl_ctx_callback6) ||          \
   fetchcheck_cb_compatible((expr), _fetch_ssl_ctx_callback7) ||          \
   fetchcheck_cb_compatible((expr), _fetch_ssl_ctx_callback8))
typedef FETCHcode (*_fetch_ssl_ctx_callback1)(FETCH *, void *, void *);
typedef FETCHcode (*_fetch_ssl_ctx_callback2)(FETCH *, void *, const void *);
typedef FETCHcode (*_fetch_ssl_ctx_callback3)(FETCH *, const void *, void *);
typedef FETCHcode (*_fetch_ssl_ctx_callback4)(FETCH *, const void *,
                                            const void *);
#ifdef HEADER_SSL_H
/* hack: if we included OpenSSL's ssl.h, we know about SSL_CTX
 * this will of course break if we are included before OpenSSL headers...
 */
typedef FETCHcode (*_fetch_ssl_ctx_callback5)(FETCH *, SSL_CTX *, void *);
typedef FETCHcode (*_fetch_ssl_ctx_callback6)(FETCH *, SSL_CTX *, const void *);
typedef FETCHcode (*_fetch_ssl_ctx_callback7)(FETCH *, const SSL_CTX *, void *);
typedef FETCHcode (*_fetch_ssl_ctx_callback8)(FETCH *, const SSL_CTX *,
                                            const void *);
#else
typedef _fetch_ssl_ctx_callback1 _fetch_ssl_ctx_callback5;
typedef _fetch_ssl_ctx_callback1 _fetch_ssl_ctx_callback6;
typedef _fetch_ssl_ctx_callback1 _fetch_ssl_ctx_callback7;
typedef _fetch_ssl_ctx_callback1 _fetch_ssl_ctx_callback8;
#endif

/* evaluates to true if expr is of type fetch_conv_callback or "similar" */
#define fetchcheck_conv_cb(expr)                                         \
  (fetchcheck_NULL(expr) ||                                              \
   fetchcheck_cb_compatible((expr), fetch_conv_callback) ||               \
   fetchcheck_cb_compatible((expr), _fetch_conv_callback1) ||             \
   fetchcheck_cb_compatible((expr), _fetch_conv_callback2) ||             \
   fetchcheck_cb_compatible((expr), _fetch_conv_callback3) ||             \
   fetchcheck_cb_compatible((expr), _fetch_conv_callback4))
typedef FETCHcode (*_fetch_conv_callback1)(char *, size_t length);
typedef FETCHcode (*_fetch_conv_callback2)(const char *, size_t length);
typedef FETCHcode (*_fetch_conv_callback3)(void *, size_t length);
typedef FETCHcode (*_fetch_conv_callback4)(const void *, size_t length);

/* evaluates to true if expr is of type fetch_seek_callback or "similar" */
#define fetchcheck_seek_cb(expr)                                         \
  (fetchcheck_NULL(expr) ||                                              \
   fetchcheck_cb_compatible((expr), fetch_seek_callback) ||               \
   fetchcheck_cb_compatible((expr), _fetch_seek_callback1) ||             \
   fetchcheck_cb_compatible((expr), _fetch_seek_callback2))
typedef FETCHcode (*_fetch_seek_callback1)(void *, fetch_off_t, int);
typedef FETCHcode (*_fetch_seek_callback2)(const void *, fetch_off_t, int);


#endif /* FETCHINC_TYPECHECK_GCC_H */
