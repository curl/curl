#ifndef CURLINC_TYPECHECK_GCC_H
#define CURLINC_TYPECHECK_GCC_H
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

/* wraps curl_easy_setopt() with typechecking */

/* To add a new kind of warning, add an
 *   if(curlcheck_sometype_option(_curl_opt))
 *     if(!curlcheck_sometype(value))
 *       Wcurl_easy_setopt_err_sometype();
 * block and define curlcheck_sometype_option, curlcheck_sometype and
 * Wcurl_easy_setopt_err_sometype below
 *
 * NOTE: We use two nested 'if' statements here instead of the && operator, in
 *       order to work around gcc bug #32061. It affects only gcc 4.3.x/4.4.x
 *       when compiling with -Wlogical-op.
 *
 * To add an option that uses the same type as an existing option, you will
 * just need to extend the appropriate _curl_*_option macro
 */

#define curl_easy_setopt(handle, option, value)                         \
  __extension__({                                                       \
      if(__builtin_constant_p(option)) {                                \
        CURL_IGNORE_DEPRECATION(                                        \
          if(curlcheck_long_option(option))                             \
            if(!curlcheck_long(value))                                  \
              Wcurl_easy_setopt_err_long();                             \
          if(curlcheck_off_t_option(option))                            \
            if(!curlcheck_off_t(value))                                 \
              Wcurl_easy_setopt_err_curl_off_t();                       \
          if(curlcheck_string_option(option))                           \
            if(!curlcheck_string(value))                                \
              Wcurl_easy_setopt_err_string();                           \
          if((option) == CURLOPT_PRIVATE) { }                           \
          if(curlcheck_write_cb_option(option))                         \
            if(!curlcheck_write_cb(value))                              \
              Wcurl_easy_setopt_err_write_callback();                   \
          if(curlcheck_curl_option(option))                             \
            if(!curlcheck_curl(value))                                  \
              Wcurl_easy_setopt_err_curl();                             \
          if((option) == CURLOPT_RESOLVER_START_FUNCTION)               \
            if(!curlcheck_resolver_start_callback(value))               \
              Wcurl_easy_setopt_err_resolver_start_callback();          \
          if((option) == CURLOPT_READFUNCTION)                          \
            if(!curlcheck_read_cb(value))                               \
              Wcurl_easy_setopt_err_read_cb();                          \
          if((option) == CURLOPT_IOCTLFUNCTION)                         \
            if(!curlcheck_ioctl_cb(value))                              \
              Wcurl_easy_setopt_err_ioctl_cb();                         \
          if((option) == CURLOPT_SOCKOPTFUNCTION)                       \
            if(!curlcheck_sockopt_cb(value))                            \
              Wcurl_easy_setopt_err_sockopt_cb();                       \
          if((option) == CURLOPT_OPENSOCKETFUNCTION)                    \
            if(!curlcheck_opensocket_cb(value))                         \
              Wcurl_easy_setopt_err_opensocket_cb();                    \
          if((option) == CURLOPT_PROGRESSFUNCTION)                      \
            if(!curlcheck_progress_cb(value))                           \
              Wcurl_easy_setopt_err_progress_cb();                      \
          if((option) == CURLOPT_XFERINFOFUNCTION)                      \
            if(!curlcheck_xferinfo_cb(value))                           \
              Wcurl_easy_setopt_err_xferinfo_cb();                      \
          if((option) == CURLOPT_DEBUGFUNCTION)                         \
            if(!curlcheck_debug_cb(value))                              \
              Wcurl_easy_setopt_err_debug_cb();                         \
          if((option) == CURLOPT_SSL_CTX_FUNCTION)                      \
            if(!curlcheck_ssl_ctx_cb(value))                            \
              Wcurl_easy_setopt_err_ssl_ctx_cb();                       \
          if(curlcheck_conv_cb_option(option))                          \
            if(!curlcheck_conv_cb(value))                               \
              Wcurl_easy_setopt_err_conv_cb();                          \
          if((option) == CURLOPT_SEEKFUNCTION)                          \
            if(!curlcheck_seek_cb(value))                               \
              Wcurl_easy_setopt_err_seek_cb();                          \
          if((option) == CURLOPT_CHUNK_BGN_FUNCTION)                    \
            if(!curlcheck_chunk_bgn_cb(value))                          \
              Wcurl_easy_setopt_err_chunk_bgn_cb();                     \
          if((option) == CURLOPT_CHUNK_END_FUNCTION)                    \
            if(!curlcheck_chunk_end_cb(value))                          \
              Wcurl_easy_setopt_err_chunk_end_cb();                     \
          if((option) == CURLOPT_CLOSESOCKETFUNCTION)                   \
            if(!curlcheck_close_socket_cb(value))                       \
              Wcurl_easy_setopt_err_close_socket_cb();                  \
          if((option) == CURLOPT_FNMATCH_FUNCTION)                      \
            if(!curlcheck_fnmatch_cb(value))                            \
              Wcurl_easy_setopt_err_fnmatch_cb();                       \
          if((option) == CURLOPT_HSTSREADFUNCTION)                      \
            if(!curlcheck_hstsread_cb(value))                           \
              Wcurl_easy_setopt_err_hstsread_cb();                      \
          if((option) == CURLOPT_HSTSWRITEFUNCTION)                     \
            if(!curlcheck_hstswrite_cb(value))                          \
              Wcurl_easy_setopt_err_hstswrite_cb();                     \
          if((option) == CURLOPT_SSH_HOSTKEYFUNCTION)                   \
            if(!curlcheck_ssh_hostkey_cb(value))                        \
              Wcurl_easy_setopt_err_ssh_hostkey_cb();                   \
          if((option) == CURLOPT_SSH_KEYFUNCTION)                       \
            if(!curlcheck_ssh_key_cb(value))                            \
              Wcurl_easy_setopt_err_ssh_key_cb();                       \
          if((option) == CURLOPT_INTERLEAVEFUNCTION)                    \
            if(!curlcheck_interleave_cb(value))                         \
              Wcurl_easy_setopt_err_interleave_cb();                    \
          if((option) == CURLOPT_PREREQFUNCTION)                        \
            if(!curlcheck_prereq_cb(value))                             \
              Wcurl_easy_setopt_err_prereq_cb();                        \
          if((option) == CURLOPT_TRAILERFUNCTION)                       \
            if(!curlcheck_trailer_cb(value))                            \
              Wcurl_easy_setopt_err_trailer_cb();                       \
          if(curlcheck_cb_data_option(option))                          \
            if(!curlcheck_cb_data(value))                               \
              Wcurl_easy_setopt_err_cb_data();                          \
          if((option) == CURLOPT_ERRORBUFFER)                           \
            if(!curlcheck_error_buffer(value))                          \
              Wcurl_easy_setopt_err_error_buffer();                     \
          if((option) == CURLOPT_CURLU)                                 \
            if(!curlcheck_ptr((value), CURLU))                          \
              Wcurl_easy_setopt_err_curlu();                            \
          if((option) == CURLOPT_STDERR)                                \
            if(!curlcheck_FILE(value))                                  \
              Wcurl_easy_setopt_err_FILE();                             \
          if(curlcheck_postfields_option(option))                       \
            if(!curlcheck_postfields(value))                            \
              Wcurl_easy_setopt_err_postfields();                       \
          if((option) == CURLOPT_HTTPPOST)                              \
            if(!curlcheck_arr((value), struct curl_httppost))           \
              Wcurl_easy_setopt_err_curl_httpost();                     \
          if((option) == CURLOPT_MIMEPOST)                              \
            if(!curlcheck_ptr((value), curl_mime))                      \
              Wcurl_easy_setopt_err_curl_mimepost();                    \
          if(curlcheck_slist_option(option))                            \
            if(!curlcheck_arr((value), struct curl_slist))              \
              Wcurl_easy_setopt_err_curl_slist();                       \
          if((option) == CURLOPT_SHARE)                                 \
            if(!curlcheck_ptr((value), CURLSH))                         \
              Wcurl_easy_setopt_err_CURLSH();                           \
          )                                                             \
          }                                                             \
      curl_easy_setopt(handle, option, value);                          \
    })

/* wraps curl_easy_getinfo() with typechecking */
#define curl_easy_getinfo(handle, info, arg)                            \
  __extension__({                                                       \
      if(__builtin_constant_p(info)) {                                  \
        CURL_IGNORE_DEPRECATION(                                        \
          if(curlcheck_string_info(info))                               \
            if(!curlcheck_arr((arg), char *))                           \
              Wcurl_easy_getinfo_err_string();                          \
          if(curlcheck_long_info(info))                                 \
            if(!curlcheck_arr((arg), long))                             \
              Wcurl_easy_getinfo_err_long();                            \
          if(curlcheck_double_info(info))                               \
            if(!curlcheck_arr((arg), double))                           \
              Wcurl_easy_getinfo_err_double();                          \
          if(curlcheck_slist_info(info))                                \
            if(!curlcheck_arr((arg), struct curl_slist *))              \
              Wcurl_easy_getinfo_err_curl_slist();                      \
          if(curlcheck_tlssessioninfo_info(info))                       \
            if(!curlcheck_arr((arg), struct curl_tlssessioninfo *))     \
              Wcurl_easy_getinfo_err_curl_tlssessioninfo();             \
          if(curlcheck_certinfo_info(info))                             \
            if(!curlcheck_arr((arg), struct curl_certinfo *))           \
              Wcurl_easy_getinfo_err_curl_certinfo();                   \
          if(curlcheck_socket_info(info))                               \
            if(!curlcheck_arr((arg), curl_socket_t))                    \
              Wcurl_easy_getinfo_err_curl_socket();                     \
          if(curlcheck_off_t_info(info))                                \
            if(!curlcheck_arr((arg), curl_off_t))                       \
              Wcurl_easy_getinfo_err_curl_off_t();                      \
          )                                                             \
          }                                                             \
      curl_easy_getinfo(handle, info, arg);                             \
    })

#define curl_multi_setopt(handle, option, value)                        \
  __extension__({                                                       \
      if(__builtin_constant_p(option)) {                                \
        if(curlcheck_long_option(option))                               \
          if(!curlcheck_long(value))                                    \
            Wcurl_multi_setopt_err_long();                              \
        if(curlcheck_off_t_option(option))                              \
          if(!curlcheck_off_t(value))                                   \
            Wcurl_multi_setopt_err_curl_off_t();                        \
        if(curlcheck_multicb_data_option(option))                       \
          if(!curlcheck_cb_data(value))                                 \
            Wcurl_multi_setopt_err_cb_data();                           \
        if(curlcheck_charpp_option(option))                             \
          if(!curlcheck_ptrptr(value, char))                            \
            Wcurl_multi_setopt_err_charpp();                            \
        if((option) == CURLMOPT_PUSHFUNCTION)                           \
          if(!curlcheck_multipush_cb(value))                            \
            Wcurl_multi_setopt_err_pushcb();                            \
        if((option) == CURLMOPT_SOCKETFUNCTION)                         \
          if(!curlcheck_multisocket_cb(value))                          \
            Wcurl_multi_setopt_err_socketcb();                          \
        if((option) == CURLMOPT_TIMERFUNCTION)                          \
          if(!curlcheck_multitimer_cb(value))                           \
            Wcurl_multi_setopt_err_timercb();                           \
      }                                                                 \
      curl_multi_setopt(handle, option, value);                         \
    })

/* evaluates to true if the option takes a data argument to pass to a
   callback */
#define curlcheck_multicb_data_option(option)                           \
  ((option) == CURLMOPT_PUSHDATA ||                                     \
   (option) == CURLMOPT_SOCKETDATA ||                                   \
   (option) == CURLMOPT_TIMERDATA ||                                    \
   0)

/* evaluates to true if the option takes a char ** argument */
#define curlcheck_charpp_option(option)                                 \
  ((option) == CURLMOPT_PIPELINING_SERVER_BL ||                         \
   (option) == CURLMOPT_PIPELINING_SITE_BL ||                           \
   0)

/* evaluates to true if expr is of type curl_multi_timer_callback */
#define curlcheck_multitimer_cb(expr)                                   \
  (curlcheck_NULL(expr) ||                                              \
   curlcheck_cb_compatible((expr), curl_multi_timer_callback))

/* evaluates to true if expr is of type curl_socket_callback */
#define curlcheck_multisocket_cb(expr)                                  \
  (curlcheck_NULL(expr) ||                                              \
   curlcheck_cb_compatible((expr), curl_socket_callback))

/* evaluates to true if expr is of type curl_push_callback */
#define curlcheck_multipush_cb(expr)                                  \
  (curlcheck_NULL(expr) ||                                            \
   curlcheck_cb_compatible((expr), curl_push_callback))

/*
 * For now, just make sure that the functions are called with three arguments
 */
#define curl_share_setopt(share,opt,param) curl_share_setopt(share,opt,param)


/* the actual warnings, triggered by calling the Wcurl_easy_setopt_err*
 * functions */

/* To define a new warning, use _CURL_WARNING(identifier, "message") */
#define CURLWARNING(id, message)                                        \
  static void __attribute__((__warning__(message)))                     \
  __attribute__((__unused__)) __attribute__((__noinline__))             \
  id(void) { __asm__(""); }

CURLWARNING(Wcurl_multi_setopt_err_long,
            "curl_multi_setopt expects a long argument")
CURLWARNING(Wcurl_multi_setopt_err_curl_off_t,
            "curl_multi_setopt expects a curl_off_t argument")
CURLWARNING(Wcurl_multi_setopt_err_cb_data,
            "curl_multi_setopt expects a 'void *' argument")
CURLWARNING(Wcurl_multi_setopt_err_charpp,
            "curl_multi_setopt expects a 'char **' argument")
CURLWARNING(Wcurl_multi_setopt_err_pushcb,
            "curl_multi_setopt expects a curl_push_callback argument")
CURLWARNING(Wcurl_multi_setopt_err_socketcb,
            "curl_multi_setopt expects a curl_socket_callback argument")
CURLWARNING(Wcurl_multi_setopt_err_timercb,
            "curl_multi_setopt expects a curl_multi_timer_callback argument")

CURLWARNING(Wcurl_easy_setopt_err_long,
            "curl_easy_setopt expects a long argument")
CURLWARNING(Wcurl_easy_setopt_err_curl_off_t,
            "curl_easy_setopt expects a curl_off_t argument")
CURLWARNING(Wcurl_easy_setopt_err_string,
            "curl_easy_setopt expects a "
            "string ('char *' or char[]) argument")
CURLWARNING(Wcurl_easy_setopt_err_write_callback,
            "curl_easy_setopt expects a curl_write_callback argument")
CURLWARNING(Wcurl_easy_setopt_err_resolver_start_callback,
            "curl_easy_setopt expects a "
            "curl_resolver_start_callback argument")
CURLWARNING(Wcurl_easy_setopt_err_read_cb,
            "curl_easy_setopt expects a curl_read_callback argument")
CURLWARNING(Wcurl_easy_setopt_err_ioctl_cb,
            "curl_easy_setopt expects a curl_ioctl_callback argument")
CURLWARNING(Wcurl_easy_setopt_err_sockopt_cb,
            "curl_easy_setopt expects a curl_sockopt_callback argument")
CURLWARNING(Wcurl_easy_setopt_err_opensocket_cb,
            "curl_easy_setopt expects a "
            "curl_opensocket_callback argument")
CURLWARNING(Wcurl_easy_setopt_err_progress_cb,
            "curl_easy_setopt expects a curl_progress_callback argument")
CURLWARNING(Wcurl_easy_setopt_err_xferinfo_cb,
            "curl_easy_setopt expects a curl_xferinfo_callback argument")
CURLWARNING(Wcurl_easy_setopt_err_debug_cb,
            "curl_easy_setopt expects a curl_debug_callback argument")
CURLWARNING(Wcurl_easy_setopt_err_ssl_ctx_cb,
            "curl_easy_setopt expects a curl_ssl_ctx_callback argument")
CURLWARNING(Wcurl_easy_setopt_err_conv_cb,
            "curl_easy_setopt expects a curl_conv_callback argument")
CURLWARNING(Wcurl_easy_setopt_err_seek_cb,
            "curl_easy_setopt expects a curl_seek_callback argument")
CURLWARNING(Wcurl_easy_setopt_err_cb_data,
            "curl_easy_setopt expects a "
            "private data pointer as argument")
CURLWARNING(Wcurl_easy_setopt_err_chunk_bgn_cb,
            "curl_easy_setopt expects a curl_chunk_bgn_callback argument")
CURLWARNING(Wcurl_easy_setopt_err_chunk_end_cb,
            "curl_easy_setopt expects a curl_chunk_end_callback argument")
CURLWARNING(Wcurl_easy_setopt_err_close_socket_cb,
            "curl_easy_setopt expects a curl_closesocket_callback argument")
CURLWARNING(Wcurl_easy_setopt_err_fnmatch_cb,
            "curl_easy_setopt expects a curl_fnmatch_callback argument")
CURLWARNING(Wcurl_easy_setopt_err_hstsread_cb,
            "curl_easy_setopt expects a curl_hstsread_callback argument")
CURLWARNING(Wcurl_easy_setopt_err_hstswrite_cb,
            "curl_easy_setopt expects a curl_hstswrite_callback argument")
CURLWARNING(Wcurl_easy_setopt_err_ssh_key_cb,
            "curl_easy_setopt expects a curl_sshkeycallback argument")
CURLWARNING(Wcurl_easy_setopt_err_ssh_hostkey_cb,
            "curl_easy_setopt expects a curl_sshhostkeycallback argument")
CURLWARNING(Wcurl_easy_setopt_err_interleave_cb,
            "curl_easy_setopt expects a curl_interleave_callback argument")
CURLWARNING(Wcurl_easy_setopt_err_prereq_cb,
            "curl_easy_setopt expects a curl_prereq_callback argument")
CURLWARNING(Wcurl_easy_setopt_err_trailer_cb,
            "curl_easy_setopt expects a curl_trailerfunc_ok argument")
CURLWARNING(Wcurl_easy_setopt_err_error_buffer,
            "curl_easy_setopt expects a "
            "char buffer of CURL_ERROR_SIZE as argument")
CURLWARNING(Wcurl_easy_setopt_err_curlu,
            "curl_easy_setopt expects a 'CURLU *' argument")
CURLWARNING(Wcurl_easy_setopt_err_curl,
            "curl_easy_setopt expects a 'CURL *' argument")
CURLWARNING(Wcurl_easy_setopt_err_FILE,
            "curl_easy_setopt expects a 'FILE *' argument")
CURLWARNING(Wcurl_easy_setopt_err_postfields,
            "curl_easy_setopt expects a 'void *' or 'char *' argument")
CURLWARNING(Wcurl_easy_setopt_err_curl_httpost,
            "curl_easy_setopt expects a 'struct curl_httppost *' "
            "argument")
CURLWARNING(Wcurl_easy_setopt_err_curl_mimepost,
            "curl_easy_setopt expects a 'curl_mime *' "
            "argument")
CURLWARNING(Wcurl_easy_setopt_err_curl_slist,
            "curl_easy_setopt expects a 'struct curl_slist *' argument")
CURLWARNING(Wcurl_easy_setopt_err_CURLSH,
            "curl_easy_setopt expects a CURLSH* argument")
CURLWARNING(Wcurl_easy_getinfo_err_string,
            "curl_easy_getinfo expects a pointer to 'char *'")
CURLWARNING(Wcurl_easy_getinfo_err_long,
            "curl_easy_getinfo expects a pointer to long")
CURLWARNING(Wcurl_easy_getinfo_err_double,
            "curl_easy_getinfo expects a pointer to double")
CURLWARNING(Wcurl_easy_getinfo_err_curl_slist,
            "curl_easy_getinfo expects a pointer to 'struct curl_slist *'")
CURLWARNING(Wcurl_easy_getinfo_err_curl_tlssessioninfo,
            "curl_easy_getinfo expects a pointer to "
            "'struct curl_tlssessioninfo *'")
CURLWARNING(Wcurl_easy_getinfo_err_curl_certinfo,
            "curl_easy_getinfo expects a pointer to "
            "'struct curl_certinfo *'")
CURLWARNING(Wcurl_easy_getinfo_err_curl_socket,
            "curl_easy_getinfo expects a pointer to curl_socket_t")
CURLWARNING(Wcurl_easy_getinfo_err_curl_off_t,
            "curl_easy_getinfo expects a pointer to curl_off_t")

/* groups of curl_easy_setops options that take the same type of argument */

/* evaluates to true if option takes a long argument */
#define curlcheck_long_option(option)                   \
  (0 < (option) && (option) < CURLOPTTYPE_OBJECTPOINT)

#define curlcheck_off_t_option(option)                                  \
  (((option) > CURLOPTTYPE_OFF_T) && ((option) < CURLOPTTYPE_BLOB))

/* option takes a CURL * argument */
#define curlcheck_curl_option(option)                                 \
  ((option) == CURLOPT_STREAM_DEPENDS ||                              \
   (option) == CURLOPT_STREAM_DEPENDS_E ||                            \
   0)

/* evaluates to true if option takes a char* argument */
#define curlcheck_string_option(option)                                 \
  ((option) == CURLOPT_ABSTRACT_UNIX_SOCKET ||                          \
   (option) == CURLOPT_ACCEPT_ENCODING ||                               \
   (option) == CURLOPT_ALTSVC ||                                        \
   (option) == CURLOPT_CAINFO ||                                        \
   (option) == CURLOPT_CAPATH ||                                        \
   (option) == CURLOPT_COOKIE ||                                        \
   (option) == CURLOPT_COOKIEFILE ||                                    \
   (option) == CURLOPT_COOKIEJAR ||                                     \
   (option) == CURLOPT_COOKIELIST ||                                    \
   (option) == CURLOPT_CRLFILE ||                                       \
   (option) == CURLOPT_CUSTOMREQUEST ||                                 \
   (option) == CURLOPT_DEFAULT_PROTOCOL ||                              \
   (option) == CURLOPT_DNS_INTERFACE ||                                 \
   (option) == CURLOPT_DNS_LOCAL_IP4 ||                                 \
   (option) == CURLOPT_DNS_LOCAL_IP6 ||                                 \
   (option) == CURLOPT_DNS_SERVERS ||                                   \
   (option) == CURLOPT_DOH_URL ||                                       \
   (option) == CURLOPT_ECH ||                                           \
   (option) == CURLOPT_EGDSOCKET ||                                     \
   (option) == CURLOPT_FTP_ACCOUNT ||                                   \
   (option) == CURLOPT_FTP_ALTERNATIVE_TO_USER ||                       \
   (option) == CURLOPT_FTPPORT ||                                       \
   (option) == CURLOPT_HAPROXY_CLIENT_IP ||                             \
   (option) == CURLOPT_HSTS ||                                          \
   (option) == CURLOPT_INTERFACE ||                                     \
   (option) == CURLOPT_ISSUERCERT ||                                    \
   (option) == CURLOPT_KEYPASSWD ||                                     \
   (option) == CURLOPT_KRBLEVEL ||                                      \
   (option) == CURLOPT_LOGIN_OPTIONS ||                                 \
   (option) == CURLOPT_MAIL_AUTH ||                                     \
   (option) == CURLOPT_MAIL_FROM ||                                     \
   (option) == CURLOPT_NETRC_FILE ||                                    \
   (option) == CURLOPT_NOPROXY ||                                       \
   (option) == CURLOPT_PASSWORD ||                                      \
   (option) == CURLOPT_PINNEDPUBLICKEY ||                               \
   (option) == CURLOPT_PRE_PROXY ||                                     \
   (option) == CURLOPT_PROTOCOLS_STR ||                                 \
   (option) == CURLOPT_PROXY ||                                         \
   (option) == CURLOPT_PROXY_CAINFO ||                                  \
   (option) == CURLOPT_PROXY_CAPATH ||                                  \
   (option) == CURLOPT_PROXY_CRLFILE ||                                 \
   (option) == CURLOPT_PROXY_ISSUERCERT ||                              \
   (option) == CURLOPT_PROXY_KEYPASSWD ||                               \
   (option) == CURLOPT_PROXY_PINNEDPUBLICKEY ||                         \
   (option) == CURLOPT_PROXY_SERVICE_NAME ||                            \
   (option) == CURLOPT_PROXY_SSL_CIPHER_LIST ||                         \
   (option) == CURLOPT_PROXY_SSLCERT ||                                 \
   (option) == CURLOPT_PROXY_SSLCERTTYPE ||                             \
   (option) == CURLOPT_PROXY_SSLKEY ||                                  \
   (option) == CURLOPT_PROXY_SSLKEYTYPE ||                              \
   (option) == CURLOPT_PROXY_TLS13_CIPHERS ||                           \
   (option) == CURLOPT_PROXY_TLSAUTH_PASSWORD ||                        \
   (option) == CURLOPT_PROXY_TLSAUTH_TYPE ||                            \
   (option) == CURLOPT_PROXY_TLSAUTH_USERNAME ||                        \
   (option) == CURLOPT_PROXYPASSWORD ||                                 \
   (option) == CURLOPT_PROXYUSERNAME ||                                 \
   (option) == CURLOPT_PROXYUSERPWD ||                                  \
   (option) == CURLOPT_RANDOM_FILE ||                                   \
   (option) == CURLOPT_RANGE ||                                         \
   (option) == CURLOPT_REDIR_PROTOCOLS_STR ||                           \
   (option) == CURLOPT_REFERER ||                                       \
   (option) == CURLOPT_REQUEST_TARGET ||                                \
   (option) == CURLOPT_RTSP_SESSION_ID ||                               \
   (option) == CURLOPT_RTSP_STREAM_URI ||                               \
   (option) == CURLOPT_RTSP_TRANSPORT ||                                \
   (option) == CURLOPT_SASL_AUTHZID ||                                  \
   (option) == CURLOPT_SERVICE_NAME ||                                  \
   (option) == CURLOPT_SOCKS5_GSSAPI_SERVICE ||                         \
   (option) == CURLOPT_SSH_HOST_PUBLIC_KEY_MD5 ||                       \
   (option) == CURLOPT_SSH_HOST_PUBLIC_KEY_SHA256 ||                    \
   (option) == CURLOPT_SSH_KNOWNHOSTS ||                                \
   (option) == CURLOPT_SSH_PRIVATE_KEYFILE ||                           \
   (option) == CURLOPT_SSH_PUBLIC_KEYFILE ||                            \
   (option) == CURLOPT_SSLCERT ||                                       \
   (option) == CURLOPT_SSLCERTTYPE ||                                   \
   (option) == CURLOPT_SSLENGINE ||                                     \
   (option) == CURLOPT_SSLKEY ||                                        \
   (option) == CURLOPT_SSLKEYTYPE ||                                    \
   (option) == CURLOPT_SSL_CIPHER_LIST ||                               \
   (option) == CURLOPT_SSL_EC_CURVES ||                                 \
   (option) == CURLOPT_SSL_SIGNATURE_ALGORITHMS ||                      \
   (option) == CURLOPT_TLS13_CIPHERS ||                                 \
   (option) == CURLOPT_TLSAUTH_PASSWORD ||                              \
   (option) == CURLOPT_TLSAUTH_TYPE ||                                  \
   (option) == CURLOPT_TLSAUTH_USERNAME ||                              \
   (option) == CURLOPT_UNIX_SOCKET_PATH ||                              \
   (option) == CURLOPT_URL ||                                           \
   (option) == CURLOPT_USERAGENT ||                                     \
   (option) == CURLOPT_USERNAME ||                                      \
   (option) == CURLOPT_AWS_SIGV4 ||                                     \
   (option) == CURLOPT_USERPWD ||                                       \
   (option) == CURLOPT_XOAUTH2_BEARER ||                                \
   0)

/* evaluates to true if option takes a curl_write_callback argument */
#define curlcheck_write_cb_option(option)                               \
  ((option) == CURLOPT_HEADERFUNCTION ||                                \
   (option) == CURLOPT_WRITEFUNCTION)

/* evaluates to true if option takes a curl_conv_callback argument */
#define curlcheck_conv_cb_option(option)                                \
  ((option) == CURLOPT_CONV_TO_NETWORK_FUNCTION ||                      \
   (option) == CURLOPT_CONV_FROM_NETWORK_FUNCTION ||                    \
   (option) == CURLOPT_CONV_FROM_UTF8_FUNCTION)

/* evaluates to true if option takes a data argument to pass to a callback */
#define curlcheck_cb_data_option(option)                                      \
  ((option) == CURLOPT_CHUNK_DATA ||                                          \
   (option) == CURLOPT_CLOSESOCKETDATA ||                                     \
   (option) == CURLOPT_DEBUGDATA ||                                           \
   (option) == CURLOPT_FNMATCH_DATA ||                                        \
   (option) == CURLOPT_HEADERDATA ||                                          \
   (option) == CURLOPT_HSTSREADDATA ||                                        \
   (option) == CURLOPT_HSTSWRITEDATA ||                                       \
   (option) == CURLOPT_INTERLEAVEDATA ||                                      \
   (option) == CURLOPT_IOCTLDATA ||                                           \
   (option) == CURLOPT_OPENSOCKETDATA ||                                      \
   (option) == CURLOPT_PREREQDATA ||                                          \
   (option) == CURLOPT_XFERINFODATA ||                                        \
   (option) == CURLOPT_READDATA ||                                            \
   (option) == CURLOPT_SEEKDATA ||                                            \
   (option) == CURLOPT_SOCKOPTDATA ||                                         \
   (option) == CURLOPT_SSH_KEYDATA ||                                         \
   (option) == CURLOPT_SSL_CTX_DATA ||                                        \
   (option) == CURLOPT_WRITEDATA ||                                           \
   (option) == CURLOPT_RESOLVER_START_DATA ||                                 \
   (option) == CURLOPT_TRAILERDATA ||                                         \
   (option) == CURLOPT_SSH_HOSTKEYDATA ||                                     \
   0)

/* evaluates to true if option takes a POST data argument (void* or char*) */
#define curlcheck_postfields_option(option)                                   \
  ((option) == CURLOPT_POSTFIELDS ||                                          \
   (option) == CURLOPT_COPYPOSTFIELDS ||                                      \
   0)

/* evaluates to true if option takes a struct curl_slist * argument */
#define curlcheck_slist_option(option)                                        \
  ((option) == CURLOPT_HTTP200ALIASES ||                                      \
   (option) == CURLOPT_HTTPHEADER ||                                          \
   (option) == CURLOPT_MAIL_RCPT ||                                           \
   (option) == CURLOPT_POSTQUOTE ||                                           \
   (option) == CURLOPT_PREQUOTE ||                                            \
   (option) == CURLOPT_PROXYHEADER ||                                         \
   (option) == CURLOPT_QUOTE ||                                               \
   (option) == CURLOPT_RESOLVE ||                                             \
   (option) == CURLOPT_TELNETOPTIONS ||                                       \
   (option) == CURLOPT_CONNECT_TO ||                                          \
   0)

/* groups of curl_easy_getinfo infos that take the same type of argument */

/* evaluates to true if info expects a pointer to char * argument */
#define curlcheck_string_info(info)                             \
  (CURLINFO_STRING < (info) && (info) < CURLINFO_LONG &&        \
   (info) != CURLINFO_PRIVATE)

/* evaluates to true if info expects a pointer to long argument */
#define curlcheck_long_info(info)                       \
  (CURLINFO_LONG < (info) && (info) < CURLINFO_DOUBLE)

/* evaluates to true if info expects a pointer to double argument */
#define curlcheck_double_info(info)                     \
  (CURLINFO_DOUBLE < (info) && (info) < CURLINFO_SLIST)

/* true if info expects a pointer to struct curl_slist * argument */
#define curlcheck_slist_info(info)                                      \
  (((info) == CURLINFO_SSL_ENGINES) || ((info) == CURLINFO_COOKIELIST))

/* true if info expects a pointer to struct curl_tlssessioninfo * argument */
#define curlcheck_tlssessioninfo_info(info)                              \
  (((info) == CURLINFO_TLS_SSL_PTR) || ((info) == CURLINFO_TLS_SESSION))

/* true if info expects a pointer to struct curl_certinfo * argument */
#define curlcheck_certinfo_info(info) ((info) == CURLINFO_CERTINFO)

/* true if info expects a pointer to struct curl_socket_t argument */
#define curlcheck_socket_info(info)                     \
  (CURLINFO_SOCKET < (info) && (info) < CURLINFO_OFF_T)

/* true if info expects a pointer to curl_off_t argument */
#define curlcheck_off_t_info(info)              \
  (CURLINFO_OFF_T < (info))


/* typecheck helpers -- check whether given expression has requested type */

/* For pointers, you can use the curlcheck_ptr/curlcheck_arr macros,
 * otherwise define a new macro. Search for __builtin_types_compatible_p
 * in the GCC manual.
 * NOTE: these macros MUST NOT EVALUATE their arguments! The argument is
 * the actual expression passed to the curl_easy_setopt macro. This
 * means that you can only apply the sizeof and __typeof__ operators, no
 * == or whatsoever.
 */

/* XXX: should evaluate to true if expr is a pointer */
#define curlcheck_any_ptr(expr)                 \
  (sizeof(expr) == sizeof(void *))

/* evaluates to true if expr is NULL */
/* XXX: must not evaluate expr, so this check is not accurate */
#define curlcheck_NULL(expr)                                            \
  (__builtin_types_compatible_p(__typeof__(expr), __typeof__(NULL)))

/* evaluates to true if expr is type*, const type* or NULL */
#define curlcheck_ptr(expr, type)                                       \
  (curlcheck_NULL(expr) ||                                              \
   __builtin_types_compatible_p(__typeof__(expr), type *) ||            \
   __builtin_types_compatible_p(__typeof__(expr), const type *))

/* evaluates to true if expr is type**, const type** or NULL */
#define curlcheck_ptrptr(expr, type)                                    \
  (curlcheck_NULL(expr) ||                                              \
   __builtin_types_compatible_p(__typeof__(expr), type **) ||           \
   __builtin_types_compatible_p(__typeof__(expr), type *[]) ||          \
   __builtin_types_compatible_p(__typeof__(expr), const type *[]) ||    \
   __builtin_types_compatible_p(__typeof__(expr), const type **))

/* evaluates to true if expr is one of type[], type*, NULL or const type* */
#define curlcheck_arr(expr, type)                                       \
  (curlcheck_ptr((expr), type) ||                                       \
   __builtin_types_compatible_p(__typeof__(expr), type []))

/* evaluates to true if expr is a string */
#define curlcheck_string(expr)                                          \
  (curlcheck_arr((expr), char) ||                                       \
   curlcheck_arr((expr), signed char) ||                                \
   curlcheck_arr((expr), unsigned char))

/* evaluates to true if expr is a CURL * */
#define curlcheck_curl(expr)                                            \
  (curlcheck_NULL(expr) ||                                              \
   __builtin_types_compatible_p(__typeof__(expr), CURL *))


/* evaluates to true if expr is a long (no matter the signedness)
 * XXX: for now, int is also accepted (and therefore short and char, which
 * are promoted to int when passed to a variadic function) */
#define curlcheck_long(expr)                                            \
  (                                                                     \
  ((sizeof(long) != sizeof(int)) &&                                     \
   (__builtin_types_compatible_p(__typeof__(expr), long) ||             \
    __builtin_types_compatible_p(__typeof__(expr), signed long) ||      \
    __builtin_types_compatible_p(__typeof__(expr), unsigned long)))     \
  ||                                                                    \
  ((sizeof(long) == sizeof(int)) &&                                     \
  (__builtin_types_compatible_p(__typeof__(expr), long) ||              \
   __builtin_types_compatible_p(__typeof__(expr), signed long) ||       \
   __builtin_types_compatible_p(__typeof__(expr), unsigned long) ||     \
   __builtin_types_compatible_p(__typeof__(expr), int) ||               \
   __builtin_types_compatible_p(__typeof__(expr), signed int) ||        \
   __builtin_types_compatible_p(__typeof__(expr), unsigned int) ||      \
   __builtin_types_compatible_p(__typeof__(expr), short) ||             \
   __builtin_types_compatible_p(__typeof__(expr), signed short) ||      \
   __builtin_types_compatible_p(__typeof__(expr), unsigned short) ||    \
   __builtin_types_compatible_p(__typeof__(expr), char) ||              \
   __builtin_types_compatible_p(__typeof__(expr), signed char) ||       \
   __builtin_types_compatible_p(__typeof__(expr), unsigned char)))      \
                                                                  )

/* evaluates to true if expr is of type curl_off_t */
#define curlcheck_off_t(expr)                                   \
  (__builtin_types_compatible_p(__typeof__(expr), curl_off_t))

/* evaluates to true if expr is abuffer suitable for CURLOPT_ERRORBUFFER */
/* XXX: also check size of an char[] array? */
#define curlcheck_error_buffer(expr)                                    \
  (curlcheck_NULL(expr) ||                                              \
   __builtin_types_compatible_p(__typeof__(expr), char *) ||            \
   __builtin_types_compatible_p(__typeof__(expr), char[]))

/* evaluates to true if expr is of type (const) void* or (const) FILE* */
#if 0
#define curlcheck_cb_data(expr)                                         \
  (curlcheck_ptr((expr), void) ||                                       \
   curlcheck_ptr((expr), FILE))
#else /* be less strict */
#define curlcheck_cb_data(expr)                 \
  curlcheck_any_ptr(expr)
#endif

/* evaluates to true if expr is of type FILE* */
#define curlcheck_FILE(expr)                                            \
  (curlcheck_NULL(expr) ||                                              \
   (__builtin_types_compatible_p(__typeof__(expr), FILE *)))

/* evaluates to true if expr can be passed as POST data (void* or char*) */
#define curlcheck_postfields(expr)                                      \
  (curlcheck_ptr((expr), void) ||                                       \
   curlcheck_arr((expr), char) ||                                       \
   curlcheck_arr((expr), unsigned char))

/* helper: __builtin_types_compatible_p distinguishes between functions and
 * function pointers, hide it */
#define curlcheck_cb_compatible(func, type)                             \
  (__builtin_types_compatible_p(__typeof__(func), type) ||              \
   __builtin_types_compatible_p(__typeof__(func) *, type))

/* evaluates to true if expr is of type curl_resolver_start_callback */
#define curlcheck_resolver_start_callback(expr)       \
  (curlcheck_NULL(expr) || \
   curlcheck_cb_compatible((expr), curl_resolver_start_callback))

/* evaluates to true if expr is of type curl_read_callback or "similar" */
#define curlcheck_read_cb(expr)                                         \
  (curlcheck_NULL(expr) ||                                              \
   curlcheck_cb_compatible((expr), __typeof__(fread) *) ||              \
   curlcheck_cb_compatible((expr), curl_read_callback) ||               \
   curlcheck_cb_compatible((expr), Wcurl_read_callback1) ||             \
   curlcheck_cb_compatible((expr), Wcurl_read_callback2) ||             \
   curlcheck_cb_compatible((expr), Wcurl_read_callback3) ||             \
   curlcheck_cb_compatible((expr), Wcurl_read_callback4) ||             \
   curlcheck_cb_compatible((expr), Wcurl_read_callback5) ||             \
   curlcheck_cb_compatible((expr), Wcurl_read_callback6))
typedef size_t (*Wcurl_read_callback1)(char *, size_t, size_t, void *);
typedef size_t (*Wcurl_read_callback2)(char *, size_t, size_t, const void *);
typedef size_t (*Wcurl_read_callback3)(char *, size_t, size_t, FILE *);
typedef size_t (*Wcurl_read_callback4)(void *, size_t, size_t, void *);
typedef size_t (*Wcurl_read_callback5)(void *, size_t, size_t, const void *);
typedef size_t (*Wcurl_read_callback6)(void *, size_t, size_t, FILE *);

/* evaluates to true if expr is of type curl_write_callback or "similar" */
#define curlcheck_write_cb(expr)                                        \
  (curlcheck_read_cb(expr) ||                                           \
   curlcheck_cb_compatible((expr), __typeof__(fwrite) *) ||             \
   curlcheck_cb_compatible((expr), curl_write_callback) ||              \
   curlcheck_cb_compatible((expr), Wcurl_write_callback1) ||            \
   curlcheck_cb_compatible((expr), Wcurl_write_callback2) ||            \
   curlcheck_cb_compatible((expr), Wcurl_write_callback3) ||            \
   curlcheck_cb_compatible((expr), Wcurl_write_callback4) ||            \
   curlcheck_cb_compatible((expr), Wcurl_write_callback5) ||            \
   curlcheck_cb_compatible((expr), Wcurl_write_callback6))
typedef size_t (*Wcurl_write_callback1)(const char *, size_t, size_t, void *);
typedef size_t (*Wcurl_write_callback2)(const char *, size_t, size_t,
                                       const void *);
typedef size_t (*Wcurl_write_callback3)(const char *, size_t, size_t, FILE *);
typedef size_t (*Wcurl_write_callback4)(const void *, size_t, size_t, void *);
typedef size_t (*Wcurl_write_callback5)(const void *, size_t, size_t,
                                       const void *);
typedef size_t (*Wcurl_write_callback6)(const void *, size_t, size_t, FILE *);

/* evaluates to true if expr is of type curl_ioctl_callback or "similar" */
#define curlcheck_ioctl_cb(expr)                                        \
  (curlcheck_NULL(expr) ||                                              \
   curlcheck_cb_compatible((expr), curl_ioctl_callback) ||              \
   curlcheck_cb_compatible((expr), Wcurl_ioctl_callback1) ||            \
   curlcheck_cb_compatible((expr), Wcurl_ioctl_callback2) ||            \
   curlcheck_cb_compatible((expr), Wcurl_ioctl_callback3) ||            \
   curlcheck_cb_compatible((expr), Wcurl_ioctl_callback4))
typedef curlioerr (*Wcurl_ioctl_callback1)(CURL *, int, void *);
typedef curlioerr (*Wcurl_ioctl_callback2)(CURL *, int, const void *);
typedef curlioerr (*Wcurl_ioctl_callback3)(CURL *, curliocmd, void *);
typedef curlioerr (*Wcurl_ioctl_callback4)(CURL *, curliocmd, const void *);

/* evaluates to true if expr is of type curl_sockopt_callback or "similar" */
#define curlcheck_sockopt_cb(expr)                                      \
  (curlcheck_NULL(expr) ||                                              \
   curlcheck_cb_compatible((expr), curl_sockopt_callback) ||            \
   curlcheck_cb_compatible((expr), Wcurl_sockopt_callback1) ||          \
   curlcheck_cb_compatible((expr), Wcurl_sockopt_callback2))
typedef int (*Wcurl_sockopt_callback1)(void *, curl_socket_t, curlsocktype);
typedef int (*Wcurl_sockopt_callback2)(const void *, curl_socket_t,
                                      curlsocktype);

/* evaluates to true if expr is of type curl_opensocket_callback or
   "similar" */
#define curlcheck_opensocket_cb(expr)                                   \
  (curlcheck_NULL(expr) ||                                              \
   curlcheck_cb_compatible((expr), curl_opensocket_callback) ||         \
   curlcheck_cb_compatible((expr), Wcurl_opensocket_callback1) ||       \
   curlcheck_cb_compatible((expr), Wcurl_opensocket_callback2) ||       \
   curlcheck_cb_compatible((expr), Wcurl_opensocket_callback3) ||       \
   curlcheck_cb_compatible((expr), Wcurl_opensocket_callback4))
typedef curl_socket_t (*Wcurl_opensocket_callback1)
  (void *, curlsocktype, struct curl_sockaddr *);
typedef curl_socket_t (*Wcurl_opensocket_callback2)
  (void *, curlsocktype, const struct curl_sockaddr *);
typedef curl_socket_t (*Wcurl_opensocket_callback3)
  (const void *, curlsocktype, struct curl_sockaddr *);
typedef curl_socket_t (*Wcurl_opensocket_callback4)
  (const void *, curlsocktype, const struct curl_sockaddr *);

/* evaluates to true if expr is of type curl_progress_callback or "similar" */
#define curlcheck_progress_cb(expr)                                     \
  (curlcheck_NULL(expr) ||                                              \
   curlcheck_cb_compatible((expr), curl_progress_callback) ||           \
   curlcheck_cb_compatible((expr), Wcurl_progress_callback1) ||         \
   curlcheck_cb_compatible((expr), Wcurl_progress_callback2))
typedef int (*Wcurl_progress_callback1)(void *,
    double, double, double, double);
typedef int (*Wcurl_progress_callback2)(const void *,
    double, double, double, double);

/* evaluates to true if expr is of type curl_xferinfo_callback */
#define curlcheck_xferinfo_cb(expr)                                     \
  (curlcheck_NULL(expr) ||                                              \
   curlcheck_cb_compatible((expr), curl_xferinfo_callback))

/* evaluates to true if expr is of type curl_debug_callback or "similar" */
#define curlcheck_debug_cb(expr)                                        \
  (curlcheck_NULL(expr) ||                                              \
   curlcheck_cb_compatible((expr), curl_debug_callback) ||              \
   curlcheck_cb_compatible((expr), Wcurl_debug_callback1) ||            \
   curlcheck_cb_compatible((expr), Wcurl_debug_callback2) ||            \
   curlcheck_cb_compatible((expr), Wcurl_debug_callback3) ||            \
   curlcheck_cb_compatible((expr), Wcurl_debug_callback4) ||            \
   curlcheck_cb_compatible((expr), Wcurl_debug_callback5) ||            \
   curlcheck_cb_compatible((expr), Wcurl_debug_callback6) ||            \
   curlcheck_cb_compatible((expr), Wcurl_debug_callback7) ||            \
   curlcheck_cb_compatible((expr), Wcurl_debug_callback8))
typedef int (*Wcurl_debug_callback1) (CURL *,
    curl_infotype, char *, size_t, void *);
typedef int (*Wcurl_debug_callback2) (CURL *,
    curl_infotype, char *, size_t, const void *);
typedef int (*Wcurl_debug_callback3) (CURL *,
    curl_infotype, const char *, size_t, void *);
typedef int (*Wcurl_debug_callback4) (CURL *,
    curl_infotype, const char *, size_t, const void *);
typedef int (*Wcurl_debug_callback5) (CURL *,
    curl_infotype, unsigned char *, size_t, void *);
typedef int (*Wcurl_debug_callback6) (CURL *,
    curl_infotype, unsigned char *, size_t, const void *);
typedef int (*Wcurl_debug_callback7) (CURL *,
    curl_infotype, const unsigned char *, size_t, void *);
typedef int (*Wcurl_debug_callback8) (CURL *,
    curl_infotype, const unsigned char *, size_t, const void *);

/* evaluates to true if expr is of type curl_ssl_ctx_callback or "similar" */
/* this is getting even messier... */
#define curlcheck_ssl_ctx_cb(expr)                                      \
  (curlcheck_NULL(expr) ||                                              \
   curlcheck_cb_compatible((expr), curl_ssl_ctx_callback) ||            \
   curlcheck_cb_compatible((expr), Wcurl_ssl_ctx_callback1) ||          \
   curlcheck_cb_compatible((expr), Wcurl_ssl_ctx_callback2) ||          \
   curlcheck_cb_compatible((expr), Wcurl_ssl_ctx_callback3) ||          \
   curlcheck_cb_compatible((expr), Wcurl_ssl_ctx_callback4) ||          \
   curlcheck_cb_compatible((expr), Wcurl_ssl_ctx_callback5) ||          \
   curlcheck_cb_compatible((expr), Wcurl_ssl_ctx_callback6) ||          \
   curlcheck_cb_compatible((expr), Wcurl_ssl_ctx_callback7) ||          \
   curlcheck_cb_compatible((expr), Wcurl_ssl_ctx_callback8))
typedef CURLcode (*Wcurl_ssl_ctx_callback1)(CURL *, void *, void *);
typedef CURLcode (*Wcurl_ssl_ctx_callback2)(CURL *, void *, const void *);
typedef CURLcode (*Wcurl_ssl_ctx_callback3)(CURL *, const void *, void *);
typedef CURLcode (*Wcurl_ssl_ctx_callback4)(CURL *, const void *,
                                            const void *);
#ifdef HEADER_SSL_H
/* hack: if we included OpenSSL's ssl.h, we know about SSL_CTX
 * this will of course break if we are included before OpenSSL headers...
 */
typedef CURLcode (*Wcurl_ssl_ctx_callback5)(CURL *, SSL_CTX *, void *);
typedef CURLcode (*Wcurl_ssl_ctx_callback6)(CURL *, SSL_CTX *, const void *);
typedef CURLcode (*Wcurl_ssl_ctx_callback7)(CURL *, const SSL_CTX *, void *);
typedef CURLcode (*Wcurl_ssl_ctx_callback8)(CURL *, const SSL_CTX *,
                                            const void *);
#else
typedef Wcurl_ssl_ctx_callback1 Wcurl_ssl_ctx_callback5;
typedef Wcurl_ssl_ctx_callback1 Wcurl_ssl_ctx_callback6;
typedef Wcurl_ssl_ctx_callback1 Wcurl_ssl_ctx_callback7;
typedef Wcurl_ssl_ctx_callback1 Wcurl_ssl_ctx_callback8;
#endif

/* evaluates to true if expr is of type curl_conv_callback or "similar" */
#define curlcheck_conv_cb(expr)                                         \
  (curlcheck_NULL(expr) ||                                              \
   curlcheck_cb_compatible((expr), curl_conv_callback) ||               \
   curlcheck_cb_compatible((expr), Wcurl_conv_callback1) ||             \
   curlcheck_cb_compatible((expr), Wcurl_conv_callback2) ||             \
   curlcheck_cb_compatible((expr), Wcurl_conv_callback3) ||             \
   curlcheck_cb_compatible((expr), Wcurl_conv_callback4))
typedef CURLcode (*Wcurl_conv_callback1)(char *, size_t length);
typedef CURLcode (*Wcurl_conv_callback2)(const char *, size_t length);
typedef CURLcode (*Wcurl_conv_callback3)(void *, size_t length);
typedef CURLcode (*Wcurl_conv_callback4)(const void *, size_t length);

/* evaluates to true if expr is of type curl_seek_callback or "similar" */
#define curlcheck_seek_cb(expr)                                         \
  (curlcheck_NULL(expr) ||                                              \
   curlcheck_cb_compatible((expr), curl_seek_callback) ||               \
   curlcheck_cb_compatible((expr), Wcurl_seek_callback1) ||             \
   curlcheck_cb_compatible((expr), Wcurl_seek_callback2))
typedef CURLcode (*Wcurl_seek_callback1)(void *, curl_off_t, int);
typedef CURLcode (*Wcurl_seek_callback2)(const void *, curl_off_t, int);

/* evaluates to true if expr is of type curl_chunk_bgn_callback */
#define curlcheck_chunk_bgn_cb(expr)                                    \
  (curlcheck_NULL(expr) ||                                              \
   curlcheck_cb_compatible((expr), curl_chunk_bgn_callback) ||          \
   curlcheck_cb_compatible((expr), Wcurl_chunk_bgn_callback1) ||        \
   curlcheck_cb_compatible((expr), Wcurl_chunk_bgn_callback2))
typedef long (*Wcurl_chunk_bgn_callback1)(struct curl_fileinfo *,
                                          void *, int);
typedef long (*Wcurl_chunk_bgn_callback2)(void *, void *, int);

/* evaluates to true if expr is of type curl_chunk_end_callback */
#define curlcheck_chunk_end_cb(expr)                                    \
  (curlcheck_NULL(expr) ||                                              \
   curlcheck_cb_compatible((expr), curl_chunk_end_callback))

/* evaluates to true if expr is of type curl_closesocket_callback */
#define curlcheck_close_socket_cb(expr)                                 \
  (curlcheck_NULL(expr) ||                                              \
   curlcheck_cb_compatible((expr), curl_closesocket_callback))

/* evaluates to true if expr is of type curl_fnmatch_callback */
#define curlcheck_fnmatch_cb(expr)                                      \
  (curlcheck_NULL(expr) ||                                              \
   curlcheck_cb_compatible((expr), curl_fnmatch_callback))

/* evaluates to true if expr is of type curl_hstsread_callback */
#define curlcheck_hstsread_cb(expr)                                     \
  (curlcheck_NULL(expr) ||                                              \
   curlcheck_cb_compatible((expr), curl_hstsread_callback))

/* evaluates to true if expr is of type curl_hstswrite_callback */
#define curlcheck_hstswrite_cb(expr)                                    \
  (curlcheck_NULL(expr) ||                                              \
   curlcheck_cb_compatible((expr), curl_hstswrite_callback))

/* evaluates to true if expr is of type curl_sshhostkeycallback */
#define curlcheck_ssh_hostkey_cb(expr)                                  \
  (curlcheck_NULL(expr) ||                                              \
   curlcheck_cb_compatible((expr), curl_sshhostkeycallback))

/* evaluates to true if expr is of type curl_sshkeycallback */
#define curlcheck_ssh_key_cb(expr)                                      \
  (curlcheck_NULL(expr) ||                                              \
   curlcheck_cb_compatible((expr), curl_sshkeycallback))

/* evaluates to true if expr is of type curl_interleave_callback */
#define curlcheck_interleave_cb(expr)                                   \
  (curlcheck_NULL(expr) ||                                              \
   curlcheck_cb_compatible((expr), Wcurl_interleave_callback1) ||       \
   curlcheck_cb_compatible((expr), Wcurl_interleave_callback2))
typedef size_t (*Wcurl_interleave_callback1)(void *p, size_t s,
                                             size_t n, void *u);
typedef size_t (*Wcurl_interleave_callback2)(char *p, size_t s,
                                             size_t n, void *u);

/* evaluates to true if expr is of type curl_prereq_callback */
#define curlcheck_prereq_cb(expr)                                       \
  (curlcheck_NULL(expr) ||                                              \
   curlcheck_cb_compatible((expr), curl_prereq_callback))

/* evaluates to true if expr is of type curl_trailer_callback */
#define curlcheck_trailer_cb(expr)                                      \
  (curlcheck_NULL(expr) ||                                              \
   curlcheck_cb_compatible((expr), curl_trailer_callback))

#endif /* CURLINC_TYPECHECK_GCC_H */
