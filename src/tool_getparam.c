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
#include "tool_setup.h"

#include "strcase.h"

#include "curlx.h"

#include "tool_binmode.h"
#include "tool_cfgable.h"
#include "tool_cb_prg.h"
#include "tool_filetime.h"
#include "tool_formparse.h"
#include "tool_getparam.h"
#include "tool_helpers.h"
#include "tool_libinfo.h"
#include "tool_msgs.h"
#include "tool_paramhlp.h"
#include "tool_parsecfg.h"
#include "tool_main.h"
#include "dynbuf.h"
#include "tool_stderr.h"
#include "var.h"

#include "memdebug.h" /* keep this as LAST include */

#ifdef MSDOS
#  define USE_WATT32
#endif

#define ALLOW_BLANK TRUE
#define DENY_BLANK FALSE

static ParameterError getstr(char **str, const char *val, bool allowblank)
{
  if(*str) {
    free(*str);
    *str = NULL;
  }
  if(val) {
    if(!allowblank && !val[0])
      return PARAM_BLANK_STRING;

    *str = strdup(val);
    if(!*str)
      return PARAM_NO_MEM;
  }
  return PARAM_OK;
}

/* this array MUST be alphasorted based on the 'lname' */
static const struct LongShort aliases[]= {
  {"abstract-unix-socket",       ARG_FILE, ' ', C_ABSTRACT_UNIX_SOCKET},
  {"alpn",                       ARG_BOOL|ARG_NO, ' ', C_ALPN},
  {"alt-svc",                    ARG_STRG, ' ', C_ALT_SVC},
  {"anyauth",                    ARG_BOOL, ' ', C_ANYAUTH},
  {"append",                     ARG_BOOL, 'a', C_APPEND},
  {"aws-sigv4",                  ARG_STRG, ' ', C_AWS_SIGV4},
  {"basic",                      ARG_BOOL, ' ', C_BASIC},
  {"buffer",                     ARG_BOOL|ARG_NO, 'N', C_BUFFER},
  {"ca-native",                  ARG_BOOL, ' ', C_CA_NATIVE},
  {"cacert",                     ARG_FILE, ' ', C_CACERT},
  {"capath",                     ARG_FILE, ' ', C_CAPATH},
  {"cert",                       ARG_FILE, 'E', C_CERT},
  {"cert-status",                ARG_BOOL, ' ', C_CERT_STATUS},
  {"cert-type",                  ARG_STRG, ' ', C_CERT_TYPE},
  {"ciphers",                    ARG_STRG, ' ', C_CIPHERS},
  {"clobber",                    ARG_BOOL|ARG_NO, ' ', C_CLOBBER},
  {"compressed",                 ARG_BOOL, ' ', C_COMPRESSED},
  {"compressed-ssh",             ARG_BOOL, ' ', C_COMPRESSED_SSH},
  {"config",                     ARG_FILE, 'K', C_CONFIG},
  {"connect-timeout",            ARG_STRG, ' ', C_CONNECT_TIMEOUT},
  {"connect-to",                 ARG_STRG, ' ', C_CONNECT_TO},
  {"continue-at",                ARG_STRG, 'C', C_CONTINUE_AT},
  {"cookie",                     ARG_STRG, 'b', C_COOKIE},
  {"cookie-jar",                 ARG_STRG, 'c', C_COOKIE_JAR},
  {"create-dirs",                ARG_BOOL, ' ', C_CREATE_DIRS},
  {"create-file-mode",           ARG_STRG, ' ', C_CREATE_FILE_MODE},
  {"crlf",                       ARG_BOOL, ' ', C_CRLF},
  {"crlfile",                    ARG_FILE, ' ', C_CRLFILE},
  {"curves",                     ARG_STRG, ' ', C_CURVES},
  {"data",                       ARG_STRG, 'd', C_DATA},
  {"data-ascii",                 ARG_STRG, ' ', C_DATA_ASCII},
  {"data-binary",                ARG_STRG, ' ', C_DATA_BINARY},
  {"data-raw",                   ARG_STRG, ' ', C_DATA_RAW},
  {"data-urlencode",             ARG_STRG, ' ', C_DATA_URLENCODE},
  {"delegation",                 ARG_STRG, ' ', C_DELEGATION},
  {"digest",                     ARG_BOOL, ' ', C_DIGEST},
  {"disable",                    ARG_BOOL, 'q', C_DISABLE},
  {"disable-eprt",               ARG_BOOL, ' ', C_DISABLE_EPRT},
  {"disable-epsv",               ARG_BOOL, ' ', C_DISABLE_EPSV},
  {"disallow-username-in-url",   ARG_BOOL, ' ', C_DISALLOW_USERNAME_IN_URL},
  {"dns-interface",              ARG_STRG, ' ', C_DNS_INTERFACE},
  {"dns-ipv4-addr",              ARG_STRG, ' ', C_DNS_IPV4_ADDR},
  {"dns-ipv6-addr",              ARG_STRG, ' ', C_DNS_IPV6_ADDR},
  {"dns-servers",                ARG_STRG, ' ', C_DNS_SERVERS},
  {"doh-cert-status",            ARG_BOOL, ' ', C_DOH_CERT_STATUS},
  {"doh-insecure",               ARG_BOOL, ' ', C_DOH_INSECURE},
  {"doh-url"        ,            ARG_STRG, ' ', C_DOH_URL},
  {"dump-ca-embed",              ARG_NONE, ' ', C_DUMP_CA_EMBED},
  {"dump-header",                ARG_FILE, 'D', C_DUMP_HEADER},
  {"ech",                        ARG_STRG, ' ', C_ECH},
  {"egd-file",                   ARG_STRG, ' ', C_EGD_FILE},
  {"engine",                     ARG_STRG, ' ', C_ENGINE},
  {"eprt",                       ARG_BOOL, ' ', C_EPRT},
  {"epsv",                       ARG_BOOL, ' ', C_EPSV},
  {"etag-compare",               ARG_FILE, ' ', C_ETAG_COMPARE},
  {"etag-save",                  ARG_FILE, ' ', C_ETAG_SAVE},
  {"expect100-timeout",          ARG_STRG, ' ', C_EXPECT100_TIMEOUT},
  {"fail",                       ARG_BOOL, 'f', C_FAIL},
  {"fail-early",                 ARG_BOOL, ' ', C_FAIL_EARLY},
  {"fail-with-body",             ARG_BOOL, ' ', C_FAIL_WITH_BODY},
  {"false-start",                ARG_BOOL, ' ', C_FALSE_START},
  {"form",                       ARG_STRG, 'F', C_FORM},
  {"form-escape",                ARG_BOOL, ' ', C_FORM_ESCAPE},
  {"form-string",                ARG_STRG, ' ', C_FORM_STRING},
  {"ftp-account",                ARG_STRG, ' ', C_FTP_ACCOUNT},
  {"ftp-alternative-to-user",    ARG_STRG, ' ', C_FTP_ALTERNATIVE_TO_USER},
  {"ftp-create-dirs",            ARG_BOOL, ' ', C_FTP_CREATE_DIRS},
  {"ftp-method",                 ARG_STRG, ' ', C_FTP_METHOD},
  {"ftp-pasv",                   ARG_BOOL, ' ', C_FTP_PASV},
  {"ftp-port",                   ARG_STRG, 'P', C_FTP_PORT},
  {"ftp-pret",                   ARG_BOOL, ' ', C_FTP_PRET},
  {"ftp-skip-pasv-ip",           ARG_BOOL, ' ', C_FTP_SKIP_PASV_IP},
  {"ftp-ssl",                    ARG_BOOL, ' ', C_FTP_SSL},
  {"ftp-ssl-ccc",                ARG_BOOL, ' ', C_FTP_SSL_CCC},
  {"ftp-ssl-ccc-mode",           ARG_STRG, ' ', C_FTP_SSL_CCC_MODE},
  {"ftp-ssl-control",            ARG_BOOL, ' ', C_FTP_SSL_CONTROL},
  {"ftp-ssl-reqd",               ARG_BOOL, ' ', C_FTP_SSL_REQD},
  {"get",                        ARG_BOOL, 'G', C_GET},
  {"globoff",                    ARG_BOOL, 'g', C_GLOBOFF},
  {"happy-eyeballs-timeout-ms",  ARG_STRG, ' ', C_HAPPY_EYEBALLS_TIMEOUT_MS},
  {"haproxy-clientip",           ARG_STRG, ' ', C_HAPROXY_CLIENTIP},
  {"haproxy-protocol",           ARG_BOOL, ' ', C_HAPROXY_PROTOCOL},
  {"head",                       ARG_BOOL, 'I', C_HEAD},
  {"header",                     ARG_STRG, 'H', C_HEADER},
  {"help",                       ARG_BOOL, 'h', C_HELP},
  {"hostpubmd5",                 ARG_STRG, ' ', C_HOSTPUBMD5},
  {"hostpubsha256",              ARG_STRG, ' ', C_HOSTPUBSHA256},
  {"hsts",                       ARG_STRG, ' ', C_HSTS},
  {"http0.9",                    ARG_BOOL, ' ', C_HTTP0_9},
  {"http1.0",                    ARG_NONE, '0', C_HTTP1_0},
  {"http1.1",                    ARG_NONE, ' ', C_HTTP1_1},
  {"http2",                      ARG_NONE, ' ', C_HTTP2},
  {"http2-prior-knowledge",      ARG_NONE, ' ', C_HTTP2_PRIOR_KNOWLEDGE},
  {"http3",                      ARG_NONE, ' ', C_HTTP3},
  {"http3-only",                 ARG_NONE, ' ', C_HTTP3_ONLY},
  {"ignore-content-length",      ARG_BOOL, ' ', C_IGNORE_CONTENT_LENGTH},
  {"include",                    ARG_BOOL, ' ', C_INCLUDE},
  {"insecure",                   ARG_BOOL, 'k', C_INSECURE},
  {"interface",                  ARG_STRG, ' ', C_INTERFACE},
  {"ip-tos",                     ARG_STRG, ' ', C_IP_TOS},
#ifndef CURL_DISABLE_IPFS
  {"ipfs-gateway",               ARG_STRG, ' ', C_IPFS_GATEWAY},
#endif /* !CURL_DISABLE_IPFS */
  {"ipv4",                       ARG_NONE, '4', C_IPV4},
  {"ipv6",                       ARG_NONE, '6', C_IPV6},
  {"json",                       ARG_STRG, ' ', C_JSON},
  {"junk-session-cookies",       ARG_BOOL, 'j', C_JUNK_SESSION_COOKIES},
  {"keepalive",                  ARG_BOOL|ARG_NO, ' ', C_KEEPALIVE},
  {"keepalive-cnt",              ARG_STRG, ' ', C_KEEPALIVE_CNT},
  {"keepalive-time",             ARG_STRG, ' ', C_KEEPALIVE_TIME},
  {"key",                        ARG_FILE, ' ', C_KEY},
  {"key-type",                   ARG_STRG, ' ', C_KEY_TYPE},
  {"krb",                        ARG_STRG, ' ', C_KRB},
  {"krb4",                       ARG_STRG, ' ', C_KRB4},
  {"libcurl",                    ARG_STRG, ' ', C_LIBCURL},
  {"limit-rate",                 ARG_STRG, ' ', C_LIMIT_RATE},
  {"list-only",                  ARG_BOOL, 'l', C_LIST_ONLY},
  {"local-port",                 ARG_STRG, ' ', C_LOCAL_PORT},
  {"location",                   ARG_BOOL, 'L', C_LOCATION},
  {"location-trusted",           ARG_BOOL, ' ', C_LOCATION_TRUSTED},
  {"login-options",              ARG_STRG, ' ', C_LOGIN_OPTIONS},
  {"mail-auth",                  ARG_STRG, ' ', C_MAIL_AUTH},
  {"mail-from",                  ARG_STRG, ' ', C_MAIL_FROM},
  {"mail-rcpt",                  ARG_STRG, ' ', C_MAIL_RCPT},
  {"mail-rcpt-allowfails",       ARG_BOOL, ' ', C_MAIL_RCPT_ALLOWFAILS},
  {"manual",                     ARG_BOOL, 'M', C_MANUAL},
  {"max-filesize",               ARG_STRG, ' ', C_MAX_FILESIZE},
  {"max-redirs",                 ARG_STRG, ' ', C_MAX_REDIRS},
  {"max-time",                   ARG_STRG, 'm', C_MAX_TIME},
  {"metalink",                   ARG_BOOL, ' ', C_METALINK},
  {"mptcp",                      ARG_BOOL, ' ', C_MPTCP},
  {"negotiate",                  ARG_BOOL, ' ', C_NEGOTIATE},
  {"netrc",                      ARG_BOOL, 'n', C_NETRC},
  {"netrc-file",                 ARG_FILE, ' ', C_NETRC_FILE},
  {"netrc-optional",             ARG_BOOL, ' ', C_NETRC_OPTIONAL},
  {"next",                       ARG_NONE, ':', C_NEXT},
  {"noproxy",                    ARG_STRG, ' ', C_NOPROXY},
  {"npn",                        ARG_BOOL|ARG_NO, ' ', C_NPN},
  {"ntlm",                       ARG_BOOL, ' ', C_NTLM},
  {"ntlm-wb",                    ARG_BOOL, ' ', C_NTLM_WB},
  {"oauth2-bearer",              ARG_STRG, ' ', C_OAUTH2_BEARER},
  {"output",                     ARG_FILE, 'o', C_OUTPUT},
  {"output-dir",                 ARG_STRG, ' ', C_OUTPUT_DIR},
  {"parallel",                   ARG_BOOL, 'Z', C_PARALLEL},
  {"parallel-immediate",         ARG_BOOL, ' ', C_PARALLEL_IMMEDIATE},
  {"parallel-max",               ARG_STRG, ' ', C_PARALLEL_MAX},
  {"pass",                       ARG_STRG, ' ', C_PASS},
  {"path-as-is",                 ARG_BOOL, ' ', C_PATH_AS_IS},
  {"pinnedpubkey",               ARG_STRG, ' ', C_PINNEDPUBKEY},
  {"post301",                    ARG_BOOL, ' ', C_POST301},
  {"post302",                    ARG_BOOL, ' ', C_POST302},
  {"post303",                    ARG_BOOL, ' ', C_POST303},
  {"preproxy",                   ARG_STRG, ' ', C_PREPROXY},
  {"progress-bar",               ARG_BOOL, '#', C_PROGRESS_BAR},
  {"progress-meter",             ARG_BOOL|ARG_NO, ' ', C_PROGRESS_METER},
  {"proto",                      ARG_STRG, ' ', C_PROTO},
  {"proto-default",              ARG_STRG, ' ', C_PROTO_DEFAULT},
  {"proto-redir",                ARG_STRG, ' ', C_PROTO_REDIR},
  {"proxy",                      ARG_STRG, 'x', C_PROXY},
  {"proxy-anyauth",              ARG_BOOL, ' ', C_PROXY_ANYAUTH},
  {"proxy-basic",                ARG_BOOL, ' ', C_PROXY_BASIC},
  {"proxy-ca-native",            ARG_BOOL, ' ', C_PROXY_CA_NATIVE},
  {"proxy-cacert",               ARG_FILE, ' ', C_PROXY_CACERT},
  {"proxy-capath",               ARG_FILE, ' ', C_PROXY_CAPATH},
  {"proxy-cert",                 ARG_FILE, ' ', C_PROXY_CERT},
  {"proxy-cert-type",            ARG_STRG, ' ', C_PROXY_CERT_TYPE},
  {"proxy-ciphers",              ARG_STRG, ' ', C_PROXY_CIPHERS},
  {"proxy-crlfile",              ARG_FILE, ' ', C_PROXY_CRLFILE},
  {"proxy-digest",               ARG_BOOL, ' ', C_PROXY_DIGEST},
  {"proxy-header",               ARG_STRG, ' ', C_PROXY_HEADER},
  {"proxy-http2",                ARG_BOOL, ' ', C_PROXY_HTTP2},
  {"proxy-insecure",             ARG_BOOL, ' ', C_PROXY_INSECURE},
  {"proxy-key",                  ARG_FILE, ' ', C_PROXY_KEY},
  {"proxy-key-type",             ARG_STRG, ' ', C_PROXY_KEY_TYPE},
  {"proxy-negotiate",            ARG_BOOL, ' ', C_PROXY_NEGOTIATE},
  {"proxy-ntlm",                 ARG_BOOL, ' ', C_PROXY_NTLM},
  {"proxy-pass",                 ARG_STRG, ' ', C_PROXY_PASS},
  {"proxy-pinnedpubkey",         ARG_STRG, ' ', C_PROXY_PINNEDPUBKEY},
  {"proxy-service-name",         ARG_STRG, ' ', C_PROXY_SERVICE_NAME},
  {"proxy-ssl-allow-beast",      ARG_BOOL, ' ', C_PROXY_SSL_ALLOW_BEAST},
  {"proxy-ssl-auto-client-cert", ARG_BOOL, ' ', C_PROXY_SSL_AUTO_CLIENT_CERT},
  {"proxy-tls13-ciphers",        ARG_STRG, ' ', C_PROXY_TLS13_CIPHERS},
  {"proxy-tlsauthtype",          ARG_STRG, ' ', C_PROXY_TLSAUTHTYPE},
  {"proxy-tlspassword",          ARG_STRG, ' ', C_PROXY_TLSPASSWORD},
  {"proxy-tlsuser",              ARG_STRG, ' ', C_PROXY_TLSUSER},
  {"proxy-tlsv1",                ARG_NONE, ' ', C_PROXY_TLSV1},
  {"proxy-user",                 ARG_STRG, 'U', C_PROXY_USER},
  {"proxy1.0",                   ARG_STRG, ' ', C_PROXY1_0},
  {"proxytunnel",                ARG_BOOL, 'p', C_PROXYTUNNEL},
  {"pubkey",                     ARG_STRG, ' ', C_PUBKEY},
  {"quote",                      ARG_STRG, 'Q', C_QUOTE},
  {"random-file",                ARG_FILE, ' ', C_RANDOM_FILE},
  {"range",                      ARG_STRG, 'r', C_RANGE},
  {"rate",                       ARG_STRG, ' ', C_RATE},
  {"raw",                        ARG_BOOL, ' ', C_RAW},
  {"referer",                    ARG_STRG, 'e', C_REFERER},
  {"remote-header-name",         ARG_BOOL, 'J', C_REMOTE_HEADER_NAME},
  {"remote-name",                ARG_BOOL, 'O', C_REMOTE_NAME},
  {"remote-name-all",            ARG_BOOL, ' ', C_REMOTE_NAME_ALL},
  {"remote-time",                ARG_BOOL, 'R', C_REMOTE_TIME},
  {"remove-on-error",            ARG_BOOL, ' ', C_REMOVE_ON_ERROR},
  {"request",                    ARG_STRG, 'X', C_REQUEST},
  {"request-target",             ARG_STRG, ' ', C_REQUEST_TARGET},
  {"resolve",                    ARG_STRG, ' ', C_RESOLVE},
  {"retry",                      ARG_STRG, ' ', C_RETRY},
  {"retry-all-errors",           ARG_BOOL, ' ', C_RETRY_ALL_ERRORS},
  {"retry-connrefused",          ARG_BOOL, ' ', C_RETRY_CONNREFUSED},
  {"retry-delay",                ARG_STRG, ' ', C_RETRY_DELAY},
  {"retry-max-time",             ARG_STRG, ' ', C_RETRY_MAX_TIME},
  {"sasl-authzid",               ARG_STRG, ' ', C_SASL_AUTHZID},
  {"sasl-ir",                    ARG_BOOL, ' ', C_SASL_IR},
  {"service-name",               ARG_STRG, ' ', C_SERVICE_NAME},
  {"sessionid",                  ARG_BOOL|ARG_NO, ' ', C_SESSIONID},
  {"show-error",                 ARG_BOOL, 'S', C_SHOW_ERROR},
  {"show-headers",               ARG_BOOL, 'i', C_SHOW_HEADERS},
  {"silent",                     ARG_BOOL, 's', C_SILENT},
  {"skip-existing",              ARG_BOOL, ' ', C_SKIP_EXISTING},
  {"socks4",                     ARG_STRG, ' ', C_SOCKS4},
  {"socks4a",                    ARG_STRG, ' ', C_SOCKS4A},
  {"socks5",                     ARG_STRG, ' ', C_SOCKS5},
  {"socks5-basic",               ARG_BOOL, ' ', C_SOCKS5_BASIC},
  {"socks5-gssapi",              ARG_BOOL, ' ', C_SOCKS5_GSSAPI},
  {"socks5-gssapi-nec",          ARG_BOOL, ' ', C_SOCKS5_GSSAPI_NEC},
  {"socks5-gssapi-service",      ARG_STRG, ' ', C_SOCKS5_GSSAPI_SERVICE},
  {"socks5-hostname",            ARG_STRG, ' ', C_SOCKS5_HOSTNAME},
  {"speed-limit",                ARG_STRG, 'Y', C_SPEED_LIMIT},
  {"speed-time",                 ARG_STRG, 'y', C_SPEED_TIME},
  {"ssl",                        ARG_BOOL, ' ', C_SSL},
  {"ssl-allow-beast",            ARG_BOOL, ' ', C_SSL_ALLOW_BEAST},
  {"ssl-auto-client-cert",       ARG_BOOL, ' ', C_SSL_AUTO_CLIENT_CERT},
  {"ssl-no-revoke",              ARG_BOOL, ' ', C_SSL_NO_REVOKE},
  {"ssl-reqd",                   ARG_BOOL, ' ', C_SSL_REQD},
  {"ssl-revoke-best-effort",     ARG_BOOL, ' ', C_SSL_REVOKE_BEST_EFFORT},
  {"sslv2",                      ARG_NONE, '2', C_SSLV2},
  {"sslv3",                      ARG_NONE, '3', C_SSLV3},
  {"stderr",                     ARG_FILE, ' ', C_STDERR},
  {"styled-output",              ARG_BOOL, ' ', C_STYLED_OUTPUT},
  {"suppress-connect-headers",   ARG_BOOL, ' ', C_SUPPRESS_CONNECT_HEADERS},
  {"tcp-fastopen",               ARG_BOOL, ' ', C_TCP_FASTOPEN},
  {"tcp-nodelay",                ARG_BOOL, ' ', C_TCP_NODELAY},
  {"telnet-option",              ARG_STRG, 't', C_TELNET_OPTION},
  {"test-event",                 ARG_BOOL, ' ', C_TEST_EVENT},
  {"tftp-blksize",               ARG_STRG, ' ', C_TFTP_BLKSIZE},
  {"tftp-no-options",            ARG_BOOL, ' ', C_TFTP_NO_OPTIONS},
  {"time-cond",                  ARG_STRG, 'z', C_TIME_COND},
  {"tls-earlydata",              ARG_BOOL, ' ', C_TLS_EARLYDATA},
  {"tls-max",                    ARG_STRG, ' ', C_TLS_MAX},
  {"tls13-ciphers",              ARG_STRG, ' ', C_TLS13_CIPHERS},
  {"tlsauthtype",                ARG_STRG, ' ', C_TLSAUTHTYPE},
  {"tlspassword",                ARG_STRG, ' ', C_TLSPASSWORD},
  {"tlsuser",                    ARG_STRG, ' ', C_TLSUSER},
  {"tlsv1",                      ARG_NONE, '1', C_TLSV1},
  {"tlsv1.0",                    ARG_NONE, ' ', C_TLSV1_0},
  {"tlsv1.1",                    ARG_NONE, ' ', C_TLSV1_1},
  {"tlsv1.2",                    ARG_NONE, ' ', C_TLSV1_2},
  {"tlsv1.3",                    ARG_NONE, ' ', C_TLSV1_3},
  {"tr-encoding",                ARG_BOOL, ' ', C_TR_ENCODING},
  {"trace",                      ARG_FILE, ' ', C_TRACE},
  {"trace-ascii",                ARG_FILE, ' ', C_TRACE_ASCII},
  {"trace-config",               ARG_STRG, ' ', C_TRACE_CONFIG},
  {"trace-ids",                  ARG_BOOL, ' ', C_TRACE_IDS},
  {"trace-time",                 ARG_BOOL, ' ', C_TRACE_TIME},
  {"unix-socket",                ARG_FILE, ' ', C_UNIX_SOCKET},
  {"upload-file",                ARG_FILE, 'T', C_UPLOAD_FILE},
  {"url",                        ARG_STRG, ' ', C_URL},
  {"url-query",                  ARG_STRG, ' ', C_URL_QUERY},
  {"use-ascii",                  ARG_BOOL, 'B', C_USE_ASCII},
  {"user",                       ARG_STRG, 'u', C_USER},
  {"user-agent",                 ARG_STRG, 'A', C_USER_AGENT},
  {"variable",                   ARG_STRG, ' ', C_VARIABLE},
  {"verbose",                    ARG_BOOL, 'v', C_VERBOSE},
  {"version",                    ARG_BOOL, 'V', C_VERSION},
  {"vlan-priority",              ARG_STRG, ' ', C_VLAN_PRIORITY},
#ifdef USE_WATT32
  {"wdebug",                     ARG_BOOL, ' ', C_WDEBUG},
#endif
  {"write-out",                  ARG_STRG, 'w', C_WRITE_OUT},
  {"xattr",                      ARG_BOOL, ' ', C_XATTR},
};

/* Split the argument of -E to 'certname' and 'passphrase' separated by colon.
 * We allow ':' and '\' to be escaped by '\' so that we can use certificate
 * nicknames containing ':'. See <https://sourceforge.net/p/curl/bugs/1196/>
 * for details. */
#ifndef UNITTESTS
static
#endif
void parse_cert_parameter(const char *cert_parameter,
                          char **certname,
                          char **passphrase)
{
  size_t param_length = strlen(cert_parameter);
  size_t span;
  const char *param_place = NULL;
  char *certname_place = NULL;
  *certname = NULL;
  *passphrase = NULL;

  /* most trivial assumption: cert_parameter is empty */
  if(param_length == 0)
    return;

  /* next less trivial: cert_parameter starts 'pkcs11:' and thus
   * looks like a RFC7512 PKCS#11 URI which can be used as-is.
   * Also if cert_parameter contains no colon nor backslash, this
   * means no passphrase was given and no characters escaped */
  if(curl_strnequal(cert_parameter, "pkcs11:", 7) ||
     !strpbrk(cert_parameter, ":\\")) {
    *certname = strdup(cert_parameter);
    return;
  }
  /* deal with escaped chars; find unescaped colon if it exists */
  certname_place = malloc(param_length + 1);
  if(!certname_place)
    return;

  *certname = certname_place;
  param_place = cert_parameter;
  while(*param_place) {
    span = strcspn(param_place, ":\\");
    memcpy(certname_place, param_place, span);
    param_place += span;
    certname_place += span;
    /* we just ate all the non-special chars. now we are on either a special
     * char or the end of the string. */
    switch(*param_place) {
    case '\0':
      break;
    case '\\':
      param_place++;
      switch(*param_place) {
        case '\0':
          *certname_place++ = '\\';
          break;
        case '\\':
          *certname_place++ = '\\';
          param_place++;
          break;
        case ':':
          *certname_place++ = ':';
          param_place++;
          break;
        default:
          *certname_place++ = '\\';
          *certname_place++ = *param_place;
          param_place++;
          break;
      }
      break;
    case ':':
      /* Since we live in a world of weirdness and confusion, the Windows
         dudes can use : when using drive letters and thus c:\file:password
         needs to work. In order not to break compatibility, we still use : as
         separator, but we try to detect when it is used for a filename! On
         Windows. */
#ifdef _WIN32
      if((param_place == &cert_parameter[1]) &&
         (cert_parameter[2] == '\\' || cert_parameter[2] == '/') &&
         (ISALPHA(cert_parameter[0])) ) {
        /* colon in the second column, followed by a backslash, and the
           first character is an alphabetic letter:

           this is a drive letter colon */
        *certname_place++ = ':';
        param_place++;
        break;
      }
#endif
      /* escaped colons and Windows drive letter colons were handled
       * above; if we are still here, this is a separating colon */
      param_place++;
      if(*param_place) {
        *passphrase = strdup(param_place);
      }
      goto done;
    }
  }
done:
  *certname_place = '\0';
}

/* Replace (in-place) '%20' by '+' according to RFC1866 */
static size_t replace_url_encoded_space_by_plus(char *url)
{
  size_t orig_len = strlen(url);
  size_t orig_index = 0;
  size_t new_index = 0;

  while(orig_index < orig_len) {
    if((url[orig_index] == '%') &&
       (url[orig_index + 1] == '2') &&
       (url[orig_index + 2] == '0')) {
      url[new_index] = '+';
      orig_index += 3;
    }
    else{
      if(new_index != orig_index) {
        url[new_index] = url[orig_index];
      }
      orig_index++;
    }
    new_index++;
  }

  url[new_index] = 0; /* terminate string */

  return new_index; /* new size */
}

static void
GetFileAndPassword(char *nextarg, char **file, char **password)
{
  char *certname, *passphrase;
  if(nextarg) {
    parse_cert_parameter(nextarg, &certname, &passphrase);
    Curl_safefree(*file);
    *file = certname;
    if(passphrase) {
      Curl_safefree(*password);
      *password = passphrase;
    }
  }
}

/* Get a size parameter for '--limit-rate' or '--max-filesize'.
 * We support a 'G', 'M' or 'K' suffix too.
  */
static ParameterError GetSizeParameter(struct GlobalConfig *global,
                                       const char *arg,
                                       const char *which,
                                       curl_off_t *value_out)
{
  char *unit;
  curl_off_t value;

  if(curlx_strtoofft(arg, &unit, 10, &value)) {
    warnf(global, "invalid number specified for %s", which);
    return PARAM_BAD_USE;
  }

  if(!*unit)
    unit = (char *)"b";
  else if(strlen(unit) > 1)
    unit = (char *)"w"; /* unsupported */

  switch(*unit) {
  case 'G':
  case 'g':
    if(value > (CURL_OFF_T_MAX / (1024*1024*1024)))
      return PARAM_NUMBER_TOO_LARGE;
    value *= 1024*1024*1024;
    break;
  case 'M':
  case 'm':
    if(value > (CURL_OFF_T_MAX / (1024*1024)))
      return PARAM_NUMBER_TOO_LARGE;
    value *= 1024*1024;
    break;
  case 'K':
  case 'k':
    if(value > (CURL_OFF_T_MAX / 1024))
      return PARAM_NUMBER_TOO_LARGE;
    value *= 1024;
    break;
  case 'b':
  case 'B':
    /* for plain bytes, leave as-is */
    break;
  default:
    warnf(global, "unsupported %s unit. Use G, M, K or B", which);
    return PARAM_BAD_USE;
  }
  *value_out = value;
  return PARAM_OK;
}

#ifdef HAVE_WRITABLE_ARGV
static void cleanarg(argv_item_t str)
{
  /* now that getstr has copied the contents of nextarg, wipe the next
   * argument out so that the username:password is not displayed in the
   * system process list */
  if(str) {
    size_t len = strlen(str);
    memset(str, ' ', len);
  }
}
#else
#define cleanarg(x)
#endif

/* the maximum size we allow the dynbuf generated string */
#define MAX_DATAURLENCODE (500*1024*1024)

/* --data-urlencode */
static ParameterError data_urlencode(struct GlobalConfig *global,
                                     char *nextarg,
                                     char **postp,
                                     size_t *lenp)
{
  /* [name]=[content], we encode the content part only
   * [name]@[filename]
   *
   * Case 2: we first load the file using that name and then encode
   * the content.
   */
  ParameterError err;
  const char *p = strchr(nextarg, '=');
  size_t nlen;
  char is_file;
  char *postdata = NULL;
  size_t size = 0;
  if(!p)
    /* there was no '=' letter, check for a '@' instead */
    p = strchr(nextarg, '@');
  if(p) {
    nlen = p - nextarg; /* length of the name part */
    is_file = *p++; /* pass the separator */
  }
  else {
    /* neither @ nor =, so no name and it is not a file */
    nlen = 0;
    is_file = 0;
    p = nextarg;
  }
  if('@' == is_file) {
    FILE *file;
    /* a '@' letter, it means that a filename or - (stdin) follows */
    if(!strcmp("-", p)) {
      file = stdin;
      set_binmode(stdin);
    }
    else {
      file = fopen(p, "rb");
      if(!file) {
        errorf(global, "Failed to open %s", p);
        return PARAM_READ_ERROR;
      }
    }

    err = file2memory(&postdata, &size, file);

    if(file && (file != stdin))
      fclose(file);
    if(err)
      return err;
  }
  else {
    err = getstr(&postdata, p, ALLOW_BLANK);
    if(err)
      goto error;
    size = strlen(postdata);
  }

  if(!postdata) {
    /* no data from the file, point to a zero byte string to make this
       get sent as a POST anyway */
    postdata = strdup("");
    if(!postdata)
      return PARAM_NO_MEM;
    size = 0;
  }
  else {
    char *enc = curl_easy_escape(NULL, postdata, (int)size);
    Curl_safefree(postdata); /* no matter if it worked or not */
    if(enc) {
      char *n;
      replace_url_encoded_space_by_plus(enc);
      if(nlen > 0) { /* only append '=' if we have a name */
        struct curlx_dynbuf dyn;
        curlx_dyn_init(&dyn, MAX_DATAURLENCODE);
        if(curlx_dyn_addn(&dyn, nextarg, nlen) ||
           curlx_dyn_addn(&dyn, "=", 1) ||
           curlx_dyn_add(&dyn, enc)) {
          curl_free(enc);
          return PARAM_NO_MEM;
        }
        curl_free(enc);
        n = curlx_dyn_ptr(&dyn);
        size = curlx_dyn_len(&dyn);
      }
      else {
        n = enc;
        size = strlen(n);
      }
      postdata = n;
    }
    else
      return PARAM_NO_MEM;
  }
  *postp = postdata;
  *lenp = size;
  return PARAM_OK;
error:
  return err;
}

static void sethttpver(struct GlobalConfig *global,
                       struct OperationConfig *config,
                       long httpversion)
{
  if(config->httpversion &&
     (config->httpversion != httpversion))
    warnf(global, "Overrides previous HTTP version option");

  config->httpversion = httpversion;
}

static CURLcode set_trace_config(struct GlobalConfig *global,
                                 const char *config)
{
  CURLcode result = CURLE_OK;
  char *token, *tmp, *name;
  bool toggle;

  tmp = strdup(config);
  if(!tmp)
    return CURLE_OUT_OF_MEMORY;

  /* Allow strtok() here since this is not used threaded */
  /* !checksrc! disable BANNEDFUNC 2 */
  token = strtok(tmp, ", ");
  while(token) {
    switch(*token) {
      case '-':
        toggle = FALSE;
        name = token + 1;
        break;
      case '+':
        toggle = TRUE;
        name = token + 1;
        break;
      default:
        toggle = TRUE;
        name = token;
        break;
    }

    if(strcasecompare(name, "all")) {
      global->traceids = toggle;
      global->tracetime = toggle;
      result = curl_global_trace(token);
      if(result)
        goto out;
    }
    else if(strcasecompare(name, "ids")) {
      global->traceids = toggle;
    }
    else if(strcasecompare(name, "time")) {
      global->tracetime = toggle;
    }
    else {
      result = curl_global_trace(token);
      if(result)
        goto out;
    }
    token = strtok(NULL, ", ");
  }
out:
  free(tmp);
  return result;
}

static int findarg(const void *a, const void *b)
{
  const struct LongShort *aa = a;
  const struct LongShort *bb = b;
  return strcmp(aa->lname, bb->lname);
}

const struct LongShort *findshortopt(char letter)
{
  static const struct LongShort *singles[128 - ' ']; /* ASCII => pointer */
  static bool singles_done = FALSE;
  if((letter >= 127) || (letter <= ' '))
    return NULL;

  if(!singles_done) {
    unsigned int j;
    for(j = 0; j < sizeof(aliases)/sizeof(aliases[0]); j++) {
      if(aliases[j].letter != ' ') {
        unsigned char l = (unsigned char)aliases[j].letter;
        singles[l - ' '] = &aliases[j];
      }
    }
    singles_done = TRUE;
  }
  return singles[letter - ' '];
}

struct TOSEntry {
  const char *name;
  unsigned char value;
};

static const struct TOSEntry tos_entries[] = {
  {"AF11", 0x28},
  {"AF12", 0x30},
  {"AF13", 0x38},
  {"AF21", 0x48},
  {"AF22", 0x50},
  {"AF23", 0x58},
  {"AF31", 0x68},
  {"AF32", 0x70},
  {"AF33", 0x78},
  {"AF41", 0x88},
  {"AF42", 0x90},
  {"AF43", 0x98},
  {"CE",   0x03},
  {"CS0",  0x00},
  {"CS1",  0x20},
  {"CS2",  0x40},
  {"CS3",  0x60},
  {"CS4",  0x80},
  {"CS5",  0xa0},
  {"CS6",  0xc0},
  {"CS7",  0xe0},
  {"ECT0", 0x02},
  {"ECT1", 0x01},
  {"EF",   0xb8},
  {"LE",   0x04},
  {"LOWCOST",     0x02},
  {"LOWDELAY",    0x10},
  {"MINCOST",     0x02},
  {"RELIABILITY", 0x04},
  {"THROUGHPUT",  0x08},
  {"VOICE-ADMIT", 0xb0}
};

static int find_tos(const void *a, const void *b)
{
  const struct TOSEntry *aa = a;
  const struct TOSEntry *bb = b;
  return strcmp(aa->name, bb->name);
}

#define MAX_QUERY_LEN 100000 /* larger is not likely to ever work */
static ParameterError url_query(char *nextarg,
                                struct GlobalConfig *global,
                                struct OperationConfig *config)
{
  size_t size = 0;
  ParameterError err = PARAM_OK;
  char *query;
  struct curlx_dynbuf dyn;
  curlx_dyn_init(&dyn, MAX_QUERY_LEN);

  if(*nextarg == '+') {
    /* use without encoding */
    query = strdup(&nextarg[1]);
    if(!query)
      err = PARAM_NO_MEM;
  }
  else
    err = data_urlencode(global, nextarg, &query, &size);

  if(!err) {
    if(config->query) {
      CURLcode result = curlx_dyn_addf(&dyn, "%s&%s", config->query, query);
      free(query);
      if(result)
        err = PARAM_NO_MEM;
      else {
        free(config->query);
        config->query = curlx_dyn_ptr(&dyn);
      }
    }
    else
      config->query = query;
  }
  return err;
}

static ParameterError set_data(cmdline_t cmd,
                               char *nextarg,
                               struct GlobalConfig *global,
                               struct OperationConfig *config)
{
  char *postdata = NULL;
  FILE *file;
  size_t size = 0;
  ParameterError err = PARAM_OK;

  if(cmd == C_DATA_URLENCODE) { /* --data-urlencode */
    err = data_urlencode(global, nextarg, &postdata, &size);
    if(err)
      return err;
  }
  else if('@' == *nextarg && (cmd != C_DATA_RAW)) {
    /* the data begins with a '@' letter, it means that a filename
       or - (stdin) follows */
    nextarg++; /* pass the @ */

    if(!strcmp("-", nextarg)) {
      file = stdin;
      if(cmd == C_DATA_BINARY) /* forced data-binary */
        set_binmode(stdin);
    }
    else {
      file = fopen(nextarg, "rb");
      if(!file) {
        errorf(global, "Failed to open %s", nextarg);
        return PARAM_READ_ERROR;
      }
    }

    if((cmd == C_DATA_BINARY) || /* --data-binary */
       (cmd == C_JSON) /* --json */)
      /* forced binary */
      err = file2memory(&postdata, &size, file);
    else {
      err = file2string(&postdata, file);
      if(postdata)
        size = strlen(postdata);
    }

    if(file && (file != stdin))
      fclose(file);
    if(err)
      return err;

    if(!postdata) {
      /* no data from the file, point to a zero byte string to make this
         get sent as a POST anyway */
      postdata = strdup("");
      if(!postdata)
        return PARAM_NO_MEM;
    }
  }
  else {
    err = getstr(&postdata, nextarg, ALLOW_BLANK);
    if(err)
      return err;
    size = strlen(postdata);
  }
  if(cmd == C_JSON)
    config->jsoned = TRUE;

  if(curlx_dyn_len(&config->postdata)) {
    /* skip separator append for --json */
    if(!err && (cmd != C_JSON)  &&
       curlx_dyn_addn(&config->postdata, "&", 1))
      err = PARAM_NO_MEM;
  }

  if(!err && curlx_dyn_addn(&config->postdata, postdata, size))
    err = PARAM_NO_MEM;

  Curl_safefree(postdata);

  config->postfields = curlx_dyn_ptr(&config->postdata);
  return err;
}

static ParameterError set_rate(struct GlobalConfig *global,
                               char *nextarg)
{
  /* --rate */
  /* support a few different suffixes, extract the suffix first, then
     get the number and convert to per hour.
     /s == per second
     /m == per minute
     /h == per hour (default)
     /d == per day (24 hours)
  */
  ParameterError err = PARAM_OK;
  char *div = strchr(nextarg, '/');
  char number[26];
  long denominator;
  long numerator = 60*60*1000; /* default per hour */
  size_t numlen = div ? (size_t)(div - nextarg) : strlen(nextarg);
  if(numlen > sizeof(number) -1)
    return PARAM_NUMBER_TOO_LARGE;

  memcpy(number, nextarg, numlen);
  number[numlen] = 0;
  err = str2unum(&denominator, number);
  if(err)
    return err;

  if(denominator < 1)
    return PARAM_BAD_USE;

  if(div) {
    char unit = div[1];
    curl_off_t numunits;
    char *endp;

    if(curlx_strtoofft(&div[1], &endp, 10, &numunits)) {
      /* if it fails, there is no legit number specified */
      if(endp == &div[1])
        /* if endp did not move, accept it as a 1 */
        numunits = 1;
      else
        return PARAM_BAD_USE;
    }
    else
      unit = *endp;

    switch(unit) {
    case 's': /* per second */
      numerator = 1000;
      break;
    case 'm': /* per minute */
      numerator = 60*1000;
      break;
    case 'h': /* per hour */
      break;
    case 'd': /* per day */
      numerator = 24*60*60*1000;
      break;
    default:
      errorf(global, "unsupported --rate unit");
      err = PARAM_BAD_USE;
      break;
    }

    if((LONG_MAX / numerator) < numunits) {
      /* overflow, too large number */
      errorf(global, "too large --rate unit");
      err = PARAM_NUMBER_TOO_LARGE;
    }
    /* this typecast is okay based on the check above */
    numerator *= (long)numunits;
  }

  if(err)
    ;
  else if(denominator > numerator)
    err = PARAM_NUMBER_TOO_LARGE;
  else
    global->ms_per_transfer = numerator/denominator;

  return err;
}

const struct LongShort *findlongopt(const char *opt)
{
  struct LongShort key;
  key.lname = opt;

  return bsearch(&key, aliases, sizeof(aliases)/sizeof(aliases[0]),
                 sizeof(aliases[0]), findarg);
}


ParameterError getparameter(const char *flag, /* f or -long-flag */
                            char *nextarg,    /* NULL if unset */
                            argv_item_t cleararg,
                            bool *usedarg,    /* set to TRUE if the arg
                                                 has been used */
                            struct GlobalConfig *global,
                            struct OperationConfig *config)
{
  int rc;
  const char *parse = NULL;
  bool longopt = FALSE;
  bool singleopt = FALSE; /* when true means '-o foo' used '-ofoo' */
  size_t nopts = 0; /* options processed in `flag`*/
  ParameterError err = PARAM_OK;
  bool toggle = TRUE; /* how to switch boolean options, on or off. Controlled
                         by using --OPTION or --no-OPTION */
  bool nextalloc = FALSE; /* if nextarg is allocated */
  struct getout *url;
  static const char *redir_protos[] = {
    "http",
    "https",
    "ftp",
    "ftps",
    NULL
  };
  const struct LongShort *a = NULL;
  curl_off_t value;
#ifdef HAVE_WRITABLE_ARGV
  argv_item_t clearthis = NULL;
#else
  (void)cleararg;
#endif

  *usedarg = FALSE; /* default is that we do not use the arg */

  if(('-' != flag[0]) || ('-' == flag[1])) {
    /* this should be a long name */
    const char *word = ('-' == flag[0]) ? flag + 2 : flag;
    bool noflagged = FALSE;
    bool expand = FALSE;

    if(!strncmp(word, "no-", 3)) {
      /* disable this option but ignore the "no-" part when looking for it */
      word += 3;
      toggle = FALSE;
      noflagged = TRUE;
    }
    else if(!strncmp(word, "expand-", 7)) {
      /* variable expansions is to be done on the argument */
      word += 7;
      expand = TRUE;
    }

    a = findlongopt(word);
    if(a) {
      longopt = TRUE;
    }
    else {
      err = PARAM_OPTION_UNKNOWN;
      goto error;
    }
    if(noflagged && (ARGTYPE(a->desc) != ARG_BOOL)) {
      /* --no- prefixed an option that is not boolean! */
      err = PARAM_NO_NOT_BOOLEAN;
      goto error;
    }
    else if(expand && nextarg) {
      struct curlx_dynbuf nbuf;
      bool replaced;

      if((ARGTYPE(a->desc) != ARG_STRG) &&
         (ARGTYPE(a->desc) != ARG_FILE)) {
        /* --expand on an option that is not a string or a filename */
        err = PARAM_EXPAND_ERROR;
        goto error;
      }
      err = varexpand(global, nextarg, &nbuf, &replaced);
      if(err) {
        curlx_dyn_free(&nbuf);
        goto error;
      }
      if(replaced) {
        nextarg = curlx_dyn_ptr(&nbuf);
        nextalloc = TRUE;
      }
    }
  }
  else {
    flag++; /* prefixed with one dash, pass it */
    parse = flag;
  }

  do {
    /* we can loop here if we have multiple single-letters */
    char letter;
    cmdline_t cmd;

    if(!longopt && !a) {
      a = findshortopt(*parse);
      if(!a) {
        err = PARAM_OPTION_UNKNOWN;
        break;
      }
    }
    letter = a->letter;
    cmd = (cmdline_t)a->cmd;
    if(ARGTYPE(a->desc) >= ARG_STRG) {
      /* this option requires an extra parameter */
      if(!longopt && parse[1]) {
        nextarg = (char *)&parse[1]; /* this is the actual extra parameter */
        singleopt = TRUE;   /* do not loop anymore after this */
      }
      else if(!nextarg) {
        err = PARAM_REQUIRES_PARAMETER;
        break;
      }
      else {
#ifdef HAVE_WRITABLE_ARGV
        clearthis = cleararg;
#endif
        *usedarg = TRUE; /* mark it as used */
      }

      if((ARGTYPE(a->desc) == ARG_FILE) &&
         (nextarg[0] == '-') && nextarg[1]) {
        /* if the filename looks like a command line option */
        warnf(global, "The filename argument '%s' looks like a flag.",
              nextarg);
      }
      else if(!strncmp("\xe2\x80\x9c", nextarg, 3)) {
        warnf(global, "The argument '%s' starts with a Unicode quote where "
              "maybe an ASCII \" was intended?",
              nextarg);
      }
    }
    else if((ARGTYPE(a->desc) == ARG_NONE) && !toggle) {
      err = PARAM_NO_PREFIX;
      break;
    }

    if(!nextarg)
      /* this is a precaution mostly to please scan-build, as all arguments
         that use nextarg should be marked as such and they will check that
         nextarg is set before continuing, but code analyzers are not always
         that aware of that state */
      nextarg = (char *)"";

    switch(cmd) {
    case C_RANDOM_FILE: /* --random-file */
    case C_EGD_FILE: /* --egd-file */
    case C_NTLM_WB: /* --ntlm-wb */
      warnf(global, "--%s is deprecated and has no function anymore",
            a->lname);
      break;
    case C_DNS_IPV4_ADDR: /* --dns-ipv4-addr */
      if(!curlinfo->ares_num) /* c-ares is needed for this */
        err = PARAM_LIBCURL_DOESNT_SUPPORT;
      else
        /* addr in dot notation */
        err = getstr(&config->dns_ipv4_addr, nextarg, DENY_BLANK);
      break;
    case C_DNS_IPV6_ADDR: /* --dns-ipv6-addr */
      if(!curlinfo->ares_num) /* c-ares is needed for this */
        err = PARAM_LIBCURL_DOESNT_SUPPORT;
      else
        /* addr in dot notation */
        err = getstr(&config->dns_ipv6_addr, nextarg, DENY_BLANK);
      break;
    case C_OAUTH2_BEARER: /* --oauth2-bearer */
      err = getstr(&config->oauth_bearer, nextarg, DENY_BLANK);
      if(!err) {
        cleanarg(clearthis);
        config->authtype |= CURLAUTH_BEARER;
      }
      break;
    case C_CONNECT_TIMEOUT: /* --connect-timeout */
      err = secs2ms(&config->connecttimeout_ms, nextarg);
      break;
    case C_DOH_URL: /* --doh-url */
      err = getstr(&config->doh_url, nextarg, ALLOW_BLANK);
      if(!err && config->doh_url && !config->doh_url[0])
        /* if given a blank string, make it NULL again */
        Curl_safefree(config->doh_url);
      break;
    case C_CIPHERS: /* -- ciphers */
      err = getstr(&config->cipher_list, nextarg, DENY_BLANK);
      break;
    case C_DNS_INTERFACE: /* --dns-interface */
      if(!curlinfo->ares_num) /* c-ares is needed for this */
        err = PARAM_LIBCURL_DOESNT_SUPPORT;
      else
        /* interface name */
        err = getstr(&config->dns_interface, nextarg, DENY_BLANK);
      break;
    case C_DISABLE_EPSV: /* --disable-epsv */
      config->disable_epsv = toggle;
      break;
    case C_DISALLOW_USERNAME_IN_URL: /* --disallow-username-in-url */
      config->disallow_username_in_url = toggle;
      break;
    case C_EPSV: /* --epsv */
      config->disable_epsv = !toggle;
      break;
    case C_DNS_SERVERS: /* --dns-servers */
      if(!curlinfo->ares_num) /* c-ares is needed for this */
        err = PARAM_LIBCURL_DOESNT_SUPPORT;
      else
        /* IP addrs of DNS servers */
        err = getstr(&config->dns_servers, nextarg, DENY_BLANK);
      break;
    case C_TRACE: /* --trace */
      err = getstr(&global->trace_dump, nextarg, DENY_BLANK);
      if(!err) {
        if(global->tracetype && (global->tracetype != TRACE_BIN))
          warnf(global, "--trace overrides an earlier trace/verbose option");
        global->tracetype = TRACE_BIN;
      }
      break;
    case C_NPN: /* --npn */
      warnf(global, "--npn is no longer supported");
      break;
    case C_TRACE_ASCII: /* --trace-ascii */
      err = getstr(&global->trace_dump, nextarg, DENY_BLANK);
      if(!err) {
        if(global->tracetype && (global->tracetype != TRACE_ASCII))
          warnf(global,
                "--trace-ascii overrides an earlier trace/verbose option");
        global->tracetype = TRACE_ASCII;
      }
      break;
    case C_ALPN: /* --alpn */
      config->noalpn = !toggle;
      break;
    case C_LIMIT_RATE: /* --limit-rate */
      err = GetSizeParameter(global, nextarg, "rate", &value);
      if(!err) {
        config->recvpersecond = value;
        config->sendpersecond = value;
      }
      break;
    case C_RATE:
      err = set_rate(global, nextarg);
      break;
    case C_COMPRESSED: /* --compressed */
      if(toggle && !(feature_libz || feature_brotli || feature_zstd))
        err = PARAM_LIBCURL_DOESNT_SUPPORT;
      else
        config->encoding = toggle;
      break;
    case C_TR_ENCODING: /* --tr-encoding */
      config->tr_encoding = toggle;
      break;
    case C_DIGEST: /* --digest */
      if(toggle)
        config->authtype |= CURLAUTH_DIGEST;
      else
        config->authtype &= ~CURLAUTH_DIGEST;
      break;
    case C_NEGOTIATE: /* --negotiate */
      if(!toggle)
        config->authtype &= ~CURLAUTH_NEGOTIATE;
      else if(feature_spnego)
        config->authtype |= CURLAUTH_NEGOTIATE;
      else
        err = PARAM_LIBCURL_DOESNT_SUPPORT;
      break;
    case C_NTLM: /* --ntlm */
      if(!toggle)
        config->authtype &= ~CURLAUTH_NTLM;
      else if(feature_ntlm)
        config->authtype |= CURLAUTH_NTLM;
      else
        err = PARAM_LIBCURL_DOESNT_SUPPORT;
      break;
    case C_BASIC: /* --basic */
      if(toggle)
        config->authtype |= CURLAUTH_BASIC;
      else
        config->authtype &= ~CURLAUTH_BASIC;
      break;
    case C_ANYAUTH: /* --anyauth */
      if(toggle)
        config->authtype = CURLAUTH_ANY;
      /* --no-anyauth simply does not touch it */
      break;
#ifdef USE_WATT32
    case C_WDEBUG: /* --wdebug */
      dbug_init();
      break;
#endif
    case C_FTP_CREATE_DIRS: /* --ftp-create-dirs */
      config->ftp_create_dirs = toggle;
      break;
    case C_CREATE_DIRS: /* --create-dirs */
      config->create_dirs = toggle;
      break;
    case C_CREATE_FILE_MODE: /* --create-file-mode */
      err = oct2nummax(&config->create_file_mode, nextarg, 0777);
      break;
    case C_MAX_REDIRS: /* --max-redirs */
      /* specified max no of redirects (http(s)), this accepts -1 as a
         special condition */
      err = str2num(&config->maxredirs, nextarg);
      if(!err && (config->maxredirs < -1))
        err = PARAM_BAD_NUMERIC;
      break;
#ifndef CURL_DISABLE_IPFS
    case C_IPFS_GATEWAY: /* --ipfs-gateway */
      err = getstr(&config->ipfs_gateway, nextarg, DENY_BLANK);
      break;
#endif /* !CURL_DISABLE_IPFS */
    case C_PROXY_NTLM: /* --proxy-ntlm */
      if(!feature_ntlm)
        err = PARAM_LIBCURL_DOESNT_SUPPORT;
      else
        config->proxyntlm = toggle;
      break;
    case C_CRLF: /* --crlf */
      /* LF -> CRLF conversion? */
      config->crlf = toggle;
      break;
    case C_AWS_SIGV4: /* --aws-sigv4 */
      config->authtype |= CURLAUTH_AWS_SIGV4;
      err = getstr(&config->aws_sigv4, nextarg, DENY_BLANK);
      break;
    case C_STDERR: /* --stderr */
      tool_set_stderr_file(global, nextarg);
      break;
    case C_INTERFACE: /* --interface */
      /* interface */
      err = getstr(&config->iface, nextarg, DENY_BLANK);
      break;
    case C_KRB: /* --krb */
      /* kerberos level string */
      if(!feature_spnego)
        err = PARAM_LIBCURL_DOESNT_SUPPORT;
      else
        err = getstr(&config->krblevel, nextarg, DENY_BLANK);
      break;
    case C_HAPROXY_PROTOCOL: /* --haproxy-protocol */
      config->haproxy_protocol = toggle;
      break;
    case C_HAPROXY_CLIENTIP: /* --haproxy-clientip */
      err = getstr(&config->haproxy_clientip, nextarg, DENY_BLANK);
      break;
    case C_MAX_FILESIZE: /* --max-filesize */
      err = GetSizeParameter(global, nextarg, "max-filesize", &value);
      if(!err)
        config->max_filesize = value;
      break;
    case C_DISABLE_EPRT: /* --disable-eprt */
      config->disable_eprt = toggle;
      break;
    case C_EPRT: /* --eprt */
      config->disable_eprt = !toggle;
      break;
    case C_XATTR: /* --xattr */
      config->xattr = toggle;
      break;
    case C_URL: /* --url */
      if(!config->url_get)
        config->url_get = config->url_list;

      if(config->url_get) {
        /* there is a node here, if it already is filled-in continue to find
           an "empty" node */
        while(config->url_get && (config->url_get->flags & GETOUT_URL))
          config->url_get = config->url_get->next;
      }

      /* now there might or might not be an available node to fill in! */

      if(config->url_get)
        /* existing node */
        url = config->url_get;
      else
        /* there was no free node, create one! */
        config->url_get = url = new_getout(config);

      if(!url)
        err = PARAM_NO_MEM;
      else {
        /* fill in the URL */
        err = getstr(&url->url, nextarg, DENY_BLANK);
        url->flags |= GETOUT_URL;
      }
      break;
    case C_FTP_SSL: /* --ftp-ssl */
    case C_SSL: /* --ssl */
      if(toggle && !feature_ssl)
        err = PARAM_LIBCURL_DOESNT_SUPPORT;
      else {
        config->ftp_ssl = toggle;
        if(config->ftp_ssl)
          warnf(global,
                "--%s is an insecure option, consider --ssl-reqd instead",
                a->lname);
      }
      break;
    case C_FTP_PASV: /* --ftp-pasv */
      Curl_safefree(config->ftpport);
      break;
    case C_SOCKS5: /* --socks5 */
      /*  socks5 proxy to use, and resolves the name locally and passes on the
          resolved address */
      err = getstr(&config->proxy, nextarg, DENY_BLANK);
      config->proxyver = CURLPROXY_SOCKS5;
      break;
    case C_SOCKS4: /* --socks4 */
      err = getstr(&config->proxy, nextarg, DENY_BLANK);
      config->proxyver = CURLPROXY_SOCKS4;
      break;
    case C_SOCKS4A: /* --socks4a */
      err = getstr(&config->proxy, nextarg, DENY_BLANK);
      config->proxyver = CURLPROXY_SOCKS4A;
      break;
    case C_SOCKS5_HOSTNAME: /* --socks5-hostname */
      err = getstr(&config->proxy, nextarg, DENY_BLANK);
      config->proxyver = CURLPROXY_SOCKS5_HOSTNAME;
      break;
    case C_TCP_NODELAY: /* --tcp-nodelay */
      config->tcp_nodelay = toggle;
      break;
    case C_IP_TOS: { /* --ip-tos */
      struct TOSEntry find;
      const struct TOSEntry *entry;
      find.name = nextarg;
      entry = bsearch(&find, tos_entries,
                      sizeof(tos_entries)/sizeof(*tos_entries),
                      sizeof(*tos_entries), find_tos);
      if(entry)
        config->ip_tos = entry->value;
      else /* numeric tos value */
        err = str2unummax(&config->ip_tos, nextarg, 0xFF);
      break;
    }
    case C_VLAN_PRIORITY: /* --vlan-priority */
      err = str2unummax(&config->vlan_priority, nextarg, 7);
      break;
    case C_PROXY_DIGEST: /* --proxy-digest */
      config->proxydigest = toggle;
      break;
    case C_PROXY_BASIC: /* --proxy-basic */
      config->proxybasic = toggle;
      break;
    case C_RETRY: /* --retry */
      err = str2unum(&config->req_retry, nextarg);
      break;
    case C_RETRY_CONNREFUSED: /* --retry-connrefused */
      config->retry_connrefused = toggle;
      break;
    case C_RETRY_DELAY: /* --retry-delay */
      err = str2unummax(&config->retry_delay, nextarg, LONG_MAX/1000);
      break;
    case C_RETRY_MAX_TIME: /* --retry-max-time */
      err = str2unummax(&config->retry_maxtime, nextarg, LONG_MAX/1000);
      break;
    case C_RETRY_ALL_ERRORS: /* --retry-all-errors */
      config->retry_all_errors = toggle;
      break;
    case C_PROXY_NEGOTIATE: /* --proxy-negotiate */
      if(!feature_spnego)
        err = PARAM_LIBCURL_DOESNT_SUPPORT;
      else
        config->proxynegotiate = toggle;
      break;
    case C_FORM_ESCAPE: /* --form-escape */
      config->mime_options &= ~CURLMIMEOPT_FORMESCAPE;
      if(toggle)
        config->mime_options |= CURLMIMEOPT_FORMESCAPE;
      break;
    case C_FTP_ACCOUNT: /* --ftp-account */
      err = getstr(&config->ftp_account, nextarg, DENY_BLANK);
      break;
    case C_PROXY_ANYAUTH: /* --proxy-anyauth */
      config->proxyanyauth = toggle;
      break;
    case C_TRACE_TIME: /* --trace-time */
      global->tracetime = toggle;
      break;
    case C_IGNORE_CONTENT_LENGTH: /* --ignore-content-length */
      config->ignorecl = toggle;
      break;
    case C_FTP_SKIP_PASV_IP: /* --ftp-skip-pasv-ip */
      config->ftp_skip_ip = toggle;
      break;
    case C_FTP_METHOD: /* --ftp-method */
      config->ftp_filemethod = ftpfilemethod(config, nextarg);
      break;
    case C_LOCAL_PORT: { /* --local-port */
      /* 16bit base 10 is 5 digits, but we allow 6 so that this catches
         overflows, not just truncates */
      char lrange[7]="";
      char *p = nextarg;
      while(ISDIGIT(*p))
        p++;
      if(*p) {
        /* if there is anything more than a plain decimal number */
        rc = sscanf(p, " - %6s", lrange);
        *p = 0; /* null-terminate to make str2unum() work below */
      }
      else
        rc = 0;

      err = str2unum(&config->localport, nextarg);
      if(err || (config->localport > 65535)) {
        err = PARAM_BAD_USE;
        break;
      }
      if(!rc)
        config->localportrange = 1; /* default number of ports to try */
      else {
        err = str2unum(&config->localportrange, lrange);
        if(err || (config->localportrange > 65535))
          err = PARAM_BAD_USE;
        else {
          config->localportrange -= (config->localport-1);
          if(config->localportrange < 1)
            err = PARAM_BAD_USE;
        }
      }
      break;
    }
    case C_FTP_ALTERNATIVE_TO_USER: /* --ftp-alternative-to-user */
      err = getstr(&config->ftp_alternative_to_user, nextarg, DENY_BLANK);
      break;
    case C_FTP_SSL_REQD: /* --ftp-ssl-reqd */
    case C_SSL_REQD: /* --ssl-reqd */
      if(toggle && !feature_ssl) {
        err = PARAM_LIBCURL_DOESNT_SUPPORT;
        break;
      }
      config->ftp_ssl_reqd = toggle;
      break;
    case C_SESSIONID: /* --sessionid */
      config->disable_sessionid = !toggle;
      break;
    case C_FTP_SSL_CONTROL: /* --ftp-ssl-control */
      if(toggle && !feature_ssl)
        err = PARAM_LIBCURL_DOESNT_SUPPORT;
      else
        config->ftp_ssl_control = toggle;
      break;
    case C_FTP_SSL_CCC: /* --ftp-ssl-ccc */
      config->ftp_ssl_ccc = toggle;
      if(!config->ftp_ssl_ccc_mode)
        config->ftp_ssl_ccc_mode = CURLFTPSSL_CCC_PASSIVE;
      break;
    case C_FTP_SSL_CCC_MODE: /* --ftp-ssl-ccc-mode */
      config->ftp_ssl_ccc = TRUE;
      config->ftp_ssl_ccc_mode = ftpcccmethod(config, nextarg);
      break;
    case C_LIBCURL: /* --libcurl */
#ifdef CURL_DISABLE_LIBCURL_OPTION
      warnf(global,
            "--libcurl option was disabled at build-time");
      err = PARAM_OPTION_UNKNOWN;
#else
      err = getstr(&global->libcurl, nextarg, DENY_BLANK);
#endif
      break;
    case C_RAW: /* --raw */
      config->raw = toggle;
      break;
    case C_KEEPALIVE: /* --keepalive */
      config->nokeepalive = !toggle;
      break;
    case C_KEEPALIVE_TIME: /* --keepalive-time */
      err = str2unum(&config->alivetime, nextarg);
      break;
    case C_KEEPALIVE_CNT: /* --keepalive-cnt */
      err = str2unum(&config->alivecnt, nextarg);
      break;
    case C_POST301: /* --post301 */
      config->post301 = toggle;
      break;
    case C_POST302: /* --post302 */
      config->post302 = toggle;
      break;
    case C_POST303: /* --post303 */
      config->post303 = toggle;
      break;
    case C_NOPROXY: /* --noproxy */
      /* This specifies the noproxy list */
      err = getstr(&config->noproxy, nextarg, ALLOW_BLANK);
      break;
    case C_SOCKS5_GSSAPI_NEC: /* --socks5-gssapi-nec */
      config->socks5_gssapi_nec = toggle;
      break;
    case C_PROXY1_0: /* --proxy1.0 */
      /* http 1.0 proxy */
      err = getstr(&config->proxy, nextarg, DENY_BLANK);
      config->proxyver = CURLPROXY_HTTP_1_0;
      break;
    case C_TFTP_BLKSIZE: /* --tftp-blksize */
      err = str2unum(&config->tftp_blksize, nextarg);
      break;
    case C_MAIL_FROM: /* --mail-from */
      err = getstr(&config->mail_from, nextarg, DENY_BLANK);
      break;
    case C_MAIL_RCPT: /* --mail-rcpt */
      /* append receiver to a list */
      err = add2list(&config->mail_rcpt, nextarg);
      break;
    case C_FTP_PRET: /* --ftp-pret */
      config->ftp_pret = toggle;
      break;
    case C_PROTO: /* --proto */
      config->proto_present = TRUE;
      err = proto2num(config, built_in_protos, &config->proto_str, nextarg);
      break;
    case C_PROTO_REDIR: /* --proto-redir */
      config->proto_redir_present = TRUE;
      if(proto2num(config, redir_protos, &config->proto_redir_str,
                   nextarg))
        err = PARAM_BAD_USE;
      break;
    case C_RESOLVE: /* --resolve */
      err = add2list(&config->resolve, nextarg);
      break;
    case C_DELEGATION: /* --delegation */
      config->gssapi_delegation = delegation(config, nextarg);
      break;
    case C_MAIL_AUTH: /* --mail-auth */
      err = getstr(&config->mail_auth, nextarg, DENY_BLANK);
      break;
    case C_METALINK: /* --metalink */
      errorf(global, "--metalink is disabled");
      err = PARAM_BAD_USE;
      break;
    case C_SASL_AUTHZID: /* --sasl-authzid */
      err = getstr(&config->sasl_authzid, nextarg, DENY_BLANK);
      break;
    case C_SASL_IR: /* --sasl-ir */
      config->sasl_ir = toggle;
      break;
    case C_TEST_EVENT: /* --test-event */
#ifdef DEBUGBUILD
      global->test_event_based = toggle;
#else
      warnf(global, "--test-event is ignored unless a debug build");
#endif
      break;
    case C_UNIX_SOCKET: /* --unix-socket */
      config->abstract_unix_socket = FALSE;
      err = getstr(&config->unix_socket_path, nextarg, DENY_BLANK);
      break;
    case C_PATH_AS_IS: /* --path-as-is */
      config->path_as_is = toggle;
      break;
    case C_PROXY_SERVICE_NAME: /* --proxy-service-name */
      err = getstr(&config->proxy_service_name, nextarg, DENY_BLANK);
      break;
    case C_SERVICE_NAME: /* --service-name */
      err = getstr(&config->service_name, nextarg, DENY_BLANK);
      break;
    case C_PROTO_DEFAULT: /* --proto-default */
      err = getstr(&config->proto_default, nextarg, DENY_BLANK);
      if(!err)
        err = check_protocol(config->proto_default);
      break;
    case C_EXPECT100_TIMEOUT: /* --expect100-timeout */
      err = secs2ms(&config->expect100timeout_ms, nextarg);
      break;
    case C_TFTP_NO_OPTIONS: /* --tftp-no-options */
      config->tftp_no_options = toggle;
      break;
    case C_CONNECT_TO: /* --connect-to */
      err = add2list(&config->connect_to, nextarg);
      break;
    case C_ABSTRACT_UNIX_SOCKET: /* --abstract-unix-socket */
      config->abstract_unix_socket = TRUE;
      err = getstr(&config->unix_socket_path, nextarg, DENY_BLANK);
      break;
    case C_TLS_EARLYDATA: /* --tls-earlydata */
      if(feature_ssl)
        config->ssl_allow_earlydata = toggle;
      break;
    case C_TLS_MAX: /* --tls-max */
      err = str2tls_max(&config->ssl_version_max, nextarg);
      break;
    case C_SUPPRESS_CONNECT_HEADERS: /* --suppress-connect-headers */
      config->suppress_connect_headers = toggle;
      break;
    case C_COMPRESSED_SSH: /* --compressed-ssh */
      config->ssh_compression = toggle;
      break;
    case C_HAPPY_EYEBALLS_TIMEOUT_MS: /* --happy-eyeballs-timeout-ms */
      err = str2unum(&config->happy_eyeballs_timeout_ms, nextarg);
      /* 0 is a valid value for this timeout */
      break;
    case C_TRACE_IDS: /* --trace-ids */
      global->traceids = toggle;
      break;
    case C_TRACE_CONFIG: /* --trace-config */
      if(set_trace_config(global, nextarg))
        err = PARAM_NO_MEM;
      break;
    case C_PROGRESS_METER: /* --progress-meter */
      global->noprogress = !toggle;
      break;
    case C_PROGRESS_BAR: /* --progress-bar */
      global->progressmode = toggle ? CURL_PROGRESS_BAR : CURL_PROGRESS_STATS;
      break;
    case C_VARIABLE: /* --variable */
      err = setvariable(global, nextarg);
      break;
    case C_NEXT: /* --next */
      err = PARAM_NEXT_OPERATION;
      break;
    case C_HTTP1_0: /* --http1.0 */
      /* HTTP version 1.0 */
      sethttpver(global, config, CURL_HTTP_VERSION_1_0);
      break;
    case C_HTTP1_1: /* --http1.1 */
      /* HTTP version 1.1 */
      sethttpver(global, config, CURL_HTTP_VERSION_1_1);
      break;
    case C_HTTP2: /* --http2 */
      /* HTTP version 2.0 */
      if(!feature_http2)
        return PARAM_LIBCURL_DOESNT_SUPPORT;
      sethttpver(global, config, CURL_HTTP_VERSION_2_0);
      break;
    case C_HTTP2_PRIOR_KNOWLEDGE: /* --http2-prior-knowledge */
      /* HTTP version 2.0 over clean TCP */
      if(!feature_http2)
        return PARAM_LIBCURL_DOESNT_SUPPORT;
      sethttpver(global, config, CURL_HTTP_VERSION_2_PRIOR_KNOWLEDGE);
      break;
    case C_HTTP3: /* --http3: */
      /* Try HTTP/3, allow fallback */
      if(!feature_http3)
        err = PARAM_LIBCURL_DOESNT_SUPPORT;
      else
        sethttpver(global, config, CURL_HTTP_VERSION_3);
      break;
    case C_HTTP3_ONLY: /* --http3-only */
      /* Try HTTP/3 without fallback */
      if(!feature_http3)
        err = PARAM_LIBCURL_DOESNT_SUPPORT;
      else
        sethttpver(global, config, CURL_HTTP_VERSION_3ONLY);
      break;
    case C_HTTP0_9: /* --http0.9 */
      /* Allow HTTP/0.9 responses! */
      config->http09_allowed = toggle;
      break;
    case C_PROXY_HTTP2: /* --proxy-http2 */
      if(!feature_httpsproxy || !feature_http2)
        err = PARAM_LIBCURL_DOESNT_SUPPORT;
      else
        config->proxyver = CURLPROXY_HTTPS2;
      break;
    case C_TLSV1: /* --tlsv1 */
      config->ssl_version = CURL_SSLVERSION_TLSv1;
      break;
    case C_TLSV1_0: /* --tlsv1.0 */
      config->ssl_version = CURL_SSLVERSION_TLSv1_0;
      break;
    case C_TLSV1_1: /* --tlsv1.1 */
      config->ssl_version = CURL_SSLVERSION_TLSv1_1;
      break;
    case C_TLSV1_2: /* --tlsv1.2 */
      config->ssl_version = CURL_SSLVERSION_TLSv1_2;
      break;
    case C_TLSV1_3: /* --tlsv1.3 */
      config->ssl_version = CURL_SSLVERSION_TLSv1_3;
      break;
    case C_TLS13_CIPHERS: /* --tls13-ciphers */
      err = getstr(&config->cipher13_list, nextarg, DENY_BLANK);
      break;
    case C_PROXY_TLS13_CIPHERS: /* --proxy-tls13-ciphers */
      err = getstr(&config->proxy_cipher13_list, nextarg, DENY_BLANK);
      break;
    case C_SSLV2: /* --sslv2 */
      warnf(global, "Ignores instruction to use SSLv2");
      break;
    case C_SSLV3: /* --sslv3 */
      warnf(global, "Ignores instruction to use SSLv3");
      break;
    case C_IPV4: /* --ipv4 */
      config->ip_version = CURL_IPRESOLVE_V4;
      break;
    case C_IPV6: /* --ipv6 */
      config->ip_version = CURL_IPRESOLVE_V6;
      break;
    case C_APPEND: /* --append */
      /* This makes the FTP sessions use APPE instead of STOR */
      config->ftp_append = toggle;
      break;
    case C_USER_AGENT: /* --user-agent */
      err = getstr(&config->useragent, nextarg, ALLOW_BLANK);
      break;
    case C_ALT_SVC: /* --alt-svc */
      if(!feature_altsvc)
        err = PARAM_LIBCURL_DOESNT_SUPPORT;
      else
        err = getstr(&config->altsvc, nextarg, ALLOW_BLANK);
      break;
    case C_HSTS: /* --hsts */
      if(!feature_hsts)
        err = PARAM_LIBCURL_DOESNT_SUPPORT;
      else
        err = getstr(&config->hsts, nextarg, ALLOW_BLANK);
      break;
    case C_COOKIE: /* --cookie */
      if(strchr(nextarg, '=')) {
        /* A cookie string must have a =-letter */
        err = add2list(&config->cookies, nextarg);
        break;
      }
      else {
        /* We have a cookie file to read from! */
        err = add2list(&config->cookiefiles, nextarg);
      }
      break;
    case C_USE_ASCII: /* --use-ascii */
      config->use_ascii = toggle;
      break;
    case C_COOKIE_JAR: /* --cookie-jar */
      err = getstr(&config->cookiejar, nextarg, DENY_BLANK);
      break;
    case C_CONTINUE_AT: /* --continue-at */
      /* This makes us continue an ftp transfer at given position */
      if(strcmp(nextarg, "-")) {
        err = str2offset(&config->resume_from, nextarg);
        config->resume_from_current = FALSE;
      }
      else {
        config->resume_from_current = TRUE;
        config->resume_from = 0;
      }
      config->use_resume = TRUE;
      break;
    case C_DATA: /* --data */
    case C_DATA_ASCII:  /* --data-ascii */
    case C_DATA_BINARY:  /* --data-binary */
    case C_DATA_URLENCODE:  /* --data-urlencode */
    case C_JSON:  /* --json */
    case C_DATA_RAW:  /* --data-raw */
      err = set_data(cmd, nextarg, global, config);
      break;
    case C_URL_QUERY:  /* --url-query */
      err = url_query(nextarg, global, config);
      break;
    case C_DUMP_CA_EMBED: /* --dump-ca-embed */
      err = PARAM_CA_EMBED_REQUESTED;
      break;
    case C_DUMP_HEADER: /* --dump-header */
      err = getstr(&config->headerfile, nextarg, DENY_BLANK);
      break;
    case C_REFERER: { /* --referer */
      char *ptr = strstr(nextarg, ";auto");
      if(ptr) {
        /* Automatic referer requested, this may be combined with a
           set initial one */
        config->autoreferer = TRUE;
        *ptr = 0; /* null-terminate here */
      }
      else
        config->autoreferer = FALSE;
      ptr = *nextarg ? nextarg : NULL;
      err = getstr(&config->referer, ptr, ALLOW_BLANK);
    }
      break;
    case C_CERT: /* --cert */
      cleanarg(clearthis);
      GetFileAndPassword(nextarg, &config->cert, &config->key_passwd);
      break;
    case C_CACERT: /* --cacert */
      err = getstr(&config->cacert, nextarg, DENY_BLANK);
      break;
    case C_CA_NATIVE: /* --ca-native */
      config->native_ca_store = toggle;
      break;
    case C_PROXY_CA_NATIVE: /* --proxy-ca-native */
      config->proxy_native_ca_store = toggle;
      break;
    case C_CERT_TYPE: /* --cert-type */
      err = getstr(&config->cert_type, nextarg, DENY_BLANK);
      break;
    case C_KEY: /* --key */
      err = getstr(&config->key, nextarg, DENY_BLANK);
      break;
    case C_KEY_TYPE: /* --key-type */
      err = getstr(&config->key_type, nextarg, DENY_BLANK);
      break;
    case C_PASS: /* --pass */
      err = getstr(&config->key_passwd, nextarg, DENY_BLANK);
      cleanarg(clearthis);
      break;
    case C_ENGINE: /* --engine */
      err = getstr(&config->engine, nextarg, DENY_BLANK);
      if(!err &&
         config->engine && !strcmp(config->engine, "list")) {
        err = PARAM_ENGINES_REQUESTED;
      }
      break;
    case C_ECH: /* --ech */
      if(!feature_ech)
        err = PARAM_LIBCURL_DOESNT_SUPPORT;
      else if(strlen(nextarg) > 4 && strncasecompare("pn:", nextarg, 3)) {
        /* a public_name */
        err = getstr(&config->ech_public, nextarg, DENY_BLANK);
      }
      else if(strlen(nextarg) > 5 && strncasecompare("ecl:", nextarg, 4)) {
        /* an ECHConfigList */
        if('@' != *(nextarg + 4)) {
          err = getstr(&config->ech_config, nextarg, DENY_BLANK);
        }
        else {
          /* Indirect case: @filename or @- for stdin */
          char *tmpcfg = NULL;
          FILE *file;

          nextarg++;        /* skip over '@' */
          if(!strcmp("-", nextarg)) {
            file = stdin;
          }
          else {
            file = fopen(nextarg, FOPEN_READTEXT);
          }
          if(!file) {
            warnf(global,
                  "Couldn't read file \"%s\" "
                  "specified for \"--ech ecl:\" option",
                  nextarg);
            return PARAM_BAD_USE; /*  */
          }
          err = file2string(&tmpcfg, file);
          if(file != stdin)
            fclose(file);
          if(err)
            return err;
          config->ech_config = aprintf("ecl:%s",tmpcfg);
          if(!config->ech_config)
            return PARAM_NO_MEM;
          free(tmpcfg);
      } /* file done */
    }
    else {
      /* Simple case: just a string, with a keyword */
      err = getstr(&config->ech, nextarg, DENY_BLANK);
    }
    break;
    case C_CAPATH: /* --capath */
      err = getstr(&config->capath, nextarg, DENY_BLANK);
      break;
    case C_PUBKEY: /* --pubkey */
      err = getstr(&config->pubkey, nextarg, DENY_BLANK);
      break;
    case C_HOSTPUBMD5: /* --hostpubmd5 */
      err = getstr(&config->hostpubmd5, nextarg, DENY_BLANK);
      if(!err) {
        if(!config->hostpubmd5 || strlen(config->hostpubmd5) != 32)
          err = PARAM_BAD_USE;
      }
      break;
    case C_HOSTPUBSHA256: /* --hostpubsha256 */
      err = getstr(&config->hostpubsha256, nextarg, DENY_BLANK);
      break;
    case C_CRLFILE: /* --crlfile */
      err = getstr(&config->crlfile, nextarg, DENY_BLANK);
      break;
    case C_TLSUSER: /* --tlsuser */
      if(!feature_tls_srp)
        err = PARAM_LIBCURL_DOESNT_SUPPORT;
      else
        err = getstr(&config->tls_username, nextarg, DENY_BLANK);
      cleanarg(clearthis);
      break;
    case C_TLSPASSWORD: /* --tlspassword */
      if(!feature_tls_srp)
        err = PARAM_LIBCURL_DOESNT_SUPPORT;
      else
        err = getstr(&config->tls_password, nextarg, ALLOW_BLANK);
      cleanarg(clearthis);
      break;
    case C_TLSAUTHTYPE: /* --tlsauthtype */
      if(!feature_tls_srp)
        err = PARAM_LIBCURL_DOESNT_SUPPORT;
      else {
        err = getstr(&config->tls_authtype, nextarg, DENY_BLANK);
        if(!err && strcmp(config->tls_authtype, "SRP"))
          err = PARAM_LIBCURL_DOESNT_SUPPORT; /* only support TLS-SRP */
      }
      break;
    case C_SSL_ALLOW_BEAST: /* --ssl-allow-beast */
      if(feature_ssl)
        config->ssl_allow_beast = toggle;
      break;
    case C_SSL_AUTO_CLIENT_CERT: /* --ssl-auto-client-cert */
      if(feature_ssl)
        config->ssl_auto_client_cert = toggle;
      break;
    case C_PROXY_SSL_AUTO_CLIENT_CERT: /* --proxy-ssl-auto-client-cert */
      if(feature_ssl)
        config->proxy_ssl_auto_client_cert = toggle;
      break;
    case C_PINNEDPUBKEY: /* --pinnedpubkey */
      err = getstr(&config->pinnedpubkey, nextarg, DENY_BLANK);
      break;
    case C_PROXY_PINNEDPUBKEY: /* --proxy-pinnedpubkey */
      err = getstr(&config->proxy_pinnedpubkey, nextarg, DENY_BLANK);
      break;
    case C_CERT_STATUS: /* --cert-status */
      config->verifystatus = TRUE;
      break;
    case C_DOH_CERT_STATUS: /* --doh-cert-status */
      config->doh_verifystatus = TRUE;
      break;
    case C_FALSE_START: /* --false-start */
      config->falsestart = TRUE;
      break;
    case C_SSL_NO_REVOKE: /* --ssl-no-revoke */
      if(feature_ssl)
        config->ssl_no_revoke = TRUE;
      break;
    case C_SSL_REVOKE_BEST_EFFORT: /* --ssl-revoke-best-effort */
      if(feature_ssl)
        config->ssl_revoke_best_effort = TRUE;
      break;
    case C_TCP_FASTOPEN: /* --tcp-fastopen */
      config->tcp_fastopen = TRUE;
      break;
    case C_PROXY_TLSUSER: /* --proxy-tlsuser */
      cleanarg(clearthis);
      if(!feature_tls_srp)
        err = PARAM_LIBCURL_DOESNT_SUPPORT;
      else
        err = getstr(&config->proxy_tls_username, nextarg, ALLOW_BLANK);
      break;
    case C_PROXY_TLSPASSWORD: /* --proxy-tlspassword */
      cleanarg(clearthis);
      if(!feature_tls_srp)
        err = PARAM_LIBCURL_DOESNT_SUPPORT;
      else
        err = getstr(&config->proxy_tls_password, nextarg, DENY_BLANK);
      break;
    case C_PROXY_TLSAUTHTYPE: /* --proxy-tlsauthtype */
      if(!feature_tls_srp)
        err = PARAM_LIBCURL_DOESNT_SUPPORT;
      else {
        err = getstr(&config->proxy_tls_authtype, nextarg, DENY_BLANK);
        if(!err && strcmp(config->proxy_tls_authtype, "SRP"))
          err = PARAM_LIBCURL_DOESNT_SUPPORT; /* only support TLS-SRP */
      }
      break;
    case C_PROXY_CERT: /* --proxy-cert */
      cleanarg(clearthis);
      GetFileAndPassword(nextarg, &config->proxy_cert,
                         &config->proxy_key_passwd);
      break;
    case C_PROXY_CERT_TYPE: /* --proxy-cert-type */
      err = getstr(&config->proxy_cert_type, nextarg, DENY_BLANK);
      break;
    case C_PROXY_KEY: /* --proxy-key */
      err = getstr(&config->proxy_key, nextarg, ALLOW_BLANK);
      break;
    case C_PROXY_KEY_TYPE: /* --proxy-key-type */
      err = getstr(&config->proxy_key_type, nextarg, DENY_BLANK);
      break;
    case C_PROXY_PASS: /* --proxy-pass */
      err = getstr(&config->proxy_key_passwd, nextarg, ALLOW_BLANK);
      cleanarg(clearthis);
      break;
    case C_PROXY_CIPHERS: /* --proxy-ciphers */
      err = getstr(&config->proxy_cipher_list, nextarg, DENY_BLANK);
      break;
    case C_PROXY_CRLFILE: /* --proxy-crlfile */
      err = getstr(&config->proxy_crlfile, nextarg, DENY_BLANK);
      break;
    case C_PROXY_SSL_ALLOW_BEAST: /* --proxy-ssl-allow-beast */
      if(feature_ssl)
        config->proxy_ssl_allow_beast = toggle;
      break;
    case C_LOGIN_OPTIONS: /* --login-options */
      err = getstr(&config->login_options, nextarg, ALLOW_BLANK);
      break;
    case C_PROXY_CACERT: /* --proxy-cacert */
      err = getstr(&config->proxy_cacert, nextarg, DENY_BLANK);
      break;
    case C_PROXY_CAPATH: /* --proxy-capath */
      err = getstr(&config->proxy_capath, nextarg, DENY_BLANK);
      break;
    case C_PROXY_INSECURE: /* --proxy-insecure */
      config->proxy_insecure_ok = toggle;
      break;
    case C_PROXY_TLSV1: /* --proxy-tlsv1 */
      /* TLS version 1 for proxy */
      config->proxy_ssl_version = CURL_SSLVERSION_TLSv1;
      break;
    case C_SOCKS5_BASIC: /* --socks5-basic */
      if(toggle)
        config->socks5_auth |= CURLAUTH_BASIC;
      else
        config->socks5_auth &= ~CURLAUTH_BASIC;
      break;
    case C_SOCKS5_GSSAPI: /* --socks5-gssapi */
      if(toggle)
        config->socks5_auth |= CURLAUTH_GSSAPI;
      else
        config->socks5_auth &= ~CURLAUTH_GSSAPI;
      break;
    case C_ETAG_SAVE: /* --etag-save */
      err = getstr(&config->etag_save_file, nextarg, DENY_BLANK);
      break;
    case C_ETAG_COMPARE: /* --etag-compare */
      err = getstr(&config->etag_compare_file, nextarg, DENY_BLANK);
      break;
    case C_CURVES: /* --curves */
      err = getstr(&config->ssl_ec_curves, nextarg, DENY_BLANK);
      break;
    case C_FAIL_EARLY: /* --fail-early */
      global->fail_early = toggle;
      break;
    case C_STYLED_OUTPUT: /* --styled-output */
      global->styled_output = toggle;
      break;
    case C_MAIL_RCPT_ALLOWFAILS: /* --mail-rcpt-allowfails */
      config->mail_rcpt_allowfails = toggle;
      break;
    case C_FAIL_WITH_BODY: /* --fail-with-body */
      config->failwithbody = toggle;
      if(config->failonerror && config->failwithbody) {
        errorf(config->global, "You must select either --fail or "
               "--fail-with-body, not both.");
        err = PARAM_BAD_USE;
      }
      break;
    case C_REMOVE_ON_ERROR: /* --remove-on-error */
      config->rm_partial = toggle;
      break;
    case C_FAIL: /* --fail */
      config->failonerror = toggle;
      if(config->failonerror && config->failwithbody) {
        errorf(config->global, "You must select either --fail or "
               "--fail-with-body, not both.");
        err = PARAM_BAD_USE;
      }
      break;
    case C_FORM: /* --form */
    case C_FORM_STRING: /* --form-string */
      /* "form data" simulation, this is a little advanced so lets do our best
         to sort this out slowly and carefully */
      if(formparse(config,
                   nextarg,
                   &config->mimeroot,
                   &config->mimecurrent,
                   (cmd == C_FORM_STRING))) /* literal string */
        err = PARAM_BAD_USE;
      else if(SetHTTPrequest(config, TOOL_HTTPREQ_MIMEPOST, &config->httpreq))
        err = PARAM_BAD_USE;
      break;
    case C_GLOBOFF: /* --globoff */
      config->globoff = toggle;
      break;
    case C_GET: /* --get */
      config->use_httpget = toggle;
      break;
    case C_REQUEST_TARGET: /* --request-target */
      err = getstr(&config->request_target, nextarg, DENY_BLANK);
      break;
    case C_HELP: /* --help */
      if(toggle) {
        if(*nextarg) {
          global->help_category = strdup(nextarg);
          if(!global->help_category) {
            err = PARAM_NO_MEM;
            break;
          }
        }
        err = PARAM_HELP_REQUESTED;
      }
      /* we now actually support --no-help too! */
      break;
    case C_HEADER: /* --header */
    case C_PROXY_HEADER: /* --proxy-header */
      /* A custom header to append to a list */
      if(nextarg[0] == '@') {
        /* read many headers from a file or stdin */
        char *string;
        size_t len;
        bool use_stdin = !strcmp(&nextarg[1], "-");
        FILE *file = use_stdin ? stdin : fopen(&nextarg[1], FOPEN_READTEXT);
        if(!file) {
          errorf(global, "Failed to open %s", &nextarg[1]);
          err = PARAM_READ_ERROR;
        }
        else {
          err = file2memory(&string, &len, file);
          if(!err && string) {
            /* Allow strtok() here since this is not used threaded */
            /* !checksrc! disable BANNEDFUNC 2 */
            char *h = strtok(string, "\r\n");
            while(h) {
              if(cmd == C_PROXY_HEADER) /* --proxy-header */
                err = add2list(&config->proxyheaders, h);
              else
                err = add2list(&config->headers, h);
              if(err)
                break;
              h = strtok(NULL, "\r\n");
            }
            free(string);
          }
          if(!use_stdin)
            fclose(file);
        }
      }
      else {
        if(cmd == C_PROXY_HEADER) /* --proxy-header */
          err = add2list(&config->proxyheaders, nextarg);
        else
          err = add2list(&config->headers, nextarg);
      }
      break;
    case C_INCLUDE: /* --include */
    case C_SHOW_HEADERS: /* --show-headers */
      config->show_headers = toggle; /* show the headers as well in the
                                        general output stream */
      break;
    case C_JUNK_SESSION_COOKIES: /* --junk-session-cookies */
      config->cookiesession = toggle;
      break;
    case C_HEAD: /* --head */
      config->no_body = toggle;
      config->show_headers = toggle;
      if(SetHTTPrequest(config, (config->no_body) ? TOOL_HTTPREQ_HEAD :
                        TOOL_HTTPREQ_GET, &config->httpreq))
        err = PARAM_BAD_USE;
      break;
    case C_REMOTE_HEADER_NAME: /* --remote-header-name */
      config->content_disposition = toggle;
      break;
    case C_INSECURE: /* --insecure */
      config->insecure_ok = toggle;
      break;
    case C_DOH_INSECURE: /* --doh-insecure */
      config->doh_insecure_ok = toggle;
      break;
    case C_CONFIG: /* --config */
      if(parseconfig(nextarg, global)) {
        errorf(global, "cannot read config from '%s'", nextarg);
        err = PARAM_READ_ERROR;
      }
      break;
    case C_LIST_ONLY: /* --list-only */
      config->dirlistonly = toggle; /* only list the names of the FTP dir */
      break;
    case C_LOCATION_TRUSTED: /* --location-trusted */
      /* Continue to send authentication (user+password) when following
       * locations, even when hostname changed */
      config->unrestricted_auth = toggle;
      FALLTHROUGH();
    case C_LOCATION: /* --location */
      config->followlocation = toggle; /* Follow Location: HTTP headers */
      break;
    case C_MAX_TIME: /* --max-time */
      /* specified max time */
      err = secs2ms(&config->timeout_ms, nextarg);
      break;
    case C_MANUAL: /* --manual */
      if(toggle) { /* --no-manual shows no manual... */
#ifndef USE_MANUAL
        warnf(global,
              "built-in manual was disabled at build-time");
#endif
        err = PARAM_MANUAL_REQUESTED;
      }
      break;
    case C_NETRC_OPTIONAL: /* --netrc-optional */
      config->netrc_opt = toggle;
      break;
    case C_NETRC_FILE: /* --netrc-file */
      err = getstr(&config->netrc_file, nextarg, DENY_BLANK);
      break;
    case C_NETRC: /* --netrc */
      /* pick info from .netrc, if this is used for http, curl will
         automatically enforce user+password with the request */
      config->netrc = toggle;
      break;
    case C_BUFFER: /* --buffer */
      /* disable the output I/O buffering. note that the option is called
         --buffer but is mostly used in the negative form: --no-buffer */
      config->nobuffer = longopt ? !toggle : TRUE;
      break;
    case C_REMOTE_NAME_ALL: /* --remote-name-all */
      config->default_node_flags = toggle ? GETOUT_USEREMOTE : 0;
      break;
    case C_OUTPUT_DIR: /* --output-dir */
      err = getstr(&config->output_dir, nextarg, DENY_BLANK);
      break;
    case C_CLOBBER: /* --clobber */
      config->file_clobber_mode = toggle ? CLOBBER_ALWAYS : CLOBBER_NEVER;
      break;
    case C_OUTPUT: /* --output */
    case C_REMOTE_NAME: /* --remote-name */
      /* output file */
      if(!config->url_out)
        config->url_out = config->url_list;
      if(config->url_out) {
        /* there is a node here, if it already is filled-in continue to find
           an "empty" node */
        while(config->url_out && (config->url_out->flags & GETOUT_OUTFILE))
          config->url_out = config->url_out->next;
      }

      /* now there might or might not be an available node to fill in! */

      if(config->url_out)
        /* existing node */
        url = config->url_out;
      else {
        if(!toggle && !config->default_node_flags)
          break;
        /* there was no free node, create one! */
        config->url_out = url = new_getout(config);
      }

      if(!url) {
        err = PARAM_NO_MEM;
        break;
      }

      /* fill in the outfile */
      if('o' == letter) {
        err = getstr(&url->outfile, nextarg, DENY_BLANK);
        url->flags &= ~GETOUT_USEREMOTE; /* switch off */
      }
      else {
        url->outfile = NULL; /* leave it */
        if(toggle)
          url->flags |= GETOUT_USEREMOTE;  /* switch on */
        else
          url->flags &= ~GETOUT_USEREMOTE; /* switch off */
      }
      url->flags |= GETOUT_OUTFILE;
      break;
    case C_FTP_PORT: /* --ftp-port */
      /* This makes the FTP sessions use PORT instead of PASV */
      /* use <eth0> or <192.168.10.10> style addresses. Anything except
         this will make us try to get the "default" address.
         NOTE: this is a changed behavior since the released 4.1!
      */
      err = getstr(&config->ftpport, nextarg, DENY_BLANK);
      break;
    case C_PROXYTUNNEL: /* --proxytunnel */
      /* proxy tunnel for non-http protocols */
      config->proxytunnel = toggle;
      break;

    case C_DISABLE: /* --disable */
      /* if used first, already taken care of, we do it like this so we do not
         cause an error! */
      break;
    case C_QUOTE: /* --quote */
      /* QUOTE command to send to FTP server */
      switch(nextarg[0]) {
      case '-':
        /* prefixed with a dash makes it a POST TRANSFER one */
        nextarg++;
        err = add2list(&config->postquote, nextarg);
        break;
      case '+':
        /* prefixed with a plus makes it a just-before-transfer one */
        nextarg++;
        err = add2list(&config->prequote, nextarg);
        break;
      default:
        err = add2list(&config->quote, nextarg);
        break;
      }
      break;
    case C_RANGE: /* --range */
      /* Specifying a range WITHOUT A DASH will create an illegal HTTP range
         (and will not actually be range by definition). The manpage
         previously claimed that to be a good way, why this code is added to
         work-around it. */
      if(ISDIGIT(*nextarg) && !strchr(nextarg, '-')) {
        char buffer[32];
        if(curlx_strtoofft(nextarg, NULL, 10, &value)) {
          warnf(global, "unsupported range point");
          err = PARAM_BAD_USE;
        }
        else {
          warnf(global,
                "A specified range MUST include at least one dash (-). "
                "Appending one for you");
          msnprintf(buffer, sizeof(buffer), "%" CURL_FORMAT_CURL_OFF_T "-",
                    value);
          Curl_safefree(config->range);
          config->range = strdup(buffer);
          if(!config->range)
            err = PARAM_NO_MEM;
        }
      }
      else {
        /* byte range requested */
        const char *tmp_range = nextarg;
        while(*tmp_range) {
          if(!ISDIGIT(*tmp_range) && *tmp_range != '-' && *tmp_range != ',') {
            warnf(global, "Invalid character is found in given range. "
                  "A specified range MUST have only digits in "
                  "\'start\'-\'stop\'. The server's response to this "
                  "request is uncertain.");
            break;
          }
          tmp_range++;
        }
        err = getstr(&config->range, nextarg, DENY_BLANK);
      }
      break;
    case C_REMOTE_TIME: /* --remote-time */
      /* use remote file's time */
      config->remote_time = toggle;
      break;
    case C_SILENT: /* --silent */
      global->silent = toggle;
      break;
    case C_SKIP_EXISTING: /* --skip-existing */
      config->skip_existing = toggle;
      break;
    case C_SHOW_ERROR: /* --show-error */
      global->showerror = toggle;
      break;
    case C_TELNET_OPTION: /* --telnet-option */
      /* Telnet options */
      err = add2list(&config->telnet_options, nextarg);
      break;
    case C_UPLOAD_FILE: /* --upload-file */
      /* we are uploading */
      if(!config->url_ul)
        config->url_ul = config->url_list;
      if(config->url_ul) {
        /* there is a node here, if it already is filled-in continue to find
           an "empty" node */
        while(config->url_ul && (config->url_ul->flags & GETOUT_UPLOAD))
          config->url_ul = config->url_ul->next;
      }

      /* now there might or might not be an available node to fill in! */

      if(config->url_ul)
        /* existing node */
        url = config->url_ul;
      else
        /* there was no free node, create one! */
        config->url_ul = url = new_getout(config);

      if(!url) {
        err = PARAM_NO_MEM;
        break;
      }

      url->flags |= GETOUT_UPLOAD; /* mark -T used */
      if(!*nextarg)
        url->flags |= GETOUT_NOUPLOAD;
      else {
        /* "-" equals stdin, but keep the string around for now */
        err = getstr(&url->infile, nextarg, DENY_BLANK);
      }
      break;
    case C_USER: /* --user */
      /* user:password  */
      err = getstr(&config->userpwd, nextarg, ALLOW_BLANK);
      cleanarg(clearthis);
      break;
    case C_PROXY_USER: /* --proxy-user */
      /* Proxy user:password  */
      err = getstr(&config->proxyuserpwd, nextarg, ALLOW_BLANK);
      cleanarg(clearthis);
      break;
    case C_VERBOSE: /* --verbose */
      /* This option is a super-boolean with side effect when applied
       * more than once in the same argument flag, like `-vvv`. */
      if(!toggle) {
        global->verbosity = 0;
        if(set_trace_config(global, "-all"))
          err = PARAM_NO_MEM;
        global->tracetype = TRACE_NONE;
        break;
      }
      else if(!nopts) {
        /* fist `-v` in an argument resets to base verbosity */
        global->verbosity = 0;
        if(set_trace_config(global, "-all")) {
          err = PARAM_NO_MEM;
          break;
        }
      }
      /* the '%' thing here will cause the trace get sent to stderr */
      switch(global->verbosity) {
      case 0:
        global->verbosity = 1;
        Curl_safefree(global->trace_dump);
        global->trace_dump = strdup("%");
        if(!global->trace_dump)
          err = PARAM_NO_MEM;
        else {
          if(global->tracetype && (global->tracetype != TRACE_PLAIN))
            warnf(global,
                  "-v, --verbose overrides an earlier trace option");
          global->tracetype = TRACE_PLAIN;
        }
        break;
      case 1:
        global->verbosity = 2;
        if(set_trace_config(global, "ids,time,protocol"))
          err = PARAM_NO_MEM;
        break;
      case 2:
        global->verbosity = 3;
        global->tracetype = TRACE_ASCII;
        if(set_trace_config(global, "ssl,read,write"))
          err = PARAM_NO_MEM;
        break;
      case 3:
        global->verbosity = 4;
        if(set_trace_config(global, "network"))
          err = PARAM_NO_MEM;
        break;
      default:
        /* no effect for now */
        break;
      }
      break;
    case C_VERSION: /* --version */
      if(toggle)    /* --no-version yields no output! */
        err = PARAM_VERSION_INFO_REQUESTED;
      break;
    case C_WRITE_OUT: /* --write-out */
      /* get the output string */
      if('@' == *nextarg) {
        /* the data begins with a '@' letter, it means that a filename
           or - (stdin) follows */
        FILE *file;
        const char *fname;
        nextarg++; /* pass the @ */
        if(!strcmp("-", nextarg)) {
          fname = "<stdin>";
          file = stdin;
        }
        else {
          fname = nextarg;
          file = fopen(fname, FOPEN_READTEXT);
          if(!file) {
            errorf(global, "Failed to open %s", fname);
            err = PARAM_READ_ERROR;
            break;
          }
        }
        Curl_safefree(config->writeout);
        err = file2string(&config->writeout, file);
        if(file && (file != stdin))
          fclose(file);
        if(err)
          break;
        if(!config->writeout)
          warnf(global, "Failed to read %s", fname);
      }
      else
        err = getstr(&config->writeout, nextarg, ALLOW_BLANK);
      break;
    case C_PREPROXY: /* --preproxy */
      err = getstr(&config->preproxy, nextarg, DENY_BLANK);
      break;
    case C_PROXY: /* --proxy */
      /* --proxy */
      err = getstr(&config->proxy, nextarg, ALLOW_BLANK);
      if(config->proxyver != CURLPROXY_HTTPS2)
        config->proxyver = CURLPROXY_HTTP;
      break;
    case C_REQUEST: /* --request */
      /* set custom request */
      err = getstr(&config->customrequest, nextarg, DENY_BLANK);
      break;
    case C_SPEED_TIME: /* --speed-time */
      /* low speed time */
      err = str2unum(&config->low_speed_time, nextarg);
      if(!err && !config->low_speed_limit)
        config->low_speed_limit = 1;
      break;
    case C_SPEED_LIMIT: /* --speed-limit */
      /* low speed limit */
      err = str2unum(&config->low_speed_limit, nextarg);
      if(!err && !config->low_speed_time)
        config->low_speed_time = 30;
      break;
    case C_PARALLEL: /* --parallel */
      global->parallel = toggle;
      break;
    case C_PARALLEL_MAX: {  /* --parallel-max */
      long val;
      err = str2unum(&val, nextarg);
      if(err)
        break;
      if(val > MAX_PARALLEL)
        global->parallel_max = MAX_PARALLEL;
      else if(val < 1)
        global->parallel_max = PARALLEL_DEFAULT;
      else
        global->parallel_max = (unsigned short)val;
      break;
    }
    case C_PARALLEL_IMMEDIATE:   /* --parallel-immediate */
      global->parallel_connect = toggle;
      break;
    case C_TIME_COND: /* --time-cond */
      switch(*nextarg) {
      case '+':
        nextarg++;
        FALLTHROUGH();
      default:
        /* If-Modified-Since: (section 14.28 in RFC2068) */
        config->timecond = CURL_TIMECOND_IFMODSINCE;
        break;
      case '-':
        /* If-Unmodified-Since:  (section 14.24 in RFC2068) */
        config->timecond = CURL_TIMECOND_IFUNMODSINCE;
        nextarg++;
        break;
      case '=':
        /* Last-Modified:  (section 14.29 in RFC2068) */
        config->timecond = CURL_TIMECOND_LASTMOD;
        nextarg++;
        break;
      }
      config->condtime = (curl_off_t)curl_getdate(nextarg, NULL);
      if(-1 == config->condtime) {
        /* now let's see if it is a filename to get the time from instead! */
        rc = getfiletime(nextarg, global, &value);
        if(!rc)
          /* pull the time out from the file */
          config->condtime = value;
        else {
          /* failed, remove time condition */
          config->timecond = CURL_TIMECOND_NONE;
          warnf(global,
                "Illegal date format for -z, --time-cond (and not "
                "a filename). Disabling time condition. "
                "See curl_getdate(3) for valid date syntax.");
        }
      }
      break;
    case C_MPTCP: /* --mptcp */
      config->mptcp = TRUE;
      break;
    default: /* unknown flag */
      err = PARAM_OPTION_UNKNOWN;
      break;
    }
    a = NULL;
    ++nopts; /* processed one option from `flag` input, loop for more */
  } while(!longopt && !singleopt && *++parse && !*usedarg && !err);

error:
  if(nextalloc)
    free(nextarg);
  return err;
}

ParameterError parse_args(struct GlobalConfig *global, int argc,
                          argv_item_t argv[])
{
  int i;
  bool stillflags;
  char *orig_opt = NULL;
  ParameterError result = PARAM_OK;
  struct OperationConfig *config = global->first;

  for(i = 1, stillflags = TRUE; i < argc && !result; i++) {
    orig_opt = curlx_convert_tchar_to_UTF8(argv[i]);
    if(!orig_opt)
      return PARAM_NO_MEM;

    if(stillflags && ('-' == orig_opt[0])) {
      bool passarg;

      if(!strcmp("--", orig_opt))
        /* This indicates the end of the flags and thus enables the
           following (URL) argument to start with -. */
        stillflags = FALSE;
      else {
        char *nextarg = NULL;
        if(i < (argc - 1)) {
          nextarg = curlx_convert_tchar_to_UTF8(argv[i + 1]);
          if(!nextarg) {
            curlx_unicodefree(orig_opt);
            return PARAM_NO_MEM;
          }
        }

        result = getparameter(orig_opt, nextarg, argv[i + 1], &passarg,
                              global, config);

        curlx_unicodefree(nextarg);
        config = global->last;
        if(result == PARAM_NEXT_OPERATION) {
          /* Reset result as PARAM_NEXT_OPERATION is only used here and not
             returned from this function */
          result = PARAM_OK;

          if(config->url_list && config->url_list->url) {
            /* Allocate the next config */
            config->next = malloc(sizeof(struct OperationConfig));
            if(config->next) {
              /* Initialise the newly created config */
              config_init(config->next);

              /* Set the global config pointer */
              config->next->global = global;

              /* Update the last config pointer */
              global->last = config->next;

              /* Move onto the new config */
              config->next->prev = config;
              config = config->next;
            }
            else
              result = PARAM_NO_MEM;
          }
          else {
            errorf(global, "missing URL before --next");
            result = PARAM_BAD_USE;
          }
        }
        else if(!result && passarg)
          i++; /* we are supposed to skip this */
      }
    }
    else {
      bool used;

      /* Just add the URL please */
      result = getparameter("--url", orig_opt, argv[i], &used, global, config);
    }

    if(!result)
      curlx_unicodefree(orig_opt);
  }

  if(!result && config->content_disposition) {
    if(config->resume_from_current)
      result = PARAM_CONTDISP_RESUME_FROM;
  }

  if(result && result != PARAM_HELP_REQUESTED &&
     result != PARAM_MANUAL_REQUESTED &&
     result != PARAM_VERSION_INFO_REQUESTED &&
     result != PARAM_ENGINES_REQUESTED &&
     result != PARAM_CA_EMBED_REQUESTED) {
    const char *reason = param2text(result);

    if(orig_opt && strcmp(":", orig_opt))
      helpf(tool_stderr, "option %s: %s", orig_opt, reason);
    else
      helpf(tool_stderr, "%s", reason);
  }

  curlx_unicodefree(orig_opt);
  return result;
}
