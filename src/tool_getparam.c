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

#define ENABLE_CURLX_PRINTF
/* use our own printf() functions */
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

struct LongShort {
  const char *lname;  /* long name option */
  enum {
    ARG_NONE,   /* stand-alone but not a boolean */
    ARG_BOOL,   /* accepts a --no-[name] prefix */
    ARG_STRING, /* requires an argument */
    ARG_FILENAME /* requires an argument, usually a file name */
  } desc;
  const char *letter; /* short name option */
  /* 'letter' strings with more than one character have *no* short option. */
};

/* this array MUST be alphasorted based on the 'lname' */
static const struct LongShort aliases[]= {
  {"abstract-unix-socket",     ARG_FILENAME, "$W"},
  {"alpn",                     ARG_BOOL,     "*H"},
  {"alt-svc",                  ARG_STRING,   "ba"},
  {"anyauth",                  ARG_BOOL,     "*o"},
  {"append",                   ARG_BOOL,     "a",},
  {"aws-sigv4",                ARG_STRING,   "*V"},
  {"basic",                    ARG_BOOL,     "*n"},
  {"buffer",                   ARG_BOOL,     "N",},
  {"ca-native",                ARG_BOOL,     "EG"},
  {"cacert",                   ARG_FILENAME, "Ea"},
  {"capath",                   ARG_FILENAME, "Eg"},
  {"cert",                     ARG_FILENAME, "E",},
  {"cert-status",              ARG_BOOL,     "Eq"},
  {"cert-type",                ARG_STRING,   "Eb"},
  {"ciphers",                  ARG_STRING,   "*d"},
  {"clobber",                  ARG_BOOL,     "Oc"},
  {"compressed",               ARG_BOOL,     "*j"},
  {"compressed-ssh",           ARG_BOOL,     "$Z"},
  {"config",                   ARG_FILENAME, "K",},
  {"connect-timeout",          ARG_STRING,   "*c"},
  {"connect-to",               ARG_STRING,   "$U"},
  {"continue-at",              ARG_STRING,   "C",},
  {"cookie",                   ARG_STRING,   "b",},
  {"cookie-jar",               ARG_STRING,   "c",},
  {"create-dirs",              ARG_BOOL,     "*r"},
  {"create-file-mode",         ARG_STRING,   "*R"},
  {"crlf",                     ARG_BOOL,     "*u"},
  {"crlfile",                  ARG_FILENAME, "Ej"},
  {"curves",                   ARG_STRING,   "EE"},
  {"data",                     ARG_STRING,   "d",},
  {"data-ascii",               ARG_STRING,   "da"},
  {"data-binary",              ARG_STRING,   "db"},
  {"data-raw",                 ARG_STRING,   "dr"},
  {"data-urlencode",           ARG_STRING,   "de"},
  {"delegation",               ARG_STRING,   "$G"},
  {"digest",                   ARG_BOOL,     "*k"},
  {"disable",                  ARG_BOOL,     "q",},
  {"disable-eprt",             ARG_BOOL,     "*z"},
  {"disable-epsv",             ARG_BOOL,     "*e"},
  {"disallow-username-in-url", ARG_BOOL,     "*f"},
  {"dns-interface",            ARG_STRING,   "*D"},
  {"dns-ipv4-addr",            ARG_STRING,   "*4"},
  {"dns-ipv6-addr",            ARG_STRING,   "*6"},
  {"dns-servers",              ARG_STRING,   "*F"},
  {"doh-cert-status",          ARG_BOOL,     "EQ"},
  {"doh-insecure",             ARG_BOOL,     "kd"},
  {"doh-url"        ,          ARG_STRING,   "*C"},
  {"dump-header",              ARG_FILENAME, "D",},
  {"egd-file",                 ARG_STRING,   "*b"},
  {"engine",                   ARG_STRING,   "Ef"},
  {"eprt",                     ARG_BOOL,     "*Z"},
  {"epsv",                     ARG_BOOL,     "*E"},
  {"etag-compare",             ARG_FILENAME, "ED"},
  {"etag-save",                ARG_FILENAME, "EC"},
  {"expect100-timeout",        ARG_STRING,   "$R"},
  {"fail",                     ARG_BOOL,     "f",},
  {"fail-early",               ARG_BOOL,     "fa"},
  {"fail-with-body",           ARG_BOOL,     "fd"},
  {"false-start",              ARG_BOOL,     "Er"},
  {"form",                     ARG_STRING,   "F",},
  {"form-escape",              ARG_BOOL,     "$l"},
  {"form-string",              ARG_STRING,   "Fs"},
  {"ftp-account",              ARG_STRING,   "$m"},
  {"ftp-alternative-to-user",  ARG_STRING,   "$u"},
  {"ftp-create-dirs",          ARG_BOOL,     "*q"},
  {"ftp-method",               ARG_STRING,   "$r"},
  {"ftp-pasv",                 ARG_BOOL,     "$b"},
  {"ftp-port",                 ARG_STRING,   "P",},
  {"ftp-pret",                 ARG_BOOL,     "$C"},
  {"ftp-skip-pasv-ip",         ARG_BOOL,     "$q"},
  {"ftp-ssl",                  ARG_BOOL,     "$a"},
  {"ftp-ssl-ccc",              ARG_BOOL,     "$y"},
  {"ftp-ssl-ccc-mode",         ARG_STRING,   "$j"},
  {"ftp-ssl-control",          ARG_BOOL,     "$x"},
  {"ftp-ssl-reqd",             ARG_BOOL,     "$v"},
  {"get",                      ARG_BOOL,     "G",},
  {"globoff",                  ARG_BOOL,     "g",},
  {"happy-eyeballs-timeout-ms", ARG_STRING,  "$~"},
  {"haproxy-clientip",         ARG_STRING,   "*P"},
  {"haproxy-protocol",         ARG_BOOL,     "*X"},
  {"head",                     ARG_BOOL,     "I",},
  {"header",                   ARG_STRING,   "H",},
  {"help",                     ARG_BOOL,     "h",},
  {"hostpubmd5",               ARG_STRING,   "Ei"},
  {"hostpubsha256",            ARG_STRING,   "EF"},
  {"hsts",                     ARG_STRING,   "bb"},
  {"http0.9",                  ARG_BOOL,     "09"},
  {"http1.0",                  ARG_NONE,     "0",},
  {"http1.1",                  ARG_NONE,     "01"},
  {"http2",                    ARG_NONE,     "02"},
  {"http2-prior-knowledge",    ARG_NONE,     "03"},
  {"http3",                    ARG_NONE,     "04"},
  {"http3-only",               ARG_NONE,     "05"},
  {"ignore-content-length",    ARG_BOOL,     "$p"},
  {"include",                  ARG_BOOL,     "i",},
  {"insecure",                 ARG_BOOL,     "k",},
  {"interface",                ARG_STRING,   "*w"},
  {"ipfs-gateway",             ARG_STRING,   "*S"},
  {"ipv4",                     ARG_NONE,     "4",},
  {"ipv6",                     ARG_NONE,     "6",},
  {"json",                     ARG_STRING,   "df"},
  {"junk-session-cookies",     ARG_BOOL,     "j",},
  {"keepalive",                ARG_BOOL,     "$1"},
  {"keepalive-time",           ARG_STRING,   "$3"},
  {"key",                      ARG_FILENAME, "Ec"},
  {"key-type",                 ARG_STRING,   "Ed"},
  {"krb",                      ARG_STRING,   "*x"},
  {"krb4",                     ARG_STRING,   "*x"},
  {"libcurl",                  ARG_STRING,   "$z"},
  {"limit-rate",               ARG_STRING,   "*i"},
  {"list-only",                ARG_BOOL,     "l",},
  {"local-port",               ARG_STRING,   "$s"},
  {"location",                 ARG_BOOL,     "L",},
  {"location-trusted",         ARG_BOOL,     "Lt"},
  {"login-options",            ARG_STRING,   "E5"},
  {"mail-auth",                ARG_STRING,   "$H"},
  {"mail-from",                ARG_STRING,   "$A"},
  {"mail-rcpt",                ARG_STRING,   "$B"},
  {"mail-rcpt-allowfails",     ARG_BOOL,     "fc"},
  {"manual",                   ARG_BOOL,     "M",},
  {"max-filesize",             ARG_STRING,   "*y"},
  {"max-redirs",               ARG_STRING,   "*s"},
  {"max-time",                 ARG_STRING,   "m",},
  {"metalink",                 ARG_BOOL,     "$J"},
  {"negotiate",                ARG_BOOL,     "*l"},
  {"netrc",                    ARG_BOOL,     "n",},
  {"netrc-file",               ARG_FILENAME, "ne"},
  {"netrc-optional",           ARG_BOOL,     "no"},
  {"next",                     ARG_NONE,     ":",},
  {"noproxy",                  ARG_STRING,   "$5"},
  {"npn",                      ARG_BOOL,     "*G"},
  {"ntlm",                     ARG_BOOL,     "*m"},
  {"ntlm-wb",                  ARG_BOOL,     "*M"},
  {"oauth2-bearer",            ARG_STRING,   "*B"},
  {"output",                   ARG_FILENAME, "o",},
  {"output-dir",               ARG_STRING,   "Ob"},
  {"parallel",                 ARG_BOOL,     "Z",},
  {"parallel-immediate",       ARG_BOOL,     "Zc"},
  {"parallel-max",             ARG_STRING,   "Zb"},
  {"pass",                     ARG_STRING,   "Ee"},
  {"path-as-is",               ARG_BOOL,     "$N"},
  {"pinnedpubkey",             ARG_STRING,   "Ep"},
  {"post301",                  ARG_BOOL,     "$0"},
  {"post302",                  ARG_BOOL,     "$4"},
  {"post303",                  ARG_BOOL,     "$I"},
  {"preproxy",                 ARG_STRING,   "xa"},
  {"progress-bar",             ARG_BOOL,     "#",},
  {"progress-meter",           ARG_BOOL,     "#m"},
  {"proto",                    ARG_STRING,   "$D"},
  {"proto-default",            ARG_STRING,   "$Q"},
  {"proto-redir",              ARG_STRING,   "$E"},
  {"proxy",                    ARG_STRING,   "x",},
  {"proxy-anyauth",            ARG_BOOL,     "$n"},
  {"proxy-basic",              ARG_BOOL,     "$f"},
  {"proxy-ca-native",          ARG_BOOL,     "EH"},
  {"proxy-cacert",             ARG_FILENAME, "E6"},
  {"proxy-capath",             ARG_FILENAME, "E7"},
  {"proxy-cert",               ARG_FILENAME, "Ex"},
  {"proxy-cert-type",          ARG_STRING,   "Ey"},
  {"proxy-ciphers",            ARG_STRING,   "E2"},
  {"proxy-crlfile",            ARG_FILENAME, "E3"},
  {"proxy-digest",             ARG_BOOL,     "$e"},
  {"proxy-header",             ARG_STRING,   "Hp"},
  {"proxy-http2",              ARG_BOOL,     "0a"},
  {"proxy-insecure",           ARG_BOOL,     "E8"},
  {"proxy-key",                ARG_FILENAME, "Ez"},
  {"proxy-key-type",           ARG_STRING,   "E0"},
  {"proxy-negotiate",          ARG_BOOL,     "$k"},
  {"proxy-ntlm",               ARG_BOOL,     "*t"},
  {"proxy-pass",               ARG_STRING,   "E1"},
  {"proxy-pinnedpubkey",       ARG_STRING,   "EP"},
  {"proxy-service-name",       ARG_STRING,   "$O"},
  {"proxy-ssl-allow-beast",    ARG_BOOL,     "E4"},
  {"proxy-ssl-auto-client-cert", ARG_BOOL,   "EO"},
  {"proxy-tls13-ciphers",      ARG_STRING,   "1B"},
  {"proxy-tlsauthtype",        ARG_STRING,   "Ew"},
  {"proxy-tlspassword",        ARG_STRING,   "Ev"},
  {"proxy-tlsuser",            ARG_STRING,   "Eu"},
  {"proxy-tlsv1",              ARG_NONE,     "E9"},
  {"proxy-user",               ARG_STRING,   "U",},
  {"proxy1.0",                 ARG_STRING,   "$8"},
  {"proxytunnel",              ARG_BOOL,     "p",},
  {"pubkey",                   ARG_STRING,   "Eh"},
  {"quote",                    ARG_STRING,   "Q",},
  {"random-file",              ARG_FILENAME, "*a"},
  {"range",                    ARG_STRING,   "r",},
  {"rate",                     ARG_STRING,   "*I"},
  {"raw",                      ARG_BOOL,     "$#"},
  {"referer",                  ARG_STRING,   "e",},
  {"remote-header-name",       ARG_BOOL,     "J",},
  {"remote-name",              ARG_BOOL,     "O",},
  {"remote-name-all",          ARG_BOOL,     "Oa"},
  {"remote-time",              ARG_BOOL,     "R",},
  {"remove-on-error",          ARG_BOOL,     "fe"},
  {"request",                  ARG_STRING,   "X",},
  {"request-target",           ARG_STRING,   "Ga"},
  {"resolve",                  ARG_STRING,   "$F"},
  {"retry",                    ARG_STRING,   "$g"},
  {"retry-all-errors",         ARG_BOOL,     "$!"},
  {"retry-connrefused",        ARG_BOOL,     "$V"},
  {"retry-delay",              ARG_STRING,   "$h"},
  {"retry-max-time",           ARG_STRING,   "$i"},
  {"sasl-authzid",             ARG_STRING,   "$6"},
  {"sasl-ir",                  ARG_BOOL,     "$K"},
  {"service-name",             ARG_STRING,   "$P"},
  {"sessionid",                ARG_BOOL,     "$w"},
  {"show-error",               ARG_BOOL,     "S",},
  {"silent",                   ARG_BOOL,     "s",},
  {"socks4",                   ARG_STRING,   "$t"},
  {"socks4a",                  ARG_STRING,   "$T"},
  {"socks5",                   ARG_STRING,   "$c"},
  {"socks5-basic",             ARG_BOOL,     "EA"},
  {"socks5-gssapi",            ARG_BOOL,     "EB"},
  {"socks5-gssapi-nec",        ARG_BOOL,     "$7"},
  {"socks5-gssapi-service",    ARG_STRING,   "$O"},
  {"socks5-hostname",          ARG_STRING,   "$2"},
  {"speed-limit",              ARG_STRING,   "Y",},
  {"speed-time",               ARG_STRING,   "y",},
  {"ssl",                      ARG_BOOL,     "$a"},
  {"ssl-allow-beast",          ARG_BOOL,     "En"},
  {"ssl-auto-client-cert",     ARG_BOOL,     "Eo"},
  {"ssl-no-revoke",            ARG_BOOL,     "Es"},
  {"ssl-reqd",                 ARG_BOOL,     "$v"},
  {"ssl-revoke-best-effort",   ARG_BOOL,     "ES"},
  {"sslv2",                    ARG_NONE,     "2",},
  {"sslv3",                    ARG_NONE,     "3",},
  {"stderr",                   ARG_FILENAME, "*v"},
  {"styled-output",            ARG_BOOL,     "fb"},
  {"suppress-connect-headers", ARG_BOOL,     "$Y"},
  {"tcp-fastopen",             ARG_BOOL,     "Et"},
  {"tcp-nodelay",              ARG_BOOL,     "$d"},
  {"telnet-option",            ARG_STRING,   "t",},
  {"test-event",               ARG_BOOL,     "$L"},
  {"tftp-blksize",             ARG_STRING,   "$9"},
  {"tftp-no-options",          ARG_BOOL,     "$S"},
  {"time-cond",                ARG_STRING,   "z",},
  {"tls-max",                  ARG_STRING,   "$X"},
  {"tls13-ciphers",            ARG_STRING,   "1A"},
  {"tlsauthtype",              ARG_STRING,   "Em"},
  {"tlspassword",              ARG_STRING,   "El"},
  {"tlsuser",                  ARG_STRING,   "Ek"},
  {"tlsv1",                    ARG_NONE,     "1",},
  {"tlsv1.0",                  ARG_NONE,     "10"},
  {"tlsv1.1",                  ARG_NONE,     "11"},
  {"tlsv1.2",                  ARG_NONE,     "12"},
  {"tlsv1.3",                  ARG_NONE,     "13"},
  {"tr-encoding",              ARG_BOOL,     "*J"},
  {"trace",                    ARG_FILENAME, "*g"},
  {"trace-ascii",              ARG_FILENAME, "*h"},
  {"trace-config",             ARG_STRING,   "$&"},
  {"trace-ids",                ARG_BOOL,     "$%"},
  {"trace-time",               ARG_BOOL,     "$o"},
  {"unix-socket",              ARG_FILENAME, "$M"},
  {"upload-file",              ARG_FILENAME, "T",},
  {"url",                      ARG_STRING,   "*@"},
  {"url-query",                ARG_STRING,   "dg"},
  {"use-ascii",                ARG_BOOL,     "B",},
  {"user",                     ARG_STRING,   "u",},
  {"user-agent",               ARG_STRING,   "A",},
  {"variable",                 ARG_STRING,   ":a"},
  {"verbose",                  ARG_BOOL,     "v",},
  {"version",                  ARG_BOOL,     "V",},
#ifdef USE_WATT32
  {"wdebug",                   ARG_BOOL,     "*p"},
#endif
  {"write-out",                ARG_STRING,   "w",},
  {"xattr",                    ARG_BOOL,     "*~"},
};

/* Split the argument of -E to 'certname' and 'passphrase' separated by colon.
 * We allow ':' and '\' to be escaped by '\' so that we can use certificate
 * nicknames containing ':'.  See <https://sourceforge.net/p/curl/bugs/1196/>
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
    strncpy(certname_place, param_place, span);
    param_place += span;
    certname_place += span;
    /* we just ate all the non-special chars. now we're on either a special
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
      /* Since we live in a world of weirdness and confusion, the win32
         dudes can use : when using drive letters and thus c:\file:password
         needs to work. In order not to break compatibility, we still use : as
         separator, but we try to detect when it is used for a file name! On
         windows. */
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
       * above; if we're still here, this is a separating colon */
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
   * argument out so that the username:password isn't displayed in the
   * system process list */
  if(str) {
    size_t len = strlen(str);
    memset(str, ' ', len);
  }
}
#else
#define cleanarg(x)
#endif

/* --data-urlencode */
static ParameterError data_urlencode(struct GlobalConfig *global,
                                     char *nextarg,
                                     char **postp,
                                     size_t *lenp)
{
  /* [name]=[content], we encode the content part only
   * [name]@[file name]
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
    /* neither @ nor =, so no name and it isn't a file */
    nlen = is_file = 0;
    p = nextarg;
  }
  if('@' == is_file) {
    FILE *file;
    /* a '@' letter, it means that a file name or - (stdin) follows */
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
    if(postdata)
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
      /* replace (in-place) '%20' by '+' according to RFC1866 */
      size_t enclen = replace_url_encoded_space_by_plus(enc);
      /* now make a string with the name from above and append the
         encoded string */
      size_t outlen = nlen + enclen + 2;
      char *n = malloc(outlen);
      if(!n) {
        curl_free(enc);
        return PARAM_NO_MEM;
      }
      if(nlen > 0) { /* only append '=' if we have a name */
        msnprintf(n, outlen, "%.*s=%s", (int)nlen, nextarg, enc);
        size = outlen-1;
      }
      else {
        strcpy(n, enc);
        size = outlen-2; /* since no '=' was inserted */
      }
      curl_free(enc);
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

  /* Allow strtok() here since this isn't used threaded */
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

static const struct LongShort *single(char letter)
{
  static const struct LongShort *singles[128 - ' ']; /* ASCII => pointer */
  static bool singles_done = FALSE;
  DEBUGASSERT((letter < 127) && (letter > ' '));

  if(!singles_done) {
    unsigned int j;
    for(j = 0; j < sizeof(aliases)/sizeof(aliases[0]); j++) {
      if(!aliases[j].letter[1]) {
        unsigned char l = aliases[j].letter[0];
        singles[l - ' '] = &aliases[j];
      }
    }
    singles_done = TRUE;
  }
  return singles[letter - ' '];
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

static ParameterError set_data(char subletter,
                               char *nextarg,
                               struct GlobalConfig *global,
                               struct OperationConfig *config)
{
  char *postdata = NULL;
  FILE *file;
  size_t size = 0;
  ParameterError err = PARAM_OK;

  if(subletter == 'e') { /* --data-urlencode */
    err = data_urlencode(global, nextarg, &postdata, &size);
    if(err)
      goto done;
  }
  else if('@' == *nextarg && (subletter != 'r')) {
    /* the data begins with a '@' letter, it means that a file name
       or - (stdin) follows */
    nextarg++; /* pass the @ */

    if(!strcmp("-", nextarg)) {
      file = stdin;
      if(subletter == 'b') /* forced data-binary */
        set_binmode(stdin);
    }
    else {
      file = fopen(nextarg, "rb");
      if(!file) {
        errorf(global, "Failed to open %s", nextarg);
        err = PARAM_READ_ERROR;
        goto done;
      }
    }

    if((subletter == 'b') || /* --data-binary */
       (subletter == 'f') /* --json */)
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
      goto done;

    if(!postdata) {
      /* no data from the file, point to a zero byte string to make this
         get sent as a POST anyway */
      postdata = strdup("");
      if(!postdata) {
        err = PARAM_NO_MEM;
        goto done;
      }
    }
  }
  else {
    err = getstr(&postdata, nextarg, ALLOW_BLANK);
    if(err)
      goto done;
    if(postdata)
      size = strlen(postdata);
  }
  if(subletter == 'f')
    config->jsoned = TRUE;

  if(config->postfields) {
    /* we already have a string, we append this one with a separating
       &-letter */
    char *oldpost = config->postfields;
    curl_off_t oldlen = config->postfieldsize;
    curl_off_t newlen = oldlen + curlx_uztoso(size) + 2;
    config->postfields = malloc((size_t)newlen);
    if(!config->postfields) {
      Curl_safefree(oldpost);
      Curl_safefree(postdata);
      err = PARAM_NO_MEM;
      goto done;
    }
    memcpy(config->postfields, oldpost, (size_t)oldlen);
    if(subletter != 'f') {
      /* skip this treatment for --json */
      /* use byte value 0x26 for '&' to accommodate non-ASCII platforms */
      config->postfields[oldlen] = '\x26';
      memcpy(&config->postfields[oldlen + 1], postdata, size);
      config->postfields[oldlen + 1 + size] = '\0';
      config->postfieldsize += size + 1;
    }
    else {
      memcpy(&config->postfields[oldlen], postdata, size);
      config->postfields[oldlen + size] = '\0';
      config->postfieldsize += size;
    }
    Curl_safefree(oldpost);
    Curl_safefree(postdata);
  }
  else {
    config->postfields = postdata;
    config->postfieldsize = curlx_uztoso(size);
  }

  /*
    We can't set the request type here, as this data might be used in
    a simple GET if -G is used. Already or soon.

    if(SetHTTPrequest(HTTPREQ_SIMPLEPOST, &config->httpreq)) {
    Curl_safefree(postdata);
    return PARAM_BAD_USE;
    }
  */

done:
  return err;
}


#define ONEOPT(x,y) (((int)x << 8) | y)

ParameterError getparameter(const char *flag, /* f or -long-flag */
                            char *nextarg,    /* NULL if unset */
                            argv_item_t cleararg,
                            bool *usedarg,    /* set to TRUE if the arg
                                                 has been used */
                            struct GlobalConfig *global,
                            struct OperationConfig *config)
{
  char letter;
  char subletter = '\0'; /* subletters can only occur on long options */
  int rc;
  const char *parse = NULL;
  time_t now;
  bool longopt = FALSE;
  bool singleopt = FALSE; /* when true means '-o foo' used '-ofoo' */
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

  *usedarg = FALSE; /* default is that we don't use the arg */

  if(('-' != flag[0]) || ('-' == flag[1])) {
    /* this should be a long name */
    const char *word = ('-' == flag[0]) ? flag + 2 : flag;
    bool noflagged = FALSE;
    bool expand = FALSE;
    struct LongShort key;

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
    key.lname = word;

    a = bsearch(&key, aliases, sizeof(aliases)/sizeof(aliases[0]),
                sizeof(aliases[0]), findarg);
    if(a) {
      longopt = TRUE;
      parse = a->letter;
    }
    else {
      err = PARAM_OPTION_UNKNOWN;
      goto error;
    }
    if(noflagged && (a->desc != ARG_BOOL)) {
      /* --no- prefixed an option that isn't boolean! */
      err = PARAM_NO_NOT_BOOLEAN;
      goto error;
    }
    else if(expand && nextarg) {
      struct curlx_dynbuf nbuf;
      bool replaced;

      if((a->desc != ARG_STRING) &&
         (a->desc != ARG_FILENAME)) {
        /* --expand on an option that isn't a string or a filename */
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

    if(!longopt) {
      letter = (char)*parse;
      subletter = '\0';
    }
    else {
      letter = parse[0];
      subletter = parse[1];
    }

    if(!a) {
      a = single(letter);
      if(!a) {
        err = PARAM_OPTION_UNKNOWN;
        break;
      }
    }

    if(a->desc >= ARG_STRING) {
      /* this option requires an extra parameter */
      if(!longopt && parse[1]) {
        nextarg = (char *)&parse[1]; /* this is the actual extra parameter */
        singleopt = TRUE;   /* don't loop anymore after this */
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

      if((a->desc == ARG_FILENAME) &&
         (nextarg[0] == '-') && nextarg[1]) {
        /* if the file name looks like a command line option */
        warnf(global, "The file name argument '%s' looks like a flag.",
              nextarg);
      }
    }
    else if((a->desc == ARG_NONE) && !toggle) {
      err = PARAM_NO_PREFIX;
      break;
    }

    if(!nextarg)
      /* this is a precaution mostly to please scan-build, as all arguments
         that use nextarg should be marked as such and they will check that
         nextarg is set before continuing, but code analyzers are not always
         that aware of that state */
      nextarg = (char *)"";

    switch(ONEOPT(letter, subletter)) {
    case ONEOPT('*', '4'): /* --dns-ipv4-addr */
      if(!curlinfo->ares_num) /* c-ares is needed for this */
        err = PARAM_LIBCURL_DOESNT_SUPPORT;
      else
        /* addr in dot notation */
        err = getstr(&config->dns_ipv4_addr, nextarg, DENY_BLANK);
      break;
    case ONEOPT('*', '6'): /* --dns-ipv6-addr */
      if(!curlinfo->ares_num) /* c-ares is needed for this */
        err = PARAM_LIBCURL_DOESNT_SUPPORT;
      else
        /* addr in dot notation */
        err = getstr(&config->dns_ipv6_addr, nextarg, DENY_BLANK);
      break;
    case ONEOPT('*', 'a'): /* --random-file */
      break;
    case ONEOPT('*', 'b'): /* --egd-file */
      break;
    case ONEOPT('*', 'B'): /* --oauth2-bearer */
      err = getstr(&config->oauth_bearer, nextarg, DENY_BLANK);
      if(!err) {
        cleanarg(clearthis);
        config->authtype |= CURLAUTH_BEARER;
      }
      break;
    case ONEOPT('*', 'c'): /* --connect-timeout */
      err = secs2ms(&config->connecttimeout_ms, nextarg);
      break;
    case ONEOPT('*', 'C'): /* --doh-url */
      err = getstr(&config->doh_url, nextarg, ALLOW_BLANK);
      if(!err && config->doh_url && !config->doh_url[0])
        /* if given a blank string, make it NULL again */
        Curl_safefree(config->doh_url);
      break;
    case ONEOPT('*', 'd'): /* -- ciphers */
      err = getstr(&config->cipher_list, nextarg, DENY_BLANK);
      break;
    case ONEOPT('*', 'D'): /* --dns-interface */
      if(!curlinfo->ares_num) /* c-ares is needed for this */
        err = PARAM_LIBCURL_DOESNT_SUPPORT;
      else
        /* interface name */
        err = getstr(&config->dns_interface, nextarg, DENY_BLANK);
      break;
    case ONEOPT('*', 'e'): /* --disable-epsv */
      config->disable_epsv = toggle;
      break;
    case ONEOPT('*', 'f'): /* --disallow-username-in-url */
      config->disallow_username_in_url = toggle;
      break;
    case ONEOPT('*', 'E'): /* --epsv */
      config->disable_epsv = (!toggle)?TRUE:FALSE;
      break;
    case ONEOPT('*', 'F'): /* --dns-servers */
      if(!curlinfo->ares_num) /* c-ares is needed for this */
        err = PARAM_LIBCURL_DOESNT_SUPPORT;
      else
        /* IP addrs of DNS servers */
        err = getstr(&config->dns_servers, nextarg, DENY_BLANK);
      break;
    case ONEOPT('*', 'g'): /* --trace */
      err = getstr(&global->trace_dump, nextarg, DENY_BLANK);
      if(!err) {
        if(global->tracetype && (global->tracetype != TRACE_BIN))
          warnf(global, "--trace overrides an earlier trace/verbose option");
        global->tracetype = TRACE_BIN;
      }
      break;
    case ONEOPT('*', 'G'): /* --npn */
      warnf(global, "--npn is no longer supported");
      break;
    case ONEOPT('*', 'h'): /* --trace-ascii */
      err = getstr(&global->trace_dump, nextarg, DENY_BLANK);
      if(!err) {
        if(global->tracetype && (global->tracetype != TRACE_ASCII))
          warnf(global,
                "--trace-ascii overrides an earlier trace/verbose option");
        global->tracetype = TRACE_ASCII;
      }
      break;
    case ONEOPT('*', 'H'): /* --alpn */
      config->noalpn = (!toggle)?TRUE:FALSE;
      break;
    case ONEOPT('*', 'i'): /* --limit-rate */
      err = GetSizeParameter(global, nextarg, "rate", &value);
      if(!err) {
        config->recvpersecond = value;
        config->sendpersecond = value;
      }
      break;
    case ONEOPT('*', 'I'): { /* --rate */
      /* support a few different suffixes, extract the suffix first, then
         get the number and convert to per hour.
         /s == per second
         /m == per minute
         /h == per hour (default)
         /d == per day (24 hours)
      */
      char *div = strchr(nextarg, '/');
      char number[26];
      long denominator;
      long numerator = 60*60*1000; /* default per hour */
      size_t numlen = div ? (size_t)(div - nextarg) : strlen(nextarg);
      if(numlen > sizeof(number)-1) {
        err = PARAM_NUMBER_TOO_LARGE;
        break;
      }
      strncpy(number, nextarg, numlen);
      number[numlen] = 0;
      err = str2unum(&denominator, number);
      if(err)
        break;

      if(denominator < 1) {
        err = PARAM_BAD_USE;
        break;
      }
      if(div) {
        char unit = div[1];
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
      }

      if(err)
        ;
      else if(denominator > numerator)
        err = PARAM_NUMBER_TOO_LARGE;
      else
        global->ms_per_transfer = numerator/denominator;
    }
      break;

    case ONEOPT('*', 'j'): /* --compressed */
      if(toggle && !(feature_libz || feature_brotli || feature_zstd))
        err = PARAM_LIBCURL_DOESNT_SUPPORT;
      else
        config->encoding = toggle;
      break;

    case ONEOPT('*', 'J'): /* --tr-encoding */
      config->tr_encoding = toggle;
      break;

    case ONEOPT('*', 'k'): /* --digest */
      if(toggle)
        config->authtype |= CURLAUTH_DIGEST;
      else
        config->authtype &= ~CURLAUTH_DIGEST;
      break;

    case ONEOPT('*', 'l'): /* --negotiate */
      if(!toggle)
        config->authtype &= ~CURLAUTH_NEGOTIATE;
      else if(feature_spnego)
        config->authtype |= CURLAUTH_NEGOTIATE;
      else
        err = PARAM_LIBCURL_DOESNT_SUPPORT;
      break;

    case ONEOPT('*', 'm'): /* --ntlm */
      if(!toggle)
        config->authtype &= ~CURLAUTH_NTLM;
      else if(feature_ntlm)
        config->authtype |= CURLAUTH_NTLM;
      else
        err = PARAM_LIBCURL_DOESNT_SUPPORT;
      break;

    case ONEOPT('*', 'M'): /* --ntlm-wb */
      if(!toggle)
        config->authtype &= ~CURLAUTH_NTLM_WB;
      else if(feature_ntlm_wb)
        config->authtype |= CURLAUTH_NTLM_WB;
      else
        err = PARAM_LIBCURL_DOESNT_SUPPORT;
      break;

    case ONEOPT('*', 'n'): /* --basic */
      if(toggle)
        config->authtype |= CURLAUTH_BASIC;
      else
        config->authtype &= ~CURLAUTH_BASIC;
      break;

    case ONEOPT('*', 'o'): /* --anyauth */
      if(toggle)
        config->authtype = CURLAUTH_ANY;
      /* --no-anyauth simply doesn't touch it */
      break;

#ifdef USE_WATT32
    case ONEOPT('*', 'p'): /* --wdebug */
      dbug_init();
      break;
#endif
    case ONEOPT('*', 'q'): /* --ftp-create-dirs */
      config->ftp_create_dirs = toggle;
      break;

    case ONEOPT('*', 'r'): /* --create-dirs */
      config->create_dirs = toggle;
      break;

    case ONEOPT('*', 'R'): /* --create-file-mode */
      err = oct2nummax(&config->create_file_mode, nextarg, 0777);
      break;

    case ONEOPT('*', 's'): /* --max-redirs */
      /* specified max no of redirects (http(s)), this accepts -1 as a
         special condition */
      err = str2num(&config->maxredirs, nextarg);
      if(!err && (config->maxredirs < -1))
        err = PARAM_BAD_NUMERIC;
      break;

    case ONEOPT('*', 'S'): /* --ipfs-gateway */
      err = getstr(&config->ipfs_gateway, nextarg, DENY_BLANK);
      break;

    case ONEOPT('*', 't'): /* --proxy-ntlm */
      if(!feature_ntlm)
        err = PARAM_LIBCURL_DOESNT_SUPPORT;
      else
        config->proxyntlm = toggle;
      break;

    case ONEOPT('*', 'u'): /* --crlf */
      /* LF -> CRLF conversion? */
      config->crlf = toggle;
      break;

    case ONEOPT('*', 'V'): /* --aws-sigv4 */
      config->authtype |= CURLAUTH_AWS_SIGV4;
      err = getstr(&config->aws_sigv4, nextarg, DENY_BLANK);
      break;

    case ONEOPT('*', 'v'): /* --stderr */
      tool_set_stderr_file(global, nextarg);
      break;
    case ONEOPT('*', 'w'): /* --interface */
      /* interface */
      err = getstr(&config->iface, nextarg, DENY_BLANK);
      break;
    case ONEOPT('*', 'x'): /* --krb */
      /* kerberos level string */
      if(!feature_spnego)
        err = PARAM_LIBCURL_DOESNT_SUPPORT;
      else
        err = getstr(&config->krblevel, nextarg, DENY_BLANK);
      break;
    case ONEOPT('*', 'X'): /* --haproxy-protocol */
      config->haproxy_protocol = toggle;
      break;
    case ONEOPT('*', 'P'): /* --haproxy-clientip */
      err = getstr(&config->haproxy_clientip, nextarg, DENY_BLANK);
      break;
    case ONEOPT('*', 'y'): /* --max-filesize */
      err = GetSizeParameter(global, nextarg, "max-filesize", &value);
      if(!err)
        config->max_filesize = value;
      break;
    case ONEOPT('*', 'z'): /* --disable-eprt */
      config->disable_eprt = toggle;
      break;
    case ONEOPT('*', 'Z'): /* --eprt */
      config->disable_eprt = (!toggle)?TRUE:FALSE;
      break;
    case ONEOPT('*', '~'): /* --xattr */
      config->xattr = toggle;
      break;
    case ONEOPT('*', '@'): /* --url */
      if(!config->url_get)
        config->url_get = config->url_list;

      if(config->url_get) {
        /* there's a node here, if it already is filled-in continue to find
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

      if(!url) {
        err = PARAM_NO_MEM;
        break;
      }

      /* fill in the URL */
      err = getstr(&url->url, nextarg, DENY_BLANK);
      url->flags |= GETOUT_URL;
      break;

    case ONEOPT('$', 'a'): /* --ssl */
      if(toggle && !feature_ssl) {
        err = PARAM_LIBCURL_DOESNT_SUPPORT;
        break;
      }
      config->ftp_ssl = toggle;
      if(config->ftp_ssl)
        warnf(global,
              "--ssl is an insecure option, consider --ssl-reqd instead");
      break;
    case ONEOPT('$', 'b'): /* --ftp-pasv */
      Curl_safefree(config->ftpport);
      break;
    case ONEOPT('$', 'c'): /* --socks5 */
      /*  socks5 proxy to use, and resolves the name locally and passes on the
          resolved address */
      err = getstr(&config->proxy, nextarg, DENY_BLANK);
      config->proxyver = CURLPROXY_SOCKS5;
      break;
    case ONEOPT('$', 't'): /* --socks4 */
      err = getstr(&config->proxy, nextarg, DENY_BLANK);
      config->proxyver = CURLPROXY_SOCKS4;
      break;
    case ONEOPT('$', 'T'): /* --socks4a */
      err = getstr(&config->proxy, nextarg, DENY_BLANK);
      config->proxyver = CURLPROXY_SOCKS4A;
      break;
    case ONEOPT('$', '2'): /* --socks5-hostname */
      err = getstr(&config->proxy, nextarg, DENY_BLANK);
      config->proxyver = CURLPROXY_SOCKS5_HOSTNAME;
      break;
    case ONEOPT('$', 'd'): /* --tcp-nodelay */
      config->tcp_nodelay = toggle;
      break;
    case ONEOPT('$', 'e'): /* --proxy-digest */
      config->proxydigest = toggle;
      break;
    case ONEOPT('$', 'f'): /* --proxy-basic */
      config->proxybasic = toggle;
      break;
    case ONEOPT('$', 'g'): /* --retry */
      err = str2unum(&config->req_retry, nextarg);
      break;
    case ONEOPT('$', 'V'): /* --retry-connrefused */
      config->retry_connrefused = toggle;
      break;
    case ONEOPT('$', 'h'): /* --retry-delay */
      err = str2unummax(&config->retry_delay, nextarg, LONG_MAX/1000);
      break;
    case ONEOPT('$', 'i'): /* --retry-max-time */
      err = str2unummax(&config->retry_maxtime, nextarg, LONG_MAX/1000);
      break;
    case ONEOPT('$', '!'): /* --retry-all-errors */
      config->retry_all_errors = toggle;
      break;

    case ONEOPT('$', 'k'): /* --proxy-negotiate */
      if(!feature_spnego) {
        err = PARAM_LIBCURL_DOESNT_SUPPORT;
        break;
      }
      config->proxynegotiate = toggle;
      break;

    case ONEOPT('$', 'l'): /* --form-escape */
      config->mime_options &= ~CURLMIMEOPT_FORMESCAPE;
      if(toggle)
        config->mime_options |= CURLMIMEOPT_FORMESCAPE;
      break;

    case ONEOPT('$', 'm'): /* --ftp-account */
      err = getstr(&config->ftp_account, nextarg, DENY_BLANK);
      break;
    case ONEOPT('$', 'n'): /* --proxy-anyauth */
      config->proxyanyauth = toggle;
      break;
    case ONEOPT('$', 'o'): /* --trace-time */
      global->tracetime = toggle;
      break;
    case ONEOPT('$', 'p'): /* --ignore-content-length */
      config->ignorecl = toggle;
      break;
    case ONEOPT('$', 'q'): /* --ftp-skip-pasv-ip */
      config->ftp_skip_ip = toggle;
      break;
    case ONEOPT('$', 'r'): /* --ftp-method */
      config->ftp_filemethod = ftpfilemethod(config, nextarg);
      break;
    case ONEOPT('$', 's'): { /* --local-port */
      /* 16bit base 10 is 5 digits, but we allow 6 so that this catches
         overflows, not just truncates */
      char lrange[7]="";
      char *p = nextarg;
      while(ISDIGIT(*p))
        p++;
      if(*p) {
        /* if there's anything more than a plain decimal number */
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
    case ONEOPT('$', 'u'): /* --ftp-alternative-to-user */
      err = getstr(&config->ftp_alternative_to_user, nextarg, DENY_BLANK);
      break;
    case ONEOPT('$', 'v'): /* --ssl-reqd */
      if(toggle && !feature_ssl) {
        err = PARAM_LIBCURL_DOESNT_SUPPORT;
        break;
      }
      config->ftp_ssl_reqd = toggle;
      break;
    case ONEOPT('$', 'w'): /* --no-sessionid */
      config->disable_sessionid = (!toggle)?TRUE:FALSE;
      break;
    case ONEOPT('$', 'x'): /* --ftp-ssl-control */
      if(toggle && !feature_ssl) {
        err = PARAM_LIBCURL_DOESNT_SUPPORT;
        break;
      }
      config->ftp_ssl_control = toggle;
      break;
    case ONEOPT('$', 'y'): /* --ftp-ssl-ccc */
      config->ftp_ssl_ccc = toggle;
      if(!config->ftp_ssl_ccc_mode)
        config->ftp_ssl_ccc_mode = CURLFTPSSL_CCC_PASSIVE;
      break;
    case ONEOPT('$', 'j'): /* --ftp-ssl-ccc-mode */
      config->ftp_ssl_ccc = TRUE;
      config->ftp_ssl_ccc_mode = ftpcccmethod(config, nextarg);
      break;
    case ONEOPT('$', 'z'): /* --libcurl */
#ifdef CURL_DISABLE_LIBCURL_OPTION
      warnf(global,
            "--libcurl option was disabled at build-time");
      err = PARAM_OPTION_UNKNOWN;
#else
      err = getstr(&global->libcurl, nextarg, DENY_BLANK);
#endif
      break;
    case ONEOPT('$', '#'): /* --raw */
      config->raw = toggle;
      break;
    case ONEOPT('$', '0'): /* --post301 */
      config->post301 = toggle;
      break;
    case ONEOPT('$', '1'): /* --no-keepalive */
      config->nokeepalive = (!toggle)?TRUE:FALSE;
      break;
    case ONEOPT('$', '3'): /* --keepalive-time */
      err = str2unum(&config->alivetime, nextarg);
      break;
    case ONEOPT('$', '4'): /* --post302 */
      config->post302 = toggle;
      break;
    case ONEOPT('$', 'I'): /* --post303 */
      config->post303 = toggle;
      break;
    case ONEOPT('$', '5'): /* --noproxy */
      /* This specifies the noproxy list */
      err = getstr(&config->noproxy, nextarg, ALLOW_BLANK);
      break;
    case ONEOPT('$', '7'): /* --socks5-gssapi-nec */
      config->socks5_gssapi_nec = toggle;
      break;
    case ONEOPT('$', '8'): /* --proxy1.0 */
      /* http 1.0 proxy */
      err = getstr(&config->proxy, nextarg, DENY_BLANK);
      config->proxyver = CURLPROXY_HTTP_1_0;
      break;
    case ONEOPT('$', '9'): /* --tftp-blksize */
      err = str2unum(&config->tftp_blksize, nextarg);
      break;
    case ONEOPT('$', 'A'): /* --mail-from */
      err = getstr(&config->mail_from, nextarg, DENY_BLANK);
      break;
    case ONEOPT('$', 'B'): /* --mail-rcpt */
      /* append receiver to a list */
      err = add2list(&config->mail_rcpt, nextarg);
      break;
    case ONEOPT('$', 'C'): /* --ftp-pret */
      config->ftp_pret = toggle;
      break;
    case ONEOPT('$', 'D'): /* --proto */
      config->proto_present = TRUE;
      err = proto2num(config, built_in_protos, &config->proto_str, nextarg);
      break;
    case ONEOPT('$', 'E'): /* --proto-redir */
      config->proto_redir_present = TRUE;
      if(proto2num(config, redir_protos, &config->proto_redir_str,
                   nextarg)) {
        err = PARAM_BAD_USE;
        break;
      }
      break;
    case ONEOPT('$', 'F'): /* --resolve */
      err = add2list(&config->resolve, nextarg);
      break;
    case ONEOPT('$', 'G'): /* --delegation */
      config->gssapi_delegation = delegation(config, nextarg);
      break;
    case ONEOPT('$', 'H'): /* --mail-auth */
      err = getstr(&config->mail_auth, nextarg, DENY_BLANK);
      break;
    case ONEOPT('$', 'J'): /* --metalink */
      errorf(global, "--metalink is disabled");
      err = PARAM_BAD_USE;
      break;
    case ONEOPT('$', '6'): /* --sasl-authzid */
      err = getstr(&config->sasl_authzid, nextarg, DENY_BLANK);
      break;
    case ONEOPT('$', 'K'): /* --sasl-ir */
      config->sasl_ir = toggle;
      break;
    case ONEOPT('$', 'L'): /* --test-event */
#ifdef CURLDEBUG
      global->test_event_based = toggle;
#else
      warnf(global, "--test-event is ignored unless a debug build");
#endif
      break;
    case ONEOPT('$', 'M'): /* --unix-socket */
      config->abstract_unix_socket = FALSE;
      err = getstr(&config->unix_socket_path, nextarg, DENY_BLANK);
      break;
    case ONEOPT('$', 'N'): /* --path-as-is */
      config->path_as_is = toggle;
      break;
    case ONEOPT('$', 'O'): /* --proxy-service-name */
      err = getstr(&config->proxy_service_name, nextarg, DENY_BLANK);
      break;
    case ONEOPT('$', 'P'): /* --service-name */
      err = getstr(&config->service_name, nextarg, DENY_BLANK);
      break;
    case ONEOPT('$', 'Q'): /* --proto-default */
      err = getstr(&config->proto_default, nextarg, DENY_BLANK);
      if(!err)
        err = check_protocol(config->proto_default);
      break;
    case ONEOPT('$', 'R'): /* --expect100-timeout */
      err = secs2ms(&config->expect100timeout_ms, nextarg);
      break;
    case ONEOPT('$', 'S'): /* --tftp-no-options */
      config->tftp_no_options = toggle;
      break;
    case ONEOPT('$', 'U'): /* --connect-to */
      err = add2list(&config->connect_to, nextarg);
      break;
    case ONEOPT('$', 'W'): /* --abstract-unix-socket */
      config->abstract_unix_socket = TRUE;
      err = getstr(&config->unix_socket_path, nextarg, DENY_BLANK);
      break;
    case ONEOPT('$', 'X'): /* --tls-max */
      err = str2tls_max(&config->ssl_version_max, nextarg);
      break;
    case ONEOPT('$', 'Y'): /* --suppress-connect-headers */
      config->suppress_connect_headers = toggle;
      break;
    case ONEOPT('$', 'Z'): /* --compressed-ssh */
      config->ssh_compression = toggle;
      break;
    case ONEOPT('$', '~'): /* --happy-eyeballs-timeout-ms */
      err = str2unum(&config->happy_eyeballs_timeout_ms, nextarg);
      /* 0 is a valid value for this timeout */
      break;
    case ONEOPT('$', '%'): /* --trace-ids */
      global->traceids = toggle;
      break;
    case ONEOPT('$', '&'): /* --trace-config */
      if(set_trace_config(global, nextarg)) {
        err = PARAM_NO_MEM;
      }
      break;
    case ONEOPT('#', 'm'): /* --progress-meter */
      global->noprogress = !toggle;
      break;
    case ONEOPT('#', '\0'): /* --progress-bar */
      global->progressmode = toggle ? CURL_PROGRESS_BAR : CURL_PROGRESS_STATS;
      break;

    case ONEOPT(':', 'a'): /* --variable */
      err = setvariable(global, nextarg);
      break;
    case ONEOPT(':', '\0'): /* --next */
      err = PARAM_NEXT_OPERATION;
      break;

    case ONEOPT('0', '\0'): /* --http1.0 */
      /* HTTP version 1.0 */
      sethttpver(global, config, CURL_HTTP_VERSION_1_0);
      break;
    case ONEOPT('0', '1'): /* --http1.1 */
      /* HTTP version 1.1 */
      sethttpver(global, config, CURL_HTTP_VERSION_1_1);
      break;
    case ONEOPT('0', '2'): /* --http2 */
      /* HTTP version 2.0 */
      if(!feature_http2)
        return PARAM_LIBCURL_DOESNT_SUPPORT;
      sethttpver(global, config, CURL_HTTP_VERSION_2_0);
      break;
    case ONEOPT('0', '3'): /* --http2-prior-knowledge */
      /* HTTP version 2.0 over clean TCP */
      if(!feature_http2)
        return PARAM_LIBCURL_DOESNT_SUPPORT;
      sethttpver(global, config, CURL_HTTP_VERSION_2_PRIOR_KNOWLEDGE);
      break;
    case ONEOPT('0', '4'): /* --http3: */
      /* Try HTTP/3, allow fallback */
      if(!feature_http3) {
        err = PARAM_LIBCURL_DOESNT_SUPPORT;
        break;
      }
      sethttpver(global, config, CURL_HTTP_VERSION_3);
      break;
    case ONEOPT('0', '5'): /* --http3-only */
      /* Try HTTP/3 without fallback */
      if(!feature_http3) {
        err = PARAM_LIBCURL_DOESNT_SUPPORT;
        break;
      }
      sethttpver(global, config, CURL_HTTP_VERSION_3ONLY);
      break;
    case ONEOPT('0', '9'): /* --http0.9 */
      /* Allow HTTP/0.9 responses! */
      config->http09_allowed = toggle;
      break;
    case ONEOPT('0', 'a'): /* --proxy-http2 */
      if(!feature_httpsproxy || !feature_http2)
        return PARAM_LIBCURL_DOESNT_SUPPORT;
      config->proxyver = CURLPROXY_HTTPS2;
      break;
    case ONEOPT('1', '\0'): /* --tlsv1 */
      config->ssl_version = CURL_SSLVERSION_TLSv1;
      break;
    case ONEOPT('1', '0'): /* --tlsv1.0 */
      config->ssl_version = CURL_SSLVERSION_TLSv1_0;
      break;
    case ONEOPT('1', '1'): /* --tlsv1.1 */
      config->ssl_version = CURL_SSLVERSION_TLSv1_1;
      break;
    case ONEOPT('1', '2'): /* --tlsv1.2 */
      config->ssl_version = CURL_SSLVERSION_TLSv1_2;
      break;
    case ONEOPT('1', '3'): /* --tlsv1.3 */
      config->ssl_version = CURL_SSLVERSION_TLSv1_3;
      break;
    case ONEOPT('1', 'A'): /* --tls13-ciphers */
      err = getstr(&config->cipher13_list, nextarg, DENY_BLANK);
      break;
    case ONEOPT('1', 'B'): /* --proxy-tls13-ciphers */
      err = getstr(&config->proxy_cipher13_list, nextarg, DENY_BLANK);
      break;
    case ONEOPT('2', '\0'): /* --sslv2 */
      warnf(global, "Ignores instruction to use SSLv2");
      break;
    case ONEOPT('3', '\0'): /* --sslv3 */
      warnf(global, "Ignores instruction to use SSLv3");
      break;
    case ONEOPT('4', '\0'): /* --ipv4 */
      config->ip_version = CURL_IPRESOLVE_V4;
      break;
    case ONEOPT('6', '\0'): /* --ipv6 */
      config->ip_version = CURL_IPRESOLVE_V6;
      break;
    case ONEOPT('a', '\0'): /* --append */
      /* This makes the FTP sessions use APPE instead of STOR */
      config->ftp_append = toggle;
      break;
    case ONEOPT('A', '\0'): /* --user-agent */
      err = getstr(&config->useragent, nextarg, ALLOW_BLANK);
      break;
    case ONEOPT('b', 'a'): /* --alt-svc */
      if(!feature_altsvc)
        err = PARAM_LIBCURL_DOESNT_SUPPORT;
      else
        err = getstr(&config->altsvc, nextarg, ALLOW_BLANK);
      break;
    case ONEOPT('b', 'b'): /* --hsts */
      if(!feature_hsts)
        err = PARAM_LIBCURL_DOESNT_SUPPORT;
      else
        err = getstr(&config->hsts, nextarg, ALLOW_BLANK);
      break;
    case ONEOPT('b', '\0'): /* --cookie */
      if(nextarg[0] == '@') {
        nextarg++;
      }
      else if(strchr(nextarg, '=')) {
        /* A cookie string must have a =-letter */
        err = add2list(&config->cookies, nextarg);
        break;
      }
      /* We have a cookie file to read from! */
      err = add2list(&config->cookiefiles, nextarg);
      break;
    case ONEOPT('B', '\0'): /* --use-ascii */
      config->use_ascii = toggle;
      break;
    case ONEOPT('c', '\0'): /* --cookie-jar */
      err = getstr(&config->cookiejar, nextarg, DENY_BLANK);
      break;
    case ONEOPT('C', '\0'): /* --continue-at */
      /* This makes us continue an ftp transfer at given position */
      if(strcmp(nextarg, "-")) {
        err = str2offset(&config->resume_from, nextarg);
        if(err)
          break;
        config->resume_from_current = FALSE;
      }
      else {
        config->resume_from_current = TRUE;
        config->resume_from = 0;
      }
      config->use_resume = TRUE;
      break;
    case ONEOPT('d', '\0'): /* --data */
    case ONEOPT('d', 'a'):  /* --data-ascii */
    case ONEOPT('d', 'b'):  /* --data-binary */
    case ONEOPT('d', 'e'):  /* --data-urlencode */
    case ONEOPT('d', 'f'):  /* --json */
    case ONEOPT('d', 'r'):  /* --data-raw */
      err = set_data(subletter, nextarg, global, config);
      break;
    case ONEOPT('d', 'g'):  /* --url-query */
      err = url_query(nextarg, global, config);
      break;
    case ONEOPT('D', '\0'): /* --dump-header */
      err = getstr(&config->headerfile, nextarg, DENY_BLANK);
      break;
    case ONEOPT('e', '\0'): { /* --referer */
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
    case ONEOPT('E', '\0'): /* --cert */
      cleanarg(clearthis);
      GetFileAndPassword(nextarg, &config->cert, &config->key_passwd);
      break;
    case ONEOPT('E', 'a'): /* --cacert */
      err = getstr(&config->cacert, nextarg, DENY_BLANK);
      break;
    case ONEOPT('E', 'G'): /* --ca-native */
      config->native_ca_store = toggle;
      break;
    case ONEOPT('E', 'H'): /* --proxy-ca-native */
      config->proxy_native_ca_store = toggle;
      break;
    case ONEOPT('E', 'b'): /* --cert-type */
      err = getstr(&config->cert_type, nextarg, DENY_BLANK);
      break;
    case ONEOPT('E', 'c'): /* --key */
      err = getstr(&config->key, nextarg, DENY_BLANK);
      break;
    case ONEOPT('E', 'd'): /* --key-type */
      err = getstr(&config->key_type, nextarg, DENY_BLANK);
      break;
    case ONEOPT('E', 'e'): /* --pass */
      err = getstr(&config->key_passwd, nextarg, DENY_BLANK);
      cleanarg(clearthis);
      break;
    case ONEOPT('E', 'f'): /* --engine */
      err = getstr(&config->engine, nextarg, DENY_BLANK);
      if(!err &&
         config->engine && !strcmp(config->engine, "list")) {
        err = PARAM_ENGINES_REQUESTED;
      }
      break;
    case ONEOPT('E', 'g'): /* --capath */
      err = getstr(&config->capath, nextarg, DENY_BLANK);
      break;
    case ONEOPT('E', 'h'): /* --pubkey */
      err = getstr(&config->pubkey, nextarg, DENY_BLANK);
      break;
    case ONEOPT('E', 'i'): /* --hostpubmd5 */
      err = getstr(&config->hostpubmd5, nextarg, DENY_BLANK);
      if(!err) {
        if(!config->hostpubmd5 || strlen(config->hostpubmd5) != 32)
          err = PARAM_BAD_USE;
      }
      break;
    case ONEOPT('E', 'F'): /* --hostpubsha256 */
      err = getstr(&config->hostpubsha256, nextarg, DENY_BLANK);
      break;
    case ONEOPT('E', 'j'): /* --crlfile */
      err = getstr(&config->crlfile, nextarg, DENY_BLANK);
      break;
    case ONEOPT('E', 'k'): /* --tlsuser */
      if(!feature_tls_srp)
        err = PARAM_LIBCURL_DOESNT_SUPPORT;
      else
        err = getstr(&config->tls_username, nextarg, DENY_BLANK);
      cleanarg(clearthis);
      break;
    case ONEOPT('E', 'l'): /* --tlspassword */
      if(!feature_tls_srp)
        err = PARAM_LIBCURL_DOESNT_SUPPORT;
      else
        err = getstr(&config->tls_password, nextarg, ALLOW_BLANK);
      cleanarg(clearthis);
      break;
    case ONEOPT('E', 'm'): /* --tlsauthtype */
      if(!feature_tls_srp)
        err = PARAM_LIBCURL_DOESNT_SUPPORT;
      else {
        err = getstr(&config->tls_authtype, nextarg, DENY_BLANK);
        if(!err && strcmp(config->tls_authtype, "SRP"))
          err = PARAM_LIBCURL_DOESNT_SUPPORT; /* only support TLS-SRP */
      }
      break;
    case ONEOPT('E', 'n'): /* --ssl-allow-beast */
      if(feature_ssl)
        config->ssl_allow_beast = toggle;
      break;

    case ONEOPT('E', 'o'): /* --ssl-auto-client-cert */
      if(feature_ssl)
        config->ssl_auto_client_cert = toggle;
      break;

    case ONEOPT('E', 'O'): /* --proxy-ssl-auto-client-cert */
      if(feature_ssl)
        config->proxy_ssl_auto_client_cert = toggle;
      break;

    case ONEOPT('E', 'p'): /* --pinnedpubkey */
      err = getstr(&config->pinnedpubkey, nextarg, DENY_BLANK);
      break;

    case ONEOPT('E', 'P'): /* --proxy-pinnedpubkey */
      err = getstr(&config->proxy_pinnedpubkey, nextarg, DENY_BLANK);
      break;

    case ONEOPT('E', 'q'): /* --cert-status */
      config->verifystatus = TRUE;
      break;

    case ONEOPT('E', 'Q'): /* --doh-cert-status */
      config->doh_verifystatus = TRUE;
      break;

    case ONEOPT('E', 'r'): /* --false-start */
      config->falsestart = TRUE;
      break;

    case ONEOPT('E', 's'): /* --ssl-no-revoke */
      if(feature_ssl)
        config->ssl_no_revoke = TRUE;
      break;

    case ONEOPT('E', 'S'): /* --ssl-revoke-best-effort */
      if(feature_ssl)
        config->ssl_revoke_best_effort = TRUE;
      break;

    case ONEOPT('E', 't'): /* --tcp-fastopen */
      config->tcp_fastopen = TRUE;
      break;

    case ONEOPT('E', 'u'): /* --proxy-tlsuser */
      cleanarg(clearthis);
      if(!feature_tls_srp)
        err = PARAM_LIBCURL_DOESNT_SUPPORT;
      else
        err = getstr(&config->proxy_tls_username, nextarg, ALLOW_BLANK);
      break;

    case ONEOPT('E', 'v'): /* --proxy-tlspassword */
      cleanarg(clearthis);
      if(!feature_tls_srp)
        err = PARAM_LIBCURL_DOESNT_SUPPORT;
      else
        err = getstr(&config->proxy_tls_password, nextarg, DENY_BLANK);
      break;

    case ONEOPT('E', 'w'): /* --proxy-tlsauthtype */
      if(!feature_tls_srp)
        err = PARAM_LIBCURL_DOESNT_SUPPORT;
      else {
        err = getstr(&config->proxy_tls_authtype, nextarg, DENY_BLANK);
        if(!err && strcmp(config->proxy_tls_authtype, "SRP"))
          err = PARAM_LIBCURL_DOESNT_SUPPORT; /* only support TLS-SRP */
      }
      break;

    case ONEOPT('E', 'x'): /* --proxy-cert */
      cleanarg(clearthis);
      GetFileAndPassword(nextarg, &config->proxy_cert,
                         &config->proxy_key_passwd);
      break;

    case ONEOPT('E', 'y'): /* --proxy-cert-type */
      err = getstr(&config->proxy_cert_type, nextarg, DENY_BLANK);
      break;

    case ONEOPT('E', 'z'): /* --proxy-key */
      err = getstr(&config->proxy_key, nextarg, ALLOW_BLANK);
      break;

    case ONEOPT('E', '0'): /* --proxy-key-type */
      err = getstr(&config->proxy_key_type, nextarg, DENY_BLANK);
      break;

    case ONEOPT('E', '1'): /* --proxy-pass */
      err = getstr(&config->proxy_key_passwd, nextarg, ALLOW_BLANK);
      cleanarg(clearthis);
      break;

    case ONEOPT('E', '2'): /* --proxy-ciphers */
      err = getstr(&config->proxy_cipher_list, nextarg, DENY_BLANK);
      break;

    case ONEOPT('E', '3'): /* --proxy-crlfile */
      err = getstr(&config->proxy_crlfile, nextarg, DENY_BLANK);
      break;

    case ONEOPT('E', '4'): /* --proxy-allow-beast */
      if(feature_ssl)
        config->proxy_ssl_allow_beast = toggle;
      break;

    case ONEOPT('E', '5'): /* --login-options */
      err = getstr(&config->login_options, nextarg, ALLOW_BLANK);
      break;

    case ONEOPT('E', '6'): /* --proxy-cacert */
      err = getstr(&config->proxy_cacert, nextarg, DENY_BLANK);
      break;

    case ONEOPT('E', '7'): /* --proxy-cainfo */
      err = getstr(&config->proxy_capath, nextarg, DENY_BLANK);
      break;

    case ONEOPT('E', '8'): /* --proxy-insecure */
      config->proxy_insecure_ok = toggle;
      break;

    case ONEOPT('E', '9'): /* --proxy-tlsv1 */
      /* TLS version 1 for proxy */
      config->proxy_ssl_version = CURL_SSLVERSION_TLSv1;
      break;

    case ONEOPT('E', 'A'): /* --socks5-basic */
      if(toggle)
        config->socks5_auth |= CURLAUTH_BASIC;
      else
        config->socks5_auth &= ~CURLAUTH_BASIC;
      break;

    case ONEOPT('E', 'B'): /* --socks5-gssapi */
      if(toggle)
        config->socks5_auth |= CURLAUTH_GSSAPI;
      else
        config->socks5_auth &= ~CURLAUTH_GSSAPI;
      break;

    case ONEOPT('E', 'C'): /* --etag-save */
      err = getstr(&config->etag_save_file, nextarg, DENY_BLANK);
      break;

    case ONEOPT('E', 'D'): /* --etag-compare */
      err = getstr(&config->etag_compare_file, nextarg, DENY_BLANK);
      break;

    case ONEOPT('E', 'E'): /* --curves */
      err = getstr(&config->ssl_ec_curves, nextarg, DENY_BLANK);
      break;

    case ONEOPT('f', 'a'): /* --fail-early */
      global->fail_early = toggle;
      break;
    case ONEOPT('f', 'b'): /* --styled-output */
      global->styled_output = toggle;
      break;
    case ONEOPT('f', 'c'): /* --mail-rcpt-allowfails */
      config->mail_rcpt_allowfails = toggle;
      break;
    case ONEOPT('f', 'd'): /* --fail-with-body */
      config->failwithbody = toggle;
      if(config->failonerror && config->failwithbody) {
        errorf(config->global, "You must select either --fail or "
               "--fail-with-body, not both.");
        err = PARAM_BAD_USE;
      }
      break;
    case ONEOPT('f', 'e'): /* --remove-on-error */
      config->rm_partial = toggle;
      break;
    case ONEOPT('f', '\0'): /* --fail */
      config->failonerror = toggle;
      if(config->failonerror && config->failwithbody) {
        errorf(config->global, "You must select either --fail or "
               "--fail-with-body, not both.");
        err = PARAM_BAD_USE;
      }
      break;

    case ONEOPT('F', '\0'): /* --form */
    case ONEOPT('F', 's'): /* --form-string */
      /* "form data" simulation, this is a little advanced so lets do our best
         to sort this out slowly and carefully */
      if(formparse(config,
                   nextarg,
                   &config->mimeroot,
                   &config->mimecurrent,
                   (subletter == 's')?TRUE:FALSE)) { /* 's' is literal
                                                        string */
        err = PARAM_BAD_USE;
      }
      else if(SetHTTPrequest(config, HTTPREQ_MIMEPOST, &config->httpreq))
        err = PARAM_BAD_USE;
      break;

    case ONEOPT('g', '\0'): /* --globoff */
      config->globoff = toggle;
      break;

    case ONEOPT('G', '\0'): /* --get */
      config->use_httpget = toggle;
      break;

    case ONEOPT('G', 'a'): /* --request-target */
      err = getstr(&config->request_target, nextarg, DENY_BLANK);
      break;

    case ONEOPT('h', '\0'): /* --help */
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
    case ONEOPT('H', '\0'): /* --header */
    case ONEOPT('H', 'p'): /* --proxy-header */
      /* A custom header to append to a list */
      if(nextarg[0] == '@') {
        /* read many headers from a file or stdin */
        char *string;
        size_t len;
        bool use_stdin = !strcmp(&nextarg[1], "-");
        FILE *file = use_stdin?stdin:fopen(&nextarg[1], FOPEN_READTEXT);
        if(!file) {
          errorf(global, "Failed to open %s", &nextarg[1]);
          err = PARAM_READ_ERROR;
          break;
        }
        else {
          err = file2memory(&string, &len, file);
          if(!err && string) {
            /* Allow strtok() here since this isn't used threaded */
            /* !checksrc! disable BANNEDFUNC 2 */
            char *h = strtok(string, "\r\n");
            while(h) {
              if(subletter == 'p') /* --proxy-header */
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
          if(err)
            break;
        }
      }
      else {
        if(subletter == 'p') /* --proxy-header */
          err = add2list(&config->proxyheaders, nextarg);
        else
          err = add2list(&config->headers, nextarg);
      }
      break;
    case ONEOPT('i', '\0'): /* --include */
      config->show_headers = toggle; /* show the headers as well in the
                                        general output stream */
      break;
    case ONEOPT('j', '\0'): /* --junk-session-cookies */
      config->cookiesession = toggle;
      break;
    case ONEOPT('I', '\0'): /* --head */
      config->no_body = toggle;
      config->show_headers = toggle;
      if(SetHTTPrequest(config,
                        (config->no_body)?HTTPREQ_HEAD:HTTPREQ_GET,
                        &config->httpreq))
        err = PARAM_BAD_USE;
      break;
    case ONEOPT('J', '\0'): /* --remote-header-name */
      config->content_disposition = toggle;
      break;
    case ONEOPT('k', '\0'): /* --insecure */
      config->insecure_ok = toggle;
      break;
    case ONEOPT('k', 'd'): /* --doh-insecure */
      config->doh_insecure_ok = toggle;
      break;
    case ONEOPT('K', '\0'): /* --config */
      if(parseconfig(nextarg, global)) {
        errorf(global, "cannot read config from '%s'", nextarg);
        err = PARAM_READ_ERROR;
      }
      break;
    case ONEOPT('l', '\0'): /* --list-only */
      config->dirlistonly = toggle; /* only list the names of the FTP dir */
      break;
    case ONEOPT('L', '\0'): /* --location */
    case ONEOPT('L', 't'): /* --location-trusted */
      config->followlocation = toggle; /* Follow Location: HTTP headers */
      if(subletter == 't')
        /* Continue to send authentication (user+password) when following
         * locations, even when hostname changed */
        config->unrestricted_auth = toggle;
      break;
    case ONEOPT('m', '\0'): /* --max-time */
      /* specified max time */
      err = secs2ms(&config->timeout_ms, nextarg);
      break;
    case ONEOPT('M', '\0'): /* --manual */
      if(toggle) { /* --no-manual shows no manual... */
#ifndef USE_MANUAL
        warnf(global,
              "built-in manual was disabled at build-time");
#endif
        err = PARAM_MANUAL_REQUESTED;
      }
      break;

    case ONEOPT('n', 'o'): /* --netrc-optional */
      config->netrc_opt = toggle;
      break;
    case ONEOPT('n', 'e'): /* --netrc-file */
      err = getstr(&config->netrc_file, nextarg, DENY_BLANK);
      break;
    case ONEOPT('n', '\0'): /* --netrc */
      /* pick info from .netrc, if this is used for http, curl will
         automatically enforce user+password with the request */
      config->netrc = toggle;
      break;

    case ONEOPT('N', '\0'): /* --buffer */
      /* disable the output I/O buffering. note that the option is called
         --buffer but is mostly used in the negative form: --no-buffer */
      config->nobuffer = longopt ? !toggle : TRUE;
      break;

    case ONEOPT('O', 'a'): /* --remote-name-all */
      config->default_node_flags = toggle?GETOUT_USEREMOTE:0;
      break;

    case ONEOPT('O', 'b'): /* --output-dir */
      err = getstr(&config->output_dir, nextarg, DENY_BLANK);
      break;

    case ONEOPT('O', 'c'): /* --clobber */
      config->file_clobber_mode = toggle ? CLOBBER_ALWAYS : CLOBBER_NEVER;
      break;

    case ONEOPT('o', '\0'): /* --output */
    case ONEOPT('O', '\0'): /* --remote-name */
      /* output file */
      if(!config->url_out)
        config->url_out = config->url_list;
      if(config->url_out) {
        /* there's a node here, if it already is filled-in continue to find
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
    case ONEOPT('P', '\0'): /* --ftp-port */
      /* This makes the FTP sessions use PORT instead of PASV */
      /* use <eth0> or <192.168.10.10> style addresses. Anything except
         this will make us try to get the "default" address.
         NOTE: this is a changed behavior since the released 4.1!
      */
      err = getstr(&config->ftpport, nextarg, DENY_BLANK);
      break;
    case ONEOPT('p', '\0'): /* --proxytunnel */
      /* proxy tunnel for non-http protocols */
      config->proxytunnel = toggle;
      break;

    case ONEOPT('q', '\0'): /* --disable */
      /* if used first, already taken care of, we do it like this so we don't
         cause an error! */
      break;
    case ONEOPT('Q', '\0'): /* --quote */
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
    case ONEOPT('r', '\0'): /* --range */
      /* Specifying a range WITHOUT A DASH will create an illegal HTTP range
         (and won't actually be range by definition). The man page previously
         claimed that to be a good way, why this code is added to work-around
         it. */
      if(ISDIGIT(*nextarg) && !strchr(nextarg, '-')) {
        char buffer[32];
        if(curlx_strtoofft(nextarg, NULL, 10, &value)) {
          warnf(global, "unsupported range point");
          err = PARAM_BAD_USE;
          break;
        }
        warnf(global,
              "A specified range MUST include at least one dash (-). "
              "Appending one for you");
        msnprintf(buffer, sizeof(buffer), "%" CURL_FORMAT_CURL_OFF_T "-",
                  value);
        Curl_safefree(config->range);
        config->range = strdup(buffer);
        if(!config->range) {
          err = PARAM_NO_MEM;
          break;
        }
      }
      else {
        /* byte range requested */
        const char *tmp_range = nextarg;
        while(*tmp_range != '\0') {
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
    case ONEOPT('R', '\0'): /* --remote-time */
      /* use remote file's time */
      config->remote_time = toggle;
      break;
    case ONEOPT('s', '\0'): /* --silent */
      global->silent = toggle;
      break;
    case ONEOPT('S', '\0'): /* --show-error */
      global->showerror = toggle;
      break;
    case ONEOPT('t', '\0'): /* --telnet-option */
      /* Telnet options */
      err = add2list(&config->telnet_options, nextarg);
      break;
    case ONEOPT('T', '\0'): /* --upload */
      /* we are uploading */
      if(!config->url_ul)
        config->url_ul = config->url_list;
      if(config->url_ul) {
        /* there's a node here, if it already is filled-in continue to find
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
    case ONEOPT('u', '\0'): /* --user */
      /* user:password  */
      err = getstr(&config->userpwd, nextarg, ALLOW_BLANK);
      cleanarg(clearthis);
      break;
    case ONEOPT('U', '\0'): /* --proxy-user */
      /* Proxy user:password  */
      err = getstr(&config->proxyuserpwd, nextarg, ALLOW_BLANK);
      cleanarg(clearthis);
      break;
    case ONEOPT('v', '\0'): /* --verbose */
      if(toggle) {
        /* the '%' thing here will cause the trace get sent to stderr */
        Curl_safefree(global->trace_dump);
        global->trace_dump = strdup("%");
        if(!global->trace_dump)
          err = PARAM_NO_MEM;
        else {
          if(global->tracetype && (global->tracetype != TRACE_PLAIN))
            warnf(global,
                  "-v, --verbose overrides an earlier trace/verbose option");
          global->tracetype = TRACE_PLAIN;
        }
      }
      else
        /* verbose is disabled here */
        global->tracetype = TRACE_NONE;
      break;
    case ONEOPT('V', '\0'): /* --version */
      if(toggle)    /* --no-version yields no output! */
        err = PARAM_VERSION_INFO_REQUESTED;
      break;

    case ONEOPT('w', '\0'): /* --write-out */
      /* get the output string */
      if('@' == *nextarg) {
        /* the data begins with a '@' letter, it means that a file name
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
        err = getstr(&config->writeout, nextarg, DENY_BLANK);
      break;
    case ONEOPT('x', 'a'): /* --preproxy */
      err = getstr(&config->preproxy, nextarg, DENY_BLANK);
      break;
    case ONEOPT('x', '\0'): /* --proxy */
      /* --proxy */
      err = getstr(&config->proxy, nextarg, ALLOW_BLANK);
      if(config->proxyver != CURLPROXY_HTTPS2)
        config->proxyver = CURLPROXY_HTTP;
      break;

    case ONEOPT('X', '\0'): /* --request */
      /* set custom request */
      err = getstr(&config->customrequest, nextarg, DENY_BLANK);
      break;
    case ONEOPT('y', '\0'): /* --speed-limit */
      /* low speed time */
      err = str2unum(&config->low_speed_time, nextarg);
      if(!err && !config->low_speed_limit)
        config->low_speed_limit = 1;
      break;
    case ONEOPT('Y', '\0'): /* --speed-time */
      /* low speed limit */
      err = str2unum(&config->low_speed_limit, nextarg);
      if(!err && !config->low_speed_time)
        config->low_speed_time = 30;
      break;
    case ONEOPT('Z', '\0'): /* --parallel */
      global->parallel = toggle;
      break;
    case ONEOPT('Z', 'b'): {  /* --parallel-max */
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
    case ONEOPT('Z', 'c'):   /* --parallel-immediate */
      global->parallel_connect = toggle;
      break;

    case ONEOPT('z', '\0'): /* --time-cond */
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
      now = time(NULL);
      config->condtime = (curl_off_t)curl_getdate(nextarg, &now);
      if(-1 == config->condtime) {
        /* now let's see if it is a file name to get the time from instead! */
        rc = getfiletime(nextarg, global, &value);
        if(!rc)
          /* pull the time out from the file */
          config->condtime = value;
        else {
          /* failed, remove time condition */
          config->timecond = CURL_TIMECOND_NONE;
          warnf(global,
                "Illegal date format for -z, --time-cond (and not "
                "a file name). Disabling time condition. "
                "See curl_getdate(3) for valid date syntax.");
        }
      }
      break;
    default: /* unknown flag */
      err = PARAM_OPTION_UNKNOWN;
      break;
    }
    a = NULL;

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
          i++; /* we're supposed to skip this */
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
    if(config->show_headers)
      result = PARAM_CONTDISP_SHOW_HEADER;
    else if(config->resume_from_current)
      result = PARAM_CONTDISP_RESUME_FROM;
  }

  if(result && result != PARAM_HELP_REQUESTED &&
     result != PARAM_MANUAL_REQUESTED &&
     result != PARAM_VERSION_INFO_REQUESTED &&
     result != PARAM_ENGINES_REQUESTED) {
    const char *reason = param2text(result);

    if(orig_opt && strcmp(":", orig_opt))
      helpf(tool_stderr, "option %s: %s", orig_opt, reason);
    else
      helpf(tool_stderr, "%s", reason);
  }

  curlx_unicodefree(orig_opt);
  return result;
}
