/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) 1998 - 2011, Daniel Stenberg, <daniel@haxx.se>, et al.
 *
 * This software is licensed as described in the file COPYING, which
 * you should have received as part of this distribution. The terms
 * are also available at http://curl.haxx.se/docs/copyright.html.
 *
 * You may opt to use, copy, modify, merge, publish, distribute and/or sell
 * copies of the Software, and permit persons to whom the Software is
 * furnished to do so, under the terms of the COPYING file.
 *
 * This software is distributed on an "AS IS" basis, WITHOUT WARRANTY OF ANY
 * KIND, either express or implied.
 *
 ***************************************************************************/
#include "setup.h"

#include <curl/curl.h>

/*
** system headers
*/

#include <sys/types.h>
#include <sys/stat.h>

#ifdef NETWARE
#  ifdef __NOVELL_LIBC__
#    include <screen.h>
#  else
#    include <nwconio.h>
#  endif
#endif

#ifdef HAVE_IO_H
#  include <io.h>
#endif

#ifdef HAVE_UNISTD_H
#  include <unistd.h>
#endif

#ifdef HAVE_FCNTL_H
#  include <fcntl.h>
#endif

#ifdef HAVE_UTIME_H
#  include <utime.h>
#elif defined(HAVE_SYS_UTIME_H)
#  include <sys/utime.h>
#endif

#ifdef HAVE_LIMITS_H
#  include <limits.h>
#endif

#ifdef HAVE_SYS_POLL_H
#  include <sys/poll.h>
#elif defined(HAVE_POLL_H)
#  include <poll.h>
#endif

#ifdef HAVE_LOCALE_H
#  include <locale.h>
#endif

#ifdef HAVE_NETINET_IN_H
#  include <netinet/in.h>
#endif

#ifdef HAVE_NETINET_TCP_H
#  include <netinet/tcp.h>
#endif

#ifdef MSDOS
#  include <dos.h>
#endif

/*
** src subdirectory headers
*/

#include "urlglob.h"
#include "writeout.h"
#include "getpass.h"
#include "homedir.h"
#include "curlutil.h"
#include "version.h"
#include "xattr.h"
#include "tool_cfgable.h"
#include "tool_convert.h"
#include "tool_dirhie.h"
#include "tool_doswin.h"
#include "tool_easysrc.h"
#include "tool_libinfo.h"
#include "tool_mfiles.h"
#include "tool_msgs.h"
#include "tool_myfunc.h"
#include "tool_cb_prg.h"
#include "tool_setopt.h"
#include "tool_vms.h"

#include "tool_cb_rea.h"
#include "tool_cb_wrt.h"
#include "tool_cb_see.h"
#include "tool_cb_skt.h"
#include "tool_cb_hdr.h"
#include "tool_cb_dbg.h"

#ifdef USE_MANUAL
#  include "hugehelp.h"
#endif
#ifdef USE_ENVIRONMENT
#  include "writeenv.h"
#endif

/*
** libcurl subdirectory headers
*/

#include "rawstr.h"

#define ENABLE_CURLX_PRINTF
/* make the curlx header define all printf() functions to use the curlx_*
   versions instead */
#include "curlx.h"

/* This is low-level hard-hacking memory leak tracking and similar. Using
   the library level code from this client-side is ugly, but we do this
   anyway for convenience. */
#include "memdebug.h" /* keep this as LAST include */

#ifdef __VMS
static int vms_show = 0;
#endif

#if defined(NETWARE)
#define PRINT_LINES_PAUSE 23
#endif

#if defined(__SYMBIAN32__)
#define PRINT_LINES_PAUSE 16
#define pressanykey() getchar()
#endif

#define DEFAULT_MAXREDIRS  50L

#if defined(O_BINARY) && defined(HAVE_SETMODE)
#ifdef __HIGHC__
#define SET_BINMODE(file) _setmode(file,O_BINARY)
#else
#define SET_BINMODE(file) setmode(fileno(file),O_BINARY)
#endif
#else
#define SET_BINMODE(file)   ((void)0)
#endif

#ifndef O_BINARY
/* since O_BINARY as used in bitmasks, setting it to zero makes it usable in
   source code but yet it doesn't ruin anything */
#define O_BINARY 0
#endif

#ifdef MSDOS
#define USE_WATT32
#ifdef DJGPP
/* we want to glob our own argv[] */
char **__crt0_glob_function (char *arg)
{
  (void)arg;
  return (char**)0;
}
#endif /* __DJGPP__ */
#endif /* MSDOS */

#ifndef STDIN_FILENO
#define STDIN_FILENO  fileno(stdin)
#endif

#ifndef STDOUT_FILENO
#define STDOUT_FILENO  fileno(stdout)
#endif

#ifndef STDERR_FILENO
#define STDERR_FILENO  fileno(stderr)
#endif

#define CURLseparator   "--_curl_--"

/*
 * Default sizeof(off_t) in case it hasn't been defined in config file.
 */

#ifndef SIZEOF_OFF_T
#  if defined(__VMS) && !defined(__VAX)
#    if defined(_LARGEFILE)
#      define SIZEOF_OFF_T 8
#    endif
#  elif defined(__OS400__) && defined(__ILEC400__)
#    if defined(_LARGE_FILES)
#      define SIZEOF_OFF_T 8
#    endif
#  elif defined(__MVS__) && defined(__IBMC__)
#    if defined(_LP64) || defined(_LARGE_FILES)
#      define SIZEOF_OFF_T 8
#    endif
#  elif defined(__370__) && defined(__IBMC__)
#    if defined(_LP64) || defined(_LARGE_FILES)
#      define SIZEOF_OFF_T 8
#    endif
#  elif defined(TPF)
#    define SIZEOF_OFF_T 8
#  endif
#  ifndef SIZEOF_OFF_T
#    define SIZEOF_OFF_T 4
#  endif
#endif

#define CURL_CA_CERT_ERRORMSG1                                          \
  "More details here: http://curl.haxx.se/docs/sslcerts.html\n\n"       \
  "curl performs SSL certificate verification by default, "             \
  "using a \"bundle\"\n"                                                \
  " of Certificate Authority (CA) public keys (CA certs). If the default\n" \
  " bundle file isn't adequate, you can specify an alternate file\n"    \
  " using the --cacert option.\n"

#define CURL_CA_CERT_ERRORMSG2                                          \
  "If this HTTPS server uses a certificate signed by a CA represented in\n" \
  " the bundle, the certificate verification probably failed due to a\n" \
  " problem with the certificate (it might be expired, or the name might\n" \
  " not match the domain name in the URL).\n"                           \
  "If you'd like to turn off curl's verification of the certificate, use\n" \
  " the -k (or --insecure) option.\n"

/*
 * This is the main global constructor for the app. Call this before
 * _any_ libcurl usage. If this fails, *NO* libcurl functions may be
 * used, or havoc may be the result.
 */
static CURLcode main_init(void)
{
#ifdef DJGPP
  /* stop stat() wasting time */
  _djstat_flags |= _STAT_INODE | _STAT_EXEC_MAGIC | _STAT_DIRSIZE;
#endif

  return curl_global_init(CURL_GLOBAL_DEFAULT);
}

/*
 * This is the main global destructor for the app. Call this after
 * _all_ libcurl usage is done.
 */
static void main_free(void)
{
  curl_global_cleanup();
  convert_cleanup();
}

static int SetHTTPrequest(struct Configurable *config,
                          HttpReq req, HttpReq *store)
{
  if((*store == HTTPREQ_UNSPEC) ||
     (*store == req)) {
    *store = req;
    return 0;
  }
  warnf(config, "You can only select one HTTP request!\n");
  return 1;
}

static void help(void)
{
  int i;
  /* A few of these source lines are >80 columns wide, but that's only because
     breaking the strings narrower makes this chunk look even worse!

     Starting with 7.18.0, this list of command line options is sorted based
     on the long option name. It is not done automatically, although a command
     line like the following can help out:

     curl --help | cut -c5- | grep "^-" | sort
  */
  static const char * const helptext[]={
    "Usage: curl [options...] <url>",
    "Options: (H) means HTTP/HTTPS only, (F) means FTP only",
    "     --anyauth       Pick \"any\" authentication method (H)",
    " -a, --append        Append to target file when uploading (F/SFTP)",
    "     --basic         Use HTTP Basic Authentication (H)",
    "     --cacert FILE   CA certificate to verify peer against (SSL)",
    "     --capath DIR    CA directory to verify peer against (SSL)",
    " -E, --cert CERT[:PASSWD] Client certificate file and password (SSL)",
    "     --cert-type TYPE Certificate file type (DER/PEM/ENG) (SSL)",
    "     --ciphers LIST  SSL ciphers to use (SSL)",
    "     --compressed    Request compressed response (using deflate or gzip)",
    " -K, --config FILE   Specify which config file to read",
    "     --connect-timeout SECONDS  Maximum time allowed for connection",
    " -C, --continue-at OFFSET  Resumed transfer offset",
    " -b, --cookie STRING/FILE  String or file to read cookies from (H)",
    " -c, --cookie-jar FILE  Write cookies to this file after operation (H)",
    "     --create-dirs   Create necessary local directory hierarchy",
    "     --crlf          Convert LF to CRLF in upload",
    "     --crlfile FILE  Get a CRL list in PEM format from the given file",
    " -d, --data DATA     HTTP POST data (H)",
    "     --data-ascii DATA  HTTP POST ASCII data (H)",
    "     --data-binary DATA  HTTP POST binary data (H)",
    "     --data-urlencode DATA  HTTP POST data url encoded (H)",
    "     --delegation STRING GSS-API delegation permission",
    "     --digest        Use HTTP Digest Authentication (H)",
    "     --disable-eprt  Inhibit using EPRT or LPRT (F)",
    "     --disable-epsv  Inhibit using EPSV (F)",
    " -D, --dump-header FILE  Write the headers to this file",
    "     --egd-file FILE  EGD socket path for random data (SSL)",
    "     --engine ENGINGE  Crypto engine (SSL). \"--engine list\" for list",
#ifdef USE_ENVIRONMENT
    "     --environment   Write results to environment variables (RISC OS)",
#endif
    " -f, --fail          Fail silently (no output at all) on HTTP errors (H)",
    " -F, --form CONTENT  Specify HTTP multipart POST data (H)",
    "     --form-string STRING  Specify HTTP multipart POST data (H)",
    "     --ftp-account DATA  Account data string (F)",
    "     --ftp-alternative-to-user COMMAND  "
    "String to replace \"USER [name]\" (F)",
    "     --ftp-create-dirs  Create the remote dirs if not present (F)",
    "     --ftp-method [MULTICWD/NOCWD/SINGLECWD] Control CWD usage (F)",
    "     --ftp-pasv      Use PASV/EPSV instead of PORT (F)",
    " -P, --ftp-port ADR  Use PORT with given address instead of PASV (F)",
    "     --ftp-skip-pasv-ip Skip the IP address for PASV (F)\n"
    "     --ftp-pret      Send PRET before PASV (for drftpd) (F)",
    "     --ftp-ssl-ccc   Send CCC after authenticating (F)",
    "     --ftp-ssl-ccc-mode ACTIVE/PASSIVE  Set CCC mode (F)",
    "     --ftp-ssl-control Require SSL/TLS for ftp login, "
    "clear for transfer (F)",
    " -G, --get           Send the -d data with a HTTP GET (H)",
    " -g, --globoff       Disable URL sequences and ranges using {} and []",
    " -H, --header LINE   Custom header to pass to server (H)",
    " -I, --head          Show document info only",
    " -h, --help          This help text",
    "     --hostpubmd5 MD5  "
    "Hex encoded MD5 string of the host public key. (SSH)",
    " -0, --http1.0       Use HTTP 1.0 (H)",
    "     --ignore-content-length  Ignore the HTTP Content-Length header",
    " -i, --include       Include protocol headers in the output (H/F)",
    " -k, --insecure      Allow connections to SSL sites without certs (H)",
    "     --interface INTERFACE  Specify network interface/address to use",
    " -4, --ipv4          Resolve name to IPv4 address",
    " -6, --ipv6          Resolve name to IPv6 address",
    " -j, --junk-session-cookies Ignore session cookies read from file (H)",
    "     --keepalive-time SECONDS  Interval between keepalive probes",
    "     --key KEY       Private key file name (SSL/SSH)",
    "     --key-type TYPE Private key file type (DER/PEM/ENG) (SSL)",
    "     --krb LEVEL     Enable Kerberos with specified security level (F)",
    "     --libcurl FILE  Dump libcurl equivalent code of this command line",
    "     --limit-rate RATE  Limit transfer speed to this rate",
    " -l, --list-only     List only names of an FTP directory (F)",
    "     --local-port RANGE  Force use of these local port numbers",
    " -L, --location      Follow redirects (H)",
    "     --location-trusted like --location and send auth to other hosts (H)",
    " -M, --manual        Display the full manual",
    "     --mail-from FROM  Mail from this address",
    "     --mail-rcpt TO  Mail to this receiver(s)",
    "     --max-filesize BYTES  Maximum file size to download (H/F)",
    "     --max-redirs NUM  Maximum number of redirects allowed (H)",
    " -m, --max-time SECONDS  Maximum time allowed for the transfer",
    "     --negotiate     Use HTTP Negotiate Authentication (H)",
    " -n, --netrc         Must read .netrc for user name and password",
    "     --netrc-optional Use either .netrc or URL; overrides -n",
    "     --netrc-file FILE  Set up the netrc filename to use",
    " -N, --no-buffer     Disable buffering of the output stream",
    "     --no-keepalive  Disable keepalive use on the connection",
    "     --no-sessionid  Disable SSL session-ID reusing (SSL)",
    "     --noproxy       List of hosts which do not use proxy",
    "     --ntlm          Use HTTP NTLM authentication (H)",
    " -o, --output FILE   Write output to <file> instead of stdout",
    "     --pass PASS     Pass phrase for the private key (SSL/SSH)",
    "     --post301       "
    "Do not switch to GET after following a 301 redirect (H)",
    "     --post302       "
    "Do not switch to GET after following a 302 redirect (H)",
    " -#, --progress-bar  Display transfer progress as a progress bar",
    "     --proto PROTOCOLS  Enable/disable specified protocols",
    "     --proto-redir PROTOCOLS  "
    "Enable/disable specified protocols on redirect",
    " -x, --proxy [PROTOCOL://]HOST[:PORT] Use proxy on given port",
    "     --proxy-anyauth Pick \"any\" proxy authentication method (H)",
    "     --proxy-basic   Use Basic authentication on the proxy (H)",
    "     --proxy-digest  Use Digest authentication on the proxy (H)",
    "     --proxy-negotiate Use Negotiate authentication on the proxy (H)",
    "     --proxy-ntlm    Use NTLM authentication on the proxy (H)",
    " -U, --proxy-user USER[:PASSWORD]  Proxy user and password",
    "     --proxy1.0 HOST[:PORT]  Use HTTP/1.0 proxy on given port",
    " -p, --proxytunnel   Operate through a HTTP proxy tunnel (using CONNECT)",
    "     --pubkey KEY    Public key file name (SSH)",
    " -Q, --quote CMD     Send command(s) to server before transfer (F/SFTP)",
    "     --random-file FILE  File for reading random data from (SSL)",
    " -r, --range RANGE   Retrieve only the bytes within a range",
    "     --raw           Do HTTP \"raw\", without any transfer decoding (H)",
    " -e, --referer       Referer URL (H)",
    " -J, --remote-header-name Use the header-provided filename (H)",
    " -O, --remote-name   Write output to a file named as the remote file",
    "     --remote-name-all Use the remote file name for all URLs",
    " -R, --remote-time   Set the remote file's time on the local output",
    " -X, --request COMMAND  Specify request command to use",
    "     --resolve HOST:PORT:ADDRESS  Force resolve of HOST:PORT to ADDRESS",
    "     --retry NUM   "
    "Retry request NUM times if transient problems occur",
    "     --retry-delay SECONDS "
    "When retrying, wait this many seconds between each",
    "     --retry-max-time SECONDS  Retry only within this period",
    " -S, --show-error    "
    "Show error. With -s, make curl show errors when they occur",
    " -s, --silent        Silent mode. Don't output anything",
    "     --socks4 HOST[:PORT]  SOCKS4 proxy on given host + port",
    "     --socks4a HOST[:PORT]  SOCKS4a proxy on given host + port",
    "     --socks5 HOST[:PORT]  SOCKS5 proxy on given host + port",
    "     --socks5-hostname HOST[:PORT] "
    "SOCKS5 proxy, pass host name to proxy",
#if defined(HAVE_GSSAPI) || defined(USE_WINDOWS_SSPI)
    "     --socks5-gssapi-service NAME  SOCKS5 proxy service name for gssapi",
    "     --socks5-gssapi-nec  Compatibility with NEC SOCKS5 server",
#endif
    " -Y, --speed-limit RATE  "
    "Stop transfers below speed-limit for 'speed-time' secs",
    " -y, --speed-time SECONDS  "
    "Time for trig speed-limit abort. Defaults to 30",
    "     --ssl           Try SSL/TLS (FTP, IMAP, POP3, SMTP)",
    "     --ssl-reqd      Require SSL/TLS (FTP, IMAP, POP3, SMTP)",
    " -2, --sslv2         Use SSLv2 (SSL)",
    " -3, --sslv3         Use SSLv3 (SSL)",
    "     --stderr FILE   Where to redirect stderr. - means stdout",
    "     --tcp-nodelay   Use the TCP_NODELAY option",
    " -t, --telnet-option OPT=VAL  Set telnet option",
    "     --tftp-blksize VALUE  Set TFTP BLKSIZE option (must be >512)",
    " -z, --time-cond TIME  Transfer based on a time condition",
    " -1, --tlsv1         Use TLSv1 (SSL)",
    "     --trace FILE    Write a debug trace to the given file",
    "     --trace-ascii FILE  Like --trace but without the hex output",
    "     --trace-time    Add time stamps to trace/verbose output",
    "     --tr-encoding   Request compressed transfer encoding (H)",
    " -T, --upload-file FILE  Transfer FILE to destination",
    "     --url URL       URL to work with",
    " -B, --use-ascii     Use ASCII/text transfer",
    " -u, --user USER[:PASSWORD]  Server user and password",
    "     --tlsuser USER  TLS username",
    "     --tlspassword STRING TLS password",
    "     --tlsauthtype STRING  TLS authentication type (default SRP)",
    " -A, --user-agent STRING  User-Agent to send to server (H)",
    " -v, --verbose       Make the operation more talkative",
    " -V, --version       Show version number and quit",

#ifdef USE_WATT32
    "     --wdebug        Turn on Watt-32 debugging",
#endif
    " -w, --write-out FORMAT  What to output after completion",
    "     --xattr        Store metadata in extended file attributes",
    " -q                 If used as the first parameter disables .curlrc",
    NULL
  };
  for(i=0; helptext[i]; i++) {
    puts(helptext[i]);
#ifdef PRINT_LINES_PAUSE
    if(i && ((i % PRINT_LINES_PAUSE) == 0))
      pressanykey();
#endif
  }
}

struct LongShort {
  const char *letter;
  const char *lname;
  bool extraparam;
};

static int parseconfig(const char *filename,
                       struct Configurable *config);
static char *my_get_line(FILE *fp);

#if 0
static void GetStr(char **string,
                   const char *value)
{
  Curl_safefree(*string);
  if(value)
    *string = strdup(value);
}
#else
#define GetStr(str,val) \
do { \
  if(*(str)) { \
    free(*(str)); \
    *(str) = NULL; \
  } \
  if((val)) \
    *(str) = strdup((val)); \
} WHILE_FALSE
#endif

static void clean_getout(struct Configurable *config)
{
  struct getout *next;
  struct getout *node = config->url_list;

  while(node) {
    next = node->next;
    Curl_safefree(node->url);
    Curl_safefree(node->outfile);
    Curl_safefree(node->infile);
    Curl_safefree(node);
    node = next;
  }
  config->url_list = NULL;
}

static struct getout *new_getout(struct Configurable *config)
{
  struct getout *node =malloc(sizeof(struct getout));
  struct getout *last= config->url_last;
  if(node) {
    /* clear the struct */
    memset(node, 0, sizeof(struct getout));

    /* append this new node last in the list */
    if(last)
      last->next = node;
    else
      config->url_list = node; /* first node */

    /* move the last pointer */
    config->url_last = node;

    node->flags = config->default_node_flags;
  }
  return node;
}

/* Print list of OpenSSL engines supported.
 */
static void list_engines(const struct curl_slist *engines)
{
  puts("Build-time engines:");
  if(!engines) {
    puts("  <none>");
    return;
  }
  for(; engines; engines = engines->next)
    printf("  %s\n", engines->data);
}

/***************************************************************************
 *
 * formparse()
 *
 * Reads a 'name=value' parameter and builds the appropriate linked list.
 *
 * Specify files to upload with 'name=@filename'. Supports specified
 * given Content-Type of the files. Such as ';type=<content-type>'.
 *
 * If literal_value is set, any initial '@' or '<' in the value string
 * loses its special meaning, as does any embedded ';type='.
 *
 * You may specify more than one file for a single name (field). Specify
 * multiple files by writing it like:
 *
 * 'name=@filename,filename2,filename3'
 *
 * If you want content-types specified for each too, write them like:
 *
 * 'name=@filename;type=image/gif,filename2,filename3'
 *
 * If you want custom headers added for a single part, write them in a separate
 * file and do like this:
 *
 * 'name=foo;headers=@headerfile' or why not
 * 'name=@filemame;headers=@headerfile'
 *
 * To upload a file, but to fake the file name that will be included in the
 * formpost, do like this:
 *
 * 'name=@filename;filename=/dev/null'
 *
 * This function uses curl_formadd to fulfill it's job. Is heavily based on
 * the old curl_formparse code.
 *
 ***************************************************************************/

#define FORM_FILE_SEPARATOR ','
#define FORM_TYPE_SEPARATOR ';'

static int formparse(struct Configurable *config,
                     const char *input,
                     struct curl_httppost **httppost,
                     struct curl_httppost **last_post,
                     bool literal_value)
{
  /* nextarg MUST be a string in the format 'name=contents' and we'll
     build a linked list with the info */
  char name[256];
  char *contents;
  char major[128];
  char minor[128];
  char *contp;
  const char *type = NULL;
  char *sep;
  char *sep2;

  if((1 == sscanf(input, "%255[^=]=", name)) &&
     ((contp = strchr(input, '=')) != NULL)) {
    /* the input was using the correct format */

    /* Allocate the contents */
    contents = strdup(contp+1);
    if(!contents) {
      fprintf(config->errors, "out of memory\n");
      return 1;
    }
    contp = contents;

    if('@' == contp[0] && !literal_value) {

      /* we use the @-letter to indicate file name(s) */

      struct multi_files *multi_start = NULL;
      struct multi_files *multi_current = NULL;

      contp++;

      do {
        /* since this was a file, it may have a content-type specifier
           at the end too, or a filename. Or both. */
        char *ptr;
        char *filename=NULL;

        sep=strchr(contp, FORM_TYPE_SEPARATOR);
        sep2=strchr(contp, FORM_FILE_SEPARATOR);

        /* pick the closest */
        if(sep2 && (sep2 < sep)) {
          sep = sep2;

          /* no type was specified! */
        }

        type = NULL;

        if(sep) {

          /* if we got here on a comma, don't do much */
          if(FORM_FILE_SEPARATOR == *sep)
            ptr = NULL;
          else
            ptr = sep+1;

          *sep=0; /* terminate file name at separator */

          while(ptr && (FORM_FILE_SEPARATOR!= *ptr)) {

            /* pass all white spaces */
            while(ISSPACE(*ptr))
              ptr++;

            if(checkprefix("type=", ptr)) {
              /* set type pointer */
              type = &ptr[5];

              /* verify that this is a fine type specifier */
              if(2 != sscanf(type, "%127[^/]/%127[^;,\n]",
                             major, minor)) {
                warnf(config, "Illegally formatted content-type field!\n");
                Curl_safefree(contents);
                FreeMultiInfo(&multi_start, &multi_current);
                return 2; /* illegal content-type syntax! */
              }

              /* now point beyond the content-type specifier */
              sep = (char *)type + strlen(major)+strlen(minor)+1;

              /* there's a semicolon following - we check if it is a filename
                 specified and if not we simply assume that it is text that
                 the user wants included in the type and include that too up
                 to the next zero or semicolon. */
              if((*sep==';') && !checkprefix(";filename=", sep)) {
                sep2 = strchr(sep+1, ';');
                if(sep2)
                  sep = sep2;
                else
                  sep = sep+strlen(sep); /* point to end of string */
              }

              if(*sep) {
                *sep=0; /* zero terminate type string */

                ptr=sep+1;
              }
              else
                ptr = NULL; /* end */
            }
            else if(checkprefix("filename=", ptr)) {
              filename = &ptr[9];
              ptr=strchr(filename, FORM_TYPE_SEPARATOR);
              if(!ptr) {
                ptr=strchr(filename, FORM_FILE_SEPARATOR);
              }
              if(ptr) {
                *ptr=0; /* zero terminate */
                ptr++;
              }
            }
            else
              /* confusion, bail out of loop */
              break;
          }
          /* find the following comma */
          if(ptr)
            sep=strchr(ptr, FORM_FILE_SEPARATOR);
          else
            sep=NULL;
        }
        else {
          sep=strchr(contp, FORM_FILE_SEPARATOR);
        }
        if(sep) {
          /* the next file name starts here */
          *sep =0;
          sep++;
        }
        /* if type == NULL curl_formadd takes care of the problem */

        if(!AddMultiFiles(contp, type, filename, &multi_start,
                          &multi_current)) {
          warnf(config, "Error building form post!\n");
          Curl_safefree(contents);
          return 3;
        }
        contp = sep; /* move the contents pointer to after the separator */

      } while(sep && *sep); /* loop if there's another file name */

      /* now we add the multiple files section */
      if(multi_start) {
        struct curl_forms *forms = NULL;
        struct multi_files *ptr = multi_start;
        unsigned int i, count = 0;
        while(ptr) {
          ptr = ptr->next;
          ++count;
        }
        forms = malloc((count+1)*sizeof(struct curl_forms));
        if(!forms) {
          fprintf(config->errors, "Error building form post!\n");
          Curl_safefree(contents);
          FreeMultiInfo(&multi_start, &multi_current);
          return 4;
        }
        for(i = 0, ptr = multi_start; i < count; ++i, ptr = ptr->next) {
          forms[i].option = ptr->form.option;
          forms[i].value = ptr->form.value;
        }
        forms[count].option = CURLFORM_END;
        FreeMultiInfo(&multi_start, &multi_current);
        if(curl_formadd(httppost, last_post,
                        CURLFORM_COPYNAME, name,
                        CURLFORM_ARRAY, forms, CURLFORM_END) != 0) {
          warnf(config, "curl_formadd failed!\n");
          Curl_safefree(forms);
          Curl_safefree(contents);
          return 5;
        }
        Curl_safefree(forms);
      }
    }
    else {
      struct curl_forms info[4];
      int i = 0;
      char *ct = literal_value? NULL: strstr(contp, ";type=");

      info[i].option = CURLFORM_COPYNAME;
      info[i].value = name;
      i++;

      if(ct) {
        info[i].option = CURLFORM_CONTENTTYPE;
        info[i].value = &ct[6];
        i++;
        ct[0]=0; /* zero terminate here */
      }

      if(contp[0]=='<' && !literal_value) {
        info[i].option = CURLFORM_FILECONTENT;
        info[i].value = contp+1;
        i++;
        info[i].option = CURLFORM_END;

        if(curl_formadd(httppost, last_post,
                        CURLFORM_ARRAY, info, CURLFORM_END ) != 0) {
          warnf(config, "curl_formadd failed, possibly the file %s is bad!\n",
                contp+1);
          Curl_safefree(contents);
          return 6;
        }
      }
      else {
#ifdef CURL_DOES_CONVERSIONS
        convert_to_network(contp, strlen(contp));
#endif
        info[i].option = CURLFORM_COPYCONTENTS;
        info[i].value = contp;
        i++;
        info[i].option = CURLFORM_END;
        if(curl_formadd(httppost, last_post,
                        CURLFORM_ARRAY, info, CURLFORM_END) != 0) {
          warnf(config, "curl_formadd failed!\n");
          Curl_safefree(contents);
          return 7;
        }
      }
    }

  }
  else {
    warnf(config, "Illegally formatted input field!\n");
    return 1;
  }
  Curl_safefree(contents);
  return 0;
}


typedef enum {
  PARAM_OK,
  PARAM_OPTION_AMBIGUOUS,
  PARAM_OPTION_UNKNOWN,
  PARAM_REQUIRES_PARAMETER,
  PARAM_BAD_USE,
  PARAM_HELP_REQUESTED,
  PARAM_GOT_EXTRA_PARAMETER,
  PARAM_BAD_NUMERIC,
  PARAM_LIBCURL_DOESNT_SUPPORT,
  PARAM_NO_MEM,
  PARAM_LAST
} ParameterError;

static const char *param2text(int res)
{
  ParameterError error = (ParameterError)res;
  switch(error) {
  case PARAM_GOT_EXTRA_PARAMETER:
    return "had unsupported trailing garbage";
  case PARAM_OPTION_UNKNOWN:
    return "is unknown";
  case PARAM_OPTION_AMBIGUOUS:
    return "is ambiguous";
  case PARAM_REQUIRES_PARAMETER:
    return "requires parameter";
  case PARAM_BAD_USE:
    return "is badly used here";
  case PARAM_BAD_NUMERIC:
    return "expected a proper numerical parameter";
  case PARAM_LIBCURL_DOESNT_SUPPORT:
    return "the installed libcurl version doesn't support this";
  case PARAM_NO_MEM:
    return "out of memory";
  default:
    return "unknown error";
  }
}

static ParameterError file2string(char **bufp, FILE *file)
{
  char buffer[256];
  char *ptr;
  char *string = NULL;
  size_t stringlen = 0;
  size_t buflen;

  if(file) {
    while(fgets(buffer, sizeof(buffer), file)) {
      if((ptr = strchr(buffer, '\r')) != NULL)
        *ptr = '\0';
      if((ptr = strchr(buffer, '\n')) != NULL)
        *ptr = '\0';
      buflen = strlen(buffer);
      if((ptr = realloc(string, stringlen+buflen+1)) == NULL) {
        Curl_safefree(string);
        return PARAM_NO_MEM;
      }
      string = ptr;
      strcpy(string+stringlen, buffer);
      stringlen += buflen;
    }
  }
  *bufp = string;
  return PARAM_OK;
}

static ParameterError file2memory(char **bufp, size_t *size, FILE *file)
{
  char *newbuf;
  char *buffer = NULL;
  size_t alloc = 512;
  size_t nused = 0;
  size_t nread;

  if(file) {
    do {
      if(!buffer || (alloc == nused)) {
        /* size_t overflow detection for huge files */
        if(alloc+1 > ((size_t)-1)/2) {
          Curl_safefree(buffer);
          return PARAM_NO_MEM;
        }
        alloc *= 2;
        /* allocate an extra char, reserved space, for null termination */
        if((newbuf = realloc(buffer, alloc+1)) == NULL) {
          Curl_safefree(buffer);
          return PARAM_NO_MEM;
        }
        buffer = newbuf;
      }
      nread = fread(buffer+nused, 1, alloc-nused, file);
      nused += nread;
    } while(nread);
    /* null terminate the buffer in case it's used as a string later */
    buffer[nused] = '\0';
    /* free trailing slack space, if possible */
    if(alloc != nused) {
      if((newbuf = realloc(buffer, nused+1)) != NULL)
        buffer = newbuf;
    }
    /* discard buffer if nothing was read */
    if(!nused) {
      Curl_safefree(buffer); /* no string */
    }
  }
  *size = nused;
  *bufp = buffer;
  return PARAM_OK;
}

static void cleanarg(char *str)
{
#ifdef HAVE_WRITABLE_ARGV
  /* now that GetStr has copied the contents of nextarg, wipe the next
   * argument out so that the username:password isn't displayed in the
   * system process list */
  if(str) {
    size_t len = strlen(str);
    memset(str, ' ', len);
  }
#else
  (void)str;
#endif
}

/*
 * Parse the string and write the integer in the given address. Return
 * non-zero on failure, zero on success.
 *
 * The string must start with a digit to be valid.
 *
 * Since this function gets called with the 'nextarg' pointer from within the
 * getparameter a lot, we must check it for NULL before accessing the str
 * data.
 */

static int str2num(long *val, const char *str)
{
  if(str && ISDIGIT(*str)) {
    char *endptr;
    long num = strtol(str, &endptr, 10);
    if((endptr != str) && (endptr == str + strlen(str))) {
      *val = num;
      return 0;  /* Ok */
    }
  }
  return 1; /* badness */
}

/*
 * Parse the string and modify the long in the given address. Return
 * non-zero on failure, zero on success.
 *
 * The string is a list of protocols
 *
 * Since this function gets called with the 'nextarg' pointer from within the
 * getparameter a lot, we must check it for NULL before accessing the str
 * data.
 */

static long proto2num(struct Configurable *config, long *val, const char *str)
{
  char *buffer;
  const char *sep = ",";
  char *token;

  static struct sprotos {
    const char *name;
    long bit;
  } const protos[] = {
    { "all", CURLPROTO_ALL },
    { "http", CURLPROTO_HTTP },
    { "https", CURLPROTO_HTTPS },
    { "ftp", CURLPROTO_FTP },
    { "ftps", CURLPROTO_FTPS },
    { "scp", CURLPROTO_SCP },
    { "sftp", CURLPROTO_SFTP },
    { "telnet", CURLPROTO_TELNET },
    { "ldap", CURLPROTO_LDAP },
    { "ldaps", CURLPROTO_LDAPS },
    { "dict", CURLPROTO_DICT },
    { "file", CURLPROTO_FILE },
    { "tftp", CURLPROTO_TFTP },
    { "imap", CURLPROTO_IMAP },
    { "imaps", CURLPROTO_IMAPS },
    { "pop3", CURLPROTO_POP3 },
    { "pop3s", CURLPROTO_POP3S },
    { "smtp", CURLPROTO_SMTP },
    { "smtps", CURLPROTO_SMTPS },
    { "rtsp", CURLPROTO_RTSP },
    { "gopher", CURLPROTO_GOPHER },
    { NULL, 0 }
  };

  if(!str)
    return 1;

  buffer = strdup(str); /* because strtok corrupts it */

  for(token = strtok(buffer, sep);
      token;
      token = strtok(NULL, sep)) {
    enum e_action { allow, deny, set } action = allow;

    struct sprotos const *pp;

    /* Process token modifiers */
    while(!ISALNUM(*token)) { /* may be NULL if token is all modifiers */
      switch (*token++) {
      case '=':
        action = set;
        break;
      case '-':
        action = deny;
        break;
      case '+':
        action = allow;
        break;
      default: /* Includes case of terminating NULL */
        Curl_safefree(buffer);
        return 1;
      }
    }

    for(pp=protos; pp->name; pp++) {
      if(curlx_raw_equal(token, pp->name)) {
        switch (action) {
        case deny:
          *val &= ~(pp->bit);
          break;
        case allow:
          *val |= pp->bit;
          break;
        case set:
          *val = pp->bit;
          break;
        }
        break;
      }
    }

    if(!(pp->name)) { /* unknown protocol */
      /* If they have specified only this protocol, we say treat it as
         if no protocols are allowed */
      if(action == set)
        *val = 0;
      warnf(config, "unrecognized protocol '%s'\n", token);
    }
  }
  Curl_safefree(buffer);
  return 0;
}

/**
 * Parses the given string looking for an offset (which may be
 * a larger-than-integer value).
 *
 * @param val  the offset to populate
 * @param str  the buffer containing the offset
 * @return zero if successful, non-zero if failure.
 */
static int str2offset(curl_off_t *val, const char *str)
{
#if(CURL_SIZEOF_CURL_OFF_T > CURL_SIZEOF_LONG)
  *val = curlx_strtoofft(str, NULL, 0);
  if((*val == CURL_OFF_T_MAX || *val == CURL_OFF_T_MIN) && (ERRNO == ERANGE))
    return 1;
#else
  *val = strtol(str, NULL, 0);
  if((*val == LONG_MIN || *val == LONG_MAX) && ERRNO == ERANGE)
    return 1;
#endif
  return 0;
}

static void checkpasswd(const char *kind, /* for what purpose */
                        char **userpwd) /* pointer to allocated string */
{
  char *ptr;
  if(!*userpwd)
    return;

  ptr = strchr(*userpwd, ':');
  if(!ptr) {
    /* no password present, prompt for one */
    char passwd[256]="";
    char prompt[256];
    size_t passwdlen;
    size_t userlen = strlen(*userpwd);
    char *passptr;

    /* build a nice-looking prompt */
    curlx_msnprintf(prompt, sizeof(prompt),
                    "Enter %s password for user '%s':",
                    kind, *userpwd);

    /* get password */
    getpass_r(prompt, passwd, sizeof(passwd));
    passwdlen = strlen(passwd);

    /* extend the allocated memory area to fit the password too */
    passptr = realloc(*userpwd,
                      passwdlen + 1 + /* an extra for the colon */
                      userlen + 1);   /* an extra for the zero */

    if(passptr) {
      /* append the password separated with a colon */
      passptr[userlen]=':';
      memcpy(&passptr[userlen+1], passwd, passwdlen+1);
      *userpwd = passptr;
    }
  }
}

static ParameterError add2list(struct curl_slist **list,
                               const char *ptr)
{
  struct curl_slist *newlist = curl_slist_append(*list, ptr);
  if(newlist)
    *list = newlist;
  else
    return PARAM_NO_MEM;

  return PARAM_OK;
}

static int ftpfilemethod(struct Configurable *config, const char *str)
{
  if(curlx_raw_equal("singlecwd", str))
    return CURLFTPMETHOD_SINGLECWD;
  if(curlx_raw_equal("nocwd", str))
    return CURLFTPMETHOD_NOCWD;
  if(curlx_raw_equal("multicwd", str))
    return CURLFTPMETHOD_MULTICWD;
  warnf(config, "unrecognized ftp file method '%s', using default\n", str);
  return CURLFTPMETHOD_MULTICWD;
}

static int ftpcccmethod(struct Configurable *config, const char *str)
{
  if(curlx_raw_equal("passive", str))
    return CURLFTPSSL_CCC_PASSIVE;
  if(curlx_raw_equal("active", str))
    return CURLFTPSSL_CCC_ACTIVE;
  warnf(config, "unrecognized ftp CCC method '%s', using default\n", str);
  return CURLFTPSSL_CCC_PASSIVE;
}

static long delegation(struct Configurable *config,
                       char *str)
{
  if(curlx_raw_equal("none", str))
    return CURLGSSAPI_DELEGATION_NONE;
  if(curlx_raw_equal("policy", str))
    return CURLGSSAPI_DELEGATION_POLICY_FLAG;
  if(curlx_raw_equal("always", str))
    return CURLGSSAPI_DELEGATION_FLAG;
  warnf(config, "unrecognized delegation method '%s', using none\n", str);
  return CURLGSSAPI_DELEGATION_NONE;
}

static ParameterError getparameter(char *flag, /* f or -long-flag */
                                   char *nextarg, /* NULL if unset */
                                   bool *usedarg, /* set to TRUE if the arg
                                                     has been used */
                                   struct Configurable *config)
{
  char letter;
  char subletter=0; /* subletters can only occur on long options */
  int rc; /* generic return code variable */
  const char *parse=NULL;
  unsigned int j;
  time_t now;
  int hit=-1;
  bool longopt=FALSE;
  bool singleopt=FALSE; /* when true means '-o foo' used '-ofoo' */
  ParameterError err;
  bool toggle=TRUE; /* how to switch boolean options, on or off. Controlled
                       by using --OPTION or --no-OPTION */

  /* single-letter,
     long-name,
     boolean whether it takes an additional argument
  */
  static const struct LongShort aliases[]= {
    /* all these ones, starting with "*" or "$" as a short-option have *no*
       short option to mention. */
    {"*", "url",         TRUE},
    {"*a", "random-file", TRUE},
    {"*b", "egd-file",   TRUE},
    {"*c", "connect-timeout", TRUE},
    {"*d", "ciphers",    TRUE},
    {"*e", "disable-epsv", FALSE},
    {"*E", "epsv", FALSE}, /* made like this to make --no-epsv and --epsv to
                              work although --disable-epsv is the documented
                              option */
#ifdef USE_ENVIRONMENT
    {"*f", "environment", FALSE},
#endif
    {"*g", "trace",      TRUE},
    {"*h", "trace-ascii", TRUE},
    {"*i", "limit-rate", TRUE},
    {"*j", "compressed",  FALSE},
    {"*J", "tr-encoding",  FALSE},
    {"*k", "digest",     FALSE},
    {"*l", "negotiate",  FALSE},
    {"*m", "ntlm",       FALSE},
    {"*M", "ntlm-wb",    FALSE},
    {"*n", "basic",      FALSE},
    {"*o", "anyauth",    FALSE},
#ifdef USE_WATT32
    {"*p", "wdebug",     FALSE},
#endif
    {"*q", "ftp-create-dirs", FALSE},
    {"*r", "create-dirs", FALSE},
    {"*s", "max-redirs",   TRUE},
    {"*t", "proxy-ntlm",   FALSE},
    {"*u", "crlf",        FALSE},
    {"*v", "stderr",      TRUE},
    {"*w", "interface",   TRUE},
    {"*x", "krb" ,        TRUE},
    {"*x", "krb4" ,       TRUE}, /* this is the previous name */
    {"*y", "max-filesize", TRUE},
    {"*z", "disable-eprt", FALSE},
    {"*Z", "eprt", FALSE}, /* made like this to make --no-eprt and --eprt to
                              work although --disable-eprt is the documented
                              option */
    {"$a", "ftp-ssl",    FALSE}, /* deprecated name since 7.20.0 */
    {"$a", "ssl",        FALSE}, /* new option name in 7.20.0, previously this
                                    was ftp-ssl */
    {"$b", "ftp-pasv",   FALSE},
    {"$c", "socks5",   TRUE},
    {"$c", "socks",      TRUE}, /* this is how the option once was documented
                                   but we prefer the --socks5 version for
                                   explicit version */
    {"$d", "tcp-nodelay",FALSE},
    {"$e", "proxy-digest", FALSE},
    {"$f", "proxy-basic", FALSE},
    {"$g", "retry",      TRUE},
    {"$h", "retry-delay", TRUE},
    {"$i", "retry-max-time", TRUE},
    {"$k", "proxy-negotiate",   FALSE},
    {"$m", "ftp-account", TRUE},
    {"$n", "proxy-anyauth", FALSE},
    {"$o", "trace-time", FALSE},
    {"$p", "ignore-content-length", FALSE},
    {"$q", "ftp-skip-pasv-ip", FALSE},
    {"$r", "ftp-method", TRUE},
    {"$s", "local-port", TRUE},
    {"$t", "socks4",     TRUE},
    {"$T", "socks4a",    TRUE},
    {"$u", "ftp-alternative-to-user", TRUE},
    {"$v", "ftp-ssl-reqd", FALSE}, /* deprecated name since 7.20.0 */
    {"$v", "ssl-reqd", FALSE},  /* new option name in 7.20.0, previously this
                                   was ftp-ssl-reqd */
    {"$w", "sessionid", FALSE}, /* listed as --no-sessionid in the help */
    {"$x", "ftp-ssl-control", FALSE},
    {"$y", "ftp-ssl-ccc", FALSE},
    {"$j", "ftp-ssl-ccc-mode", TRUE},
    {"$z", "libcurl",    TRUE},
    {"$#", "raw",        FALSE},
    {"$0", "post301",    FALSE},
    {"$1", "keepalive",   FALSE}, /* listed as --no-keepalive in the help */
    {"$2", "socks5-hostname", TRUE},
    {"$3", "keepalive-time",  TRUE},
    {"$4", "post302",    FALSE},
    {"$5", "noproxy",    TRUE},

#if defined(HAVE_GSSAPI) || defined(USE_WINDOWS_SSPI)
    {"$6", "socks5-gssapi-service",  TRUE},
    {"$7", "socks5-gssapi-nec",  FALSE},
#endif
    {"$8", "proxy1.0",   TRUE},
    {"$9", "tftp-blksize", TRUE},
    {"$A", "mail-from", TRUE},
    {"$B", "mail-rcpt", TRUE},
    {"$C", "ftp-pret",   FALSE},
    {"$D", "proto",      TRUE},
    {"$E", "proto-redir", TRUE},
    {"$F", "resolve",    TRUE},
    {"$G", "delegation", TRUE},
    {"0", "http1.0",     FALSE},
    {"1", "tlsv1",       FALSE},
    {"2", "sslv2",       FALSE},
    {"3", "sslv3",       FALSE},
    {"4", "ipv4",       FALSE},
    {"6", "ipv6",       FALSE},
    {"a", "append",      FALSE},
    {"A", "user-agent",  TRUE},
    {"b", "cookie",      TRUE},
    {"B", "use-ascii",   FALSE},
    {"c", "cookie-jar",  TRUE},
    {"C", "continue-at", TRUE},
    {"d", "data",        TRUE},
    {"da", "data-ascii", TRUE},
    {"db", "data-binary", TRUE},
    {"de", "data-urlencode", TRUE},
    {"D", "dump-header", TRUE},
    {"e", "referer",     TRUE},
    {"E", "cert",        TRUE},
    {"Ea", "cacert",     TRUE},
    {"Eb","cert-type",   TRUE},
    {"Ec","key",         TRUE},
    {"Ed","key-type",    TRUE},
    {"Ee","pass",        TRUE},
    {"Ef","engine",      TRUE},
    {"Eg","capath ",     TRUE},
    {"Eh","pubkey",      TRUE},
    {"Ei", "hostpubmd5", TRUE},
    {"Ej","crlfile",     TRUE},
    {"Ek","tlsuser",     TRUE},
    {"El","tlspassword", TRUE},
    {"Em","tlsauthtype", TRUE},
    {"f", "fail",        FALSE},
    {"F", "form",        TRUE},
    {"Fs","form-string", TRUE},
    {"g", "globoff",     FALSE},
    {"G", "get",         FALSE},
    {"h", "help",        FALSE},
    {"H", "header",      TRUE},
    {"i", "include",     FALSE},
    {"I", "head",        FALSE},
    {"j", "junk-session-cookies", FALSE},
    {"J", "remote-header-name", FALSE},
    {"k", "insecure",    FALSE},
    {"K", "config",      TRUE},
    {"l", "list-only",   FALSE},
    {"L", "location",    FALSE},
    {"Lt", "location-trusted", FALSE},
    {"m", "max-time",    TRUE},
    {"M", "manual",      FALSE},
    {"n", "netrc",       FALSE},
    {"no", "netrc-optional", FALSE},
    {"ne", "netrc-file", TRUE},
    {"N", "buffer",   FALSE}, /* listed as --no-buffer in the help */
    {"o", "output",      TRUE},
    {"O",  "remote-name", FALSE},
    {"Oa", "remote-name-all", FALSE},
    {"p", "proxytunnel", FALSE},
    {"P", "ftpport",     TRUE}, /* older version */
    {"P", "ftp-port",    TRUE},
    {"q", "disable",     FALSE},
    {"Q", "quote",       TRUE},
    {"r", "range",       TRUE},
    {"R", "remote-time", FALSE},
    {"s", "silent",      FALSE},
    {"S", "show-error",  FALSE},
    {"t", "telnet-options", TRUE}, /* this is documented as telnet-option */
    {"T", "upload-file", TRUE},
    {"u", "user",        TRUE},
    {"U", "proxy-user",  TRUE},
    {"v", "verbose",     FALSE},
    {"V", "version",     FALSE},
    {"w", "write-out",   TRUE},
    {"x", "proxy",       TRUE},
    {"X", "request",     TRUE},
    {"X", "http-request", TRUE}, /* OBSOLETE VERSION */
    {"Y", "speed-limit",  TRUE},
    {"y", "speed-time", TRUE},
    {"z", "time-cond",   TRUE},
    {"#", "progress-bar",FALSE},
    {"~", "xattr",FALSE},
  };

  if(('-' != flag[0]) ||
     (('-' == flag[0]) && ('-' == flag[1]))) {
    /* this should be a long name */
    char *word=('-' == flag[0])?flag+2:flag;
    size_t fnam=strlen(word);
    int numhits=0;

    if(!strncmp(word, "no-", 3)) {
      /* disable this option but ignore the "no-" part when looking for it */
      word += 3;
      toggle = FALSE;
    }

    for(j=0; j< sizeof(aliases)/sizeof(aliases[0]); j++) {
      if(curlx_strnequal(aliases[j].lname, word, fnam)) {
        longopt = TRUE;
        numhits++;
        if(curlx_raw_equal(aliases[j].lname, word)) {
          parse = aliases[j].letter;
          hit = j;
          numhits = 1; /* a single unique hit */
          break;
        }
        parse = aliases[j].letter;
        hit = j;
      }
    }
    if(numhits>1) {
      /* this is at least the second match! */
      return PARAM_OPTION_AMBIGUOUS;
    }
    if(hit < 0) {
      return PARAM_OPTION_UNKNOWN;
    }
  }
  else {
    flag++; /* prefixed with one dash, pass it */
    hit=-1;
    parse = flag;
  }

  do {
    /* we can loop here if we have multiple single-letters */

    if(!longopt) {
      if(NULL != parse) {
        letter = (char)*parse;
      }
      else {
        letter = '\0';
      }
      subletter='\0';
    }
    else {
      letter = parse[0];
      subletter = parse[1];
    }
    *usedarg = FALSE; /* default is that we don't use the arg */

    if(hit < 0) {
      for(j=0; j< sizeof(aliases)/sizeof(aliases[0]); j++) {
        if(letter == aliases[j].letter[0]) {
          hit = j;
          break;
        }
      }
      if(hit < 0) {
        return PARAM_OPTION_UNKNOWN;
      }
    }

    if(aliases[hit].extraparam) {
      /* this option requires an extra parameter */
      if(!longopt && parse[1]) {
        nextarg=(char *)&parse[1]; /* this is the actual extra parameter */
        singleopt=TRUE;   /* don't loop anymore after this */
      }
      else if(!nextarg)
        return PARAM_REQUIRES_PARAMETER;
      else
        *usedarg = TRUE; /* mark it as used */
    }

    switch(letter) {
    case '*': /* options without a short option */
      switch(subletter) {
      case 'a': /* random-file */
        GetStr(&config->random_file, nextarg);
        break;
      case 'b': /* egd-file */
        GetStr(&config->egd_file, nextarg);
        break;
      case 'c': /* connect-timeout */
        if(str2num(&config->connecttimeout, nextarg))
          return PARAM_BAD_NUMERIC;
        break;
      case 'd': /* ciphers */
        GetStr(&config->cipher_list, nextarg);
        break;
      case 'e': /* --disable-epsv */
        config->disable_epsv = toggle;
        break;
      case 'E': /* --epsv */
        config->disable_epsv = (!toggle)?TRUE:FALSE;
        break;
#ifdef USE_ENVIRONMENT
      case 'f':
        config->writeenv = toggle;
        break;
#endif
      case 'g': /* --trace */
        GetStr(&config->trace_dump, nextarg);
        if(config->tracetype && (config->tracetype != TRACE_BIN))
          warnf(config, "--trace overrides an earlier trace/verbose option\n");
        config->tracetype = TRACE_BIN;
        break;
      case 'h': /* --trace-ascii */
        GetStr(&config->trace_dump, nextarg);
        if(config->tracetype && (config->tracetype != TRACE_ASCII))
          warnf(config,
                "--trace-ascii overrides an earlier trace/verbose option\n");
        config->tracetype = TRACE_ASCII;
        break;
      case 'i': /* --limit-rate */
      {
        /* We support G, M, K too */
        char *unit;
        curl_off_t value = curlx_strtoofft(nextarg, &unit, 0);

        if(!*unit)
          unit=(char *)"b";
        else if(strlen(unit) > 1)
          unit=(char *)"w"; /* unsupported */

        switch(*unit) {
        case 'G':
        case 'g':
          value *= 1024*1024*1024;
          break;
        case 'M':
        case 'm':
          value *= 1024*1024;
          break;
        case 'K':
        case 'k':
          value *= 1024;
          break;
        case 'b':
        case 'B':
          /* for plain bytes, leave as-is */
          break;
        default:
          warnf(config, "unsupported rate unit. Use G, M, K or B!\n");
          return PARAM_BAD_USE;
        }
        config->recvpersecond = value;
        config->sendpersecond = value;
      }
      break;

      case 'j': /* --compressed */
        if(toggle && !(curlinfo->features & CURL_VERSION_LIBZ))
          return PARAM_LIBCURL_DOESNT_SUPPORT;
        config->encoding = toggle;
        break;

      case 'J': /* --tr-encoding */
        config->tr_encoding = toggle;
        break;

      case 'k': /* --digest */
        if(toggle)
          config->authtype |= CURLAUTH_DIGEST;
        else
          config->authtype &= ~CURLAUTH_DIGEST;
        break;

      case 'l': /* --negotiate */
        if(toggle) {
          if(curlinfo->features & CURL_VERSION_GSSNEGOTIATE)
            config->authtype |= CURLAUTH_GSSNEGOTIATE;
          else
            return PARAM_LIBCURL_DOESNT_SUPPORT;
        }
        else
          config->authtype &= ~CURLAUTH_GSSNEGOTIATE;
        break;

      case 'm': /* --ntlm */
        if(toggle) {
          if(curlinfo->features & CURL_VERSION_NTLM)
            config->authtype |= CURLAUTH_NTLM;
          else
            return PARAM_LIBCURL_DOESNT_SUPPORT;
        }
        else
          config->authtype &= ~CURLAUTH_NTLM;
        break;

      case 'M': /* --ntlm-wb */
        if(toggle) {
          if(curlinfo->features & CURL_VERSION_NTLM_WB)
            config->authtype |= CURLAUTH_NTLM_WB;
          else
            return PARAM_LIBCURL_DOESNT_SUPPORT;
        }
        else
          config->authtype &= ~CURLAUTH_NTLM_WB;
        break;

      case 'n': /* --basic for completeness */
        if(toggle)
          config->authtype |= CURLAUTH_BASIC;
        else
          config->authtype &= ~CURLAUTH_BASIC;
        break;

      case 'o': /* --anyauth, let libcurl pick it */
        if(toggle)
          config->authtype = CURLAUTH_ANY;
        /* --no-anyauth simply doesn't touch it */
        break;

#ifdef USE_WATT32
      case 'p': /* --wdebug */
        dbug_init();
        break;
#endif
      case 'q': /* --ftp-create-dirs */
        config->ftp_create_dirs = toggle;
        break;

      case 'r': /* --create-dirs */
        config->create_dirs = TRUE;
        break;

      case 's': /* --max-redirs */
        /* specified max no of redirects (http(s)) */
        if(str2num(&config->maxredirs, nextarg))
          return PARAM_BAD_NUMERIC;
        break;

      case 't': /* --proxy-ntlm */
        if(curlinfo->features & CURL_VERSION_NTLM)
          config->proxyntlm = toggle;
        else
          return PARAM_LIBCURL_DOESNT_SUPPORT;
        break;

      case 'u': /* --crlf */
        /* LF -> CRLF conversion? */
        config->crlf = TRUE;
        break;

      case 'v': /* --stderr */
        if(strcmp(nextarg, "-")) {
          FILE *newfile = fopen(nextarg, "wt");
          if(!newfile)
            warnf(config, "Failed to open %s!\n", nextarg);
          else {
            if(config->errors_fopened)
              fclose(config->errors);
            config->errors = newfile;
            config->errors_fopened = TRUE;
          }
        }
        else
          config->errors = stdout;
        break;
      case 'w': /* --interface */
        /* interface */
        GetStr(&config->iface, nextarg);
        break;
      case 'x': /* --krb */
        /* kerberos level string */
        if(curlinfo->features & (CURL_VERSION_KERBEROS4 |
                                 CURL_VERSION_GSSNEGOTIATE))
          GetStr(&config->krblevel, nextarg);
        else
          return PARAM_LIBCURL_DOESNT_SUPPORT;
        break;
      case 'y': /* --max-filesize */
        if(str2offset(&config->max_filesize, nextarg))
          return PARAM_BAD_NUMERIC;
        break;
      case 'z': /* --disable-eprt */
        config->disable_eprt = toggle;
        break;
      case 'Z': /* --eprt */
        config->disable_eprt = (!toggle)?TRUE:FALSE;
        break;

      default: /* the URL! */
      {
        struct getout *url;
        if(config->url_get || ((config->url_get = config->url_list) != NULL)) {
          /* there's a node here, if it already is filled-in continue to find
             an "empty" node */
          while(config->url_get && (config->url_get->flags&GETOUT_URL))
            config->url_get = config->url_get->next;
        }

        /* now there might or might not be an available node to fill in! */

        if(config->url_get)
          /* existing node */
          url = config->url_get;
        else
          /* there was no free node, create one! */
          url=new_getout(config);

        if(url) {
          /* fill in the URL */
          GetStr(&url->url, nextarg);
          url->flags |= GETOUT_URL;
        }
      }
      }
      break;
    case '$': /* more options without a short option */
      switch(subletter) {
      case 'a': /* --ftp-ssl */
        if(toggle && !(curlinfo->features & CURL_VERSION_SSL))
          return PARAM_LIBCURL_DOESNT_SUPPORT;
        config->ftp_ssl = toggle;
        break;
      case 'b': /* --ftp-pasv */
        Curl_safefree(config->ftpport);
        break;
      case 'c': /* --socks5 specifies a socks5 proxy to use, and resolves
                   the name locally and passes on the resolved address */
        GetStr(&config->socksproxy, nextarg);
        config->socksver = CURLPROXY_SOCKS5;
        break;
      case 't': /* --socks4 specifies a socks4 proxy to use */
        GetStr(&config->socksproxy, nextarg);
        config->socksver = CURLPROXY_SOCKS4;
        break;
      case 'T': /* --socks4a specifies a socks4a proxy to use */
        GetStr(&config->socksproxy, nextarg);
        config->socksver = CURLPROXY_SOCKS4A;
        break;
      case '2': /* --socks5-hostname specifies a socks5 proxy and enables name
                   resolving with the proxy */
        GetStr(&config->socksproxy, nextarg);
        config->socksver = CURLPROXY_SOCKS5_HOSTNAME;
        break;
      case 'd': /* --tcp-nodelay option */
        config->tcp_nodelay = toggle;
        break;
      case 'e': /* --proxy-digest */
        config->proxydigest = toggle;
        break;
      case 'f': /* --proxy-basic */
        config->proxybasic = toggle;
        break;
      case 'g': /* --retry */
        if(str2num(&config->req_retry, nextarg))
          return PARAM_BAD_NUMERIC;
        break;
      case 'h': /* --retry-delay */
        if(str2num(&config->retry_delay, nextarg))
          return PARAM_BAD_NUMERIC;
        break;
      case 'i': /* --retry-max-time */
        if(str2num(&config->retry_maxtime, nextarg))
          return PARAM_BAD_NUMERIC;
        break;

      case 'k': /* --proxy-negotiate */
        if(curlinfo->features & CURL_VERSION_GSSNEGOTIATE)
          config->proxynegotiate = toggle;
        else
          return PARAM_LIBCURL_DOESNT_SUPPORT;
        break;
      case 'm': /* --ftp-account */
        GetStr(&config->ftp_account, nextarg);
        break;
      case 'n': /* --proxy-anyauth */
        config->proxyanyauth = toggle;
        break;
      case 'o': /* --trace-time */
        config->tracetime = toggle;
        break;
      case 'p': /* --ignore-content-length */
        config->ignorecl = toggle;
        break;
      case 'q': /* --ftp-skip-pasv-ip */
        config->ftp_skip_ip = toggle;
        break;
      case 'r': /* --ftp-method (undocumented at this point) */
        config->ftp_filemethod = ftpfilemethod(config, nextarg);
        break;
      case 's': /* --local-port */
        rc = sscanf(nextarg, "%d - %d",
                    &config->localport,
                    &config->localportrange);
        if(!rc)
          return PARAM_BAD_USE;
        else if(rc == 1)
          config->localportrange = 1; /* default number of ports to try */
        else {
          config->localportrange -= config->localport;
          if(config->localportrange < 1) {
            warnf(config, "bad range input\n");
            return PARAM_BAD_USE;
          }
        }
        break;
      case 'u': /* --ftp-alternative-to-user */
        GetStr(&config->ftp_alternative_to_user, nextarg);
        break;
      case 'v': /* --ftp-ssl-reqd */
        if(toggle && !(curlinfo->features & CURL_VERSION_SSL))
          return PARAM_LIBCURL_DOESNT_SUPPORT;
        config->ftp_ssl_reqd = toggle;
        break;
      case 'w': /* --no-sessionid */
        config->disable_sessionid = (!toggle)?TRUE:FALSE;
        break;
      case 'x': /* --ftp-ssl-control */
        if(toggle && !(curlinfo->features & CURL_VERSION_SSL))
          return PARAM_LIBCURL_DOESNT_SUPPORT;
        config->ftp_ssl_control = toggle;
        break;
      case 'y': /* --ftp-ssl-ccc */
        config->ftp_ssl_ccc = toggle;
        if(!config->ftp_ssl_ccc_mode)
          config->ftp_ssl_ccc_mode = CURLFTPSSL_CCC_PASSIVE;
        break;
      case 'j': /* --ftp-ssl-ccc-mode */
        config->ftp_ssl_ccc = TRUE;
        config->ftp_ssl_ccc_mode = ftpcccmethod(config, nextarg);
        break;
      case 'z': /* --libcurl */
        GetStr(&config->libcurl, nextarg);
        break;
      case '#': /* --raw */
        config->raw = toggle;
        break;
      case '0': /* --post301 */
        config->post301 = toggle;
        break;
      case '1': /* --no-keepalive */
        config->nokeepalive = (!toggle)?TRUE:FALSE;
        break;
      case '3': /* --keepalive-time */
        if(str2num(&config->alivetime, nextarg))
          return PARAM_BAD_NUMERIC;
        break;
      case '4': /* --post302 */
        config->post302 = toggle;
        break;
      case '5': /* --noproxy */
        /* This specifies the noproxy list */
        GetStr(&config->noproxy, nextarg);
        break;
#if defined(HAVE_GSSAPI) || defined(USE_WINDOWS_SSPI)
      case '6': /* --socks5-gssapi-service */
        GetStr(&config->socks5_gssapi_service, nextarg);
        break;
      case '7': /* --socks5-gssapi-nec*/
        config->socks5_gssapi_nec = TRUE;
        break;
#endif
      case '8': /* --proxy1.0 */
        /* http 1.0 proxy */
        GetStr(&config->proxy, nextarg);
        config->proxyver = CURLPROXY_HTTP_1_0;
        break;
      case '9': /* --tftp-blksize */
        str2num(&config->tftp_blksize, nextarg);
        break;
      case 'A': /* --mail-from */
        GetStr(&config->mail_from, nextarg);
        break;
      case 'B': /* --mail-rcpt */
        /* append receiver to a list */
        err = add2list(&config->mail_rcpt, nextarg);
        if(err)
          return err;
        break;
      case 'C': /* --ftp-pret */
        config->ftp_pret = toggle;
        break;
      case 'D': /* --proto */
        config->proto_present = TRUE;
        if(proto2num(config, &config->proto, nextarg))
          return PARAM_BAD_USE;
        break;
      case 'E': /* --proto-redir */
        config->proto_redir_present = TRUE;
        if(proto2num(config, &config->proto_redir, nextarg))
          return PARAM_BAD_USE;
        break;
      case 'F': /* --resolve */
        err = add2list(&config->resolve, nextarg);
        if(err)
          return err;
        break;
      case 'G': /* --delegation LEVEL */
        config->gssapi_delegation = delegation(config, nextarg);
        break;
      }
      break;
    case '#': /* --progress-bar */
      if(toggle)
        config->progressmode = CURL_PROGRESS_BAR;
      else
        config->progressmode = CURL_PROGRESS_STATS;
      break;
    case '~': /* --xattr */
      config->xattr = toggle;
      break;
    case '0':
      /* HTTP version 1.0 */
      config->httpversion = CURL_HTTP_VERSION_1_0;
      break;
    case '1':
      /* TLS version 1 */
      config->ssl_version = CURL_SSLVERSION_TLSv1;
      break;
    case '2':
      /* SSL version 2 */
      config->ssl_version = CURL_SSLVERSION_SSLv2;
      break;
    case '3':
      /* SSL version 3 */
      config->ssl_version = CURL_SSLVERSION_SSLv3;
      break;
    case '4':
      /* IPv4 */
      config->ip_version = 4;
      break;
    case '6':
      /* IPv6 */
      config->ip_version = 6;
      break;
    case 'a':
      /* This makes the FTP sessions use APPE instead of STOR */
      config->ftp_append = toggle;
      break;
    case 'A':
      /* This specifies the User-Agent name */
      GetStr(&config->useragent, nextarg);
      break;
    case 'b': /* cookie string coming up: */
      if(nextarg[0] == '@') {
        nextarg++;
      }
      else if(strchr(nextarg, '=')) {
        /* A cookie string must have a =-letter */
        GetStr(&config->cookie, nextarg);
        break;
      }
      /* We have a cookie file to read from! */
      GetStr(&config->cookiefile, nextarg);
      break;
    case 'B':
      /* use ASCII/text when transferring */
      config->use_ascii = toggle;
      break;
    case 'c':
      /* get the file name to dump all cookies in */
      GetStr(&config->cookiejar, nextarg);
      break;
    case 'C':
      /* This makes us continue an ftp transfer at given position */
      if(!curlx_strequal(nextarg, "-")) {
        if(str2offset(&config->resume_from, nextarg))
          return PARAM_BAD_NUMERIC;
        config->resume_from_current = FALSE;
      }
      else {
        config->resume_from_current = TRUE;
        config->resume_from = 0;
      }
      config->use_resume=TRUE;
      break;
    case 'd':
      /* postfield data */
    {
      char *postdata=NULL;
      FILE *file;
      size_t size = 0;

      if(subletter == 'e') { /* --data-urlencode*/
        /* [name]=[content], we encode the content part only
         * [name]@[file name]
         *
         * Case 2: we first load the file using that name and then encode
         * the content.
         */
        const char *p = strchr(nextarg, '=');
        size_t nlen;
        char is_file;
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
          /* a '@' letter, it means that a file name or - (stdin) follows */

          if(curlx_strequal("-", p)) {
            file = stdin;
            SET_BINMODE(stdin);
          }
          else {
            file = fopen(p, "rb");
            if(!file)
              warnf(config,
                    "Couldn't read data from file \"%s\", this makes "
                    "an empty POST.\n", nextarg);
          }

          err = file2memory(&postdata, &size, file);

          if(file && (file != stdin))
            fclose(file);
          if(err)
            return err;
        }
        else {
          GetStr(&postdata, p);
          size = strlen(postdata);
        }

        if(!postdata) {
          /* no data from the file, point to a zero byte string to make this
             get sent as a POST anyway */
          postdata=strdup("");
          size = 0;
        }
        else {
          char *enc = curl_easy_escape(config->easy, postdata, (int)size);
          Curl_safefree(postdata); /* no matter if it worked or not */
          if(enc) {
            /* now make a string with the name from above and append the
               encoded string */
            size_t outlen = nlen + strlen(enc) + 2;
            char *n = malloc(outlen);
            if(!n) {
              curl_free(enc);
              return PARAM_NO_MEM;
            }
            if(nlen > 0) { /* only append '=' if we have a name */
              snprintf(n, outlen, "%.*s=%s", nlen, nextarg, enc);
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
      }
      else if('@' == *nextarg) {
        /* the data begins with a '@' letter, it means that a file name
           or - (stdin) follows */
        nextarg++; /* pass the @ */

        if(curlx_strequal("-", nextarg)) {
          file = stdin;
          if(subletter == 'b') /* forced data-binary */
            SET_BINMODE(stdin);
        }
        else {
          file = fopen(nextarg, "rb");
          if(!file)
            warnf(config, "Couldn't read data from file \"%s\", this makes "
                  "an empty POST.\n", nextarg);
        }

        if(subletter == 'b')
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
          postdata=strdup("");
        }
      }
      else {
        GetStr(&postdata, nextarg);
        size=strlen(postdata);
      }

#ifdef CURL_DOES_CONVERSIONS
      if(subletter != 'b') { /* NOT forced binary, convert to ASCII */
        convert_to_network(postdata, strlen(postdata));
      }
#endif

      if(config->postfields) {
        /* we already have a string, we append this one with a separating
           &-letter */
        char *oldpost=config->postfields;
        curl_off_t oldlen = config->postfieldsize;
        curl_off_t newlen = oldlen + size + 2;
        config->postfields=malloc((size_t)newlen);
        if(!config->postfields) {
          Curl_safefree(postdata);
          return PARAM_NO_MEM;
        }
        memcpy(config->postfields, oldpost, (size_t)oldlen);
        /* use byte value 0x26 for '&' to accommodate non-ASCII platforms */
        config->postfields[oldlen]='\x26';
        memcpy(&config->postfields[oldlen+1], postdata, size);
        config->postfields[oldlen+1+size]=0;
        Curl_safefree(oldpost);
        Curl_safefree(postdata);
        config->postfieldsize += size+1;
      }
      else {
        config->postfields=postdata;
        config->postfieldsize = size;
      }
    }
    /*
      We can't set the request type here, as this data might be used in
      a simple GET if -G is used. Already or soon.

      if(SetHTTPrequest(HTTPREQ_SIMPLEPOST, &config->httpreq))
      return PARAM_BAD_USE;
    */
    break;
    case 'D':
      /* dump-header to given file name */
      GetStr(&config->headerfile, nextarg);
      break;
    case 'e':
    {
      char *ptr = strstr(nextarg, ";auto");
      if(ptr) {
        /* Automatic referer requested, this may be combined with a
           set initial one */
        config->autoreferer = TRUE;
        *ptr = 0; /* zero terminate here */
      }
      else
        config->autoreferer = FALSE;
      GetStr(&config->referer, nextarg);
    }
    break;
    case 'E':
      switch(subletter) {
      case 'a': /* CA info PEM file */
        /* CA info PEM file */
        GetStr(&config->cacert, nextarg);
        break;
      case 'b': /* cert file type */
        GetStr(&config->cert_type, nextarg);
        break;
      case 'c': /* private key file */
        GetStr(&config->key, nextarg);
        break;
      case 'd': /* private key file type */
        GetStr(&config->key_type, nextarg);
        break;
      case 'e': /* private key passphrase */
        GetStr(&config->key_passwd, nextarg);
        cleanarg(nextarg);
        break;
      case 'f': /* crypto engine */
        GetStr(&config->engine, nextarg);
        if(config->engine && curlx_raw_equal(config->engine,"list"))
          config->list_engines = TRUE;
        break;
      case 'g': /* CA info PEM file */
        /* CA cert directory */
        GetStr(&config->capath, nextarg);
        break;
      case 'h': /* --pubkey public key file */
        GetStr(&config->pubkey, nextarg);
        break;
      case 'i': /* --hostpubmd5 md5 of the host public key */
        GetStr(&config->hostpubmd5, nextarg);
        if(!config->hostpubmd5 || strlen(config->hostpubmd5) != 32)
          return PARAM_BAD_USE;
        break;
      case 'j': /* CRL info PEM file */
        /* CRL file */
        GetStr(&config->crlfile, nextarg);
        break;
      case 'k': /* TLS username */
        if(curlinfo->features & CURL_VERSION_TLSAUTH_SRP)
          GetStr(&config->tls_username, nextarg);
        else
          return PARAM_LIBCURL_DOESNT_SUPPORT;
        break;
      case 'l': /* TLS password */
        if(curlinfo->features & CURL_VERSION_TLSAUTH_SRP)
          GetStr(&config->tls_password, nextarg);
        else
          return PARAM_LIBCURL_DOESNT_SUPPORT;
        break;
      case 'm': /* TLS authentication type */
        if(curlinfo->features & CURL_VERSION_TLSAUTH_SRP) {
          GetStr(&config->tls_authtype, nextarg);
          if(!strequal(config->tls_authtype, "SRP"))
            return PARAM_LIBCURL_DOESNT_SUPPORT; /* only support TLS-SRP */
        }
        else
          return PARAM_LIBCURL_DOESNT_SUPPORT;
        break;
      default: /* certificate file */
      {
        char *ptr = strchr(nextarg, ':');
        /* Since we live in a world of weirdness and confusion, the win32
           dudes can use : when using drive letters and thus
           c:\file:password needs to work. In order not to break
           compatibility, we still use : as separator, but we try to detect
           when it is used for a file name! On windows. */
#ifdef WIN32
        if(ptr &&
           (ptr == &nextarg[1]) &&
           (nextarg[2] == '\\' || nextarg[2] == '/') &&
           (ISALPHA(nextarg[0])) )
          /* colon in the second column, followed by a backslash, and the
             first character is an alphabetic letter:

             this is a drive letter colon */
          ptr = strchr(&nextarg[3], ':'); /* find the next one instead */
#endif
        if(ptr) {
          /* we have a password too */
          *ptr=0;
          ptr++;
          GetStr(&config->key_passwd, ptr);
        }
        GetStr(&config->cert, nextarg);
        cleanarg(nextarg);
      }
      }
      break;
    case 'f':
      /* fail hard on errors  */
      config->failonerror = toggle;
      break;
    case 'F':
      /* "form data" simulation, this is a little advanced so lets do our best
         to sort this out slowly and carefully */
      if(formparse(config,
                   nextarg,
                   &config->httppost,
                   &config->last_post,
                   (subletter=='s')?TRUE:FALSE)) /* 's' means literal string */
        return PARAM_BAD_USE;
      if(SetHTTPrequest(config, HTTPREQ_POST, &config->httpreq))
        return PARAM_BAD_USE;
      break;

    case 'g': /* g disables URLglobbing */
      config->globoff = toggle;
      break;

    case 'G': /* HTTP GET */
      config->use_httpget = TRUE;
      break;

    case 'h': /* h for help */
      if(toggle) {
        help();
        return PARAM_HELP_REQUESTED;
      }
      /* we now actually support --no-help too! */
      break;
    case 'H':
      /* A custom header to append to a list */
      err = add2list(&config->headers, nextarg);
      if(err)
        return err;
      break;
    case 'i':
      config->include_headers = toggle; /* include the headers as well in the
                                           general output stream */
      break;
    case 'j':
      config->cookiesession = toggle;
      break;
    case 'I':
      /*
       * no_body will imply include_headers later on
       */
      config->no_body = toggle;
      if(SetHTTPrequest(config,
                        (config->no_body)?HTTPREQ_HEAD:HTTPREQ_GET,
                        &config->httpreq))
        return PARAM_BAD_USE;
      break;
    case 'J': /* --remote-header-name */
      if(config->include_headers) {
        warnf(config,
              "--include and --remote-header-name cannot be combined.\n");
        return PARAM_BAD_USE;
      }
      config->content_disposition = toggle;
      break;
    case 'k': /* allow insecure SSL connects */
      config->insecure_ok = toggle;
      break;
    case 'K': /* parse config file */
      if(parseconfig(nextarg, config))
        warnf(config, "error trying read config from the '%s' file\n",
              nextarg);
      break;
    case 'l':
      config->dirlistonly = toggle; /* only list the names of the FTP dir */
      break;
    case 'L':
      config->followlocation = toggle; /* Follow Location: HTTP headers */
      switch (subletter) {
      case 't':
        /* Continue to send authentication (user+password) when following
         * locations, even when hostname changed */
        config->unrestricted_auth = toggle;
        break;
      }
      break;
    case 'm':
      /* specified max time */
      if(str2num(&config->timeout, nextarg))
        return PARAM_BAD_NUMERIC;
      break;
    case 'M': /* M for manual, huge help */
      if(toggle) { /* --no-manual shows no manual... */
#ifdef USE_MANUAL
        hugehelp();
        return PARAM_HELP_REQUESTED;
#else
        warnf(config,
              "built-in manual was disabled at build-time!\n");
        return PARAM_OPTION_UNKNOWN;
#endif
      }
      break;
    case 'n':
      switch(subletter) {
      case 'o': /* CA info PEM file */
        /* use .netrc or URL */
        config->netrc_opt = toggle;
        break;
      case 'e': /* netrc-file */
        GetStr(&config->netrc_file, nextarg);
        break;
      default:
        /* pick info from .netrc, if this is used for http, curl will
           automatically enfore user+password with the request */
        config->netrc = toggle;
        break;
      }
      break;
    case 'N':
      /* disable the output I/O buffering. note that the option is called
         --buffer but is mostly used in the negative form: --no-buffer */
      if(longopt)
        config->nobuffer = (!toggle)?TRUE:FALSE;
      else
        config->nobuffer = toggle;
      break;
    case 'O': /* --remote-name */
      if(subletter == 'a') { /* --remote-name-all */
        config->default_node_flags = toggle?GETOUT_USEREMOTE:0;
        break;
      }
      /* fall-through! */
    case 'o': /* --output */
      /* output file */
    {
      struct getout *url;
      if(config->url_out || ((config->url_out = config->url_list) != NULL)) {
        /* there's a node here, if it already is filled-in continue to find
           an "empty" node */
        while(config->url_out && (config->url_out->flags&GETOUT_OUTFILE))
          config->url_out = config->url_out->next;
      }

      /* now there might or might not be an available node to fill in! */

      if(config->url_out)
        /* existing node */
        url = config->url_out;
      else
        /* there was no free node, create one! */
        url=new_getout(config);

      if(url) {
        /* fill in the outfile */
        if('o' == letter) {
          GetStr(&url->outfile, nextarg);
          url->flags &= ~GETOUT_USEREMOTE; /* switch off */
        }
        else {
          url->outfile=NULL; /* leave it */
          if(toggle)
            url->flags |= GETOUT_USEREMOTE;  /* switch on */
          else
            url->flags &= ~GETOUT_USEREMOTE; /* switch off */
        }
        url->flags |= GETOUT_OUTFILE;
      }
    }
    break;
    case 'P':
      /* This makes the FTP sessions use PORT instead of PASV */
      /* use <eth0> or <192.168.10.10> style addresses. Anything except
         this will make us try to get the "default" address.
         NOTE: this is a changed behaviour since the released 4.1!
      */
      GetStr(&config->ftpport, nextarg);
      break;
    case 'p':
      /* proxy tunnel for non-http protocols */
      config->proxytunnel = toggle;
      break;

    case 'q': /* if used first, already taken care of, we do it like
                 this so we don't cause an error! */
      break;
    case 'Q':
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
      if(err)
        return err;
      break;
    case 'r':
      /* Specifying a range WITHOUT A DASH will create an illegal HTTP range
         (and won't actually be range by definition). The man page previously
         claimed that to be a good way, why this code is added to work-around
         it. */
      if(ISDIGIT(*nextarg) && !strchr(nextarg, '-')) {
        char buffer[32];
        curl_off_t off;
        warnf(config,
              "A specified range MUST include at least one dash (-). "
              "Appending one for you!\n");
        off = curlx_strtoofft(nextarg, NULL, 10);
        snprintf(buffer, sizeof(buffer), "%" CURL_FORMAT_CURL_OFF_T "-", off);
        Curl_safefree(config->range);
        config->range = strdup(buffer);
      }
      {
        /* byte range requested */
        char* tmp_range;
        tmp_range=nextarg;
        while(*tmp_range != '\0') {
          if(!ISDIGIT(*tmp_range)&&*tmp_range!='-'&&*tmp_range!=',') {
            warnf(config,"Invalid character is found in given range. "
                  "A specified range MUST have only digits in "
                  "\'start\'-\'stop\'. The server's response to this "
                  "request is uncertain.\n");
            break;
          }
          tmp_range++;
        }
        /* byte range requested */
        GetStr(&config->range, nextarg);
      }
      break;
    case 'R':
      /* use remote file's time */
      config->remote_time = toggle;
      break;
    case 's':
      /* don't show progress meter, don't show errors : */
      if(toggle)
        config->mute = config->noprogress = TRUE;
      else
        config->mute = config->noprogress = FALSE;
      config->showerror = (!toggle)?TRUE:FALSE; /* toggle off */
      break;
    case 'S':
      /* show errors */
      config->showerror = toggle; /* toggle on if used with -s */
      break;
    case 't':
      /* Telnet options */
      err = add2list(&config->telnet_options, nextarg);
      if(err)
        return err;
      break;
    case 'T':
      /* we are uploading */
    {
      struct getout *url;
      if(config->url_out || ((config->url_out = config->url_list) != NULL)) {
        /* there's a node here, if it already is filled-in continue to find
           an "empty" node */
        while(config->url_out && (config->url_out->flags&GETOUT_UPLOAD))
          config->url_out = config->url_out->next;
      }

      /* now there might or might not be an available node to fill in! */

      if(config->url_out)
        /* existing node */
        url = config->url_out;
      else
        /* there was no free node, create one! */
        url=new_getout(config);

      if(url) {
        url->flags |= GETOUT_UPLOAD; /* mark -T used */
        if(!*nextarg)
          url->flags |= GETOUT_NOUPLOAD;
        else {
          /* "-" equals stdin, but keep the string around for now */
          GetStr(&url->infile, nextarg);
        }
      }
    }
    break;
    case 'u':
      /* user:password  */
      GetStr(&config->userpwd, nextarg);
      cleanarg(nextarg);
      checkpasswd("host", &config->userpwd);
      break;
    case 'U':
      /* Proxy user:password  */
      GetStr(&config->proxyuserpwd, nextarg);
      cleanarg(nextarg);
      checkpasswd("proxy", &config->proxyuserpwd);
      break;
    case 'v':
      if(toggle) {
        /* the '%' thing here will cause the trace get sent to stderr */
        Curl_safefree(config->trace_dump);
        config->trace_dump = strdup("%");
        if(config->tracetype && (config->tracetype != TRACE_PLAIN))
          warnf(config,
                "-v, --verbose overrides an earlier trace/verbose option\n");
        config->tracetype = TRACE_PLAIN;
      }
      else
        /* verbose is disabled here */
        config->tracetype = TRACE_NONE;
      break;
    case 'V':
    {
      const char * const *proto;

      if(!toggle)
        /* --no-version yields no output! */
        break;

      printf(CURL_ID "%s\n", curl_version());
      if(curlinfo->protocols) {
        printf("Protocols: ");
        for(proto=curlinfo->protocols; *proto; ++proto) {
          printf("%s ", *proto);
        }
        puts(""); /* newline */
      }
      if(curlinfo->features) {
        unsigned int i;
        struct feat {
          const char *name;
          int bitmask;
        };
        static const struct feat feats[] = {
          {"AsynchDNS", CURL_VERSION_ASYNCHDNS},
          {"Debug", CURL_VERSION_DEBUG},
          {"TrackMemory", CURL_VERSION_CURLDEBUG},
          {"GSS-Negotiate", CURL_VERSION_GSSNEGOTIATE},
          {"IDN", CURL_VERSION_IDN},
          {"IPv6", CURL_VERSION_IPV6},
          {"Largefile", CURL_VERSION_LARGEFILE},
          {"NTLM", CURL_VERSION_NTLM},
          {"NTLM_WB", CURL_VERSION_NTLM_WB},
          {"SPNEGO", CURL_VERSION_SPNEGO},
          {"SSL",  CURL_VERSION_SSL},
          {"SSPI",  CURL_VERSION_SSPI},
          {"krb4", CURL_VERSION_KERBEROS4},
          {"libz", CURL_VERSION_LIBZ},
          {"CharConv", CURL_VERSION_CONV},
          {"TLS-SRP", CURL_VERSION_TLSAUTH_SRP}
        };
        printf("Features: ");
        for(i=0; i<sizeof(feats)/sizeof(feats[0]); i++) {
          if(curlinfo->features & feats[i].bitmask)
            printf("%s ", feats[i].name);
        }
        puts(""); /* newline */
      }
    }
    return PARAM_HELP_REQUESTED;
    case 'w':
      /* get the output string */
      if('@' == *nextarg) {
        /* the data begins with a '@' letter, it means that a file name
           or - (stdin) follows */
        FILE *file;
        const char *fname;
        nextarg++; /* pass the @ */
        if(curlx_strequal("-", nextarg)) {
          fname = "<stdin>";
          file = stdin;
        }
        else {
          fname = nextarg;
          file = fopen(nextarg, "r");
        }
        err = file2string(&config->writeout, file);
        if(file && (file != stdin))
          fclose(file);
        if(err)
          return err;
        if(!config->writeout)
          warnf(config, "Failed to read %s", fname);
      }
      else
        GetStr(&config->writeout, nextarg);
      break;
    case 'x':
      /* proxy */
      GetStr(&config->proxy, nextarg);
      config->proxyver = CURLPROXY_HTTP;
      break;
    case 'X':
      /* set custom request */
      GetStr(&config->customrequest, nextarg);
      break;
    case 'y':
      /* low speed time */
      if(str2num(&config->low_speed_time, nextarg))
        return PARAM_BAD_NUMERIC;
      if(!config->low_speed_limit)
        config->low_speed_limit = 1;
      break;
    case 'Y':
      /* low speed limit */
      if(str2num(&config->low_speed_limit, nextarg))
        return PARAM_BAD_NUMERIC;
      if(!config->low_speed_time)
        config->low_speed_time=30;
      break;
    case 'z': /* time condition coming up */
      switch(*nextarg) {
      case '+':
        nextarg++;
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
      now=time(NULL);
      config->condtime=curl_getdate(nextarg, &now);
      if(-1 == (int)config->condtime) {
        /* now let's see if it is a file name to get the time from instead! */
        struct_stat statbuf;
        if(-1 == stat(nextarg, &statbuf)) {
          /* failed, remove time condition */
          config->timecond = CURL_TIMECOND_NONE;
          warnf(config,
                "Illegal date format for -z, --timecond (and not "
                "a file name). Disabling time condition. "
                "See curl_getdate(3) for valid date syntax.\n");
        }
        else {
          /* pull the time out from the file */
          config->condtime = statbuf.st_mtime;
        }
      }
      break;
    default: /* unknown flag */
      return PARAM_OPTION_UNKNOWN;
    }
    hit = -1;

  } while(!longopt && !singleopt && *++parse && !*usedarg);

  return PARAM_OK;
}

/*
 * Copies the string from line to the buffer at param, unquoting
 * backslash-quoted characters and NUL-terminating the output string.
 * Stops at the first non-backslash-quoted double quote character or the
 * end of the input string. param must be at least as long as the input
 * string.  Returns the pointer after the last handled input character.
 */
static const char *unslashquote(const char *line, char *param)
{
  while(*line && (*line != '\"')) {
    if(*line == '\\') {
      char out;
      line++;

      /* default is to output the letter after the backslash */
      switch(out = *line) {
      case '\0':
        continue; /* this'll break out of the loop */
      case 't':
        out='\t';
        break;
      case 'n':
        out='\n';
        break;
      case 'r':
        out='\r';
        break;
      case 'v':
        out='\v';
        break;
      }
      *param++=out;
      line++;
    }
    else
      *param++=*line++;
  }
  *param=0; /* always zero terminate */
  return line;
}

/* return 0 on everything-is-fine, and non-zero otherwise */
static int parseconfig(const char *filename,
                       struct Configurable *config)
{
  int res;
  FILE *file;
  char filebuffer[512];
  bool usedarg;
  char *home;
  int rc = 0;

  if(!filename || !*filename) {
    /* NULL or no file name attempts to load .curlrc from the homedir! */

#define CURLRC DOT_CHAR "curlrc"

#ifndef __AMIGA__
    filename = CURLRC;   /* sensible default */
    home = homedir();    /* portable homedir finder */
    if(home) {
      if(strlen(home)<(sizeof(filebuffer)-strlen(CURLRC))) {
        snprintf(filebuffer, sizeof(filebuffer),
                 "%s%s%s", home, DIR_CHAR, CURLRC);

#ifdef WIN32
        /* Check if the file exists - if not, try CURLRC in the same
         * directory as our executable
         */
        file = fopen(filebuffer, "r");
        if(file != NULL) {
          fclose(file);
          filename = filebuffer;
        }
        else {
          /* Get the filename of our executable. GetModuleFileName is
           * already declared via inclusions done in setup header file.
           * We assume that we are using the ASCII version here.
           */
          int n = GetModuleFileName(0, filebuffer, sizeof(filebuffer));
          if(n > 0 && n < (int)sizeof(filebuffer)) {
            /* We got a valid filename - get the directory part */
            char *lastdirchar = strrchr(filebuffer, '\\');
            if(lastdirchar) {
              size_t remaining;
              *lastdirchar = 0;
              /* If we have enough space, build the RC filename */
              remaining = sizeof(filebuffer) - strlen(filebuffer);
              if(strlen(CURLRC) < remaining - 1) {
                snprintf(lastdirchar, remaining,
                         "%s%s", DIR_CHAR, CURLRC);
                /* Don't bother checking if it exists - we do
                 * that later
                 */
                filename = filebuffer;
              }
            }
          }
        }
#else /* WIN32 */
        filename = filebuffer;
#endif /* WIN32 */
      }
      Curl_safefree(home); /* we've used it, now free it */
    }

# else /* __AMIGA__ */
    /* On AmigaOS all the config files are into env:
     */
    filename = "ENV:" CURLRC;

#endif
  }

  if(strcmp(filename,"-"))
    file = fopen(filename, "r");
  else
    file = stdin;

  if(file) {
    char *line;
    char *aline;
    char *option;
    char *param;
    int lineno=0;
    bool alloced_param;

#define ISSEP(x) (((x)=='=') || ((x) == ':'))

    while(NULL != (aline = my_get_line(file))) {
      lineno++;
      line = aline;
      alloced_param=FALSE;

      /* line with # in the first non-blank column is a comment! */
      while(*line && ISSPACE(*line))
        line++;

      switch(*line) {
      case '#':
      case '/':
      case '\r':
      case '\n':
      case '*':
      case '\0':
        Curl_safefree(aline);
        continue;
      }

      /* the option keywords starts here */
      option = line;
      while(*line && !ISSPACE(*line) && !ISSEP(*line))
        line++;
      /* ... and has ended here */

      if(*line)
        *line++=0; /* zero terminate, we have a local copy of the data */

#ifdef DEBUG_CONFIG
      fprintf(stderr, "GOT: %s\n", option);
#endif

      /* pass spaces and separator(s) */
      while(*line && (ISSPACE(*line) || ISSEP(*line)))
        line++;

      /* the parameter starts here (unless quoted) */
      if(*line == '\"') {
        /* quoted parameter, do the quote dance */
        line++;
        param=malloc(strlen(line)+1); /* parameter */
        if(!param) {
          /* out of memory */
          Curl_safefree(aline);
          rc = 1;
          break;
        }
        alloced_param=TRUE;
        (void)unslashquote(line, param);
      }
      else {
        param=line; /* parameter starts here */
        while(*line && !ISSPACE(*line))
          line++;
        *line=0; /* zero terminate */
      }

      if(param && !*param) {
        /* do this so getparameter can check for required parameters.
           Otherwise it always thinks there's a parameter. */
        if(alloced_param)
          Curl_safefree(param);
        param = NULL;
      }

#ifdef DEBUG_CONFIG
      fprintf(stderr, "PARAM: \"%s\"\n",(param ? param : "(null)"));
#endif
      res = getparameter(option, param, &usedarg, config);

      if(param && *param && !usedarg)
        /* we passed in a parameter that wasn't used! */
        res = PARAM_GOT_EXTRA_PARAMETER;

      if(res != PARAM_OK) {
        /* the help request isn't really an error */
        if(!strcmp(filename, "-")) {
          filename=(char *)"<stdin>";
        }
        if(PARAM_HELP_REQUESTED != res) {
          const char *reason = param2text(res);
          warnf(config, "%s:%d: warning: '%s' %s\n",
                filename, lineno, option, reason);
        }
      }

      if(alloced_param)
        Curl_safefree(param);

      Curl_safefree(aline);
    }
    if(file != stdin)
      fclose(file);
  }
  else
    rc = 1; /* couldn't open the file */
  return rc;
}

static void go_sleep(long ms)
{
#ifdef HAVE_POLL_FINE
  /* portable subsecond "sleep" */
  poll((void *)0, 0, (int)ms);
#else
  /* systems without poll() need other solutions */

#ifdef WIN32
  /* Windows offers a millisecond sleep */
  Sleep(ms);
#elif defined(MSDOS)
  delay(ms);
#else
  /* Other systems must use select() for this */
  struct timeval timeout;

  timeout.tv_sec = ms/1000;
  ms = ms%1000;
  timeout.tv_usec = ms * 1000;

  select(0, NULL,  NULL, NULL, &timeout);
#endif

#endif
}

#define RETRY_SLEEP_DEFAULT 1000L   /* ms */
#define RETRY_SLEEP_MAX     600000L /* ms == 10 minutes */

static bool
output_expected(const char* url, const char* uploadfile)
{
  if(!uploadfile)
    return TRUE;  /* download */
  if(checkprefix("http://", url) || checkprefix("https://", url))
    return TRUE;   /* HTTP(S) upload */

  return FALSE; /* non-HTTP upload, probably no output should be expected */
}

static bool stdin_upload(const char *uploadfile)
{
  return (curlx_strequal(uploadfile, "-") ||
          curlx_strequal(uploadfile, ".")) ? TRUE : FALSE;
}

/* Adds the file name to the URL if it doesn't already have one.
 * url will be freed before return if the returned pointer is different
 */
static char *add_file_name_to_url(CURL *curl, char *url, const char *filename)
{
  /* If no file name part is given in the URL, we add this file name */
  char *ptr=strstr(url, "://");
  if(ptr)
    ptr+=3;
  else
    ptr=url;
  ptr = strrchr(ptr, '/');
  if(!ptr || !strlen(++ptr)) {
    /* The URL has no file name part, add the local file name. In order
       to be able to do so, we have to create a new URL in another
       buffer.*/

    /* We only want the part of the local path that is on the right
       side of the rightmost slash and backslash. */
    const char *filep = strrchr(filename, '/');
    char *file2 = strrchr(filep?filep:filename, '\\');
    char *encfile;

    if(file2)
      filep = file2+1;
    else if(filep)
      filep++;
    else
      filep = filename;

    /* URL encode the file name */
    encfile = curl_easy_escape(curl, filep, 0 /* use strlen */);
    if(encfile) {
      char *urlbuffer = malloc(strlen(url) + strlen(encfile) + 3);
      if(!urlbuffer) {
        Curl_safefree(url);
        return NULL;
      }
      if(ptr)
        /* there is a trailing slash on the URL */
        sprintf(urlbuffer, "%s%s", url, encfile);
      else
        /* there is no trailing slash on the URL */
        sprintf(urlbuffer, "%s/%s", url, encfile);

      curl_free(encfile);

      Curl_safefree(url);
      url = urlbuffer; /* use our new URL instead! */
    }
  }
  return url;
}

/* Extracts the name portion of the URL.
 * Returns a heap-allocated string, or NULL if no name part
 */
static char *get_url_file_name(const char *url)
{
  char *fn = NULL;

  /* Find and get the remote file name */
  const char * pc =strstr(url, "://");
  if(pc)
    pc+=3;
  else
    pc=url;
  pc = strrchr(pc, '/');

  if(pc) {
    /* duplicate the string beyond the slash */
    pc++;
    fn = *pc ? strdup(pc): NULL;
  }
  return fn;
}

#ifdef CURLDEBUG
static void memory_tracking_init(void)
{
  char *env;
  /* if CURL_MEMDEBUG is set, this starts memory tracking message logging */
  env = curlx_getenv("CURL_MEMDEBUG");
  if(env) {
    /* use the value as file name */
    char fname[CURL_MT_LOGFNAME_BUFSIZE];
    if(strlen(env) >= CURL_MT_LOGFNAME_BUFSIZE)
      env[CURL_MT_LOGFNAME_BUFSIZE-1] = '\0';
    strcpy(fname, env);
    curl_free(env);
    curl_memdebug(fname);
    /* this weird stuff here is to make curl_free() get called
       before curl_memdebug() as otherwise memory tracking will
       log a free() without an alloc! */
  }
  /* if CURL_MEMLIMIT is set, this enables fail-on-alloc-number-N feature */
  env = curlx_getenv("CURL_MEMLIMIT");
  if(env) {
    char *endptr;
    long num = strtol(env, &endptr, 10);
    if((endptr != env) && (endptr == env + strlen(env)) && (num > 0))
      curl_memlimit(num);
    curl_free(env);
  }
}
#else
#  define memory_tracking_init() Curl_nop_stmt
#endif

static int
operate(struct Configurable *config, int argc, argv_item_t argv[])
{
  char errorbuffer[CURL_ERROR_SIZE];
  struct ProgressData progressbar;
  struct getout *urlnode;

  struct OutStruct outs;
  struct OutStruct heads;

  CURL *curl = NULL;
  char *httpgetfields = NULL;

  bool stillflags;
  int res = 0;
  int i;

  errorbuffer[0] = '\0';
  memset(&outs, 0, sizeof(struct OutStruct));
  memset(&heads, 0, sizeof(struct OutStruct));

  memory_tracking_init();

  /*
  ** Initialize curl library - do not call any libcurl functions before
  ** this point. Note that the memory_tracking_init() magic above is an
  ** exception, but then that's not part of the official public API.
  */
  if(main_init() != CURLE_OK) {
    helpf(config->errors, "error initializing curl library\n");
    return CURLE_FAILED_INIT;
  }

  /* Get libcurl info right away */
  if(get_libcurl_info() != CURLE_OK) {
    helpf(config->errors, "error retrieving curl library information\n");
    main_free();
    return CURLE_FAILED_INIT;
  }

  /* Get a curl handle to use for all forthcoming curl transfers */
  curl = curl_easy_init();
  if(!curl) {
    helpf(config->errors, "error initializing curl easy handle\n");
    main_free();
    return CURLE_FAILED_INIT;
  }
  config->easy = curl;

  /* Store a pointer to our 'outs' struct used for output writing */
  config->outs = &outs;

  /*
  ** Beyond this point no return'ing from this function allowed.
  ** Jump to label 'quit_curl' in order to abandon this function
  ** from outside of nested loops further down below.
  */

  /* setup proper locale from environment */
#ifdef HAVE_SETLOCALE
  setlocale(LC_ALL, "");
#endif

  /* inits */
  config->postfieldsize = -1;
  config->showerror = TRUE;
  config->use_httpget = FALSE;
  config->create_dirs = FALSE;
  config->maxredirs = DEFAULT_MAXREDIRS;
  config->proto = CURLPROTO_ALL; /* FIXME: better to read from library */
  config->proto_present = FALSE;
  config->proto_redir =
    CURLPROTO_ALL & ~(CURLPROTO_FILE|CURLPROTO_SCP); /* not FILE or SCP */
  config->proto_redir_present = FALSE;

  if((argc > 1) &&
     (!curlx_strnequal("--", argv[1], 2) && (argv[1][0] == '-')) &&
     strchr(argv[1], 'q')) {
    /*
     * The first flag, that is not a verbose name, but a shortname
     * and it includes the 'q' flag!
     */
    ;
  }
  else {
    parseconfig(NULL, config); /* ignore possible failure */
  }

  if((argc < 2)  && !config->url_list) {
    helpf(config->errors, NULL);
    res = CURLE_FAILED_INIT;
    goto quit_curl;
  }

  /* Parse options */
  for(i = 1, stillflags = TRUE; i < argc; i++) {
    if(stillflags &&
       ('-' == argv[i][0])) {
      char *nextarg;
      bool passarg;
      char *origopt = argv[i];

      char *flag = argv[i];

      if(curlx_strequal("--", argv[i]))
        /* this indicates the end of the flags and thus enables the
           following (URL) argument to start with -. */
        stillflags = FALSE;
      else {
        nextarg = (i < (argc-1)) ? argv[i+1] : NULL;

        res = getparameter(flag, nextarg, &passarg, config);
        if(res) {
          int retval = CURLE_OK;
          if(res != PARAM_HELP_REQUESTED) {
            const char *reason = param2text(res);
            helpf(config->errors, "option %s: %s\n", origopt, reason);
            retval = CURLE_FAILED_INIT;
          }
          res = retval;
          goto quit_curl;
        }

        if(passarg) /* we're supposed to skip this */
          i++;
      }
    }
    else {
      bool used;
      /* just add the URL please */
      res = getparameter((char *)"--url", argv[i], &used, config);
      if(res)
        goto quit_curl;
    }
  }

  if((!config->url_list || !config->url_list->url) && !config->list_engines) {
    helpf(config->errors, "no URL specified!\n");
    res = CURLE_FAILED_INIT;
    goto quit_curl;
  }

  if(!config->useragent)
    config->useragent = my_useragent();
  if(!config->useragent) {
    helpf(config->errors, "out of memory\n");
    res = CURLE_OUT_OF_MEMORY;
    goto quit_curl;
  }

  /* On WIN32 we can't set the path to curl-ca-bundle.crt
   * at compile time. So we look here for the file in two ways:
   * 1: look at the environment variable CURL_CA_BUNDLE for a path
   * 2: if #1 isn't found, use the windows API function SearchPath()
   *    to find it along the app's path (includes app's dir and CWD)
   *
   * We support the environment variable thing for non-Windows platforms
   * too. Just for the sake of it.
   */
  if(!config->cacert &&
     !config->capath &&
     !config->insecure_ok) {
    char *env;
    env = curlx_getenv("CURL_CA_BUNDLE");
    if(env) {
      config->cacert = strdup(env);
      if(!config->cacert) {
        curl_free(env);
        helpf(config->errors, "out of memory\n");
        res = CURLE_OUT_OF_MEMORY;
        goto quit_curl;
      }
    }
    else {
      env = curlx_getenv("SSL_CERT_DIR");
      if(env) {
        config->capath = strdup(env);
        if(!config->capath) {
          curl_free(env);
          helpf(config->errors, "out of memory\n");
          res = CURLE_OUT_OF_MEMORY;
          goto quit_curl;
        }
      }
      else {
        env = curlx_getenv("SSL_CERT_FILE");
        if(env) {
          config->cacert = strdup(env);
          if(!config->cacert) {
            curl_free(env);
            helpf(config->errors, "out of memory\n");
            res = CURLE_OUT_OF_MEMORY;
            goto quit_curl;
          }
        }
      }
    }

    if(env)
      curl_free(env);
#ifdef WIN32
    else {
      res = FindWin32CACert(config, "curl-ca-bundle.crt");
      if(res)
        goto quit_curl;
    }
#endif
  }

  if(config->postfields) {
    if(config->use_httpget) {
      /* Use the postfields data for a http get */
      httpgetfields = strdup(config->postfields);
      Curl_safefree(config->postfields);
      if(SetHTTPrequest(config,
                        (config->no_body?HTTPREQ_HEAD:HTTPREQ_GET),
                        &config->httpreq)) {
        res = PARAM_BAD_USE;
        goto quit_curl;
      }
    }
    else {
      if(SetHTTPrequest(config, HTTPREQ_SIMPLEPOST, &config->httpreq)) {
        res = PARAM_BAD_USE;
        goto quit_curl;
      }
    }
  }

  /* This is the first entry added to easysrc and it initializes the slist */
  easysrc = curl_slist_append(easysrc, "CURL *hnd = curl_easy_init();");
  if(!easysrc) {
    helpf(config->errors, "out of memory\n");
    res = CURLE_OUT_OF_MEMORY;
    goto quit_curl;
  }

  if(config->list_engines) {
    struct curl_slist *engines = NULL;
    curl_easy_getinfo(curl, CURLINFO_SSL_ENGINES, &engines);
    list_engines(engines);
    curl_slist_free_all(engines);
    res = CURLE_OK;
    goto quit_curl;
  }

  /* Single header file for all URLs */
  if(config->headerfile) {
    /* open file for output: */
    if(strcmp(config->headerfile, "-")) {
      FILE *newfile = fopen(config->headerfile, "wb");
      if(!newfile) {
        warnf(config, "Failed to open %s\n", config->headerfile);
        res = CURLE_WRITE_ERROR;
        goto quit_curl;
      }
      else {
        heads.filename = config->headerfile;
        heads.alloc_filename = FALSE;
        heads.stream = newfile;
        heads.config = config;
      }
    }
    else {
      heads.filename = config->headerfile; /* "-" */
      heads.alloc_filename = FALSE;
      heads.stream = stdout;
      heads.config = config;
    }
  }

  /*
  ** Nested loops start here.
  */

  /* loop through the list of given URLs */

  for(urlnode = config->url_list; urlnode; urlnode = urlnode->next) {

    int up; /* upload file counter within a single upload glob */
    char *infiles; /* might be a glob pattern */
    char *outfiles;
    int infilenum;
    URLGlob *inglob;

    outfiles = NULL;
    infilenum = 0;
    inglob = NULL;

    /* urlnode->url is the full URL (it might be NULL) */

    if(!urlnode->url) {
      /* This node has no URL. Free node data without destroying the
         node itself nor modifying next pointer and continue to next */
      Curl_safefree(urlnode->outfile);
      Curl_safefree(urlnode->infile);
      urlnode->flags = 0;
      continue; /* next URL please */
    }

    /* default output stream is stdout */
    outs.stream = stdout;
    outs.config = config;
    outs.bytes = 0; /* nothing written yet */
    outs.filename = NULL;

    /* save outfile pattern before expansion */
    if(urlnode->outfile) {
      outfiles = strdup(urlnode->outfile);
      if(!outfiles) {
        helpf(config->errors, "out of memory\n");
        res = CURLE_OUT_OF_MEMORY;
        break;
      }
    }

    infiles = urlnode->infile;

    if(!config->globoff && infiles) {
      /* Unless explicitly shut off */
      res = glob_url(&inglob, infiles, &infilenum,
                     config->showerror?config->errors:NULL);
      if(res) {
        Curl_safefree(outfiles);
        break;
      }
    }

    /* Here's the loop for uploading multiple files within the same
       single globbed string. If no upload, we enter the loop once anyway. */
    for(up = 0 ;; up++) {

      char *uploadfile; /* a single file, never a glob */
      int separator;
      URLGlob *urls;
      int urlnum;

      uploadfile = NULL;
      separator = 0;
      urls = NULL;
      urlnum = 0;

      if(!up && !infiles)
        Curl_nop_stmt;
      else {
        if(inglob)
          uploadfile = glob_next_url(inglob);
        else if(!up)
          uploadfile = strdup(infiles);
        else
          uploadfile = NULL;
        if(!uploadfile)
          break;
      }

      if(!config->globoff) {
        /* Unless explicitly shut off, we expand '{...}' and '[...]'
           expressions and return total number of URLs in pattern set */
        res = glob_url(&urls, urlnode->url, &urlnum,
                       config->showerror?config->errors:NULL);
        if(res) {
          Curl_safefree(uploadfile);
          break;
        }
      }
      else
        urlnum = 1; /* without globbing, this is a single URL */

      /* if multiple files extracted to stdout, insert separators! */
      separator= ((!outfiles || curlx_strequal(outfiles, "-")) && urlnum > 1);

      /* Here's looping around each globbed URL */
      for(i = 0 ;; i++) {

        int infd;
        bool infdopen;
        char *outfile;
        struct InStruct input;
        struct timeval retrystart;
        curl_off_t uploadfilesize;
        long retry_numretries;
        long retry_sleep_default;
        long retry_sleep;
        char *this_url;

        outfile = NULL;
        infdopen = FALSE;
        infd = STDIN_FILENO;
        uploadfilesize = -1; /* -1 means unknown */

        if(urls)
          this_url = glob_next_url(urls);
        else if(!i) {
          this_url = strdup(urlnode->url);
        }
        else
          this_url = NULL;
        if(!this_url)
          break;

        if(outfiles) {
          outfile = strdup(outfiles);
          if(!outfile) {
            res = CURLE_OUT_OF_MEMORY;
            goto show_error;
          }
        }

        if((urlnode->flags&GETOUT_USEREMOTE) ||
           (outfile && !curlx_strequal("-", outfile)) ) {

          /*
           * We have specified a file name to store the result in, or we have
           * decided we want to use the remote file name.
           */

          if(!outfile) {
            /* extract the file name from the URL */
            outfile = get_url_file_name(this_url);
            if((!outfile || !*outfile) && !config->content_disposition) {
              helpf(config->errors, "Remote file name has no length!\n");
              res = CURLE_WRITE_ERROR;
              goto quit_urls;
            }
#if defined(MSDOS) || defined(WIN32)
            /* For DOS and WIN32, we do some major replacing of
               bad characters in the file name before using it */
            outfile = sanitize_dos_name(outfile);
            if(!outfile) {
              res = CURLE_OUT_OF_MEMORY;
              goto show_error;
            }
#endif /* MSDOS || WIN32 */
          }
          else if(urls) {
            /* fill '#1' ... '#9' terms from URL pattern */
            char *storefile = outfile;
            outfile = glob_match_url(storefile, urls);
            Curl_safefree(storefile);
            if(!outfile) {
              /* bad globbing */
              warnf(config, "bad output glob!\n");
              res = CURLE_FAILED_INIT;
              goto quit_urls;
            }
          }

          /* Create the directory hierarchy, if not pre-existent to a multiple
             file output call */

          if(config->create_dirs) {
            res = create_dir_hierarchy(outfile, config->errors);
            /* create_dir_hierarchy shows error upon CURLE_WRITE_ERROR */
            if(res == CURLE_WRITE_ERROR)
              goto quit_urls;
            if(res) {
              goto show_error;
            }
          }

          if(config->resume_from_current) {
            /* We're told to continue from where we are now. Get the
               size of the file as it is now and open it for append instead */

            struct_stat fileinfo;

            /* VMS -- Danger, the filesize is only valid for stream files */
            if(0 == stat(outfile, &fileinfo))
              /* set offset to current file size: */
              config->resume_from = fileinfo.st_size;
            else
              /* let offset be 0 */
              config->resume_from = 0;
          }

          outs.filename = outfile;
          outs.alloc_filename = FALSE;

          if(config->resume_from) {
            outs.init = config->resume_from;
            /* open file for output: */
            outs.stream = fopen(outfile, config->resume_from?"ab":"wb");
            if(!outs.stream) {
              helpf(config->errors, "Can't open '%s'!\n", outfile);
              res = CURLE_WRITE_ERROR;
              goto quit_urls;
            }
          }
          else {
            outs.stream = NULL; /* open when needed */
            outs.bytes = 0;     /* reset byte counter */
          }
        }

        if(uploadfile && !stdin_upload(uploadfile)) {
          /*
           * We have specified a file to upload and it isn't "-".
           */
          struct_stat fileinfo;

          this_url = add_file_name_to_url(curl, this_url, uploadfile);
          if(!this_url) {
            res = CURLE_OUT_OF_MEMORY;
            goto show_error;
          }
          /* VMS Note:
           *
           * Reading binary from files can be a problem...  Only FIXED, VAR
           * etc WITHOUT implied CC will work Others need a \n appended to a
           * line
           *
           * - Stat gives a size but this is UNRELIABLE in VMS As a f.e. a
           * fixed file with implied CC needs to have a byte added for every
           * record processed, this can by derived from Filesize & recordsize
           * for VARiable record files the records need to be counted!  for
           * every record add 1 for linefeed and subtract 2 for the record
           * header for VARIABLE header files only the bare record data needs
           * to be considered with one appended if implied CC
           */

          infd = open(uploadfile, O_RDONLY | O_BINARY);
          if((infd == -1) || fstat(infd, &fileinfo)) {
            helpf(config->errors, "Can't open '%s'!\n", uploadfile);
            if(infd != -1) {
              close(infd);
              infd = STDIN_FILENO;
            }
            res = CURLE_READ_ERROR;
            goto quit_urls;
          }
          infdopen = TRUE;

          /* we ignore file size for char/block devices, sockets, etc. */
          if(S_ISREG(fileinfo.st_mode))
            uploadfilesize = fileinfo.st_size;

        }
        else if(uploadfile && stdin_upload(uploadfile)) {
          /* count to see if there are more than one auth bit set
             in the authtype field */
          int authbits = 0;
          int bitcheck = 0;
          while(bitcheck < 32) {
            if(config->authtype & (1 << bitcheck++)) {
              authbits++;
              if(authbits > 1) {
                /* more than one, we're done! */
                break;
              }
            }
          }

          /*
           * If the user has also selected --anyauth or --proxy-anyauth
           * we should warn him/her.
           */
          if(config->proxyanyauth || (authbits>1)) {
            warnf(config,
                  "Using --anyauth or --proxy-anyauth with upload from stdin"
                  " involves a big risk of it not working. Use a temporary"
                  " file or a fixed auth type instead!\n");
          }

          DEBUGASSERT(infdopen == FALSE);
          DEBUGASSERT(infd == STDIN_FILENO);

          SET_BINMODE(stdin);
          if(curlx_strequal(uploadfile, ".")) {
            if(curlx_nonblock((curl_socket_t)infd, TRUE) < 0)
              warnf(config,
                    "fcntl failed on fd=%d: %s\n", infd, strerror(errno));
          }
        }

        if(uploadfile && config->resume_from_current)
          config->resume_from = -1; /* -1 will then force get-it-yourself */

        if(output_expected(this_url, uploadfile)
           && outs.stream && isatty(fileno(outs.stream)))
          /* we send the output to a tty, therefore we switch off the progress
             meter */
          config->noprogress = config->isatty = TRUE;

        if(urlnum > 1 && !(config->mute)) {
          fprintf(config->errors, "\n[%d/%d]: %s --> %s\n",
                  i+1, urlnum, this_url, outfile ? outfile : "<stdout>");
          if(separator)
            printf("%s%s\n", CURLseparator, this_url);
        }
        if(httpgetfields) {
          char *urlbuffer;
          /* Find out whether the url contains a file name */
          const char *pc = strstr(this_url, "://");
          char sep = '?';
          if(pc)
            pc += 3;
          else
            pc = this_url;

          pc = strrchr(pc, '/'); /* check for a slash */

          if(pc) {
            /* there is a slash present in the URL */

            if(strchr(pc, '?'))
              /* Ouch, there's already a question mark in the URL string, we
                 then append the data with an ampersand separator instead! */
              sep='&';
          }
          /*
           * Then append ? followed by the get fields to the url.
           */
          urlbuffer = malloc(strlen(this_url) + strlen(httpgetfields) + 3);
          if(!urlbuffer) {
            res = CURLE_OUT_OF_MEMORY;
            goto show_error;
          }
          if(pc)
            sprintf(urlbuffer, "%s%c%s", this_url, sep, httpgetfields);
          else
            /* Append  / before the ? to create a well-formed url
               if the url contains a hostname only
            */
            sprintf(urlbuffer, "%s/?%s", this_url, httpgetfields);

          Curl_safefree(this_url); /* free previous URL */
          this_url = urlbuffer; /* use our new URL instead! */
        }

        if(!config->errors)
          config->errors = stderr;

        if((!outfile || !strcmp(outfile, "-")) && !config->use_ascii) {
          /* We get the output to stdout and we have not got the ASCII/text
             flag, then set stdout to be binary */
          SET_BINMODE(stdout);
        }

        if(config->tcp_nodelay)
          my_setopt(curl, CURLOPT_TCP_NODELAY, 1);

        /* where to store */
        my_setopt(curl, CURLOPT_WRITEDATA, &outs);
        /* what call to write */
        my_setopt(curl, CURLOPT_WRITEFUNCTION, tool_write_cb);

        /* for uploads */
        input.fd = infd;
        input.config = config;
        my_setopt(curl, CURLOPT_READDATA, &input);
        /* what call to read */
        if((outfile && !curlx_strequal("-", outfile)) ||
           !checkprefix("telnet:", this_url))
          my_setopt(curl, CURLOPT_READFUNCTION, tool_read_cb);

        /* in 7.18.0, the CURLOPT_SEEKFUNCTION/DATA pair is taking over what
           CURLOPT_IOCTLFUNCTION/DATA pair previously provided for seeking */
        my_setopt(curl, CURLOPT_SEEKDATA, &input);
        my_setopt(curl, CURLOPT_SEEKFUNCTION, tool_seek_cb);

        if(config->recvpersecond)
          /* tell libcurl to use a smaller sized buffer as it allows us to
             make better sleeps! 7.9.9 stuff! */
          my_setopt(curl, CURLOPT_BUFFERSIZE, config->recvpersecond);

        /* size of uploaded file: */
        if(uploadfilesize != -1)
          my_setopt(curl, CURLOPT_INFILESIZE_LARGE, uploadfilesize);
        my_setopt_str(curl, CURLOPT_URL, this_url);     /* what to fetch */
        my_setopt(curl, CURLOPT_NOPROGRESS, config->noprogress);
        if(config->no_body) {
          my_setopt(curl, CURLOPT_NOBODY, 1);
          my_setopt(curl, CURLOPT_HEADER, 1);
        }
        else
          my_setopt(curl, CURLOPT_HEADER, config->include_headers);

#if !defined(CURL_DISABLE_PROXY)
        {
          /* TODO: Make this a run-time check instead of compile-time one. */

          my_setopt_str(curl, CURLOPT_PROXY, config->proxy);
          my_setopt_str(curl, CURLOPT_PROXYUSERPWD, config->proxyuserpwd);

          /* new in libcurl 7.3 */
          my_setopt(curl, CURLOPT_HTTPPROXYTUNNEL, config->proxytunnel);

          /* new in libcurl 7.5 */
          if(config->proxy)
            my_setopt(curl, CURLOPT_PROXYTYPE, config->proxyver);

          /* new in libcurl 7.10 */
          if(config->socksproxy) {
            my_setopt_str(curl, CURLOPT_PROXY, config->socksproxy);
            my_setopt(curl, CURLOPT_PROXYTYPE, config->socksver);
          }

          /* new in libcurl 7.10.6 */
          if(config->proxyanyauth)
            my_setopt(curl, CURLOPT_PROXYAUTH, CURLAUTH_ANY);
          else if(config->proxynegotiate)
            my_setopt(curl, CURLOPT_PROXYAUTH, CURLAUTH_GSSNEGOTIATE);
          else if(config->proxyntlm)
            my_setopt(curl, CURLOPT_PROXYAUTH, CURLAUTH_NTLM);
          else if(config->proxydigest)
            my_setopt(curl, CURLOPT_PROXYAUTH, CURLAUTH_DIGEST);
          else if(config->proxybasic)
            my_setopt(curl, CURLOPT_PROXYAUTH, CURLAUTH_BASIC);

          /* new in libcurl 7.19.4 */
          my_setopt(curl, CURLOPT_NOPROXY, config->noproxy);
        }
#endif

        my_setopt(curl, CURLOPT_FAILONERROR, config->failonerror);
        my_setopt(curl, CURLOPT_UPLOAD, uploadfile?TRUE:FALSE);
        my_setopt(curl, CURLOPT_DIRLISTONLY, config->dirlistonly);
        my_setopt(curl, CURLOPT_APPEND, config->ftp_append);

        if(config->netrc_opt)
          my_setopt(curl, CURLOPT_NETRC, CURL_NETRC_OPTIONAL);
        else if(config->netrc || config->netrc_file)
          my_setopt(curl, CURLOPT_NETRC, CURL_NETRC_REQUIRED);
        else
          my_setopt(curl, CURLOPT_NETRC, CURL_NETRC_IGNORED);

        if(config->netrc_file)
          my_setopt(curl, CURLOPT_NETRC_FILE, config->netrc_file);

        my_setopt(curl, CURLOPT_TRANSFERTEXT, config->use_ascii);
        my_setopt_str(curl, CURLOPT_USERPWD, config->userpwd);
        my_setopt_str(curl, CURLOPT_RANGE, config->range);
        my_setopt(curl, CURLOPT_ERRORBUFFER, errorbuffer);
        my_setopt(curl, CURLOPT_TIMEOUT, config->timeout);

        if(built_in_protos & CURLPROTO_HTTP) {

          my_setopt(curl, CURLOPT_FOLLOWLOCATION,
                    config->followlocation);
          my_setopt(curl, CURLOPT_UNRESTRICTED_AUTH,
                    config->unrestricted_auth);

          switch(config->httpreq) {
          case HTTPREQ_SIMPLEPOST:
            my_setopt_str(curl, CURLOPT_POSTFIELDS,
                          config->postfields);
            my_setopt(curl, CURLOPT_POSTFIELDSIZE_LARGE,
                      config->postfieldsize);
            break;
          case HTTPREQ_POST:
            my_setopt(curl, CURLOPT_HTTPPOST, config->httppost);
            break;
          default:
            break;
          }

          my_setopt_str(curl, CURLOPT_REFERER, config->referer);
          my_setopt(curl, CURLOPT_AUTOREFERER, config->autoreferer);
          my_setopt_str(curl, CURLOPT_USERAGENT, config->useragent);
          my_setopt(curl, CURLOPT_HTTPHEADER, config->headers);

          /* new in libcurl 7.5 */
          my_setopt(curl, CURLOPT_MAXREDIRS, config->maxredirs);

          /* new in libcurl 7.9.1 */
          if(config->httpversion)
            my_setopt(curl, CURLOPT_HTTP_VERSION, config->httpversion);

          /* new in libcurl 7.10.6 (default is Basic) */
          if(config->authtype)
            my_setopt(curl, CURLOPT_HTTPAUTH, config->authtype);

          /* curl 7.19.1 (the 301 version existed in 7.18.2) */
          my_setopt(curl, CURLOPT_POSTREDIR, config->post301 |
                    (config->post302 ? CURL_REDIR_POST_302 : FALSE));

          /* new in libcurl 7.21.6 */
          if(config->encoding)
            my_setopt_str(curl, CURLOPT_ACCEPT_ENCODING, "");

          /* new in libcurl 7.21.6 */
          if(config->tr_encoding)
            my_setopt(curl, CURLOPT_TRANSFER_ENCODING, 1);

        } /* (built_in_protos & CURLPROTO_HTTP) */

        my_setopt_str(curl, CURLOPT_FTPPORT, config->ftpport);
        my_setopt(curl, CURLOPT_LOW_SPEED_LIMIT,
                  config->low_speed_limit);
        my_setopt(curl, CURLOPT_LOW_SPEED_TIME, config->low_speed_time);
        my_setopt(curl, CURLOPT_MAX_SEND_SPEED_LARGE,
                  config->sendpersecond);
        my_setopt(curl, CURLOPT_MAX_RECV_SPEED_LARGE,
                  config->recvpersecond);
        my_setopt(curl, CURLOPT_RESUME_FROM_LARGE,
                  config->use_resume?config->resume_from:0);

        my_setopt(curl, CURLOPT_SSLCERT, config->cert);
        my_setopt_str(curl, CURLOPT_SSLCERTTYPE, config->cert_type);
        my_setopt(curl, CURLOPT_SSLKEY, config->key);
        my_setopt_str(curl, CURLOPT_SSLKEYTYPE, config->key_type);
        my_setopt_str(curl, CURLOPT_KEYPASSWD, config->key_passwd);

        if(built_in_protos & (CURLPROTO_SCP|CURLPROTO_SFTP)) {

          /* SSH and SSL private key uses same command-line option */
          /* new in libcurl 7.16.1 */
          my_setopt_str(curl, CURLOPT_SSH_PRIVATE_KEYFILE, config->key);
          /* new in libcurl 7.16.1 */
          my_setopt_str(curl, CURLOPT_SSH_PUBLIC_KEYFILE, config->pubkey);

          /* new in libcurl 7.17.1: SSH host key md5 checking allows us
             to fail if we are not talking to who we think we should */
          my_setopt_str(curl, CURLOPT_SSH_HOST_PUBLIC_KEY_MD5,
                        config->hostpubmd5);
        }

        if(config->cacert)
          my_setopt_str(curl, CURLOPT_CAINFO, config->cacert);
        if(config->capath)
          my_setopt_str(curl, CURLOPT_CAPATH, config->capath);
        if(config->crlfile)
          my_setopt_str(curl, CURLOPT_CRLFILE, config->crlfile);

        if(curlinfo->features & CURL_VERSION_SSL) {
          if(config->insecure_ok) {
            my_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
            my_setopt(curl, CURLOPT_SSL_VERIFYHOST, 1L);
          }
          else {
            my_setopt(curl, CURLOPT_SSL_VERIFYPEER, 1L);
            /* libcurl default is strict verifyhost -> 2L   */
            /* my_setopt(curl, CURLOPT_SSL_VERIFYHOST, 2L); */
          }
        }

        if(built_in_protos & (CURLPROTO_SCP|CURLPROTO_SFTP)) {
          if(!config->insecure_ok) {
            char *home;
            char *file;
            res = CURLE_OUT_OF_MEMORY;
            home = homedir();
            if(home) {
              file = aprintf("%s/%sssh/known_hosts", home, DOT_CHAR);
              if(file) {
                /* new in curl 7.19.6 */
                res = res_setopt_str(curl, CURLOPT_SSH_KNOWNHOSTS, file);
                curl_free(file);
                if(res == CURLE_UNKNOWN_OPTION)
                  /* libssh2 version older than 1.1.1 */
                  res = CURLE_OK;
              }
              free(home);
            }
            if(res)
              goto show_error;
          }
        }

        if(config->no_body || config->remote_time) {
          /* no body or use remote time */
          my_setopt(curl, CURLOPT_FILETIME, TRUE);
        }

        my_setopt(curl, CURLOPT_CRLF, config->crlf);
        my_setopt(curl, CURLOPT_QUOTE, config->quote);
        my_setopt(curl, CURLOPT_POSTQUOTE, config->postquote);
        my_setopt(curl, CURLOPT_PREQUOTE, config->prequote);

#if !defined(CURL_DISABLE_HTTP) && !defined(CURL_DISABLE_COOKIES)
        {
          /* TODO: Make this a run-time check instead of compile-time one. */

          if(config->cookie)
            my_setopt_str(curl, CURLOPT_COOKIE, config->cookie);

          if(config->cookiefile)
            my_setopt_str(curl, CURLOPT_COOKIEFILE, config->cookiefile);

          /* new in libcurl 7.9 */
          if(config->cookiejar)
            my_setopt_str(curl, CURLOPT_COOKIEJAR, config->cookiejar);

          /* new in libcurl 7.9.7 */
          my_setopt(curl, CURLOPT_COOKIESESSION, config->cookiesession);
        }
#endif

        my_setopt(curl, CURLOPT_SSLVERSION, config->ssl_version);
        my_setopt(curl, CURLOPT_TIMECONDITION, config->timecond);
        my_setopt(curl, CURLOPT_TIMEVALUE, config->condtime);
        my_setopt_str(curl, CURLOPT_CUSTOMREQUEST, config->customrequest);
        my_setopt(curl, CURLOPT_STDERR, config->errors);

        /* three new ones in libcurl 7.3: */
        my_setopt_str(curl, CURLOPT_INTERFACE, config->iface);
        my_setopt_str(curl, CURLOPT_KRBLEVEL, config->krblevel);

        progressbarinit(&progressbar, config);
        if((config->progressmode == CURL_PROGRESS_BAR) &&
           !config->noprogress && !config->mute) {
          /* we want the alternative style, then we have to implement it
             ourselves! */
          my_setopt(curl, CURLOPT_PROGRESSFUNCTION, tool_progress_cb);
          my_setopt(curl, CURLOPT_PROGRESSDATA, &progressbar);
        }

        /* new in libcurl 7.6.2: */
        my_setopt(curl, CURLOPT_TELNETOPTIONS, config->telnet_options);

        /* new in libcurl 7.7: */
        my_setopt_str(curl, CURLOPT_RANDOM_FILE, config->random_file);
        my_setopt(curl, CURLOPT_EGDSOCKET, config->egd_file);
        my_setopt(curl, CURLOPT_CONNECTTIMEOUT, config->connecttimeout);

        if(config->cipher_list)
          my_setopt_str(curl, CURLOPT_SSL_CIPHER_LIST, config->cipher_list);

        /* new in libcurl 7.9.2: */
        if(config->disable_epsv)
          /* disable it */
          my_setopt(curl, CURLOPT_FTP_USE_EPSV, FALSE);

        /* new in libcurl 7.10.5 */
        if(config->disable_eprt)
          /* disable it */
          my_setopt(curl, CURLOPT_FTP_USE_EPRT, FALSE);

        if(config->tracetype != TRACE_NONE) {
          my_setopt(curl, CURLOPT_DEBUGFUNCTION, tool_debug_cb);
          my_setopt(curl, CURLOPT_DEBUGDATA, config);
          my_setopt(curl, CURLOPT_VERBOSE, TRUE);
        }

        /* new in curl 7.9.3 */
        if(config->engine) {
          res = res_setopt_str(curl, CURLOPT_SSLENGINE, config->engine);
          if(res)
            goto show_error;
          my_setopt(curl, CURLOPT_SSLENGINE_DEFAULT, 1);
        }

        /* new in curl 7.10.7, extended in 7.19.4 but this only sets 0 or 1 */
        my_setopt(curl, CURLOPT_FTP_CREATE_MISSING_DIRS,
                  config->ftp_create_dirs);

        /* new in curl 7.10.8 */
        if(config->max_filesize)
          my_setopt(curl, CURLOPT_MAXFILESIZE_LARGE,
                    config->max_filesize);

        if(4 == config->ip_version)
          my_setopt(curl, CURLOPT_IPRESOLVE, CURL_IPRESOLVE_V4);
        else if(6 == config->ip_version)
          my_setopt(curl, CURLOPT_IPRESOLVE, CURL_IPRESOLVE_V6);
        else
          my_setopt(curl, CURLOPT_IPRESOLVE, CURL_IPRESOLVE_WHATEVER);

        /* new in curl 7.15.5 */
        if(config->ftp_ssl_reqd)
          my_setopt(curl, CURLOPT_USE_SSL, CURLUSESSL_ALL);

        /* new in curl 7.11.0 */
        else if(config->ftp_ssl)
          my_setopt(curl, CURLOPT_USE_SSL, CURLUSESSL_TRY);

        /* new in curl 7.16.0 */
        else if(config->ftp_ssl_control)
          my_setopt(curl, CURLOPT_USE_SSL, CURLUSESSL_CONTROL);

        /* new in curl 7.16.1 */
        if(config->ftp_ssl_ccc)
          my_setopt(curl, CURLOPT_FTP_SSL_CCC, config->ftp_ssl_ccc_mode);

#if defined(HAVE_GSSAPI) || defined(USE_WINDOWS_SSPI)
        {
          /* TODO: Make this a run-time check instead of compile-time one. */

          /* new in curl 7.19.4 */
          if(config->socks5_gssapi_service)
            my_setopt_str(curl, CURLOPT_SOCKS5_GSSAPI_SERVICE,
                          config->socks5_gssapi_service);

          /* new in curl 7.19.4 */
          if(config->socks5_gssapi_nec)
            my_setopt_str(curl, CURLOPT_SOCKS5_GSSAPI_NEC,
                          config->socks5_gssapi_nec);
        }
#endif
        /* curl 7.13.0 */
        my_setopt_str(curl, CURLOPT_FTP_ACCOUNT, config->ftp_account);

        my_setopt(curl, CURLOPT_IGNORE_CONTENT_LENGTH, config->ignorecl);

        /* curl 7.14.2 */
        my_setopt(curl, CURLOPT_FTP_SKIP_PASV_IP, config->ftp_skip_ip);

        /* curl 7.15.1 */
        my_setopt(curl, CURLOPT_FTP_FILEMETHOD, config->ftp_filemethod);

        /* curl 7.15.2 */
        if(config->localport) {
          my_setopt(curl, CURLOPT_LOCALPORT, config->localport);
          my_setopt_str(curl, CURLOPT_LOCALPORTRANGE,
                        config->localportrange);
        }

        /* curl 7.15.5 */
        my_setopt_str(curl, CURLOPT_FTP_ALTERNATIVE_TO_USER,
                      config->ftp_alternative_to_user);

        /* curl 7.16.0 */
        if(config->disable_sessionid)
          my_setopt(curl, CURLOPT_SSL_SESSIONID_CACHE,
                    !config->disable_sessionid);

        /* curl 7.16.2 */
        if(config->raw) {
          my_setopt(curl, CURLOPT_HTTP_CONTENT_DECODING, FALSE);
          my_setopt(curl, CURLOPT_HTTP_TRANSFER_DECODING, FALSE);
        }

        /* curl 7.17.1 */
        if(!config->nokeepalive) {
          my_setopt(curl, CURLOPT_SOCKOPTFUNCTION, tool_sockopt_cb);
          my_setopt(curl, CURLOPT_SOCKOPTDATA, config);
        }

        /* curl 7.20.0 */
        if(config->tftp_blksize)
          my_setopt(curl, CURLOPT_TFTP_BLKSIZE, config->tftp_blksize);

        if(config->mail_from)
          my_setopt_str(curl, CURLOPT_MAIL_FROM, config->mail_from);

        if(config->mail_rcpt)
          my_setopt(curl, CURLOPT_MAIL_RCPT, config->mail_rcpt);

        /* curl 7.20.x */
        if(config->ftp_pret)
          my_setopt(curl, CURLOPT_FTP_USE_PRET, TRUE);

        if(config->proto_present)
          my_setopt(curl, CURLOPT_PROTOCOLS, config->proto);
        if(config->proto_redir_present)
          my_setopt(curl, CURLOPT_REDIR_PROTOCOLS, config->proto_redir);

        if((urlnode->flags & GETOUT_USEREMOTE)
           && config->content_disposition) {
          my_setopt(curl, CURLOPT_HEADERFUNCTION, tool_header_cb);
          my_setopt(curl, CURLOPT_HEADERDATA, &outs);
        }
        else {
          /* if HEADERFUNCTION was set to something in the previous loop, it
             is important that we set it (back) to NULL now */
          my_setopt(curl, CURLOPT_HEADERFUNCTION, NULL);
          my_setopt(curl, CURLOPT_HEADERDATA, config->headerfile?&heads:NULL);
        }

        if(config->resolve)
          /* new in 7.21.3 */
          my_setopt(curl, CURLOPT_RESOLVE, config->resolve);

        /* new in 7.21.4 */
        if(curlinfo->features & CURL_VERSION_TLSAUTH_SRP) {
          if(config->tls_username)
            my_setopt_str(curl, CURLOPT_TLSAUTH_USERNAME,
                          config->tls_username);
          if(config->tls_password)
            my_setopt_str(curl, CURLOPT_TLSAUTH_PASSWORD,
                          config->tls_password);
          if(config->tls_authtype)
            my_setopt_str(curl, CURLOPT_TLSAUTH_TYPE,
                          config->tls_authtype);
        }

        /* new in 7.22.0 */
        if(config->gssapi_delegation)
          my_setopt_str(curl, CURLOPT_GSSAPI_DELEGATION,
                        config->gssapi_delegation);

        /* initialize retry vars for loop below */
        retry_sleep_default = (config->retry_delay) ?
          config->retry_delay*1000L : RETRY_SLEEP_DEFAULT; /* ms */

        retry_numretries = config->req_retry;
        retry_sleep = retry_sleep_default; /* ms */
        retrystart = cutil_tvnow();

        for(;;) {
          res = curl_easy_perform(curl);
          if(!curl_slist_append(easysrc, "ret = curl_easy_perform(hnd);")) {
            res = CURLE_OUT_OF_MEMORY;
            goto show_error;
          }

          if(config->content_disposition && outs.stream && !config->mute &&
             outs.filename)
            printf("curl: Saved to filename '%s'\n", outs.filename);

          /* if retry-max-time is non-zero, make sure we haven't exceeded the
             time */
          if(retry_numretries &&
             (!config->retry_maxtime ||
              (cutil_tvdiff(cutil_tvnow(), retrystart)<
               config->retry_maxtime*1000L)) ) {
            enum {
              RETRY_NO,
              RETRY_TIMEOUT,
              RETRY_HTTP,
              RETRY_FTP,
              RETRY_LAST /* not used */
            } retry = RETRY_NO;
            long response;
            if(CURLE_OPERATION_TIMEDOUT == res)
              /* retry timeout always */
              retry = RETRY_TIMEOUT;
            else if((CURLE_OK == res) ||
                    (config->failonerror &&
                     (CURLE_HTTP_RETURNED_ERROR == res))) {
              /* If it returned OK. _or_ failonerror was enabled and it
                 returned due to such an error, check for HTTP transient
                 errors to retry on. */
              char *effective_url = NULL;
              curl_easy_getinfo(curl, CURLINFO_EFFECTIVE_URL, &effective_url);
              if(effective_url &&
                 checkprefix("http", effective_url)) {
                /* This was HTTP(S) */
                curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &response);

                switch(response) {
                case 500: /* Internal Server Error */
                case 502: /* Bad Gateway */
                case 503: /* Service Unavailable */
                case 504: /* Gateway Timeout */
                  retry = RETRY_HTTP;
                  /*
                   * At this point, we have already written data to the output
                   * file (or terminal). If we write to a file, we must rewind
                   * or close/re-open the file so that the next attempt starts
                   * over from the beginning.
                   *
                   * TODO: similar action for the upload case. We might need
                   * to start over reading from a previous point if we have
                   * uploaded something when this was returned.
                   */
                  break;
                }
              }
            } /* if CURLE_OK */
            else if(res) {
              curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &response);

              if(response/100 == 4)
                /*
                 * This is typically when the FTP server only allows a certain
                 * amount of users and we are not one of them.  All 4xx codes
                 * are transient.
                 */
                retry = RETRY_FTP;
            }

            if(retry) {
              static const char * const m[]={
                NULL, "timeout", "HTTP error", "FTP error"
              };
              warnf(config, "Transient problem: %s "
                    "Will retry in %ld seconds. "
                    "%ld retries left.\n",
                    m[retry], retry_sleep/1000L, retry_numretries);

              go_sleep(retry_sleep);
              retry_numretries--;
              if(!config->retry_delay) {
                retry_sleep *= 2;
                if(retry_sleep > RETRY_SLEEP_MAX)
                  retry_sleep = RETRY_SLEEP_MAX;
              }
              if(outs.bytes && outs.filename) {
                /* We have written data to a output file, we truncate file
                 */
                if(!config->mute)
                  fprintf(config->errors, "Throwing away %"
                          CURL_FORMAT_CURL_OFF_T " bytes\n",
                          outs.bytes);
                fflush(outs.stream);
                /* truncate file at the position where we started appending */
#ifdef HAVE_FTRUNCATE
                if(ftruncate( fileno(outs.stream), outs.init)) {
                  /* when truncate fails, we can't just append as then we'll
                     create something strange, bail out */
                  if(!config->mute)
                    fprintf(config->errors,
                            "failed to truncate, exiting\n");
                  res = CURLE_WRITE_ERROR;
                  goto quit_urls;
                }
                /* now seek to the end of the file, the position where we
                   just truncated the file in a large file-safe way */
                fseek(outs.stream, 0, SEEK_END);
#else
                /* ftruncate is not available, so just reposition the file
                   to the location we would have truncated it. This won't
                   work properly with large files on 32-bit systems, but
                   most of those will have ftruncate. */
                fseek(outs.stream, (long)outs.init, SEEK_SET);
#endif
                outs.bytes = 0; /* clear for next round */
              }
              continue; /* curl_easy_perform loop */
            }
          } /* if retry_numretries */

          /* In all ordinary cases, just break out of loop here */
          break; /* curl_easy_perform loop */

        }

        if((config->progressmode == CURL_PROGRESS_BAR) &&
           progressbar.calls)
          /* if the custom progress bar has been displayed, we output a
             newline here */
          fputs("\n", progressbar.out);

        if(config->writeout)
          ourWriteOut(curl, config->writeout);
#ifdef USE_ENVIRONMENT
        if(config->writeenv)
          ourWriteEnv(curl);
#endif

        /*
        ** Code within this loop may jump directly here to label 'show_error'
        ** in order to display an error message for CURLcode stored in 'res'
        ** variable and exit loop once that necessary writing and cleanup
        ** in label 'quit_urls' has been done.
        */

        show_error:

#ifdef __VMS
        if(is_vms_shell()) {
          /* VMS DCL shell behavior */
          if(!config->showerror)
            vms_show = VMSSTS_HIDE;
        }
        else
#endif
        if(res && config->showerror) {
          fprintf(config->errors, "curl: (%d) %s\n", res, (errorbuffer[0]) ?
                  errorbuffer : curl_easy_strerror((CURLcode)res));
          if(res == CURLE_SSL_CACERT)
            fprintf(config->errors, "%s%s",
                    CURL_CA_CERT_ERRORMSG1, CURL_CA_CERT_ERRORMSG2);
        }

        /* Fall through comment to 'quit_urls' label */

        /*
        ** Upon error condition and always that a message has already been
        ** displayed, code within this loop may jump directly here to label
        ** 'quit_urls' otherwise it should jump to 'show_error' label above.
        **
        ** When 'res' variable is _not_ CURLE_OK loop will exit once that
        ** all code following 'quit_urls' has been executed. Otherwise it
        ** will loop to the beginning from where it may exit if there are
        ** no more urls left.
        */

        quit_urls:

        /* Set file extended attributes */
        if(!res && config->xattr &&
           outfile && !curlx_strequal(outfile, "-") && outs.stream) {
          int rc = fwrite_xattr(curl, fileno(outs.stream));
          if(rc)
            warnf(config, "Error setting extended attributes: %s\n",
                  strerror(errno));
        }

        /* Close the file */
        if(outfile && !curlx_strequal(outfile, "-") && outs.stream) {
          int rc = fclose(outs.stream);
          if(!res && rc) {
            /* something went wrong in the writing process */
            res = CURLE_WRITE_ERROR;
            fprintf(config->errors, "(%d) Failed writing body\n", res);
          }
          if(outs.alloc_filename)
            Curl_safefree(outs.filename);
        }

#ifdef __AMIGA__
        if(!res) {
          /* Set the url (up to 80 chars) as comment for the file */
          if(strlen(url) > 78)
            url[79] = '\0';
          SetComment( outs.filename, url);
        }
#endif

#ifdef HAVE_UTIME
        /* File time can only be set _after_ the file has been closed */
        if(!res && config->remote_time &&
           outs.filename && !curlx_strequal("-", outs.filename)) {
          /* Ask libcurl if we got a remote file time */
          long filetime = -1;
          curl_easy_getinfo(curl, CURLINFO_FILETIME, &filetime);
          if(filetime >= 0) {
            struct utimbuf times;
            times.actime = (time_t)filetime;
            times.modtime = (time_t)filetime;
            utime(outs.filename, &times); /* set the time we got */
          }
        }
#endif

        /* Free loop-local allocated memory and close loop-local opened fd */

        Curl_safefree(outfile);
        Curl_safefree(this_url);

        if(infdopen) {
          close(infd);
          infdopen = FALSE;
          infd = STDIN_FILENO;
        }

        /* upon error exit loop */
        if(res)
          break;

      } /* loop to the next URL */

      /* Free loop-local allocated memory and close loop-local opened fd */

      Curl_safefree(uploadfile);

      if(urls) {
        /* Free list of remaining URLs */
        glob_cleanup(urls);
        urls = NULL;
      }

      /* upon error exit loop */
      if(res)
        break;

    } /* loop to the next globbed upload file */

    /* Free loop-local allocated memory and close loop-local opened fd */

    Curl_safefree(outfiles);

    if(inglob) {
      /* Free list of globbed upload files */
      glob_cleanup(inglob);
      inglob = NULL;
    }

    /* Free this URL node data without destroying the
       the node itself nor modifying next pointer. */
    Curl_safefree(urlnode->url);
    Curl_safefree(urlnode->outfile);
    Curl_safefree(urlnode->infile);
    urlnode->flags = 0;

    /* TODO: Should CURLE_SSL_CACERT be included as critical error ? */

    /*
    ** Bail out upon critical errors
    */
    switch(res) {
    case CURLE_FAILED_INIT:
    case CURLE_OUT_OF_MEMORY:
    case CURLE_FUNCTION_NOT_FOUND:
    case CURLE_BAD_FUNCTION_ARGUMENT:
      goto quit_curl;
    default:
      /* Merrily loop to next URL */
      break;
    }

  } /* for-loop through all URLs */

  /*
  ** Nested loops end here.
  */

  quit_curl:

  /* Free function-local referenced allocated memory */
  Curl_safefree(httpgetfields);

  /* Free list of given URLs */
  clean_getout(config);

  /* Cleanup the curl handle now that our
     progressbar struct is still in scope */
  if(curl) {
    curl_easy_cleanup(curl);
    config->easy = curl = NULL;
  }
  if(easysrc)
    curl_slist_append(easysrc, "curl_easy_cleanup(hnd);");

  /* Close function-local opened file descriptors */

  if(config->headerfile) {
    if(strcmp(heads.filename, "-") && heads.stream)
      fclose(heads.stream);
    if(heads.alloc_filename)
      Curl_safefree(heads.filename);
  }

  if(config->trace_fopened && config->trace_stream)
    fclose(config->trace_stream);

  /* Dump the libcurl code if previously enabled.
     NOTE: that this function relies on config->errors amongst other things
     so not everything can be closed and cleaned before this is called */
  dumpeasysrc(config);

  if(config->errors_fopened && config->errors)
    fclose(config->errors);

  main_free(); /* cleanup */

  return res;
}

/* Ensure that file descriptors 0, 1 and 2 (stdin, stdout, stderr) are
   open before starting to run.  Otherwise, the first three network
   sockets opened by curl could be used for input sources, downloaded data
   or error logs as they will effectively be stdin, stdout and/or stderr.
*/
static void checkfds(void)
{
#ifdef HAVE_PIPE
  int fd[2] = { STDIN_FILENO, STDIN_FILENO };
  while(fd[0] == STDIN_FILENO ||
        fd[0] == STDOUT_FILENO ||
        fd[0] == STDERR_FILENO ||
        fd[1] == STDIN_FILENO ||
        fd[1] == STDOUT_FILENO ||
        fd[1] == STDERR_FILENO)
    if(pipe(fd) < 0)
      return;   /* Out of handles. This isn't really a big problem now, but
                   will be when we try to create a socket later. */
  close(fd[0]);
  close(fd[1]);
#endif
}



int main(int argc, char *argv[])
{
  int res;
  struct Configurable config;

  memset(&config, 0, sizeof(struct Configurable));

  config.errors = stderr; /* default errors to stderr */

  checkfds();

  res = operate(&config, argc, argv);
#ifdef __SYMBIAN32__
  if(config.showerror)
    pressanykey();
#endif
  free_config_fields(&config);

#ifdef __NOVELL_LIBC__
  if(getenv("_IN_NETWARE_BASH_") == NULL)
    pressanykey();
#endif
#ifdef __VMS
  vms_special_exit(res, vms_show);
#else
  return res;
#endif
}

/*
 * Reads a line from the given file, ensuring is NUL terminated.
 * The pointer must be freed by the caller.
 * NULL is returned on an out of memory condition.
 */
static char *my_get_line(FILE *fp)
{
  char buf[4096];
  char *nl = NULL;
  char *retval = NULL;

  do {
    if(NULL == fgets(buf, sizeof(buf), fp))
      break;
    if(NULL == retval) {
      retval = strdup(buf);
      if(!retval)
        return NULL;
    }
    else {
      char *ptr;
      ptr = realloc(retval, strlen(retval) + strlen(buf) + 1);
      if(NULL == ptr) {
        Curl_safefree(retval);
        return NULL;
      }
      retval = ptr;
      strcat(retval, buf);
    }
  }
  while(NULL == (nl = strchr(retval, '\n')));

  if(NULL != nl)
    *nl = '\0';

  return retval;
}

