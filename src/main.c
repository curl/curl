/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) 1998 - 2006, Daniel Stenberg, <daniel@haxx.se>, et al.
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
 * $Id$
 ***************************************************************************/

#include "setup.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <ctype.h>
#include <errno.h>

#include <curl/curl.h>

#include "urlglob.h"
#include "writeout.h"
#include "getpass.h"
#include "homedir.h"
#ifdef USE_MANUAL
#include "hugehelp.h"
#endif
#ifdef USE_ENVIRONMENT
#include "writeenv.h"
#endif

#define CURLseparator   "--_curl_--"

#ifdef __NOVELL_LIBC__
#include <screen.h>
#endif

#ifdef TIME_WITH_SYS_TIME
/* We can include both fine */
#include <sys/time.h>
#include <time.h>
#else
#ifdef HAVE_SYS_TIME_H
# include <sys/time.h>
#else
# include <time.h>
#endif
#endif


#include "version.h"

#ifdef HAVE_IO_H /* typical win32 habit */
#include <io.h>
#endif

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif

#ifdef HAVE_FCNTL_H
#include <fcntl.h>
#endif

#ifdef HAVE_UTIME_H
#include <utime.h>
#else
#ifdef HAVE_SYS_UTIME_H
#include <sys/utime.h>
#endif

#endif /* HAVE_UTIME_H */

#ifdef HAVE_LIMITS_H
#include <limits.h>
#endif

#ifdef HAVE_SYS_POLL_H
#include <sys/poll.h>
#endif

#ifdef HAVE_LOCALE_H
#include <locale.h> /* for setlocale() */
#endif

#define ENABLE_CURLX_PRINTF
/* make the curlx header define all printf() functions to use the curlx_*
   versions instead */
#include <curlx.h> /* header from the libcurl directory */

/* The last #include file should be: */
#ifdef CURLDEBUG
#ifndef CURLTOOLDEBUG
#define MEMDEBUG_NODEFINES
#endif
/* This is low-level hard-hacking memory leak tracking and similar. Using
   the library level code from this client-side is ugly, but we do this
   anyway for convenience. */
#include "memdebug.h"
#endif

#define DEFAULT_MAXREDIRS  50L

#ifdef __DJGPP__
#include <dos.h>

char *msdosify(char *);
char *rename_if_dos_device_name(char *);

/* we want to glob our own argv[] */
char **__crt0_glob_function (char *arg)
{
  (void)arg;
  return (char**)0;
}
#endif /* __DJGPP__ */

#define CURL_PROGRESS_STATS 0 /* default progress display */
#define CURL_PROGRESS_BAR   1

/**
 * @def MIN
 * standard MIN macro
 */
#ifndef MIN
#define MIN(X,Y)        (((X) < (Y)) ? (X) : (Y))
#endif

typedef enum {
  HTTPREQ_UNSPEC,
  HTTPREQ_GET,
  HTTPREQ_HEAD,
  HTTPREQ_POST,
  HTTPREQ_SIMPLEPOST,
  HTTPREQ_CUSTOM,
  HTTPREQ_LAST
} HttpReq;

/* Just a set of bits */
#define CONF_DEFAULT  0

#define CONF_AUTO_REFERER (1<<4) /* the automatic referer-system please! */
#define CONF_HEADER   (1<<8) /* throw the header out too */
#define CONF_NOPROGRESS (1<<10) /* shut off the progress meter */
#define CONF_NOBODY   (1<<11) /* use HEAD to get http document */
#define CONF_FAILONERROR (1<<12) /* no output on http error codes >= 300 */
#define CONF_FTPLISTONLY (1<<16) /* Use NLST when listing ftp dir */
#define CONF_FTPAPPEND (1<<20) /* Append instead of overwrite on upload! */
#define CONF_NETRC    (1<<22)  /* read user+password from .netrc */
#define CONF_FOLLOWLOCATION (1<<23) /* use Location: Luke! */
#define CONF_GETTEXT  (1<<24) /* use ASCII/text for transfer */
#define CONF_MUTE     (1<<28) /* force NOPROGRESS */

#define CONF_NETRC_OPT (1<<29)  /* read user+password from either
                                 * .netrc or URL*/
#define CONF_UNRESTRICTED_AUTH (1<<30)
/* Send authentication (user+password) when following
 * locations, even when hostname changed */

#ifndef HAVE_STRDUP
/* Ultrix doesn't have strdup(), so make a quick clone: */
char *strdup(char *str)
{
  int len;
  char *newstr;

  len = strlen(str);
  newstr = (char *) malloc((len+1)*sizeof(char));
  if (!newstr)
    return (char *)NULL;

  strcpy(newstr,str);

  return newstr;

}
#endif

#ifdef WIN32
#include <direct.h>
#define F_OK 0
#define mkdir(x,y) (mkdir)(x)
#endif

#ifdef  VMS
#include "curlmsg_vms.h"
#endif

/* Support uploading and resuming of >2GB files
 */
#if defined(WIN32) && (SIZEOF_CURL_OFF_T > 4)
#define struct_stat struct _stati64
#define stat(file,st) _stati64(file,st)
#else
#define struct_stat struct stat
#endif

#ifdef WIN32
/*
 * Truncate a file handle at a 64-bit position 'where'.
 * Borland doesn't even support 64-bit types.
 */
#ifdef __BORLANDC__
#define _lseeki64(hnd,ofs,whence) lseek(hnd,ofs,whence)
#endif

static int ftruncate64 (int fd, curl_off_t where)
{
  curl_off_t curr;
  int rc = 0;

  if ((curr = _lseeki64(fd, 0, SEEK_CUR)) < 0)
     return -1;

  if (_lseeki64(fd, where, SEEK_SET) < 0)
     return -1;

  if (write(fd, 0, 0) < 0)
     rc = -1;
  _lseeki64(fd, curr, SEEK_SET);
  return rc;
}
#define ftruncate(fd,where) ftruncate64(fd,where)
#endif

typedef enum {
    TRACE_BIN,   /* tcpdump inspired look */
    TRACE_ASCII, /* like *BIN but without the hex output */
    TRACE_PLAIN  /* -v/--verbose type */
} trace;

struct Configurable {
  bool remote_time;
  char *random_file;
  char *egd_file;
  char *useragent;
  char *cookie;     /* single line with specified cookies */
  char *cookiejar;  /* write to this file */
  char *cookiefile; /* read from this file */
  bool cookiesession; /* new session? */
  bool encoding;    /* Accept-Encoding please */
  long authtype;    /* auth bitmask */
  bool use_resume;
  bool resume_from_current;
  bool disable_epsv;
  bool disable_eprt;
  curl_off_t resume_from;
  char *postfields;
  long postfieldsize;
  char *referer;
  long timeout;
  long connecttimeout;
  long maxredirs;
  curl_off_t max_filesize;
  char *headerfile;
  char *ftpport;
  char *iface;
  int localport;
  int localportrange;
  unsigned short porttouse;
  char *range;
  long low_speed_limit;
  long low_speed_time;
  bool showerror;
  char *userpwd;
  char *proxyuserpwd;
  char *proxy;
  bool proxytunnel;
  long conf;
  struct getout *url_list; /* point to the first node */
  struct getout *url_last; /* point to the last/current node */
  struct getout *url_get;  /* point to the node to fill in URL */
  struct getout *url_out;  /* point to the node to fill in outfile */
  char *cipher_list;
  char *cert;
  char *cert_type;
  char *cacert;
  char *capath;
  char *key;
  char *key_type;
  char *key_passwd;
  char *engine;
  bool list_engines;
  bool crlf;
  char *customrequest;
  char *krb4level;
  char *trace_dump; /* file to dump the network trace to, or NULL */
  FILE *trace_stream;
  bool trace_fopened;
  trace tracetype;
  bool tracetime; /* include timestamp? */
  long httpversion;
  bool progressmode;
  bool nobuffer;
  bool globoff;
  bool use_httpget;
  bool insecure_ok; /* set TRUE to allow insecure SSL connects */
  bool create_dirs;
  bool ftp_create_dirs;
  bool ftp_skip_ip;
  bool proxyntlm;
  bool proxydigest;
  bool proxybasic;
  bool proxyanyauth;
  char *writeout; /* %-styled format string to output */
  bool writeenv; /* write results to environment, if available */
  FILE *errors; /* if stderr redirect is requested */
  bool errors_fopened;
  struct curl_slist *quote;
  struct curl_slist *postquote;
  struct curl_slist *prequote;
  long ssl_version;
  long ip_version;
  curl_TimeCond timecond;
  time_t condtime;
  struct curl_slist *headers;
  struct curl_httppost *httppost;
  struct curl_httppost *last_post;
  struct curl_slist *telnet_options;
  HttpReq httpreq;

  /* for bandwidth limiting features: */
  curl_off_t sendpersecond; /* send to peer */
  curl_off_t recvpersecond; /* receive from peer */
  struct timeval lastsendtime;
  size_t lastsendsize;
  struct timeval lastrecvtime;
  size_t lastrecvsize;
  bool ftp_ssl;

  char *socksproxy; /* set to server string */
  int socksver;     /* set to CURLPROXY_SOCKS* define */

  bool tcp_nodelay;
  long req_retry;   /* number of retries */
  long retry_delay; /* delay between retries (in seconds) */
  long retry_maxtime; /* maximum time to keep retrying */

  char *tp_url; /* third party URL */
  char *tp_user; /* third party userpwd */
  struct curl_slist *tp_quote;
  struct curl_slist *tp_postquote;
  struct curl_slist *tp_prequote;
  char *ftp_account; /* for ACCT */
  int ftp_filemethod;

  bool ignorecl; /* --ignore-content-length */
};

#define WARN_PREFIX "Warning: "
#define WARN_TEXTWIDTH (79 - (int)strlen(WARN_PREFIX))
/* produce this text message to the user unless mute was selected */
static void warnf(struct Configurable *config, const char *fmt, ...)
{
  if(!(config->conf & CONF_MUTE)) {
    va_list ap;
    int len;
    char *ptr;
    char print_buffer[256];

    va_start(ap, fmt);
    va_start(ap, fmt);
    len = vsnprintf(print_buffer, sizeof(print_buffer), fmt, ap);
    va_end(ap);

    ptr = print_buffer;
    while(len > 0) {
      fputs(WARN_PREFIX, config->errors);

      if(len > (int)WARN_TEXTWIDTH) {
        int cut = WARN_TEXTWIDTH-1;

        while(!isspace((int)ptr[cut]) && cut) {
          cut--;
        }

        fwrite(ptr, cut + 1, 1, config->errors);
        fputs("\n", config->errors);
        ptr += cut+1; /* skip the space too */
        len -= cut;
      }
      else {
        fputs(ptr, config->errors);
        len = 0;
      }
    }
  }
}

/*
 * This is the main global constructor for the app. Call this before
 * _any_ libcurl usage. If this fails, *NO* libcurl functions may be
 * used, or havoc may be the result.
 */
static CURLcode main_init(void)
{
  return curl_global_init(CURL_GLOBAL_DEFAULT);
}

/*
 * This is the main global destructor for the app. Call this after
 * _all_ libcurl usage is done.
 */
static void main_free(void)
{
  curl_global_cleanup();
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

static void helpf(const char *fmt, ...)
{
  va_list ap;
  if(fmt) {
    va_start(ap, fmt);
    fputs("curl: ", stderr); /* prefix it */
    vfprintf(stderr, fmt, ap);
    va_end(ap);
  }
  fprintf(stderr, "curl: try 'curl --help' "
#ifdef USE_MANUAL
          "or 'curl --manual' "
#endif
          "for more information\n");
}

/*
 * A chain of these nodes contain URL to get and where to put the URL's
 * contents.
 */
struct getout {
  struct getout *next; /* next one */
  char *url;     /* the URL we deal with */
  char *outfile; /* where to store the output */
  char *infile;  /* file to upload, if GETOUT_UPLOAD is set */
  int flags;     /* options */
};
#define GETOUT_OUTFILE (1<<0)   /* set when outfile is deemed done */
#define GETOUT_URL     (1<<1)   /* set when URL is deemed done */
#define GETOUT_USEREMOTE (1<<2) /* use remote file name locally */
#define GETOUT_UPLOAD  (1<<3)   /* if set, -T has been used */
#define GETOUT_NOUPLOAD  (1<<4) /* if set, -T "" has been used */

static void help(void)
{
  int i;
  static const char * const helptext[]={
    "Usage: curl [options...] <url>",
    "Options: (H) means HTTP/HTTPS only, (F) means FTP only",
    " -a/--append        Append to target file when uploading (F)",
    " -A/--user-agent <string> User-Agent to send to server (H)",
    "    --anyauth       Pick \"any\" authentication method (H)",
    " -b/--cookie <name=string/file> Cookie string or file to read cookies from (H)",
    "    --basic         Use HTTP Basic Authentication (H)",
    " -B/--use-ascii     Use ASCII/text transfer",
    " -c/--cookie-jar <file> Write cookies to this file after operation (H)",
    " -C/--continue-at <offset> Resumed transfer offset",
    " -d/--data <data>   HTTP POST data (H)",
    "    --data-ascii <data>  HTTP POST ASCII data (H)",
    "    --data-binary <data> HTTP POST binary data (H)",
    "    --negotiate     Use HTTP Negotiate Authentication (H)",
    "    --digest        Use HTTP Digest Authentication (H)",
    "    --disable-eprt  Inhibit using EPRT or LPRT (F)",
    "    --disable-epsv  Inhibit using EPSV (F)",
    " -D/--dump-header <file> Write the headers to this file",
    "    --egd-file <file> EGD socket path for random data (SSL)",
    "    --tcp-nodelay   Use the TCP_NODELAY option",
#ifdef USE_ENVIRONMENT
    "    --environment   Write results to environment variables (RISC OS)",
#endif
    " -e/--referer       Referer URL (H)",
    " -E/--cert <cert[:passwd]> Client certificate file and password (SSL)",
    "    --cert-type <type> Certificate file type (DER/PEM/ENG) (SSL)",
    "    --key <key>     Private key file name (SSL)",
    "    --key-type <type> Private key file type (DER/PEM/ENG) (SSL)",
    "    --pass  <pass>  Pass phrase for the private key (SSL)",
    "    --engine <eng>  Crypto engine to use (SSL). \"--engine list\" for list",
    "    --cacert <file> CA certificate to verify peer against (SSL)",
    "    --capath <directory> CA directory (made using c_rehash) to verify",
    "                    peer against (SSL)",
    "    --ciphers <list> SSL ciphers to use (SSL)",
    "    --compressed    Request compressed response (using deflate or gzip)",
    "    --connect-timeout <seconds> Maximum time allowed for connection",
    "    --create-dirs   Create necessary local directory hierarchy",
    "    --crlf          Convert LF to CRLF in upload",
    " -f/--fail          Fail silently (no output at all) on HTTP errors (H)",
    "    --ftp-create-dirs Create the remote dirs if not present (F)",
    "    --ftp-pasv      Use PASV/EPSV instead of PORT (F)",
    "    --ftp-skip-pasv-ip Skip the IP address for PASV (F)\n"
    "    --ftp-ssl       Enable SSL/TLS for the ftp transfer (F)",
    " -F/--form <name=content> Specify HTTP multipart POST data (H)",
    "    --form-string <name=string> Specify HTTP multipart POST data (H)",
    " -g/--globoff       Disable URL sequences and ranges using {} and []",
    " -G/--get           Send the -d data with a HTTP GET (H)",
    " -h/--help          This help text",
    " -H/--header <line> Custom header to pass to server (H)",
    "    --ignore-content-length  Ignore the HTTP Content-Length header",
    " -i/--include       Include protocol headers in the output (H/F)",
    " -I/--head          Show document info only",
    " -j/--junk-session-cookies Ignore session cookies read from file (H)",
    "    --interface <interface> Specify network interface/address to use",
    "    --krb4 <level>  Enable krb4 with specified security level (F)",
    " -k/--insecure      Allow connections to SSL sites without certs (H)",
    " -K/--config        Specify which config file to read",
    " -l/--list-only     List only names of an FTP directory (F)",
    "    --limit-rate <rate> Limit transfer speed to this rate",
    "    --local-port <num>[-num] Force use of these local port numbers\n",
    " -L/--location      Follow Location: hints (H)",
    "    --location-trusted Follow Location: and send authentication even ",
    "                    to other hostnames (H)",
    " -m/--max-time <seconds> Maximum time allowed for the transfer",
    "    --max-redirs <num> Maximum number of redirects allowed (H)",
    "    --max-filesize <bytes> Maximum file size to download (H/F)",
    " -M/--manual        Display the full manual",
    " -n/--netrc         Must read .netrc for user name and password",
    "    --netrc-optional Use either .netrc or URL; overrides -n",
    "    --ntlm          Use HTTP NTLM authentication (H)",
    " -N/--no-buffer     Disable buffering of the output stream",
    " -o/--output <file> Write output to <file> instead of stdout",
    " -O/--remote-name   Write output to a file named as the remote file",
    " -p/--proxytunnel   Operate through a HTTP proxy tunnel (using CONNECT)",
    "    --proxy-anyauth Pick \"any\" proxy authentication method (H)",
    "    --proxy-basic   Use Basic authentication on the proxy (H)",
    "    --proxy-digest  Use Digest authentication on the proxy (H)",
    "    --proxy-ntlm    Use NTLM authentication on the proxy (H)",
    " -P/--ftp-port <address> Use PORT with address instead of PASV (F)",
    " -q                 If used as the first parameter disables .curlrc",
    " -Q/--quote <cmd>   Send command(s) to server before file transfer (F)",
    " -r/--range <range> Retrieve a byte range from a HTTP/1.1 or FTP server",
    "    --random-file <file> File for reading random data from (SSL)",
    " -R/--remote-time   Set the remote file's time on the local output",
    "    --retry <num>   Retry request <num> times if transient problems occur",
    "    --retry-delay <seconds> When retrying, wait this many seconds between each",
    "    --retry-max-time <seconds> Retry only within this period",
    " -s/--silent        Silent mode. Don't output anything",
    " -S/--show-error    Show error. With -s, make curl show errors when they occur",
    "    --socks4 <host[:port]> Use SOCKS4 proxy on given host + port",
    "    --socks5 <host[:port]> Use SOCKS5 proxy on given host + port",
    "    --stderr <file> Where to redirect stderr. - means stdout",
    " -t/--telnet-option <OPT=val> Set telnet option",
    "    --trace <file>  Write a debug trace to the given file",
    "    --trace-ascii <file> Like --trace but without the hex output",
    "    --trace-time    Add time stamps to trace/verbose output",
    " -T/--upload-file <file> Transfer <file> to remote site",
    "    --url <URL>     Spet URL to work with",
    " -u/--user <user[:password]> Set server user and password",
    " -U/--proxy-user <user[:password]> Set proxy user and password",
    " -v/--verbose       Make the operation more talkative",
    " -V/--version       Show version number and quit",
#ifdef __DJGPP__
    "    --wdebug        Turn on Watt-32 debugging under DJGPP",
#endif
    " -w/--write-out [format] What to output after completion",
    " -x/--proxy <host[:port]> Use HTTP proxy on given port",
    " -X/--request <command> Specify request command to use",
    " -y/--speed-time    Time needed to trig speed-limit abort. Defaults to 30",
    " -Y/--speed-limit   Stop transfer if below speed-limit for 'speed-time' secs",
    " -z/--time-cond <time> Transfer based on a time condition",
    " -0/--http1.0       Use HTTP 1.0 (H)",
    " -1/--tlsv1         Use TLSv1 (SSL)",
    " -2/--sslv2         Use SSLv2 (SSL)",
    " -3/--sslv3         Use SSLv3 (SSL)",
    "    --3p-quote      like -Q for the source URL for 3rd party transfer (F)",
    "    --3p-url        source URL to activate 3rd party transfer (F)",
    "    --3p-user       user and password for source 3rd party transfer (F)",
    " -4/--ipv4          Resolve name to IPv4 address",
    " -6/--ipv6          Resolve name to IPv6 address",
    " -#/--progress-bar  Display transfer progress as a progress bar",
    NULL
  };
  for(i=0; helptext[i]; i++) {
    puts(helptext[i]);
#ifdef __NOVELL_LIBC__
    if (i && ((i % 23) == 0))
      pressanykey();
#endif
  }
}

struct LongShort {
  const char *letter;
  const char *lname;
  bool extraparam;
};

/* global variable to hold info about libcurl */
static curl_version_info_data *curlinfo;

static void parseconfig(const char *filename,
                        struct Configurable *config);
static char *my_get_line(FILE *fp);
static int create_dir_hierarchy(char *outfile);

static void GetStr(char **string,
                   char *value)
{
  if(*string)
    free(*string);
  if(value)
    *string = strdup(value);
  else
    *string = NULL;
}

static char *file2string(FILE *file)
{
  char buffer[256];
  char *ptr;
  char *string=NULL;
  size_t len=0;
  size_t stringlen;

  if(file) {
    while(fgets(buffer, sizeof(buffer), file)) {
      ptr= strchr(buffer, '\r');
      if(ptr)
        *ptr=0;
      ptr= strchr(buffer, '\n');
      if(ptr)
        *ptr=0;
      stringlen=strlen(buffer);
      if(string)
        string = realloc(string, len+stringlen+1);
      else
        string = malloc(stringlen+1);

      strcpy(string+len, buffer);

      len+=stringlen;
    }
    return string;
  }
  else
    return NULL; /* no string */
}

static char *file2memory(FILE *file, long *size)
{
  char buffer[1024];
  char *string=NULL;
  char *newstring=NULL;
  size_t len=0;
  long stringlen=0;

  if(file) {
    while((len = fread(buffer, 1, sizeof(buffer), file))) {
      if(string) {
        newstring = realloc(string, len+stringlen);
        if(newstring)
          string = newstring;
        else
          break; /* no more strings attached! :-) */
      }
      else
        string = malloc(len);
      memcpy(&string[stringlen], buffer, len);
      stringlen+=len;
    }
    *size = stringlen;
    return string;
  }
  else
    return NULL; /* no string */
}

static void clean_getout(struct Configurable *config)
{
  struct getout *node=config->url_list;
  struct getout *next;

  while(node) {
    next = node->next;
    if(node->url)
      free(node->url);
    if(node->outfile)
      free(node->outfile);
    if(node->infile)
      free(node->infile);
    free(node);

    node = next; /* GOTO next */
  }
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
  }
  return node;
}

/* Structure for storing the information needed to build a multiple files
 * section
*/
struct multi_files {
  struct curl_forms   form;
  struct multi_files *next;
};

/* Add a new list entry possibly with a type_name
 */
static struct multi_files *
AddMultiFiles (const char *file_name,
               const char *type_name,
               const char *show_filename,
               struct multi_files **multi_start,
               struct multi_files **multi_current)
{
  struct multi_files *multi;
  struct multi_files *multi_type = NULL;
  struct multi_files *multi_name = NULL;
  multi = (struct multi_files *)malloc(sizeof(struct multi_files));
  if (multi) {
    memset(multi, 0, sizeof(struct multi_files));
    multi->form.option = CURLFORM_FILE;
    multi->form.value = file_name;
  }
  else
    return NULL;

  if (!*multi_start)
    *multi_start = multi;

  if (type_name) {
    multi_type = (struct multi_files *)malloc(sizeof(struct multi_files));
    if (multi_type) {
      memset(multi_type, 0, sizeof(struct multi_files));
      multi_type->form.option = CURLFORM_CONTENTTYPE;
      multi_type->form.value = type_name;
      multi->next = multi_type;

      multi = multi_type;
    }
    else {
      free (multi);
      return NULL;
    }
  }
  if (show_filename) {
    multi_name = (struct multi_files *)malloc(sizeof(struct multi_files));
    if (multi_name) {
      memset(multi_name, 0, sizeof(struct multi_files));
      multi_name->form.option = CURLFORM_FILENAME;
      multi_name->form.value = show_filename;
      multi->next = multi_name;

      multi = multi_name;
    }
    else {
      free (multi);
      return NULL;
    }
  }

  if (*multi_current)
    (*multi_current)->next = multi;

  *multi_current = multi;

  return *multi_current;
}

/* Free the items of the list.
 */
static void FreeMultiInfo (struct multi_files *multi_start)
{
  struct multi_files *multi;
  while (multi_start) {
    multi = multi_start;
    multi_start = multi_start->next;
    free (multi);
  }
}

/* Print list of OpenSSL engines supported.
 */
static void list_engines (const struct curl_slist *engines)
{
  puts ("Build-time engines:");
  if (!engines) {
    puts ("  <none>");
    return;
  }
  for ( ; engines; engines = engines->next)
    printf ("  %s\n", engines->data);
}

/***************************************************************************
 *
 * formparse()
 *
 * Reads a 'name=value' paramter and builds the appropriate linked list.
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
                     char *input,
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
     (contp = strchr(input, '='))) {
    /* the input was using the correct format */

    /* Allocate the contents */
    contents = strdup(contp+1);
    if(!contents) {
      fprintf(stderr, "out of memory\n");
      return 1;
    }
    contp = contents;

    if('@' == contp[0] && !literal_value) {
      struct multi_files *multi_start = NULL, *multi_current = NULL;
      /* we use the @-letter to indicate file name(s) */
      contp++;

      multi_start = multi_current=NULL;

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
            while(isspace((int)*ptr))
              ptr++;

            if(curlx_strnequal("type=", ptr, 5)) {
              /* set type pointer */
              type = &ptr[5];

              /* verify that this is a fine type specifier */
              if(2 != sscanf(type, "%127[^/]/%127[^;,\n]",
                             major, minor)) {
                warnf(config, "Illegally formatted content-type field!\n");
                free(contents);
                FreeMultiInfo (multi_start);
                return 2; /* illegal content-type syntax! */
              }
              /* now point beyond the content-type specifier */
              sep = (char *)type + strlen(major)+strlen(minor)+1;

              if(*sep) {
                *sep=0; /* zero terminate type string */

                ptr=sep+1;
              }
              else
                ptr = NULL; /* end */
            }
            else if(curlx_strnequal("filename=", ptr, 9)) {
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

        if (!AddMultiFiles (contp, type, filename, &multi_start,
                            &multi_current)) {
          warnf(config, "Error building form post!\n");
          free(contents);
          FreeMultiInfo (multi_start);
          return 3;
        }
        contp = sep; /* move the contents pointer to after the separator */

      } while(sep && *sep); /* loop if there's another file name */

      /* now we add the multiple files section */
      if (multi_start) {
        struct curl_forms *forms = NULL;
        struct multi_files *ptr = multi_start;
        unsigned int i, count = 0;
        while (ptr) {
          ptr = ptr->next;
          ++count;
        }
        forms =
          (struct curl_forms *)malloc((count+1)*sizeof(struct curl_forms));
        if (!forms)
        {
          fprintf(stderr, "Error building form post!\n");
          free(contents);
          FreeMultiInfo (multi_start);
          return 4;
        }
        for (i = 0, ptr = multi_start; i < count; ++i, ptr = ptr->next)
        {
          forms[i].option = ptr->form.option;
          forms[i].value = ptr->form.value;
        }
        forms[count].option = CURLFORM_END;
        FreeMultiInfo (multi_start);
        if (curl_formadd(httppost, last_post,
                         CURLFORM_COPYNAME, name,
                         CURLFORM_ARRAY, forms, CURLFORM_END) != 0) {
          warnf(config, "curl_formadd failed!\n");
          free(forms);
          free(contents);
          return 5;
        }
        free(forms);
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

      if( contp[0]=='<' && !literal_value) {
        info[i].option = CURLFORM_FILECONTENT;
        info[i].value = contp+1;
        i++;
        info[i].option = CURLFORM_END;

        if (curl_formadd(httppost, last_post,
                         CURLFORM_ARRAY, info, CURLFORM_END ) != 0) {
          warnf(config, "curl_formadd failed, possibly the file %s is bad!\n",
                contp+1);
          free(contents);
          return 6;
        }
      }
      else {
        info[i].option = CURLFORM_COPYCONTENTS;
        info[i].value = contp;
        i++;
        info[i].option = CURLFORM_END;
        if (curl_formadd(httppost, last_post,
                         CURLFORM_ARRAY, info, CURLFORM_END) != 0) {
          warnf(config, "curl_formadd failed!\n");
          free(contents);
          return 7;
        }
      }
    }

  }
  else {
    warnf(config, "Illegally formatted input field!\n");
    return 1;
  }
  free(contents);
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

static void cleanarg(char *str)
{
#ifdef HAVE_WRITABLE_ARGV
  /* now that GetStr has copied the contents of nextarg, wipe the next
   * argument out so that the username:password isn't displayed in the
   * system process list */
  if (str) {
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
 */

static int str2num(long *val, char *str)
{
  int retcode = 0;
  if(isdigit((int)*str))
    *val = atoi(str);
  else
    retcode = 1; /* badness */
  return retcode;
}

/**
 * Parses the given string looking for an offset (which may be
 * a larger-than-integer value).
 *
 * @param val  the offset to populate
 * @param str  the buffer containing the offset
 * @return zero if successful, non-zero if failure.
 */
static int str2offset(curl_off_t *val, char *str)
{
#if SIZEOF_CURL_OFF_T > 4
  /* Ugly, but without going through a bunch of rigmarole, we don't have the
   * definitions for LLONG_{MIN,MAX} or LONG_LONG_{MIN,MAX}.
   */
#ifndef LLONG_MAX
#ifdef _MSC_VER
#define LLONG_MAX (curl_off_t)0x7FFFFFFFFFFFFFFFi64
#define LLONG_MIN (curl_off_t)0x8000000000000000i64
#else
#define LLONG_MAX (curl_off_t)0x7FFFFFFFFFFFFFFFLL
#define LLONG_MIN (curl_off_t)0x8000000000000000LL
#endif
#endif

  /* this is a duplicate of the function that is also used in libcurl */
  *val = curlx_strtoofft(str, NULL, 0);

  if ((*val == LLONG_MAX || *val == LLONG_MIN) && errno == ERANGE)
    return 1;
#else
  *val = strtol(str, NULL, 0);
  if ((*val == LONG_MIN || *val == LONG_MAX) && errno == ERANGE)
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
                               char *ptr)
{
  struct curl_slist *newlist = curl_slist_append(*list, ptr);
  if(newlist)
    *list = newlist;
  else
    return PARAM_NO_MEM;

  return PARAM_OK;
}

static int ftpfilemethod(struct Configurable *config, char *str)
{
  if(strequal("singlecwd", str))
    return 3;
  if(strequal("nocwd", str))
    return 2;
  if(strequal("multicwd", str))
    return 1;
  warnf(config, "unrecognized ftp file method '%s', using default\n", str);
  return 1;
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
#ifdef USE_ENVIRONMENT
    {"*f", "environment", FALSE},
#endif
    {"*g", "trace",      TRUE},
    {"*h", "trace-ascii", TRUE},
    {"*i", "limit-rate", TRUE},
    {"*j", "compressed",  FALSE}, /* might take an arg someday */
    {"*k", "digest",     FALSE},
    {"*l", "negotiate",  FALSE},
    {"*m", "ntlm",       FALSE},
    {"*n", "basic",      FALSE},
    {"*o", "anyauth",    FALSE},
#ifdef __DJGPP__
    {"*p", "wdebug",     FALSE},
#endif
    {"*q", "ftp-create-dirs", FALSE},
    {"*r", "create-dirs", FALSE},
    {"*s", "max-redirs",   TRUE},
    {"*t", "proxy-ntlm",   FALSE},
    {"*u", "crlf",        FALSE},
    {"*v", "stderr",      TRUE},
    {"*w", "interface",   TRUE},
    {"*x", "krb4",        TRUE},
    {"*y", "max-filesize", TRUE},
    {"*z", "disable-eprt", FALSE},
    {"$a", "ftp-ssl",    FALSE},
    {"$b", "ftp-pasv",   FALSE},
    {"$c", "socks5",     TRUE},
    {"$c", "socks",      TRUE}, /* this is how the option was documented but
                                   we prefer the --socks5 version for explicit
                                   version */
    {"$d", "tcp-nodelay",FALSE},
    {"$e", "proxy-digest", FALSE},
    {"$f", "proxy-basic", FALSE},
    {"$g", "retry",      TRUE},
    {"$h", "retry-delay", TRUE},
    {"$i", "retry-max-time", TRUE},
    {"$j", "3p-url", TRUE},
    {"$k", "3p-user", TRUE},
    {"$l", "3p-quote", TRUE},
    {"$m", "ftp-account", TRUE},
    {"$n", "proxy-anyauth", FALSE},
    {"$o", "trace-time", FALSE},
    {"$p", "ignore-content-length", FALSE},
    {"$q", "ftp-skip-pasv-ip", FALSE},
    {"$r", "ftp-method", TRUE},
    {"$s", "local-port", TRUE},
    {"$t", "socks4",     TRUE},

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
    {"k", "insecure",    FALSE},
    {"K", "config",      TRUE},
    {"l", "list-only",   FALSE},
    {"L", "location",    FALSE},
    {"Lt", "location-trusted", FALSE},
    {"m", "max-time",    TRUE},
    {"M", "manual",      FALSE},
    {"n", "netrc",       FALSE},
    {"no", "netrc-optional", FALSE},
    {"N", "no-buffer",   FALSE},
    {"o", "output",      TRUE},
    {"O", "remote-name", FALSE},
    {"p", "proxytunnel", FALSE},
    {"P", "ftpport",     TRUE}, /* older version */
    {"P", "ftp-port",    TRUE},
    {"q", "disable",     FALSE},
    {"Q", "quote",       TRUE},
    {"r", "range",       TRUE},
    {"R", "remote-time", FALSE},
    {"s", "silent",      FALSE},
    {"S", "show-error",  FALSE},
    {"t", "telnet-options", TRUE},
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
  };

  if(('-' != flag[0]) ||
     (('-' == flag[0]) && ('-' == flag[1]))) {
    /* this should be a long name */
    char *word=('-' == flag[0])?flag+2:flag;
    size_t fnam=strlen(word);
    int numhits=0;
    for(j=0; j< sizeof(aliases)/sizeof(aliases[0]); j++) {
      if(curlx_strnequal(aliases[j].lname, word, fnam)) {
        longopt = TRUE;
        numhits++;
        if(curlx_strequal(aliases[j].lname, word)) {
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
      letter = parse?(char)*parse:'\0';
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
    if(hit < 0) {
      return PARAM_OPTION_UNKNOWN;
    }
    if(!longopt && aliases[hit].extraparam && parse[1]) {
      nextarg=(char *)&parse[1]; /* this is the actual extra parameter */
      singleopt=TRUE;   /* don't loop anymore after this */
    }
    else if(!nextarg && aliases[hit].extraparam) {
      return PARAM_REQUIRES_PARAMETER;
    }
    else if(nextarg && aliases[hit].extraparam)
      *usedarg = TRUE; /* mark it as used */

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
        config->disable_epsv ^= TRUE;
        break;
#ifdef USE_ENVIRONMENT
      case 'f':
        config->writeenv ^= TRUE;
        break;
#endif
      case 'g': /* --trace */
        GetStr(&config->trace_dump, nextarg);
        config->tracetype = TRACE_BIN;
        break;
      case 'h': /* --trace-ascii */
        GetStr(&config->trace_dump, nextarg);
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
        config->encoding ^= TRUE;
        break;

      case 'k': /* --digest */
        config->authtype = CURLAUTH_DIGEST;
        break;

      case 'l': /* --negotiate */
        if(curlinfo->features & CURL_VERSION_GSSNEGOTIATE)
          config->authtype = CURLAUTH_GSSNEGOTIATE;
        else
          return PARAM_LIBCURL_DOESNT_SUPPORT;
        break;

      case 'm': /* --ntlm */
        if(curlinfo->features & CURL_VERSION_NTLM)
          config->authtype = CURLAUTH_NTLM;
        else
          return PARAM_LIBCURL_DOESNT_SUPPORT;
        break;

      case 'n': /* --basic for completeness */
        config->authtype = CURLAUTH_BASIC;
        break;

      case 'o': /* --anyauth, let libcurl pick it */
        config->authtype = CURLAUTH_ANY;
        break;

#ifdef __DJGPP__
      case 'p': /* --wdebug */
        dbug_init();
        break;
#endif
      case 'q': /* --ftp-create-dirs */
        config->ftp_create_dirs ^= TRUE;
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
          config->proxyntlm ^= TRUE;
        else
          return PARAM_LIBCURL_DOESNT_SUPPORT;
        break;

      case 'u': /* --crlf */
        /* LF -> CRLF conversinon? */
        config->crlf = TRUE;
        break;

      case 'v': /* --stderr */
        if(strcmp(nextarg, "-")) {
          FILE *newfile = fopen(nextarg, "wt");
          if(!config->errors)
            warnf(config, "Failed to open %s!\n", nextarg);
          else {
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
      case 'x': /* --krb4 */
        /* krb4 level string */
        if(curlinfo->features & CURL_VERSION_KERBEROS4)
          GetStr(&config->krb4level, nextarg);
        else
          return PARAM_LIBCURL_DOESNT_SUPPORT;
        break;
      case 'y': /* --max-filesize */
        if(str2offset(&config->max_filesize, nextarg))
          return PARAM_BAD_NUMERIC;
        break;
      case 'z': /* --disable-eprt */
        config->disable_eprt ^= TRUE;
        break;

      default: /* the URL! */
        {
          struct getout *url;
          if(config->url_get || (config->url_get=config->url_list)) {
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
        config->ftp_ssl ^= TRUE;
        break;
      case 'b': /* --ftp-pasv */
        if(config->ftpport)
          free(config->ftpport);
        config->ftpport = NULL;
        break;
      case 'c': /* --socks5 specifies a socks5 proxy to use */
        GetStr(&config->socksproxy, nextarg);
        config->socksver = CURLPROXY_SOCKS5;
        break;
      case 't': /* --socks4 specifies a socks4 proxy to use */
        GetStr(&config->socksproxy, nextarg);
        config->socksver = CURLPROXY_SOCKS4;
        break;
      case 'd': /* --tcp-nodelay option */
        config->tcp_nodelay ^= TRUE;
        break;
      case 'e': /* --proxy-digest */
        config->proxydigest ^= TRUE;
        break;
      case 'f': /* --proxy-basic */
        config->proxybasic ^= TRUE;
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

      case 'j': /* --3p-url */
        GetStr(&config->tp_url, nextarg);
        break;
      case 'k': /* --3p-user */
        GetStr(&config->tp_user, nextarg);
        break;
      case 'l': /* --3p-quote */
        /* QUOTE commands to send to source FTP server */
        err = PARAM_OK;
        switch(nextarg[0]) {
        case '-':
          /* prefixed with a dash makes it a POST TRANSFER one */
          nextarg++;
          err = add2list(&config->tp_postquote, nextarg);
          break;
        case '+':
          /* prefixed with a plus makes it a just-before-transfer one */
          nextarg++;
          err = add2list(&config->tp_prequote, nextarg);
          break;
        default:
          err = add2list(&config->tp_quote, nextarg);
          break;
        }
        if(err)
          return err;

        break;
        /* break */
      case 'm': /* --ftp-account */
        GetStr(&config->ftp_account, nextarg);
        break;
      case 'n': /* --proxy-anyauth */
        config->proxyanyauth ^= TRUE;
        break;
      case 'o': /* --trace-time */
        config->tracetime ^= TRUE;
        break;
      case 'p': /* --ignore-content-length */
        config->ignorecl ^= TRUE;
        break;
      case 'q': /* --ftp-skip-pasv-ip */
        config->ftp_skip_ip ^= TRUE;
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
      }
      break;
    case '#': /* --progress-bar */
      config->progressmode ^= CURL_PROGRESS_BAR;
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
      config->conf ^= CONF_FTPAPPEND;
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
      /* use ASCII/text when transfering */
      config->conf ^= CONF_GETTEXT;
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

        if('@' == *nextarg) {
          /* the data begins with a '@' letter, it means that a file name
             or - (stdin) follows */
          FILE *file;

          nextarg++; /* pass the @ */

          if(curlx_strequal("-", nextarg)) {
            file = stdin;
#ifdef O_BINARY
            if(subletter == 'b') /* forced binary */
              setmode(fileno(stdin), O_BINARY);
#endif
          }
          else {
            file = fopen(nextarg, "rb");
            if(!file)
              warnf(config, "Couldn't read data from file \"%s\", this makes "
                    "an empty POST.\n", nextarg);
          }

          if(subletter == 'b') /* forced binary */
            postdata = file2memory(file, &config->postfieldsize);
          else
            postdata = file2string(file);

          if(file && (file != stdin))
            fclose(file);

          if(!postdata) {
            /* no data from the file, point to a zero byte string to make this
               get sent as a POST anyway */
            postdata=strdup("");
          }
        }
        else {
          GetStr(&postdata, nextarg);
        }

        if(config->postfields) {
          /* we already have a string, we append this one
             with a separating &-letter */
          char *oldpost=config->postfields;
          config->postfields=aprintf("%s&%s", oldpost, postdata);
          free(oldpost);
          free(postdata);
        }
        else
          config->postfields=postdata;
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
          config->conf |= CONF_AUTO_REFERER;
          *ptr = 0; /* zero terminate here */
        }
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
        if (config->engine && curlx_strequal(config->engine,"list"))
           config->list_engines = TRUE;
        break;
      case 'g': /* CA info PEM file */
        /* CA cert directory */
        GetStr(&config->capath, nextarg);
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
             (isalpha((int)nextarg[0])) )
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
      config->conf ^= CONF_FAILONERROR;
      break;
    case 'F':
      /* "form data" simulation, this is a little advanced so lets do our best
         to sort this out slowly and carefully */
      if(formparse(config,
                   nextarg,
                   &config->httppost,
                   &config->last_post,
                   (bool) (subletter=='s'))) /* 's' means literal string */
        return PARAM_BAD_USE;
      if(SetHTTPrequest(config, HTTPREQ_POST, &config->httpreq))
        return PARAM_BAD_USE;
      break;

    case 'g': /* g disables URLglobbing */
      config->globoff ^= TRUE;
      break;

    case 'G': /* HTTP GET */
      config->use_httpget = TRUE;
      break;

    case 'h': /* h for help */
      help();
      return PARAM_HELP_REQUESTED;
    case 'H':
      /* A custom header to append to a list */
      err = add2list(&config->headers, nextarg);
      if(err)
        return err;
      break;
    case 'i':
      config->conf ^= CONF_HEADER; /* include the HTTP header as well */
      break;
    case 'j':
      config->cookiesession ^= TRUE;
      break;
    case 'I':
      /*
       * This is a bit tricky. We either SET both bits, or we clear both
       * bits. Let's not make any other outcomes from this.
       */
      if((CONF_HEADER|CONF_NOBODY) !=
         (config->conf&(CONF_HEADER|CONF_NOBODY)) ) {
        /* one of them weren't set, set both */
        config->conf |= (CONF_HEADER|CONF_NOBODY);
        if(SetHTTPrequest(config, HTTPREQ_HEAD, &config->httpreq))
          return PARAM_BAD_USE;
      }
      else {
        /* both were set, clear both */
        config->conf &= ~(CONF_HEADER|CONF_NOBODY);
        if(SetHTTPrequest(config, HTTPREQ_GET, &config->httpreq))
          return PARAM_BAD_USE;
      }
      break;
    case 'k': /* allow insecure SSL connects */
      config->insecure_ok ^= TRUE;
      break;
    case 'K': /* parse config file */
      parseconfig(nextarg, config);
      break;
    case 'l':
      config->conf ^= CONF_FTPLISTONLY; /* only list the names of the FTP dir */
      break;
    case 'L':
      config->conf ^= CONF_FOLLOWLOCATION; /* Follow Location: HTTP headers */
      switch (subletter) {
      case 't':
        /* Continue to send authentication (user+password) when following
         * locations, even when hostname changed */
        config->conf ^= CONF_UNRESTRICTED_AUTH;
        break;
      }
      break;
    case 'm':
      /* specified max time */
      if(str2num(&config->timeout, nextarg))
        return PARAM_BAD_NUMERIC;
      break;
    case 'M': /* M for manual, huge help */
#ifdef USE_MANUAL
      hugehelp();
      return PARAM_HELP_REQUESTED;
#else
      warnf(config,
            "built-in manual was disabled at build-time!\n");
      return PARAM_OPTION_UNKNOWN;
#endif
    case 'n':
      switch(subletter) {
      case 'o': /* CA info PEM file */
        /* use .netrc or URL */
        config->conf ^= CONF_NETRC_OPT;
        break;
      default:
        /* pick info from .netrc, if this is used for http, curl will
           automatically enfore user+password with the request */
        config->conf ^= CONF_NETRC;
        break;
      }
      break;
    case 'N':
      /* disable the output I/O buffering */
      config->nobuffer ^= 1;
      break;
    case 'o':
    case 'O':
      /* output file */
      {
        struct getout *url;
        if(config->url_out || (config->url_out=config->url_list)) {
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
          if('o' == letter)
            GetStr(&url->outfile, nextarg);
          else {
            url->outfile=NULL; /* leave it */
            url->flags |= GETOUT_USEREMOTE;
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
      config->proxytunnel ^= TRUE;
      break;

    case 'q': /* if used first, already taken care of, we do it like
                 this so we don't cause an error! */
      break;
    case 'Q':
      /* QUOTE command to send to FTP server */
      err = PARAM_OK;
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
      if(!strchr(nextarg, '-')) {
        char buffer[32];
        curl_off_t off;
        warnf(config,
              "A specfied range MUST include at least one dash (-). "
              "Appending one for you!\n");
        off = curlx_strtoofft(nextarg, NULL, 10);
        snprintf(buffer, sizeof(buffer), CURL_FORMAT_OFF_T "-", off);
        GetStr(&config->range, buffer);
      }
      else
        /* byte range requested */
        GetStr(&config->range, nextarg);

      break;
    case 'R':
      /* use remote file's time */
      config->remote_time ^= TRUE;
      break;
    case 's':
      /* don't show progress meter, don't show errors : */
      config->conf |= (CONF_MUTE|CONF_NOPROGRESS);
      config->showerror ^= TRUE; /* toggle off */
      break;
    case 'S':
      /* show errors */
      config->showerror ^= TRUE; /* toggle on if used with -s */
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
        if(config->url_out || (config->url_out=config->url_list)) {
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
      GetStr(&config->trace_dump, (char *)"%");
      config->tracetype = TRACE_PLAIN;
      break;
    case 'V':
    {
      const char * const *proto;

      printf(CURL_ID "%s\n", curl_version());
      if (curlinfo->protocols) {
        printf("Protocols: ");
        for (proto=curlinfo->protocols; *proto; ++proto) {
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
          {"GSS-Negotiate", CURL_VERSION_GSSNEGOTIATE},
          {"IDN", CURL_VERSION_IDN},
          {"IPv6", CURL_VERSION_IPV6},
          {"Largefile", CURL_VERSION_LARGEFILE},
          {"NTLM", CURL_VERSION_NTLM},
          {"SPNEGO", CURL_VERSION_SPNEGO},
          {"SSL",  CURL_VERSION_SSL},
          {"SSPI",  CURL_VERSION_SSPI},
          {"krb4", CURL_VERSION_KERBEROS4},
          {"libz", CURL_VERSION_LIBZ}
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
        nextarg++; /* pass the @ */
        if(curlx_strequal("-", nextarg))
          file = stdin;
        else
          file = fopen(nextarg, "r");
        config->writeout = file2string(file);
        if(!config->writeout)
          warnf(config, "Failed to read %s", file);
        if(file && (file != stdin))
          fclose(file);
      }
      else
        GetStr(&config->writeout, nextarg);
      break;
    case 'x':
      /* proxy */
      GetStr(&config->proxy, nextarg);
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
                "Illegal date format for -z/--timecond (and not "
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


static void parseconfig(const char *filename,
                        struct Configurable *config)
{
  int res;
  FILE *file;
  char filebuffer[512];
  bool usedarg;
  char *home;

  if(!filename || !*filename) {
    /* NULL or no file name attempts to load .curlrc from the homedir! */

#define CURLRC DOT_CHAR "curlrc"

#ifndef AMIGA
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
        if (file != NULL) {
          fclose(file);
          filename = filebuffer;
        }
        else {
          /* Get the filename of our executable. GetModuleFileName is
           * already declared via inclusions done in setup header file.
           * We assume that we are using the ASCII version here.
           */
          int n = GetModuleFileName(0, filebuffer, sizeof(filebuffer));
          if (n > 0 && n < (int)sizeof(filebuffer)) {
            /* We got a valid filename - get the directory part */
            char *lastdirchar = strrchr(filebuffer, '\\');
            if (lastdirchar) {
              int remaining;
              *lastdirchar = 0;
              /* If we have enough space, build the RC filename */
              remaining = sizeof(filebuffer) - strlen(filebuffer);
              if ((int)strlen(CURLRC) < remaining - 1) {
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
      free(home); /* we've used it, now free it */
    }

# else /* AmigaOS */
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

#define isseparator(x) (((x)=='=') || ((x) == ':'))

    while (NULL != (aline = my_get_line(file))) {
      lineno++;
      line = aline;
      alloced_param=FALSE;

      /* lines with # in the fist column is a comment! */
      while(*line && isspace((int)*line))
        line++;

      switch(*line) {
      case '#':
      case '/':
      case '\r':
      case '\n':
      case '*':
      case '\0':
        free(aline);
        continue;
      }

      /* the option keywords starts here */
      option = line;
      while(*line && !isspace((int)*line) && !isseparator(*line))
        line++;
      /* ... and has ended here */

      if(*line)
        *line++=0; /* zero terminate, we have a local copy of the data */

#ifdef DEBUG_CONFIG
      fprintf(stderr, "GOT: %s\n", option);
#endif

      /* pass spaces and separator(s) */
      while(*line && (isspace((int)*line) || isseparator(*line)))
        line++;

      /* the parameter starts here (unless quoted) */
      if(*line == '\"') {
        char *ptr;
        /* quoted parameter, do the qoute dance */
        line++;
        param=strdup(line); /* parameter */
        alloced_param=TRUE;

        ptr=param;
        while(*line && (*line != '\"')) {
          if(*line == '\\') {
            char out;
            line++;

            /* default is to output the letter after the backslah */
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
            *ptr++=out;
            line++;
          }
          else
            *ptr++=*line++;
        }
        *ptr=0; /* always zero terminate */

      }
      else {
        param=line; /* parameter starts here */
        while(*line && !isspace((int)*line))
          line++;
        *line=0; /* zero terminate */
      }

      if (param && !*param) {
        /* do this so getparameter can check for required parameters.
           Otherwise it always thinks there's a parameter. */
        if (alloced_param)
          free(param);
        param = NULL;
      }

#ifdef DEBUG_CONFIG
      fprintf(stderr, "PARAM: \"%s\"\n",(param ? param : "(null)"));
#endif
      res = getparameter(option, param, &usedarg, config);

      if (param && *param && !usedarg)
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
      {
        free(param);
        param = NULL;
      }

      free(aline);
    }
    if(file != stdin)
      fclose(file);
  }
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
#elif defined(__MSDOS__)
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

struct OutStruct {
  char *filename;
  FILE *stream;
  struct Configurable *config;
  curl_off_t bytes; /* amount written so far */
  curl_off_t init;  /* original size (non-zero when appending) */
};

static size_t my_fwrite(void *buffer, size_t sz, size_t nmemb, void *stream)
{
  size_t rc;
  struct OutStruct *out=(struct OutStruct *)stream;
  struct Configurable *config = out->config;
  curl_off_t size = (curl_off_t)(sz * nmemb); /* typecast to prevent
                                                 warnings when converting from
                                                 unsigned to signed */
  if(out && !out->stream) {
    /* open file for writing */
    out->stream=fopen(out->filename, "wb");
    if(!out->stream) {
      warnf(config, "Failed to create the file %s\n", out->filename);
      /*
       * Once that libcurl has called back my_fwrite() the returned value
       * is checked against the amount that was intended to be written, if
       * it does not match then it fails with CURLE_WRITE_ERROR. So at this
       * point returning a value different from sz*nmemb indicates failure.
       */
      rc = (0 == (sz * nmemb)) ? 1 : 0;
      return rc; /* failure */
    }
  }

  if(config->recvpersecond) {
    /*
     * We know when we received data the previous time. We know how much data
     * we get now. Make sure that this is not faster than we are told to run.
     * If we're faster, sleep a while *before* doing the fwrite() here.
     */

    struct timeval now;
    long timediff;
    long sleep_time;

    static curl_off_t addit = 0;

    now = curlx_tvnow();
    timediff = curlx_tvdiff(now, config->lastrecvtime); /* milliseconds */

    if((config->recvpersecond > CURL_MAX_WRITE_SIZE) && (timediff < 100) ) {
      /* If we allow a rather speedy transfer, add this amount for later
       * checking. Also, do not modify the lastrecvtime as we will use a
       * longer scope due to this addition.  We wait for at least 100 ms to
       * pass to get better values to do better math for the sleep. */
      addit += size;
    }
    else {
      size += addit; /* add up the possibly added bonus rounds from the
                        zero timediff calls */
      addit = 0; /* clear the addition pool */

      if( size*1000 > config->recvpersecond*timediff) {
        /* figure out how many milliseconds to rest */
        sleep_time = (long)(size*1000/config->recvpersecond - timediff);

        /*
         * Make sure we don't sleep for so long that we trigger the speed
         * limit.  This won't limit the bandwidth quite the way we've been
         * asked to, but at least the transfer has a chance.
         */
        if (config->low_speed_time > 0)
          sleep_time = MIN(sleep_time,(config->low_speed_time * 1000) / 2);

        if(sleep_time > 0) {
          go_sleep(sleep_time);
          now = curlx_tvnow();
        }
      }
      config->lastrecvtime = now;
    }
  }

  rc = fwrite(buffer, sz, nmemb, out->stream);

  if((sz * nmemb) == rc) {
    /* we added this amount of data to the output */
    out->bytes += (sz * nmemb);
  }

  if(config->nobuffer)
    /* disable output buffering */
    fflush(out->stream);

  return rc;
}

struct InStruct {
  FILE *stream;
  struct Configurable *config;
};

static curlioerr my_ioctl(CURL *handle, curliocmd cmd, void *userp)
{
  struct InStruct *in=(struct InStruct *)userp;
  (void)handle; /* not used in here */

  switch(cmd) {
  case CURLIOCMD_RESTARTREAD:
    /* mr libcurl kindly asks as to rewind the read data stream to start */
    if(-1 == fseek(in->stream, 0, SEEK_SET))
      /* couldn't rewind, the reason is in errno but errno is just not
         portable enough and we don't actually care that much why we failed. */
      return CURLIOE_FAILRESTART;

    break;

  default: /* ignore unknown commands */
    return CURLIOE_UNKNOWNCMD;
  }
  return CURLIOE_OK;
}

static size_t my_fread(void *buffer, size_t sz, size_t nmemb, void *userp)
{
  size_t rc;
  struct InStruct *in=(struct InStruct *)userp;
  struct Configurable *config = in->config;
  curl_off_t size = (curl_off_t)(sz * nmemb);  /* typecast to prevent warnings
                                                  when converting from
                                                  unsigned to signed */

  if(config->sendpersecond) {
    /*
     * We know when we sent data the previous time. We know how much data
     * we sent. Make sure that this was not faster than we are told to run.
     * If we're faster, sleep a while *before* doing the fread() here.
     * Also, make no larger fread() than should be sent this second!
     */

    struct timeval now;
    long timediff;
    long sleep_time;

    static curl_off_t addit = 0;

    now = curlx_tvnow();
    timediff = curlx_tvdiff(now, config->lastsendtime); /* milliseconds */

    if((config->sendpersecond > CURL_MAX_WRITE_SIZE) &&
       (timediff < 100)) {
      /*
       * We allow very fast transfers, then allow at least 100 ms between
       * each sleeping mile-stone to create more accurate long-term rates.
       */
      addit += size;
    }
    else {
      /* If 'addit' is non-zero, it contains the total amount of bytes
         uploaded during the last 'timediff' milliseconds. If it is zero,
         we use the stored previous size. */
      curl_off_t xfered = addit?addit:(curl_off_t)config->lastsendsize;
      addit = 0; /* clear it for the next round */

      if( xfered*1000 > config->sendpersecond*timediff) {
        /* figure out how many milliseconds to rest */
        sleep_time = (long)(xfered*1000/config->sendpersecond - timediff);
        if(sleep_time > 0) {
          go_sleep (sleep_time);
          now = curlx_tvnow();
        }
      }
      config->lastsendtime = now;

      if(size > config->sendpersecond) {
        /* lower the size to actually read */
        nmemb = (size_t)config->sendpersecond;
        sz = 1;
      }
    }

    config->lastsendsize = sz*nmemb;
  }

  rc = fread(buffer, sz, nmemb, in->stream);
#if 0
  if (sizeof(rc) > sizeof(unsigned int))
    fprintf(stderr, "CALLBACK returning %lu bytes data\n", rc);
  else
    fprintf(stderr, "CALLBACK returning %u bytes data\n", rc);
#endif
  return rc;
}

struct ProgressData {
  int calls;
  curl_off_t prev;
  int width;
  FILE *out; /* where to write everything to */
  curl_off_t initial_size;
};

static int myprogress (void *clientp,
                       double dltotal,
                       double dlnow,
                       double ultotal,
                       double ulnow)
{
  /* The original progress-bar source code was written for curl by Lars Aas,
     and this new edition inherits some of his concepts. */

  char line[256];
  char outline[256];
  char format[40];
  double frac;
  double percent;
  int barwidth;
  int num;
  int i;

  struct ProgressData *bar = (struct ProgressData *)clientp;
  curl_off_t total = (curl_off_t)dltotal + (curl_off_t)ultotal +
    bar->initial_size; /* expected transfer size */
  curl_off_t point = (curl_off_t)dlnow + (curl_off_t)ulnow +
    bar->initial_size; /* we've come this far */

  if(point > total)
    /* we have got more than the expected total! */
    total = point;

  bar->calls++; /* simply count invokes */

  if(total < 1) {
    curl_off_t prevblock = bar->prev / 1024;
    curl_off_t thisblock = point / 1024;
    while ( thisblock > prevblock ) {
      fprintf( bar->out, "#" );
      prevblock++;
    }
  }
  else {
    frac = (double)point / (double)total;
    percent = frac * 100.0f;
    barwidth = bar->width - 7;
    num = (int) (((double)barwidth) * frac);
    i = 0;
    for ( i = 0; i < num; i++ ) {
      line[i] = '#';
    }
    line[i] = '\0';
    snprintf( format, sizeof(format), "%%-%ds %%5.1f%%%%", barwidth );
    snprintf( outline, sizeof(outline), format, line, percent );
    fprintf( bar->out, "\r%s", outline );
  }
  fflush(bar->out);
  bar->prev = point;

  return 0;
}

static
void progressbarinit(struct ProgressData *bar,
                     struct Configurable *config)
{
#ifdef __EMX__
  /* 20000318 mgs */
  int scr_size [2];
#endif
  char *colp;

  memset(bar, 0, sizeof(struct ProgressData));

  /* pass this through to progress function so
   * it can display progress towards total file
   * not just the part that's left. (21-may-03, dbyron) */
  if (config->use_resume)
    bar->initial_size = config->resume_from;

/* TODO: get terminal width through ansi escapes or something similar.
         try to update width when xterm is resized... - 19990617 larsa */
#ifndef __EMX__
  /* 20000318 mgs
   * OS/2 users most likely won't have this env var set, and besides that
   * we're using our own way to determine screen width */
  colp = curlx_getenv("COLUMNS");
  if (colp != NULL) {
    bar->width = atoi(colp);
    curl_free(colp);
  }
  else
    bar->width = 79;
#else
  /* 20000318 mgs
   * We use this emx library call to get the screen width, and subtract
   * one from what we got in order to avoid a problem with the cursor
   * advancing to the next line if we print a string that is as long as
   * the screen is wide. */

  _scrsize(scr_size);
  bar->width = scr_size[0] - 1;
#endif

  bar->out = config->errors;
}

static
void dump(char *timebuf, const char *text,
          FILE *stream, unsigned char *ptr, size_t size,
          trace tracetype)
{
  size_t i;
  size_t c;

  unsigned int width=0x10;

  if(tracetype == TRACE_ASCII)
    /* without the hex output, we can fit more on screen */
    width = 0x40;

  fprintf(stream, "%s%s, %zd bytes (0x%zx)\n", timebuf, text, size, size);

  for(i=0; i<size; i+= width) {

    fprintf(stream, "%04zx: ", i);

    if(tracetype == TRACE_BIN) {
      /* hex not disabled, show it */
      for(c = 0; c < width; c++)
        if(i+c < size)
          fprintf(stream, "%02x ", ptr[i+c]);
        else
          fputs("   ", stream);
    }

    for(c = 0; (c < width) && (i+c < size); c++) {
      /* check for 0D0A; if found, skip past and start a new line of output */
      if ((tracetype == TRACE_ASCII) &&
          (i+c+1 < size) && ptr[i+c]==0x0D && ptr[i+c+1]==0x0A) {
        i+=(c+2-width);
        break;
      }
      fprintf(stream, "%c",
              (ptr[i+c]>=0x20) && (ptr[i+c]<0x80)?ptr[i+c]:'.');
      /* check again for 0D0A, to avoid an extra \n if it's at width */
      if ((tracetype == TRACE_ASCII) &&
          (i+c+2 < size) && ptr[i+c+1]==0x0D && ptr[i+c+2]==0x0A) {
        i+=(c+3-width);
        break;
      }
    }
    fputc('\n', stream); /* newline */
  }
  fflush(stream);
}

static
int my_trace(CURL *handle, curl_infotype type,
             unsigned char *data, size_t size,
             void *userp)
{
  struct Configurable *config = (struct Configurable *)userp;
  FILE *output=config->errors;
  const char *text;
  struct timeval tv;
  struct tm *now;
  char timebuf[20];

  (void)handle; /* prevent compiler warning */

  tv = curlx_tvnow();
  now = localtime((time_t *)&tv.tv_sec);  /* not multithread safe but we don't care */
  if(config->tracetime)
    snprintf(timebuf, sizeof(timebuf), "%02d:%02d:%02d.%06d ",
             now->tm_hour, now->tm_min, now->tm_sec, tv.tv_usec);
  else
    timebuf[0]=0;

  if(!config->trace_stream) {
    /* open for append */
    if(curlx_strequal("-", config->trace_dump))
      config->trace_stream = stdout;
    else if(curlx_strequal("%", config->trace_dump))
      /* Ok, this is somewhat hackish but we do it undocumented for now */
      config->trace_stream = stderr;
    else {
      config->trace_stream = fopen(config->trace_dump, "w");
      config->trace_fopened = TRUE;
    }
  }

  if(config->trace_stream)
    output = config->trace_stream;

  if(config->tracetype == TRACE_PLAIN) {
    /*
     * This is the trace look that is similar to what libcurl makes on its
     * own.
     */
    static const char * const s_infotype[] = {
      "*", "<", ">"
    };
    size_t i;
    size_t st=0;
    static bool newl = FALSE;

    switch(type) {
    case CURLINFO_HEADER_OUT:
      for(i=0; i<size-1; i++) {
        if(data[i] == '\n') { /* LF */
          if(!newl) {
            fprintf(config->trace_stream, "%s%s ",
                    timebuf, s_infotype[type]);
          }
          fwrite(data+st, i-st+1, 1, config->trace_stream);
          st = i+1;
          newl = FALSE;
        }
      }
      if(!newl)
        fprintf(config->trace_stream, "%s%s ", timebuf, s_infotype[type]);
      fwrite(data+st, i-st+1, 1, config->trace_stream);
      break;
    case CURLINFO_TEXT:
    case CURLINFO_HEADER_IN:
      if(!newl)
        fprintf(config->trace_stream, "%s%s ", timebuf, s_infotype[type]);
      fwrite(data, size, 1, config->trace_stream);
      break;
    default: /* nada */
      newl = FALSE;
      break;
    }

    newl = (size && (data[size-1] != '\n'));

    return 0;
  }


  switch (type) {
  case CURLINFO_TEXT:
    fprintf(output, "%s== Info: %s", timebuf, data);
  default: /* in case a new one is introduced to shock us */
    return 0;

  case CURLINFO_HEADER_OUT:
    text = "=> Send header";
    break;
  case CURLINFO_DATA_OUT:
    text = "=> Send data";
    break;
  case CURLINFO_HEADER_IN:
    text = "<= Recv header";
    break;
  case CURLINFO_DATA_IN:
    text = "<= Recv data";
    break;
  case CURLINFO_SSL_DATA_IN:
    text = "<= Recv SSL data";
    break;
  case CURLINFO_SSL_DATA_OUT:
    text = "<= Send SSL data";
    break;
  }

  dump(timebuf, text, output, data, size, config->tracetype);
  return 0;
}

static void free_config_fields(struct Configurable *config)
{
  if(config->random_file)
    free(config->random_file);
  if(config->egd_file)
    free(config->egd_file);
  if(config->trace_dump)
    free(config->trace_dump);
  if(config->cipher_list)
    free(config->cipher_list);
  if(config->userpwd)
    free(config->userpwd);
  if(config->postfields)
    free(config->postfields);
  if(config->proxy)
    free(config->proxy);
  if(config->proxyuserpwd)
    free(config->proxyuserpwd);
  if(config->cookie)
    free(config->cookie);
  if(config->cookiefile)
    free(config->cookiefile);
  if(config->krb4level)
    free(config->krb4level);
  if(config->headerfile)
    free(config->headerfile);
  if(config->ftpport)
    free(config->ftpport);
  if(config->range)
    free(config->range);
  if(config->customrequest)
    free(config->customrequest);
  if(config->writeout)
    free(config->writeout);
  if(config->httppost)
    curl_formfree(config->httppost);
  if(config->cacert)
    free(config->cacert);
  if(config->capath)
    free(config->capath);
  if(config->cookiejar)
    free(config->cookiejar);
  if(config->tp_url)
    free(config->tp_url);
  if(config->tp_user)
    free(config->tp_user);
  if(config->ftp_account)
    free(config->ftp_account);

  curl_slist_free_all(config->quote); /* checks for config->quote == NULL */
  curl_slist_free_all(config->prequote);
  curl_slist_free_all(config->postquote);
  curl_slist_free_all(config->tp_quote);
  curl_slist_free_all(config->tp_prequote);
  curl_slist_free_all(config->tp_postquote);
  curl_slist_free_all(config->headers);
}

#if defined(WIN32) && !defined(__CYGWIN32__)

/* Function to find CACert bundle on a Win32 platform using SearchPath.
 * (SearchPath is already declared via inclusions done in setup header file)
 * (Use the ASCII version instead of the unicode one!)
 * The order of the directories it searches is:
 *  1. application's directory
 *  2. current working directory
 *  3. Windows System directory (e.g. C:\windows\system32)
 *  4. Windows Directory (e.g. C:\windows)
 *  5. all directories along %PATH%
 */
static void FindWin32CACert(struct Configurable *config,
                            const char *bundle_file)
{
  /* only check for cert file if "we" support SSL */
  if(curlinfo->features & CURL_VERSION_SSL) {
    DWORD buflen;
    char *ptr = NULL;
    char *retval = (char *) malloc(sizeof (TCHAR) * (MAX_PATH + 1));
    if (!retval)
      return;
    retval[0] = '\0';
    buflen = SearchPathA(NULL, bundle_file, NULL, MAX_PATH+2, retval, &ptr);
    if (buflen > 0) {
      GetStr(&config->cacert, retval);
    }
    free(retval);
  }
}

#endif

#define RETRY_SLEEP_DEFAULT 1000  /* ms */
#define RETRY_SLEEP_MAX     600000 /* ms == 10 minutes */

static bool
output_expected(char* url, char* uploadfile)
{
  if(!uploadfile)
    return TRUE;  /* download */
  if(checkprefix("http://", url) || checkprefix("https://", url))
    return TRUE;   /* HTTP(S) upload */

  return FALSE; /* non-HTTP upload, probably no output should be expected */
}

static int
operate(struct Configurable *config, int argc, char *argv[])
{
  char errorbuffer[CURL_ERROR_SIZE];
  char useragent[128]; /* buah, we don't want a larger default user agent */
  struct ProgressData progressbar;
  struct getout *urlnode;
  struct getout *nextnode;

  struct OutStruct outs;
  struct OutStruct heads;
  struct InStruct input;

  char *url = NULL;

  URLGlob *urls=NULL;
  URLGlob *inglob=NULL;
  int urlnum;
  int infilenum;
  char *outfiles;
  char *infiles; /* might a glob pattern */
  char *uploadfile=NULL; /* a single file, never a glob */

  int separator = 0;

  FILE *infd = stdin;
  bool infdfopen;
  FILE *headerfilep = NULL;
  char *urlbuffer=NULL;
  curl_off_t uploadfilesize; /* -1 means unknown */
  bool stillflags=TRUE;

  bool allocuseragent=FALSE;

  char *httpgetfields=NULL;

  CURL *curl;
  int res = 0;
  int i;
  int up; /* upload file counter within a single upload glob */
  long retry_sleep_default;
  long retry_numretries;
  long retry_sleep;
  long response;
  struct timeval retrystart;

  char *env;
#ifdef CURLDEBUG
  /* this sends all memory debug messages to a logfile named memdump */
  env = curlx_getenv("CURL_MEMDEBUG");
  if(env) {
    /* use the value as file name */
    char *s = strdup(env);
    curl_free(env);
    curl_memdebug(s);
    free(s);
    /* this weird strdup() and stuff here is to make the curl_free() get
       called before the memdebug() as otherwise the memdebug tracing will
       with tracing a free() without an alloc! */
  }
  env = curlx_getenv("CURL_MEMLIMIT");
  if(env) {
    curl_memlimit(atoi(env));
    curl_free(env);
  }
#endif

  memset(&outs,0,sizeof(outs));

  /* we get libcurl info right away */
  curlinfo = curl_version_info(CURLVERSION_NOW);

  errorbuffer[0]=0; /* prevent junk from being output */

  /* setup proper locale from environment */
#ifdef HAVE_SETLOCALE
  setlocale(LC_ALL, "");
#endif

  /* inits */
  if (main_init() != CURLE_OK) {
    helpf("error initializing curl library\n");
    return CURLE_FAILED_INIT;
  }
  config->postfieldsize = -1;
  config->showerror=TRUE;
  config->conf=CONF_DEFAULT;
  config->use_httpget=FALSE;
  config->create_dirs=FALSE;
  config->lastrecvtime = curlx_tvnow();
  config->lastsendtime = curlx_tvnow();
  config->maxredirs = DEFAULT_MAXREDIRS;

  if(argc>1 &&
     (!curlx_strnequal("--", argv[1], 2) && (argv[1][0] == '-')) &&
     strchr(argv[1], 'q')) {
    /*
     * The first flag, that is not a verbose name, but a shortname
     * and it includes the 'q' flag!
     */
    ;
  }
  else {
    parseconfig(NULL, config);
  }

  if ((argc < 2)  && !config->url_list) {
    helpf(NULL);
    return CURLE_FAILED_INIT;
  }

  /* Parse options */
  for (i = 1; i < argc; i++) {
    if(stillflags &&
       ('-' == argv[i][0])) {
      char *nextarg;
      bool passarg;
      char *origopt=argv[i];

      char *flag = argv[i];

      if(curlx_strequal("--", argv[i]))
        /* this indicates the end of the flags and thus enables the
           following (URL) argument to start with -. */
        stillflags=FALSE;
      else {
        nextarg= (i < argc - 1)? argv[i+1]: NULL;

        res = getparameter(flag, nextarg, &passarg, config);
        if(res) {
          const char *reason = param2text(res);
          if(res != PARAM_HELP_REQUESTED)
            helpf("option %s: %s\n", origopt, reason);
          clean_getout(config);
          return CURLE_FAILED_INIT;
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
        return res;
    }
  }

  retry_sleep_default = config->retry_delay?
    config->retry_delay*1000:RETRY_SLEEP_DEFAULT; /* ms */
  retry_sleep = retry_sleep_default;

  if((!config->url_list || !config->url_list->url) && !config->list_engines) {
    clean_getout(config);
    helpf("no URL specified!\n");
    return CURLE_FAILED_INIT;
  }
  if(NULL == config->useragent) {
    /* set non-zero default values: */
    snprintf(useragent, sizeof(useragent),
             CURL_NAME "/" CURL_VERSION " (" OS ") " "%s", curl_version());
    config->useragent= useragent;
  }
  else
    allocuseragent = TRUE;

  /* On WIN32 (non-cygwin), we can't set the path to curl-ca-bundle.crt
   * at compile time. So we look here for the file in two ways:
   * 1: look at the environment variable CURL_CA_BUNDLE for a path
   * 2: if #1 isn't found, use the windows API function SearchPath()
   *    to find it along the app's path (includes app's dir and CWD)
   *
   * We support the environment variable thing for non-Windows platforms
   * too. Just for the sake of it.
   */
  if (!config->cacert &&
      !config->capath &&
      !config->insecure_ok) {
    env = curlx_getenv("CURL_CA_BUNDLE");
    if(env)
      GetStr(&config->cacert, env);
    else {
      env = curlx_getenv("SSL_CERT_DIR");
      if(env)
        GetStr(&config->capath, env);
      else {
        env = curlx_getenv("SSL_CERT_FILE");
        if(env)
          GetStr(&config->cacert, env);
      }
    }

    if(env)
      curl_free(env);
#if defined(WIN32) && !defined(__CYGWIN32__)
    else
      FindWin32CACert(config, "curl-ca-bundle.crt");
#endif
  }

  if (config->postfields) {
    if (config->use_httpget) {
      /* Use the postfields data for a http get */
      httpgetfields = strdup(config->postfields);
      free(config->postfields);
      config->postfields = NULL;
      if(SetHTTPrequest(config,
                        (config->conf&CONF_NOBODY?HTTPREQ_HEAD:HTTPREQ_GET),
                        &config->httpreq)) {
        free(httpgetfields);
        return PARAM_BAD_USE;
      }
    }
    else {
      if(SetHTTPrequest(config, HTTPREQ_SIMPLEPOST, &config->httpreq))
        return PARAM_BAD_USE;
    }
  }

  /*
   * Get a curl handle to use for all forthcoming curl transfers.  Cleanup
   * when all transfers are done.
   */
  curl = curl_easy_init();
  if(!curl) {
    clean_getout(config);
    return CURLE_FAILED_INIT;
  }


  if (config->list_engines) {
    struct curl_slist *engines = NULL;

    curl_easy_getinfo(curl, CURLINFO_SSL_ENGINES, &engines);
    list_engines(engines);
    curl_slist_free_all(engines);
    res = CURLE_OK;
    goto quit_curl;
  }

  /* After this point, we should call curl_easy_cleanup() if we decide to bail
   * out from this function! */

  urlnode = config->url_list;

  if(config->headerfile) {
    /* open file for output: */
    if(strcmp(config->headerfile,"-")) {
      heads.filename = config->headerfile;
      headerfilep=NULL;
    }
    else
      headerfilep=stdout;
    heads.stream = headerfilep;
    heads.config = config;
  }

  /* loop through the list of given URLs */
  while(urlnode) {
    char *dourl;

    /* get the full URL (it might be NULL) */
    dourl=urlnode->url;

    url = dourl;

    if(NULL == url) {
      /* This node had no URL, skip it and continue to the next */
      if(urlnode->outfile)
        free(urlnode->outfile);

      /* move on to the next URL */
      nextnode=urlnode->next;
      free(urlnode); /* free the node */
      urlnode = nextnode;
      continue; /* next please */
    }

    /* default output stream is stdout */
    outs.stream = stdout;
    outs.config = config;
    outs.bytes = 0; /* nothing written yet */

    /* save outfile pattern before expansion */
    outfiles = urlnode->outfile?strdup(urlnode->outfile):NULL;

    infiles = urlnode->infile;

    if(!config->globoff && infiles) {
      /* Unless explicitly shut off */
      res = glob_url(&inglob, infiles, &infilenum,
                     config->showerror?
                     (config->errors?config->errors:stderr):NULL);
      if(res != CURLE_OK) {
        clean_getout(config);
        if(outfiles)
          free(outfiles);
        break;
      }
    }

    /* Here's the loop for uploading multiple files within the same
       single globbed string. If no upload, we enter the loop once anyway. */
    for(up = 0;
        (!up && !infiles) ||
          (uploadfile = inglob?
           glob_next_url(inglob):
           (!up?strdup(infiles):NULL));
        up++) {
      uploadfilesize=-1;

      if(!config->globoff) {
        /* Unless explicitly shut off, we expand '{...}' and '[...]'
           expressions and return total number of URLs in pattern set */
        res = glob_url(&urls, dourl, &urlnum,
                       config->showerror?
                       (config->errors?config->errors:stderr):NULL);
        if(res != CURLE_OK) {
          break;
        }
      }
      else
        urlnum = 1; /* without globbing, this is a single URL */

      /* if multiple files extracted to stdout, insert separators! */
      separator= ((!outfiles || curlx_strequal(outfiles, "-")) && urlnum > 1);

      /* Here's looping around each globbed URL */
      for(i = 0;
          (url = urls?glob_next_url(urls):(i?NULL:strdup(url)));
          i++) {
        char *outfile;
        outfile = outfiles?strdup(outfiles):NULL;

        if((urlnode->flags&GETOUT_USEREMOTE) ||
           (outfile && !curlx_strequal("-", outfile)) ) {

          /*
           * We have specified a file name to store the result in, or we have
           * decided we want to use the remote file name.
           */

          if(!outfile) {
            /* Find and get the remote file name */
            char * pc =strstr(url, "://");
            if(pc)
              pc+=3;
            else
              pc=url;
            pc = strrchr(pc, '/');

            if(pc) {
              /* duplicate the string beyond the slash */
              pc++;
              outfile = *pc ? strdup(pc): NULL;
            }
            if(!outfile || !*outfile) {
              helpf("Remote file name has no length!\n");
              res = CURLE_WRITE_ERROR;
              free(url);
              break;
            }
#if defined(__DJGPP__)
            {
              /* This is for DOS, and then we do some major replacing of
                 bad characters in the file name before using it */
              char file1 [PATH_MAX];

              strcpy(file1, msdosify(outfile));
              free (outfile);
              outfile = strdup (rename_if_dos_device_name(file1));
            }
#endif /* __DJGPP__ */
          }
          else if(urls) {
            /* fill '#1' ... '#9' terms from URL pattern */
            char *storefile = outfile;
            outfile = glob_match_url(storefile, urls);
            free(storefile);
            if(!outfile) {
              /* bad globbing */
              warnf(config, "bad output glob!\n");
              free(url);
              res = CURLE_FAILED_INIT;
              break;
            }
          }

          /* Create the directory hierarchy, if not pre-existant to a multiple
             file output call */

          if(config->create_dirs &&
             (-1 == create_dir_hierarchy(outfile)))
            return CURLE_WRITE_ERROR;

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

          if(config->resume_from) {
            outs.init = config->resume_from;
            /* open file for output: */
            outs.stream=(FILE *) fopen(outfile, config->resume_from?"ab":"wb");
            if (!outs.stream) {
              helpf("Can't open '%s'!\n", outfile);
              return CURLE_WRITE_ERROR;
            }
          }
          else {
            outs.stream = NULL; /* open when needed */
          }
        }
        infdfopen=FALSE;
        if(uploadfile && !curlx_strequal(uploadfile, "-")) {
          /*
           * We have specified a file to upload and it isn't "-".
           */
          struct_stat fileinfo;

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
            char *filep = strrchr(uploadfile, '/');
            char *file2 = strrchr(filep?filep:uploadfile, '\\');

            if(file2)
              filep = file2+1;
            else if(filep)
              filep++;
            else
              filep = uploadfile;

            /* URL encode the file name */
            filep = curl_escape(filep, 0 /* use strlen */);

            if(filep) {

              urlbuffer=(char *)malloc(strlen(url) + strlen(filep) + 3);
              if(!urlbuffer) {
                helpf("out of memory\n");
                return CURLE_OUT_OF_MEMORY;
              }
              if(ptr)
                /* there is a trailing slash on the URL */
                sprintf(urlbuffer, "%s%s", url, filep);
              else
                /* thers is no trailing slash on the URL */
                sprintf(urlbuffer, "%s/%s", url, filep);

              curl_free(filep);

              free(url);
              url = urlbuffer; /* use our new URL instead! */
            }
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

          infd=(FILE *) fopen(uploadfile, "rb");
          if (!infd || stat(uploadfile, &fileinfo)) {
            helpf("Can't open '%s'!\n", uploadfile);
            return CURLE_READ_ERROR;
          }
          infdfopen=TRUE;
          uploadfilesize=fileinfo.st_size;

        }
        else if(uploadfile && curlx_strequal(uploadfile, "-")) {
#ifdef O_BINARY
          setmode(fileno(stdin), O_BINARY);
#endif
          infd = stdin;
        }

        if(uploadfile && config->resume_from_current)
          config->resume_from = -1; /* -1 will then force get-it-yourself */

        if(output_expected(url, uploadfile)
           && outs.stream && isatty(fileno(outs.stream)))
          /* we send the output to a tty, therefore we switch off the progress
             meter */
          config->conf |= CONF_NOPROGRESS;

        if (urlnum > 1 && !(config->conf&CONF_MUTE)) {
          fprintf(stderr, "\n[%d/%d]: %s --> %s\n",
                  i+1, urlnum, url, outfile ? outfile : "<stdout>");
          if (separator)
            printf("%s%s\n", CURLseparator, url);
        }
        if (httpgetfields) {
          /* Find out whether the url contains a file name */
          const char *pc =strstr(url, "://");
          char sep='?';
          if(pc)
            pc+=3;
          else
            pc=url;

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
          urlbuffer=(char *)malloc(strlen(url) + strlen(httpgetfields) + 2);
          if(!urlbuffer) {
            helpf("out of memory\n");
            return CURLE_OUT_OF_MEMORY;
          }
          if (pc)
            sprintf(urlbuffer, "%s%c%s", url, sep, httpgetfields);
          else
            /* Append  / before the ? to create a well-formed url
               if the url contains a hostname only
            */
            sprintf(urlbuffer, "%s/?%s", url, httpgetfields);

          free(url); /* free previous URL */
          url = urlbuffer; /* use our new URL instead! */
        }

        if(!config->errors)
          config->errors = stderr;

#ifdef O_BINARY
        if(!outfile && !(config->conf & CONF_GETTEXT)) {
          /* We get the output to stdout and we have not got the ASCII/text flag,
             then set stdout to be binary */
          setmode( fileno(stdout), O_BINARY );
        }
#endif

        if(1 == config->tcp_nodelay)
          curl_easy_setopt(curl, CURLOPT_TCP_NODELAY, 1);

        /* where to store */
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, (FILE *)&outs);
        /* what call to write */
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, my_fwrite);

        /* for uploads */
        input.stream = infd;
        input.config = config;
        curl_easy_setopt(curl, CURLOPT_READDATA, &input);
        /* what call to read */
        curl_easy_setopt(curl, CURLOPT_READFUNCTION, my_fread);

        /* libcurl 7.12.3 business: */
        curl_easy_setopt(curl, CURLOPT_IOCTLDATA, &input);
        curl_easy_setopt(curl, CURLOPT_IOCTLFUNCTION, my_ioctl);

        if(config->recvpersecond) {
          /* tell libcurl to use a smaller sized buffer as it allows us to
             make better sleeps! 7.9.9 stuff! */
          curl_easy_setopt(curl, CURLOPT_BUFFERSIZE, config->recvpersecond);
        }

        /* size of uploaded file: */
        curl_easy_setopt(curl, CURLOPT_INFILESIZE_LARGE, uploadfilesize);
        curl_easy_setopt(curl, CURLOPT_URL, url);     /* what to fetch */
        curl_easy_setopt(curl, CURLOPT_PROXY, config->proxy); /* proxy to use */
        curl_easy_setopt(curl, CURLOPT_HEADER, config->conf&CONF_HEADER);
        curl_easy_setopt(curl, CURLOPT_NOPROGRESS, config->conf&CONF_NOPROGRESS);
        curl_easy_setopt(curl, CURLOPT_NOBODY, config->conf&CONF_NOBODY);
        curl_easy_setopt(curl, CURLOPT_FAILONERROR,
                         config->conf&CONF_FAILONERROR);
        curl_easy_setopt(curl, CURLOPT_UPLOAD, uploadfile?TRUE:FALSE);
        curl_easy_setopt(curl, CURLOPT_FTPLISTONLY,
                         config->conf&CONF_FTPLISTONLY);
        curl_easy_setopt(curl, CURLOPT_FTPAPPEND, config->conf&CONF_FTPAPPEND);

        if (config->conf&CONF_NETRC_OPT)
          curl_easy_setopt(curl, CURLOPT_NETRC, CURL_NETRC_OPTIONAL);
        else if (config->conf&CONF_NETRC)
          curl_easy_setopt(curl, CURLOPT_NETRC, CURL_NETRC_REQUIRED);
        else
          curl_easy_setopt(curl, CURLOPT_NETRC, CURL_NETRC_IGNORED);

        curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION,
                         config->conf&CONF_FOLLOWLOCATION);
        curl_easy_setopt(curl, CURLOPT_UNRESTRICTED_AUTH,
                         config->conf&CONF_UNRESTRICTED_AUTH);
        curl_easy_setopt(curl, CURLOPT_TRANSFERTEXT, config->conf&CONF_GETTEXT);
        curl_easy_setopt(curl, CURLOPT_USERPWD, config->userpwd);
        curl_easy_setopt(curl, CURLOPT_PROXYUSERPWD, config->proxyuserpwd);
        curl_easy_setopt(curl, CURLOPT_RANGE, config->range);
        curl_easy_setopt(curl, CURLOPT_ERRORBUFFER, errorbuffer);
        curl_easy_setopt(curl, CURLOPT_TIMEOUT, config->timeout);

        switch(config->httpreq) {
        case HTTPREQ_SIMPLEPOST:
          curl_easy_setopt(curl, CURLOPT_POSTFIELDS, config->postfields);
          curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, config->postfieldsize);
          break;
        case HTTPREQ_POST:
          curl_easy_setopt(curl, CURLOPT_HTTPPOST, config->httppost);
          break;
        default:
          break;
        }
        curl_easy_setopt(curl, CURLOPT_REFERER, config->referer);
        curl_easy_setopt(curl, CURLOPT_AUTOREFERER,
                         config->conf&CONF_AUTO_REFERER);
        curl_easy_setopt(curl, CURLOPT_USERAGENT, config->useragent);
        curl_easy_setopt(curl, CURLOPT_FTPPORT, config->ftpport);
        curl_easy_setopt(curl, CURLOPT_LOW_SPEED_LIMIT, config->low_speed_limit);
        curl_easy_setopt(curl, CURLOPT_LOW_SPEED_TIME, config->low_speed_time);
        curl_easy_setopt(curl, CURLOPT_RESUME_FROM_LARGE,
                         config->use_resume?config->resume_from:0);
        curl_easy_setopt(curl, CURLOPT_COOKIE, config->cookie);
        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, config->headers);
        curl_easy_setopt(curl, CURLOPT_SSLCERT, config->cert);
        curl_easy_setopt(curl, CURLOPT_SSLCERTTYPE, config->cert_type);
        curl_easy_setopt(curl, CURLOPT_SSLKEY, config->key);
        curl_easy_setopt(curl, CURLOPT_SSLKEYTYPE, config->key_type);
        curl_easy_setopt(curl, CURLOPT_SSLKEYPASSWD, config->key_passwd);

        /* default to strict verifyhost */
        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 2);
        if(config->cacert || config->capath) {
          if (config->cacert)
            curl_easy_setopt(curl, CURLOPT_CAINFO, config->cacert);

          if (config->capath)
            curl_easy_setopt(curl, CURLOPT_CAPATH, config->capath);
          curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, TRUE);
        }
        if(config->insecure_ok) {
          /* new stuff needed for libcurl 7.10 */
          curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, FALSE);
          curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 1);
        }

        if((config->conf&CONF_NOBODY) ||
           config->remote_time) {
          /* no body or use remote time */
          curl_easy_setopt(curl, CURLOPT_FILETIME, TRUE);
        }

        curl_easy_setopt(curl, CURLOPT_MAXREDIRS, config->maxredirs);
        curl_easy_setopt(curl, CURLOPT_CRLF, config->crlf);
        curl_easy_setopt(curl, CURLOPT_QUOTE, config->quote);
        curl_easy_setopt(curl, CURLOPT_POSTQUOTE, config->postquote);
        curl_easy_setopt(curl, CURLOPT_PREQUOTE, config->prequote);
        curl_easy_setopt(curl, CURLOPT_WRITEHEADER,
                         config->headerfile?&heads:NULL);
        curl_easy_setopt(curl, CURLOPT_COOKIEFILE, config->cookiefile);
        /* cookie jar was added in 7.9 */
        if(config->cookiejar)
          curl_easy_setopt(curl, CURLOPT_COOKIEJAR, config->cookiejar);
        /* cookie session added in 7.9.7 */
        curl_easy_setopt(curl, CURLOPT_COOKIESESSION, config->cookiesession);

        curl_easy_setopt(curl, CURLOPT_SSLVERSION, config->ssl_version);
        curl_easy_setopt(curl, CURLOPT_TIMECONDITION, config->timecond);
        curl_easy_setopt(curl, CURLOPT_TIMEVALUE, config->condtime);
        curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST, config->customrequest);
        curl_easy_setopt(curl, CURLOPT_STDERR, config->errors);

        /* three new ones in libcurl 7.3: */
        curl_easy_setopt(curl, CURLOPT_HTTPPROXYTUNNEL, config->proxytunnel);
        curl_easy_setopt(curl, CURLOPT_INTERFACE, config->iface);
        curl_easy_setopt(curl, CURLOPT_KRB4LEVEL, config->krb4level);

        progressbarinit(&progressbar, config);
        if((config->progressmode == CURL_PROGRESS_BAR) &&
           !(config->conf&(CONF_NOPROGRESS|CONF_MUTE))) {
          /* we want the alternative style, then we have to implement it
             ourselves! */
          curl_easy_setopt(curl, CURLOPT_PROGRESSFUNCTION, myprogress);
          curl_easy_setopt(curl, CURLOPT_PROGRESSDATA, &progressbar);
        }

        /* new in libcurl 7.6.2: */
        curl_easy_setopt(curl, CURLOPT_TELNETOPTIONS, config->telnet_options);

        /* new in libcurl 7.7: */
        curl_easy_setopt(curl, CURLOPT_RANDOM_FILE, config->random_file);
        curl_easy_setopt(curl, CURLOPT_EGDSOCKET, config->egd_file);
        curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, config->connecttimeout);

        if(config->cipher_list)
          curl_easy_setopt(curl, CURLOPT_SSL_CIPHER_LIST, config->cipher_list);

        if(config->httpversion)
          curl_easy_setopt(curl, CURLOPT_HTTP_VERSION, config->httpversion);

        /* new in libcurl 7.9.2: */
        if(config->disable_epsv)
          /* disable it */
          curl_easy_setopt(curl, CURLOPT_FTP_USE_EPSV, FALSE);

        /* new in libcurl 7.10.5 */
        if(config->disable_eprt)
          /* disable it */
          curl_easy_setopt(curl, CURLOPT_FTP_USE_EPRT, FALSE);

        /* new in libcurl 7.10.6 (default is Basic) */
        if(config->authtype)
          curl_easy_setopt(curl, CURLOPT_HTTPAUTH, config->authtype);

        /* new in curl 7.9.7 */
        if(config->trace_dump) {
          curl_easy_setopt(curl, CURLOPT_DEBUGFUNCTION, my_trace);
          curl_easy_setopt(curl, CURLOPT_DEBUGDATA, config);
          curl_easy_setopt(curl, CURLOPT_VERBOSE, TRUE);
        }

        res = CURLE_OK;

        /* new in curl ?? */
        if (config->engine) {
          res = curl_easy_setopt(curl, CURLOPT_SSLENGINE, config->engine);
          curl_easy_setopt(curl, CURLOPT_SSLENGINE_DEFAULT, 1);
        }

        if (res != CURLE_OK)
           goto show_error;

        /* new in curl 7.10 */
        curl_easy_setopt(curl, CURLOPT_ENCODING,
                         (config->encoding) ? "" : NULL);

        /* new in curl 7.10.7 */
        curl_easy_setopt(curl, CURLOPT_FTP_CREATE_MISSING_DIRS,
                         config->ftp_create_dirs);
        if(config->proxyanyauth)
          curl_easy_setopt(curl, CURLOPT_PROXYAUTH, CURLAUTH_ANY);
        else if(config->proxyntlm)
          curl_easy_setopt(curl, CURLOPT_PROXYAUTH, CURLAUTH_NTLM);
        else if(config->proxydigest)
          curl_easy_setopt(curl, CURLOPT_PROXYAUTH, CURLAUTH_DIGEST);
        else if(config->proxybasic)
          curl_easy_setopt(curl, CURLOPT_PROXYAUTH, CURLAUTH_BASIC);

        /* new in curl 7.10.8 */
        if(config->max_filesize)
          curl_easy_setopt(curl, CURLOPT_MAXFILESIZE_LARGE,
                           config->max_filesize);

        if(4 == config->ip_version)
          curl_easy_setopt(curl, CURLOPT_IPRESOLVE, CURL_IPRESOLVE_V4);
        else if(6 == config->ip_version)
          curl_easy_setopt(curl, CURLOPT_IPRESOLVE, CURL_IPRESOLVE_V6);
        else
          curl_easy_setopt(curl, CURLOPT_IPRESOLVE, CURL_IPRESOLVE_WHATEVER);

        /* new in curl 7.11.0 */
        if(config->ftp_ssl)
          curl_easy_setopt(curl, CURLOPT_FTP_SSL, CURLFTPSSL_TRY);

        /* new in curl 7.11.1, modified in 7.15.2 */
        if(config->socksproxy) {
          curl_easy_setopt(curl, CURLOPT_PROXY, config->socksproxy);
          curl_easy_setopt(curl, CURLOPT_PROXYTYPE, config->socksver);
        }

        /* curl 7.13.0 */
        curl_easy_setopt(curl, CURLOPT_SOURCE_URL, config->tp_url);
        curl_easy_setopt(curl, CURLOPT_SOURCE_USERPWD, config->tp_user);
        curl_easy_setopt(curl, CURLOPT_SOURCE_PREQUOTE, config->tp_prequote);
        curl_easy_setopt(curl, CURLOPT_SOURCE_POSTQUOTE, config->tp_postquote);
        curl_easy_setopt(curl, CURLOPT_SOURCE_QUOTE, config->tp_quote);
        curl_easy_setopt(curl, CURLOPT_FTP_ACCOUNT, config->ftp_account);

        curl_easy_setopt(curl, CURLOPT_IGNORE_CONTENT_LENGTH, config->ignorecl);

        /* curl 7.14.2 */
        curl_easy_setopt(curl, CURLOPT_FTP_SKIP_PASV_IP, config->ftp_skip_ip);

        /* curl 7.15.1 */
        curl_easy_setopt(curl, CURLOPT_FTP_FILEMETHOD, config->ftp_filemethod);

        /* curl 7.15.2 */
        if(config->localport) {
          curl_easy_setopt(curl, CURLOPT_LOCALPORT, config->localport);
          curl_easy_setopt(curl, CURLOPT_LOCALPORTRANGE, config->localportrange);
        }

        retry_numretries = config->req_retry;

        retrystart = curlx_tvnow();

        do {
          res = curl_easy_perform(curl);

          /* if retry-max-time is non-zero, make sure we haven't exceeded the
             time */
          if(retry_numretries &&
             (!config->retry_maxtime ||
              (curlx_tvdiff(curlx_tvnow(), retrystart)<
               config->retry_maxtime*1000)) ) {
            enum {
              RETRY_NO,
              RETRY_TIMEOUT,
              RETRY_HTTP,
              RETRY_FTP,
              RETRY_LAST /* not used */
            } retry = RETRY_NO;
            if(CURLE_OPERATION_TIMEDOUT == res)
              /* retry timeout always */
              retry = RETRY_TIMEOUT;
            else if(CURLE_OK == res) {
              /* Check for HTTP transient errors */
              char *url=NULL;
              curl_easy_getinfo(curl, CURLINFO_EFFECTIVE_URL, &url);
              if(url &&
                 curlx_strnequal(url, "http", 4)) {
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
            else if((CURLE_FTP_USER_PASSWORD_INCORRECT == res) ||
                    (CURLE_LOGIN_DENIED == res)) {
              curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &response);

              if(response/100 == 5)
                /*
                 * This is typically when the FTP server only allows a certain
                 * amount of users and we are not one of them. It mostly
                 * returns 530 in this case, but all 5xx codes are transient.
                 */
                retry = RETRY_FTP;
            }

            if(retry) {
              static const char * const m[]={NULL,
                                             "timeout",
                                             "HTTP error",
                                             "FTP error"
              };
              warnf(config, "Transient problem: %s "
                    "Will retry in %ld seconds. "
                    "%ld retries left.\n",
                    m[retry],
                    retry_sleep/1000,
                    retry_numretries);

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
                if(!(config->conf&CONF_MUTE))
                  fprintf(stderr, "Throwing away " CURL_FORMAT_OFF_T
                          " bytes\n", outs.bytes);
                fflush(outs.stream);
                /* truncate file at the position where we started appending */
#ifdef HAVE_FTRUNCATE
                ftruncate( fileno(outs.stream), outs.init);
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
              continue;
            }
          } /* if retry_numretries */

          /* In all ordinary cases, just break out of loop here */
          retry_sleep = retry_sleep_default;
          break;

        } while(1);

        if((config->progressmode == CURL_PROGRESS_BAR) &&
           progressbar.calls) {
          /* if the custom progress bar has been displayed, we output a
             newline here */
          fputs("\n", progressbar.out);
        }

        if(config->writeout) {
          ourWriteOut(curl, config->writeout);
        }
#ifdef USE_ENVIRONMENT
        if (config->writeenv)
          ourWriteEnv(curl);
#endif

show_error:

#ifdef  VMS
        if (!config->showerror)  {
          vms_show = VMSSTS_HIDE;
        }
#else
        if((res!=CURLE_OK) && config->showerror) {
          fprintf(config->errors, "curl: (%d) %s\n", (int)res,
                  errorbuffer[0]? errorbuffer:
                  curl_easy_strerror((CURLcode)res));
          if(CURLE_SSL_CACERT == res) {
#define CURL_CA_CERT_ERRORMSG1 \
"More details here: http://curl.haxx.se/docs/sslcerts.html\n\n" \
"curl performs SSL certificate verification by default, using a \"bundle\"\n" \
" of Certificate Authority (CA) public keys (CA certs). The default\n" \
" bundle is named curl-ca-bundle.crt; you can specify an alternate file\n" \
" using the --cacert option.\n"

#define CURL_CA_CERT_ERRORMSG2 \
"If this HTTPS server uses a certificate signed by a CA represented in\n" \
" the bundle, the certificate verification probably failed due to a\n" \
" problem with the certificate (it might be expired, or the name might\n" \
" not match the domain name in the URL).\n" \
"If you'd like to turn off curl's verification of the certificate, use\n" \
" the -k (or --insecure) option.\n"

            fprintf(config->errors, "%s%s",
                    CURL_CA_CERT_ERRORMSG1,
                    CURL_CA_CERT_ERRORMSG2 );
          }
        }
#endif

        if (outfile && !curlx_strequal(outfile, "-") && outs.stream)
          fclose(outs.stream);

#ifdef HAVE_UTIME
        /* Important that we set the time _after_ the file has been
           closed, as is done above here */
        if(config->remote_time && outs.filename) {
          /* ask libcurl if we got a time. Pretty please */
          long filetime;
          curl_easy_getinfo(curl, CURLINFO_FILETIME, &filetime);
          if(filetime >= 0) {
            struct utimbuf times;
            times.actime = (time_t)filetime;
            times.modtime = (time_t)filetime;
            utime(outs.filename, &times); /* set the time we got */
          }
        }
#endif
#ifdef AMIGA
        /* Set the url as comment for the file. (up to 80 chars are allowed)
         */
        if( strlen(url) > 78 )
          url[79] = '\0';

        SetComment( outs.filename, url);
#endif

        if(headerfilep)
          fclose(headerfilep);

        if(url)
          free(url);

        if(outfile)
          free(outfile);

        if(infdfopen)
          fclose(infd);

      } /* loop to the next URL */

      if(urls)
        /* cleanup memory used for URL globbing patterns */
        glob_cleanup(urls);

      if(uploadfile)
        free(uploadfile);

    } /* loop to the next globbed upload file */

    if(inglob) {
      glob_cleanup(inglob);
      inglob = NULL;
    }

    if(outfiles)
      free(outfiles);

    /* empty this urlnode struct */
    if(urlnode->url)
      free(urlnode->url);
    if(urlnode->outfile)
      free(urlnode->outfile);
    if(urlnode->infile)
      free(urlnode->infile);

    /* move on to the next URL */
    nextnode=urlnode->next;
    free(urlnode); /* free the node */
    urlnode = nextnode;

  } /* while-loop through all URLs */

quit_curl:
  if (httpgetfields)
    free(httpgetfields);

  if (config->engine)
    free(config->engine);

  /* cleanup the curl handle! */
  curl_easy_cleanup(curl);

  if(config->headerfile && !headerfilep && heads.stream)
    fclose(heads.stream);

  if(allocuseragent)
    free(config->useragent);

  if(config->trace_fopened && config->trace_stream)
    fclose(config->trace_stream);

  if(config->errors_fopened)
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
  while( fd[0] == STDIN_FILENO ||
         fd[0] == STDOUT_FILENO ||
         fd[0] == STDERR_FILENO ||
         fd[1] == STDIN_FILENO ||
         fd[1] == STDOUT_FILENO ||
         fd[1] == STDERR_FILENO )
    if (pipe(fd) < 0)
      return;	/* Out of handles. This isn't really a big problem now, but
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
  free_config_fields(&config);

#ifdef __NOVELL_LIBC__
  pressanykey();
#endif
#ifdef  VMS
  if (res > CURL_LAST) res = CURL_LAST; /* If CURL_LAST exceeded then */
  return (vms_cond[res]|vms_show);      /* curlmsg.h is out of sync.  */
#else
  return res;
#endif
}

static char *my_get_line(FILE *fp)
{
   char buf[4096];
   char *nl = NULL;
   char *retval = NULL;

   do {
     if (NULL == fgets(buf, sizeof(buf), fp))
       break;
     if (NULL == retval)
       retval = strdup(buf);
     else {
       if (NULL == (retval = realloc(retval,
                                     strlen(retval) + strlen(buf) + 1)))
         break;
       strcat(retval, buf);
     }
   }
   while (NULL == (nl = strchr(retval, '\n')));

   if (NULL != nl)
     *nl = '\0';

   return retval;
}


/* Create the needed directory hierarchy recursively in order to save
   multi-GETs in file output, ie:
   curl "http://my.site/dir[1-5]/file[1-5].txt" -o "dir#1/file#2.txt"
   should create all the dir* automagically
*/
static int create_dir_hierarchy(char *outfile)
{
  char *tempdir;
  char *tempdir2;
  char *outdup;
  char *dirbuildup;
  int result=0;

  outdup = strdup(outfile);
  dirbuildup = malloc(sizeof(char) * strlen(outfile));
  if(!dirbuildup)
    return -1;
  dirbuildup[0] = '\0';

  tempdir = strtok(outdup, DIR_CHAR);

  while (tempdir != NULL) {
    tempdir2 = strtok(NULL, DIR_CHAR);
    /* since strtok returns a token for the last word even
       if not ending with DIR_CHAR, we need to prune it */
    if (tempdir2 != NULL) {
      if (strlen(dirbuildup) > 0)
        sprintf(dirbuildup,"%s%s%s",dirbuildup, DIR_CHAR, tempdir);
      else {
        if (0 != strncmp(outdup, DIR_CHAR, 1))
          sprintf(dirbuildup,"%s",tempdir);
        else
          sprintf(dirbuildup,"%s%s", DIR_CHAR, tempdir);
      }
      if (access(dirbuildup, F_OK) == -1) {
        result = mkdir(dirbuildup,(mode_t)0000750);
        if (-1 == result) {
          switch (errno) {
#ifdef EACCES
          case EACCES:
            fprintf(stderr,"You don't have permission to create %s.\n",
                    dirbuildup);
            break;
#endif
#ifdef ENAMETOOLONG
          case ENAMETOOLONG:
            fprintf(stderr,"The directory name %s is too long.\n",
                    dirbuildup);
            break;
#endif
#ifdef EROFS
          case EROFS:
            fprintf(stderr,"%s resides on a read-only file system.\n",
                    dirbuildup);
            break;
#endif
#ifdef ENOSPC
          case ENOSPC:
            fprintf(stderr,"No space left on the file system that will "
                    "contain the directory %s.\n", dirbuildup);
            break;
#endif
#ifdef EDQUOT
          case EDQUOT:
            fprintf(stderr,"Cannot create directory %s because you "
                    "exceeded your quota.\n", dirbuildup);
            break;
#endif
          default :
            fprintf(stderr,"Error creating directory %s.\n", dirbuildup);
            break;
          }
          break; /* get out of loop */
        }
      }
    }
    tempdir = tempdir2;
  }
  free(dirbuildup);
  free(outdup);

  return result; /* 0 is fine, -1 is badness */
}

#ifdef __DJGPP__
/* The following functions are taken with modification from the DJGPP
 * port of tar 1.12. They use algorithms originally from DJTAR. */

char *
msdosify (char *file_name)
{
  static char dos_name[PATH_MAX];
  static const char illegal_chars_dos[] = ".+, ;=[]|<>\\\":?*";
  static const char *illegal_chars_w95 = &illegal_chars_dos[8];
  int idx, dot_idx;
  char *s = file_name, *d = dos_name;
  const char *illegal_aliens = illegal_chars_dos;
  size_t len = sizeof (illegal_chars_dos) - 1;
  int lfn = 0;

  /* Support for Windows 9X VFAT systems, when available.  */
  if (_use_lfn (file_name))
    lfn = 1;
  if (lfn) {
    illegal_aliens = illegal_chars_w95;
    len -= (illegal_chars_w95 - illegal_chars_dos);
  }

  /* Get past the drive letter, if any. */
  if (s[0] >= 'A' && s[0] <= 'z' && s[1] == ':') {
    *d++ = *s++;
    *d++ = *s++;
  }

  for (idx = 0, dot_idx = -1; *s; s++, d++) {
    if (memchr (illegal_aliens, *s, len)) {
      /* Dots are special: DOS doesn't allow them as the leading character,
         and a file name cannot have more than a single dot.  We leave the
         first non-leading dot alone, unless it comes too close to the
         beginning of the name: we want sh.lex.c to become sh_lex.c, not
         sh.lex-c.  */
      if (*s == '.') {
        if (idx == 0 && (s[1] == '/' || (s[1] == '.' && s[2] == '/'))) {
          /* Copy "./" and "../" verbatim.  */
          *d++ = *s++;
          if (*s == '.')
            *d++ = *s++;
          *d = *s;
        }
        else if (idx == 0)
          *d = '_';
        else if (dot_idx >= 0) {
          if (dot_idx < 5) { /* 5 is a heuristic ad-hoc'ery */
            d[dot_idx - idx] = '_'; /* replace previous dot */
            *d = '.';
          }
          else
            *d = '-';
        }
        else
          *d = '.';

        if (*s == '.')
          dot_idx = idx;
      }
      else if (*s == '+' && s[1] == '+') {
        if (idx - 2 == dot_idx) { /* .c++, .h++ etc. */
          *d++ = 'x';
          *d   = 'x';
        }
        else {
          /* libg++ etc.  */
          memcpy (d, "plus", 4);
          d += 3;
        }
        s++;
        idx++;
      }
      else
        *d = '_';
    }
    else
      *d = *s;
    if (*s == '/') {
      idx = 0;
      dot_idx = -1;
    }
    else
      idx++;
  }

  *d = '\0';
  return dos_name;
}

char *
rename_if_dos_device_name (char *file_name)
{
  /* We could have a file whose name is a device on MS-DOS.  Trying to
   * retrieve such a file would fail at best and wedge us at worst.  We need
   * to rename such files. */
  char *base;
  struct stat st_buf;
  char fname[PATH_MAX];

  strcpy (fname, file_name);
  base = basename (fname);
  if (((stat(base, &st_buf)) == 0) && (S_ISCHR(st_buf.st_mode))) {
    size_t blen = strlen (base);

    /* Prepend a '_'.  */
    memmove (base + 1, base, blen + 1);
    base[0] = '_';
    strcpy (file_name, fname);
  }
  return file_name;
}

#endif /* __DJGPP__ */
