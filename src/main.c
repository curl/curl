/***************************************************************************
 *                                  _   _ ____  _     
 *  Project                     ___| | | |  _ \| |    
 *                             / __| | | | |_) | |    
 *                            | (__| |_| |  _ <| |___ 
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) 1998 - 2002, Daniel Stenberg, <daniel@haxx.se>, et al.
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

/* This is now designed to have its own local setup.h */
#include "setup.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <ctype.h>
#include <sys/errno.h>

#include <curl/curl.h>

#define _MPRINTF_REPLACE /* we want curl-functions instead of native ones */
#include <curl/mprintf.h>

#include "urlglob.h"
#include "writeout.h"
#ifdef USE_ENVIRONMENT
#include "writeenv.h"
#endif

#define CURLseparator	"--_curl_--"

#if defined(WIN32)&&!defined(__CYGWIN32__)
#include <winsock.h>
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

#endif

#ifdef HAVE_SYS_POLL_H
#include <sys/poll.h>
#endif

/* The last #include file should be: */
#ifdef MALLOCDEBUG
/* this is low-level hard-hacking memory leak tracking shit */
#include "../lib/memdebug.h"
#endif

#define DEFAULT_MAXREDIRS  50L

#ifndef __cplusplus        /* (rabe) */
#ifndef typedef_bool
typedef char bool;
#endif
#endif                     /* (rabe) */

#define CURL_PROGRESS_STATS 0 /* default progress display */
#define CURL_PROGRESS_BAR   1

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
#define CONF_VERBOSE  (1<<5) /* talk a lot */
#define CONF_HEADER   (1<<8) /* throw the header out too */
#define CONF_NOPROGRESS (1<<10) /* shut off the progress meter */
#define CONF_NOBODY   (1<<11) /* use HEAD to get http document */
#define CONF_FAILONERROR (1<<12) /* no output on http error codes >= 300 */
#define CONF_UPLOAD   (1<<14) /* this is an upload */
#define CONF_FTPLISTONLY (1<<16) /* Use NLST when listing ftp dir */
#define CONF_FTPAPPEND (1<<20) /* Append instead of overwrite on upload! */
#define CONF_NETRC    (1<<22)  /* read user+password from .netrc */
#define CONF_FOLLOWLOCATION (1<<23) /* use Location: Luke! */
#define CONF_GETTEXT  (1<<24) /* use ASCII/text for transfer */
#define CONF_HTTPPOST (1<<25) /* multipart/form-data HTTP POST */

#define CONF_MUTE     (1<<28) /* force NOPROGRESS */

#define CONF_NETRC_OPT (1<<29)  /* read user+password from either
                                 * .netrc or URL*/

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

#ifdef	VMS
int	vms_show = 0;
#define	FAC_CURL	0xC01
#define	FAC_SYSTEM	0
#define	MSG_NORMAL	0
#define	VMS_STS(c,f,e,s) (((c&0xF)<<28)|((f&0xFFF)<<16)|((e&0x1FFF)<3)|(s&7))
#define	VMSSTS_HIDE	VMS_STS(1,0,0,0)
#define	SEV_WARNING	0
#define	SEV_SUCCESS	1
#define	SEV_ERROR	2
#define	SEV_INFO	3	/* success, with an extra hint */
#define	SEV_FATAL	4
globalvalue int  CURL_UNSUPPROTO;		/* these are from curlmsg.msg file..... */
globalvalue int  CURL_FAILINIT;
globalvalue int  CURL_BADURLSYN;
globalvalue int  CURL_BADURLUSER;
globalvalue int  CURL_BADPROXY;
globalvalue int  CURL_BADHOST;
globalvalue int  CURL_FAILHOST;
globalvalue int  CURL_FTPUNKREPLY;
globalvalue int  CURL_FTPNOACC;
globalvalue int  CURL_FTPUSRPW;
globalvalue int  CURL_FTPBADPASS;
globalvalue int  CURL_FTPBADUSER;
globalvalue int  CURL_FTPBADPASV;
globalvalue int  CURL_FTPBAD227;
globalvalue int  CURL_FTPBADHOST227;
globalvalue int  CURL_FTPNORECONN;
globalvalue int  CURL_FTPNOBIN;
globalvalue int  CURL_PARTIALFILE;
globalvalue int  CURL_FTPNORETR;
globalvalue int  CURL_FTPWRITERR;
globalvalue int  CURL_FTPNOQUOTE;
globalvalue int  CURL_HTTPPNF;
globalvalue int  CURL_WRITERR;
globalvalue int  CURL_BADUSER;
globalvalue int  CURL_FTPNOSTOR;
globalvalue int  CURL_READERR;
globalvalue int  CURL_OUTOFMEM;
globalvalue int  CURL_TIMEOUT;
globalvalue int  CURL_FTPNOASCII;
globalvalue int  CURL_FTPNOPORT;
globalvalue int  CURL_FTPNOREST;
globalvalue int  CURL_FTPNOSIZE;
globalvalue int  CURL_HTTPRNGERR;
globalvalue int  CURL_HTTPPOSTERR;
globalvalue int  CURL_SSLNOCONN;
globalvalue int  CURL_FTPBADRESUME;
globalvalue int  CURL_FILENOACC;
globalvalue int  CURL_LDAPNOBIND;
globalvalue int  CURL_LDAPNOSRCH;
globalvalue int  CURL_LDAPNOLIB;
globalvalue int  CURL_LDAPNOFUNC;
globalvalue int  CURL_ABORTCB;
globalvalue int  CURL_BADPARAM;
globalvalue int  CURL_BADORDER;
globalvalue int  CURL_BADPWD;
globalvalue int  CURL_MNYREDIR;
globalvalue int  CURL_UNKTELNET;
globalvalue int  CURL_UNKMSG;
globalvalue int  CURL_BADSSLCERT;
globalvalue int  CURL_SRVNOERR;
globalvalue int  CURL_MAXMSG;
long	vms_cond[] = {
	VMS_STS(1,FAC_SYSTEM,MSG_NORMAL,SEV_SUCCESS),
	CURL_UNSUPPROTO,		/* these are from curlmsg.msg file..... */
	CURL_FAILINIT,
	CURL_BADURLSYN,
	CURL_BADURLUSER,
	CURL_BADPROXY,
	CURL_BADHOST,
	CURL_FAILHOST,
	CURL_FTPUNKREPLY,
	CURL_FTPNOACC,
	CURL_FTPUSRPW,
	CURL_FTPBADPASS,
	CURL_FTPBADUSER,
	CURL_FTPBADPASV,
	CURL_FTPBAD227,
	CURL_FTPBADHOST227,
	CURL_FTPNORECONN,
	CURL_FTPNOBIN,
	CURL_PARTIALFILE,
	CURL_FTPNORETR,
	CURL_FTPWRITERR,
	CURL_FTPNOQUOTE,
	CURL_HTTPPNF,
	CURL_WRITERR,
	CURL_BADUSER,
	CURL_FTPNOSTOR,
	CURL_READERR,
	CURL_OUTOFMEM,
	CURL_TIMEOUT,
	CURL_FTPNOASCII,
	CURL_FTPNOPORT,
	CURL_FTPNOREST,
	CURL_FTPNOSIZE,
	CURL_HTTPRNGERR,
	CURL_HTTPPOSTERR,
	CURL_SSLNOCONN,
	CURL_FTPBADRESUME,
	CURL_FILENOACC,
	CURL_LDAPNOBIND,
	CURL_LDAPNOSRCH,
	CURL_LDAPNOLIB,
	CURL_LDAPNOFUNC,
	CURL_ABORTCB,
	CURL_BADPARAM,
	CURL_BADORDER,
	CURL_BADPWD,
	CURL_MNYREDIR,
	CURL_UNKTELNET,
	CURL_UNKMSG,
	CURL_BADSSLCERT,
	CURL_SRVNOERR,
	CURL_MAXMSG
};
#endif

extern void hugehelp(void);

/*
 * This is the main global constructor for the app. Call this before
 * _any_ libcurl usage. If this fails, *NO* libcurl functions may be
 * used, or havoc may be the result.
 */
CURLcode main_init(void)
{
  return curl_global_init(CURL_GLOBAL_DEFAULT);
}

/*
 * This is the main global destructor for the app. Call this after
 * _all_ libcurl usage is done.
 */
void main_free(void)
{
  curl_global_cleanup();
}

int SetHTTPrequest(HttpReq req, HttpReq *store)
{
  if((*store == HTTPREQ_UNSPEC) ||
     (*store == req)) {
    *store = req;
    return 0;
  }
  fprintf(stderr, "You can only select one HTTP request!\n");
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
  fprintf(stderr, "curl: try 'curl --help' for more information\n");
}

/*
 * A chain of these nodes contain URL to get and where to put the URL's
 * contents.
 */
struct getout {
  struct getout *next;
  char *url;
  char *outfile;
  int flags;
};
#define GETOUT_OUTFILE (1<<0) /* set when outfile is deemed done */
#define GETOUT_URL     (1<<1) /* set when URL is deemed done */
#define GETOUT_USEREMOTE (1<<2) /* use remote file name locally */

static void help(void)
{
  printf(CURL_ID "%s\n"
       "Usage: curl [options...] <url>\n"
       "Options: (H) means HTTP/HTTPS only, (F) means FTP only\n"
       " -a/--append        Append to target file when uploading (F)\n"
       " -A/--user-agent <string> User-Agent to send to server (H)\n"
       " -b/--cookie <name=string/file> Cookie string or file to read cookies from (H)\n"
       " -B/--use-ascii     Use ASCII/text transfer\n",
         curl_version());
  puts(" -c/--cookie-jar <file> Write all cookies to this file after operation (H)\n"
       " -C/--continue-at <offset> Specify absolute resume offset\n"
       " -d/--data <data>   HTTP POST data (H)\n"
       "    --data-ascii <data>   HTTP POST ASCII data (H)\n"
       "    --data-binary <data>  HTTP POST binary data (H)\n"
       "    --disable-epsv  Prevents curl from using EPSV (F)\n"
       " -D/--dump-header <file> Write the headers to this file\n"
       "    --egd-file <file> EGD socket path for random data (SSL)\n"
#ifdef USE_ENVIRONMENT
       "    --environment   Write result codes to environment variables (RISC OS)\n"
#endif
       " -e/--referer       Referer page (H)");
  puts(" -E/--cert <cert[:passwd]> Specifies your certificate file and password (HTTPS)\n"
       "    --cert-type <type> Specifies certificate file type (DER/PEM/ENG) (HTTPS)\n"
       "    --key <key>     Specifies private key file (HTTPS)\n"
       "    --key-type <type> Specifies private key  file type (DER/PEM/ENG) (HTTPS)\n"
       "    --pass  <pass>  Specifies passphrase for the private key (HTTPS)");
  puts("    --engine <eng>  Specifies the crypto engine to use (HTTPS)\n"
       "    --cacert <file> CA certifciate to verify peer against (SSL)\n"
       "    --capath <directory> CA directory (made using c_rehash) to verify\n"
       "                    peer against (SSL, NOT Windows)\n"
       "    --ciphers <list> What SSL ciphers to use (SSL)\n"
       "    --compressed    Request a compressed response (using deflate).");
  puts("    --connect-timeout <seconds> Maximum time allowed for connection\n"
       "    --create-dirs   Create the necessary local directory hierarchy\n"
       "    --crlf          Convert LF to CRLF in upload. Useful for MVS (OS/390)\n"
       " -f/--fail          Fail silently (no output at all) on errors (H)\n"
       " -F/--form <name=content> Specify HTTP POST data (H)\n"
       " -g/--globoff       Disable URL sequences and ranges using {} and []\n"
       " -G/--get           Send the -d data with a HTTP GET (H)");
  puts(" -h/--help          This help text\n"
       " -H/--header <line> Custom header to pass to server. (H)\n"
       " -i/--include       Include the HTTP-header in the output (H)\n"
       " -I/--head          Fetch document info only (HTTP HEAD/FTP SIZE)");
  puts(" -j/--junk-session-cookies Ignore session cookies read from file (H)\n"
       "    --interface <interface> Specify the interface to be used\n"
       "    --krb4 <level>  Enable krb4 with specified security level (F)\n"
       " -k/--insecure      Allow curl to connect to SSL sites without certs (H)\n"
       " -K/--config        Specify which config file to read\n"
       " -l/--list-only     List only names of an FTP directory (F)\n"
       "    --limit-rate <rate> Limit how fast transfers to allow");
  puts(" -L/--location      Follow Location: hints (H)\n"
       " -m/--max-time <seconds> Maximum time allowed for the transfer\n"
       " -M/--manual        Display huge help text\n"
       " -n/--netrc         Must read .netrc for user name and password\n"
       "    --netrc-optional  Use either .netrc or URL; overrides -n\n"
       " -N/--no-buffer     Disables the buffering of the output stream");
  puts(" -o/--output <file> Write output to <file> instead of stdout\n"
       " -O/--remote-name   Write output to a file named as the remote file\n"
       " -p/--proxytunnel   Perform non-HTTP services through a HTTP proxy\n"
       " -P/--ftpport <address> Use PORT with address instead of PASV when ftping (F)\n"
       " -q                 When used as the first parameter disables .curlrc\n"
       " -Q/--quote <cmd>   Send QUOTE command to FTP before file transfer (F)");
  puts(" -r/--range <range> Retrieve a byte range from a HTTP/1.1 or FTP server\n"
       " -R/--remote-time   Set the remote file's time on the local output\n"
       " -s/--silent        Silent mode. Don't output anything\n"
       " -S/--show-error    Show error. With -s, make curl show errors when they occur");
  puts("    --stderr <file> Where to redirect stderr. - means stdout.\n"
       " -t/--telnet-option <OPT=val> Set telnet option\n"
       "    --trace <file>  Dump a network/debug trace to the given file\n"
       "    --trace-ascii <file>  Like --trace but without the hex output\n"
       " -T/--upload-file <file> Transfer/upload <file> to remote site\n"
       "    --url <URL>     Another way to specify URL to work with");
  puts(" -u/--user <user[:password]> Specify user and password to use\n"
       "                    Overrides -n and --netrc-optional\n"
       " -U/--proxy-user <user[:password]> Specify Proxy authentication\n"
       " -v/--verbose       Makes the operation more talkative\n"
       " -V/--version       Outputs version number then quits");
  puts(" -w/--write-out [format] What to output after completion\n"
       " -x/--proxy <host[:port]>  Use proxy. (Default port is 1080)\n"
       "    --random-file <file> File to use for reading random data from (SSL)\n"
       " -X/--request <command> Specific request command to use");
  puts(" -y/--speed-time    Time needed to trig speed-limit abort. Defaults to 30\n"
       " -Y/--speed-limit   Stop transfer if below speed-limit for 'speed-time' secs\n"
       " -z/--time-cond <time> Includes a time condition to the server (H)\n"
       " -Z/--max-redirs <num> Set maximum number of redirections allowed (H)\n"
       " -0/--http1.0       Force usage of HTTP 1.0 (H)\n"
       " -1/--tlsv1         Force usage of TLSv1 (H)\n"
       " -2/--sslv2         Force usage of SSLv2 (H)\n"
       " -3/--sslv3         Force usage of SSLv3 (H)");
  puts(" -#/--progress-bar  Display transfer progress as a progress bar");
}

struct LongShort {
  const char *letter;
  const char *lname;
  bool extraparam;
};

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
  bool use_resume;
  bool resume_from_current;
  bool disable_epsv;
  int resume_from;
  char *postfields;
  long postfieldsize;
  char *referer;
  long timeout;
  long connecttimeout;
  long maxredirs;
  char *headerfile;
  char *ftpport;
  char *iface;
  unsigned short porttouse;
  char *range;
  int low_speed_limit;
  int low_speed_time;
  bool showerror;
  char *infile;
  char *userpwd;
  char *proxyuserpwd;
  char *proxy;
  bool configread;
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
  bool crlf;
  char *customrequest;
  char *krb4level;
  char *trace_dump; /* file to dump the network trace to, or NULL */
  FILE *trace_stream;
  bool trace_fopened;
  bool trace_ascii;

  long httpversion;
  bool progressmode;
  bool nobuffer;
  bool globoff;
  bool use_httpget;
  bool insecure_ok; /* set TRUE to allow insecure SSL connects */
  bool create_dirs;

  char *writeout; /* %-styled format string to output */
  bool writeenv; /* write results to environment, if available */

  FILE *errors; /* if stderr redirect is requested */
  bool errors_fopened;

  struct curl_slist *quote;
  struct curl_slist *postquote;
  struct curl_slist *prequote;

  long ssl_version;
  curl_TimeCond timecond;
  time_t condtime;

  struct curl_slist *headers;

  struct curl_httppost *httppost;
  struct curl_httppost *last_post;

  struct curl_slist *telnet_options;
        
  HttpReq httpreq;

  /* for bandwidth limiting features: */

  size_t sendpersecond; /* send to peer */
  size_t recvpersecond; /* receive from peer */

  time_t lastsendtime;
  size_t lastsendsize;

  time_t lastrecvtime;
  size_t lastrecvsize;
};

static int parseconfig(const char *filename,
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
  int len=0;
  int stringlen;

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
  long len=0;
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

void clean_getout(struct Configurable *config)
{
  struct getout *node=config->url_list;
  struct getout *next;

  while(node) {
    next = node->next;
    if(node->url)
      free(node->url);
    if(node->outfile)
      free(node->outfile);
    free(node);

    node = next; /* GOTO next */
  }
}

struct getout *new_getout(struct Configurable *config)
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

/***************************************************************************
 *
 * formparse()
 *	
 * Reads a 'name=value' paramter and builds the appropriate linked list.
 *
 * Specify files to upload with 'name=@filename'. Supports specified
 * given Content-Type of the files. Such as ';type=<content-type>'.
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

static int formparse(char *input,
                     struct curl_httppost **httppost,
                     struct curl_httppost **last_post)
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

  /* Preallocate contents to the length of input to make sure we don't
     overwrite anything. */
  contents = malloc(strlen(input));
  contents[0] = '\000';
 
  if(1 <= sscanf(input, "%255[^=]=%[^\n]", name, contents)) {
    /* the input was using the correct format */
    contp = contents;

    if('@' == contp[0]) {
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

            if(curl_strnequal("type=", ptr, 5)) {

              /* set type pointer */
              type = &ptr[5];
	    
              /* verify that this is a fine type specifier */
              if(2 != sscanf(type, "%127[^/]/%127[^;,\n]",
                             major, minor)) {
                fprintf(stderr, "Illegally formatted content-type field!\n");
                free(contents);
                FreeMultiInfo (multi_start);
                return 2; /* illegal content-type syntax! */
              }
              /* now point beyond the content-type specifier */
              sep = (char *)type + strlen(major)+strlen(minor)+1;

              *sep=0; /* zero terminate type string */

              ptr=sep+1;
            }
            else if(curl_strnequal("filename=", ptr, 9)) {
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
          fprintf(stderr, "Error building form post!\n");
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
        if (curl_formadd (httppost, last_post,
                          CURLFORM_COPYNAME, name,
                          CURLFORM_ARRAY, forms, CURLFORM_END) != 0) {
          fprintf(stderr, "curl_formadd failed!\n");
          free(forms);
          free(contents);
          return 5;
        }
        free(forms);
      }
    }
    else {
      if( contp[0]=='<' ) {
        if (curl_formadd (httppost, last_post,
                          CURLFORM_COPYNAME, name,
                          CURLFORM_FILECONTENT, contp+1, CURLFORM_END) != 0) {
          fprintf(stderr, "curl_formadd failed!\n");
          free(contents);
          return 6;
        }
      }
      else {
        if (curl_formadd (httppost, last_post,
                          CURLFORM_COPYNAME, name,
                          CURLFORM_COPYCONTENTS, contp, CURLFORM_END) != 0) {
          fprintf(stderr, "curl_formadd failed!\n");
          free(contents);
          return 7;
        }
      }
    }

  }
  else {
    fprintf(stderr, "Illegally formatted input field!\n");
    free(contents);
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

  PARAM_LAST
} ParameterError;

static ParameterError getparameter(char *flag, /* f or -long-flag */
                                   char *nextarg, /* NULL if unset */
                                   bool *usedarg, /* set to TRUE if the arg
                                                     has been used */
                                   struct Configurable *config)
{
  char letter;
  char subletter=0; /* subletters can only occur on long options */

  const char *parse=NULL;
  int res;
  unsigned int j;
  time_t now;
  int hit=-1;
  bool longopt=FALSE;
  bool singleopt=FALSE; /* when true means '-o foo' used '-ofoo' */


  /* single-letter,
     long-name,
     boolean whether it takes an additional argument
     */
  struct LongShort aliases[]= {
    {"9", "crlf",        FALSE},
    {"8", "stderr",      TRUE},
    {"7", "interface",   TRUE},
    {"6", "krb4",        TRUE},
    /* all these ones, starting with 5 as a short-option have *no* short
       option to mention. */
    {"5", "url",         TRUE},
    {"5a", "random-file", TRUE},
    {"5b", "egd-file",   TRUE},
    {"5c", "connect-timeout", TRUE},
    {"5d", "ciphers",    TRUE},
    {"5e", "disable-epsv", FALSE},
#ifdef USE_ENVIRONMENT
    {"5f", "environment", FALSE},
#endif
    {"5g", "trace",      TRUE},
    {"5h", "trace-ascii", TRUE},
    {"5i", "limit-rate", TRUE},
    {"5j", "compressed",  FALSE}, /* might take an arg someday */
    {"0", "http1.0",     FALSE},
    {"1", "tlsv1",       FALSE},
    {"2", "sslv2",       FALSE},
    {"3", "sslv3",       FALSE},
    {"a", "append",      FALSE},
    {"A", "user-agent",  TRUE},
    {"b", "cookie",      TRUE},
    {"B", "ftp-ascii",   FALSE}, /* this long format is OBSOLETE now! */
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
    {"m", "max-time",    TRUE},
    {"M", "manual",      FALSE},
    {"n", "netrc",       FALSE},
    {"no", "netrc-optional", FALSE},
    {"N", "no-buffer",   FALSE},
    {"o", "output",      TRUE},
    {"O", "remote-name", FALSE},
    {"p", "proxytunnel", FALSE},
    {"P", "ftpport",     TRUE},
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
    {"Z", "max-redirs",   TRUE},
    {"#", "progress-bar",FALSE},
    {"@", "create-dirs", FALSE},
  };

  if(('-' != flag[0]) ||
     (('-' == flag[0]) && ('-' == flag[1]))) {
    /* this should be a long name */
    char *word=('-' == flag[0])?flag+2:flag;
    int fnam=strlen(word);
    int numhits=0;
    for(j=0; j< sizeof(aliases)/sizeof(aliases[0]); j++) {
      if(strnequal(aliases[j].lname, word, fnam)) {
        longopt = TRUE;
        numhits++;
        if(strequal(aliases[j].lname, word)) {
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

    if(!longopt)
      letter = parse?*parse:'\0';
    else {
      letter = parse[0];
      subletter = parse[1];
    }
    *usedarg = FALSE; /* default is that we don't use the arg */

#if 0
    fprintf(stderr, "OPTION: %c %s\n", letter, nextarg?nextarg:"<null>");
#endif
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
    case '9': /* there is no short letter for this */
      /* LF -> CRLF conversinon? */
      config->crlf = TRUE;
      break;
    case '8': /* there is no short letter for this */
      if(strcmp(nextarg, "-")) {
        config->errors = fopen(nextarg, "wt");
        config->errors_fopened = TRUE;
      }
      else
        config->errors = stdout;
      break;
    case '7': /* there is no short letter for this */
      /* interface */
      GetStr(&config->iface, nextarg);
      break;
    case '6': /* there is no short letter for this */
      /* krb4 level string */
      GetStr(&config->krb4level, nextarg);
      break;
    case '5':
      switch(subletter) {
      case 'a': /* random-file */
        GetStr(&config->random_file, nextarg);
        break;
      case 'b': /* egd-file */
        GetStr(&config->egd_file, nextarg);
        break;
      case 'c': /* connect-timeout */
        config->connecttimeout=atoi(nextarg);
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
        break;
      case 'h': /* --trace-ascii */
        GetStr(&config->trace_dump, nextarg);
        config->trace_ascii = TRUE;
        break;
      case 'i': /* --limit-rate */
        {
          /* We support G, M, K too */
          char *unit;
          unsigned long value = strtol(nextarg, &unit, 0);
          switch(nextarg[strlen(nextarg)-1]) {
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
          }
          config->recvpersecond = value;
          config->sendpersecond = value;
        }
        break;

      case 'j': /* --compressed */
 	config->encoding ^= TRUE;
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
    case '#': /* added 19990617 larsa */
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
      if(!strequal(nextarg, "-")) {
        config->resume_from= atoi(nextarg);
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

          if(strequal("-", nextarg))
            file = stdin;
          else 
            file = fopen(nextarg, "rb");

          if(subletter == 'b') /* forced binary */
            postdata = file2memory(file, &config->postfieldsize);
          else
            postdata = file2string(file);
          if(file && (file != stdin))
            fclose(file);
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
        break;
      case 'f': /* crypto engine */
        GetStr(&config->engine, nextarg);
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
             (nextarg[2] == '\\') &&
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
      if(formparse(nextarg,
                   &config->httppost,
                   &config->last_post))
	return PARAM_BAD_USE;
      if(SetHTTPrequest(HTTPREQ_POST, &config->httpreq))
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
      config->headers = curl_slist_append(config->headers, nextarg);
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
        if(SetHTTPrequest(HTTPREQ_HEAD, &config->httpreq))
          return PARAM_BAD_USE;
      }
      else {
        /* both were set, clear both */
        config->conf &= ~(CONF_HEADER|CONF_NOBODY);
        if(SetHTTPrequest(HTTPREQ_GET, &config->httpreq))
          return PARAM_BAD_USE;
      }
      break;
    case 'k': /* allow insecure SSL connects */
      config->insecure_ok ^= TRUE;
      break;
    case 'K': /* parse config file */
      res = parseconfig(nextarg, config);
      config->configread = TRUE;
      if(res)
	return res;
      break;
    case 'l':
      config->conf ^= CONF_FTPLISTONLY; /* only list the names of the FTP dir */
      break;
    case 'L':
      config->conf ^= CONF_FOLLOWLOCATION; /* Follow Location: HTTP headers */
      break;
    case 'm':
      /* specified max time */
      config->timeout = atoi(nextarg);
      break;
    case 'M': /* M for manual, huge help */
      hugehelp();
      return PARAM_HELP_REQUESTED;
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
      switch(nextarg[0]) {
      case '-':
        /* prefixed with a dash makes it a POST TRANSFER one */
        nextarg++;
        config->postquote = curl_slist_append(config->postquote, nextarg);
        break;
      case '+':
        /* prefixed with a plus makes it a just-before-transfer one */
        nextarg++;
        config->prequote = curl_slist_append(config->prequote, nextarg);
        break;
      default:
        config->quote = curl_slist_append(config->quote, nextarg);
      }
      break;
    case 'r':
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
      config->telnet_options =
        curl_slist_append(config->telnet_options, nextarg);
      break;
    case 'T':
      /* we are uploading */
      config->conf |= CONF_UPLOAD;
      if(!strequal("-", nextarg))
        /* make - equal stdin */
        GetStr(&config->infile, nextarg);
      break;
    case 'u':
      /* user:password  */
      GetStr(&config->userpwd, nextarg);
      break;
    case 'U':
      /* Proxy user:password  */
      GetStr(&config->proxyuserpwd, nextarg);
      break;
    case 'v':
      config->conf ^= CONF_VERBOSE; /* talk a lot */
      break;
    case 'V':
      printf(CURL_ID "%s\n", curl_version());
      return PARAM_HELP_REQUESTED;
    case 'w':
      /* get the output string */
      if('@' == *nextarg) {
        /* the data begins with a '@' letter, it means that a file name
           or - (stdin) follows */
        FILE *file;
        nextarg++; /* pass the @ */
        if(strequal("-", nextarg))
          file = stdin;
        else 
          file = fopen(nextarg, "r");
        config->writeout = file2string(file);
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
      config->low_speed_time = atoi(nextarg);
      if(!config->low_speed_limit)
	config->low_speed_limit = 1;
      break;
    case 'Y':
      /* low speed limit */
      config->low_speed_limit = atoi(nextarg);
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
        struct stat statbuf;
        if(-1 == stat(nextarg, &statbuf)) {
          /* failed, remove time condition */
          config->timecond = CURL_TIMECOND_NONE;
        }
        else {
          /* pull the time out from the file */
          config->condtime = statbuf.st_mtime;
        }
      }
      break;
    case 'Z':
      /* specified max no of redirects (http(s)) */
      config->maxredirs = atoi(nextarg);
      break;

    case '@':
      config->create_dirs = TRUE;
      break;

    default: /* unknown flag */
      return PARAM_OPTION_UNKNOWN;
    }
    hit = -1;

  } while(!longopt && !singleopt && *++parse && !*usedarg);

  return PARAM_OK;
}


static int parseconfig(const char *filename,
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

    filename = CURLRC;          /* sensible default */
    home = curl_getenv("HOME"); /* portable environment reader */
    if(home) {
      if(strlen(home)<(sizeof(filebuffer)-strlen(CURLRC))) {

        snprintf(filebuffer, sizeof(filebuffer),
                 "%s%s%s", home, DIR_CHAR, CURLRC);

        filename = filebuffer;
      }
      free(home); /* we've used it, now free it */
    }
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
      while(isspace((int)*line))
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

      *line++=0; /* zero terminate, we have a local copy of the data */

#ifdef DEBUG_CONFIG
      fprintf(stderr, "GOT: %s\n", option);
#endif

      /* pass spaces and separator(s) */
      while(isspace((int)*line) || isseparator(*line))
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
#ifdef DEBUG_CONFIG
      fprintf(stderr, "PARAM: \"%s\"\n", param);
#endif
      res = getparameter(option, param, &usedarg, config);

      if(*param && !usedarg)
        /* we passed in a parameter that wasn't used! */
        res = PARAM_GOT_EXTRA_PARAMETER;

      if(res != PARAM_OK) {
        /* the help request isn't really an error */
        if(!strcmp(filename, "-")) {
          filename=(char *)"<stdin>";
        }
        if(PARAM_HELP_REQUESTED != res) {
          const char *reason;
          switch(res) {
          default:
          case PARAM_GOT_EXTRA_PARAMETER:
            reason = "had unsupported trailing garbage";
            break;
          case PARAM_OPTION_UNKNOWN:
            reason = "is unknown";
            break;
          case PARAM_OPTION_AMBIGUOUS:
            reason = "is ambiguous";
            break;
          case PARAM_REQUIRES_PARAMETER:
            reason = "requires parameter";
            break;
          case PARAM_BAD_USE:
            reason = "is badly used here";
            break;
          }
          fprintf(stderr, "%s:%d: warning: '%s' %s\n",
                  filename, lineno, option, reason);
        }
      }

      if(alloced_param)
        free(param);

      free(aline);
    }
    if(file != stdin)
      fclose(file);
  }
  return 0;
}

static void go_sleep(long ms)
{
#ifdef HAVE_POLL
  /* portable subsecond "sleep" */
  poll((void *)0, 0, ms);
#else
  /* systems without poll() need other solutions */

#ifdef WIN32
  /* Windows offers a millisecond sleep */
  Sleep(ms);
#else
  /* Other systems must use select() for this */
  struct timeval timeout;

  timeout.tv_sec = 0;
  timeout.tv_usec = ms * 1000;

  select(0, NULL,  NULL, NULL, &timeout);
#endif

#endif
}

struct OutStruct {
  char *filename;
  FILE *stream;
  struct Configurable *config;
};

int my_fwrite(void *buffer, size_t size, size_t nmemb, void *stream)
{
  struct OutStruct *out=(struct OutStruct *)stream;
  struct Configurable *config = out->config;
  if(out && !out->stream) {
    /* open file for writing */
    out->stream=fopen(out->filename, "wb");
    if(!out->stream)
      return -1; /* failure */
    if(config->nobuffer) {
      /* disable output buffering */
#ifdef HAVE_SETVBUF
      setvbuf(out->stream, NULL, _IONBF, 0);
#endif
    }
  }

  if(config->recvpersecond) {
    /*
     * We know when we received data the previous time. We know how much data
     * we get now. Make sure that this is not faster than we are told to run.
     * If we're faster, sleep a while *before* doing the fwrite() here.
     */

    time_t timediff;
    time_t now;

    now = time(NULL);
    timediff = now - config->lastrecvtime;
    if( size*nmemb > config->recvpersecond*timediff) {
      /* figure out how many milliseconds to rest */
      go_sleep ( (size*nmemb)*1000/config->recvpersecond - timediff*1000 );
      now = time(NULL);
    }
    config->lastrecvtime = now;
  }

  return fwrite(buffer, size, nmemb, out->stream);
}

struct InStruct {
  FILE *stream;
  struct Configurable *config;
};

int my_fread(void *buffer, size_t size, size_t nmemb, void *userp)
{
  struct InStruct *in=(struct InStruct *)userp;

  struct Configurable *config = in->config;

  if(config->sendpersecond) {
    /*
     * We know when we sent data the previous time. We know how much data
     * we sent. Make sure that this was not faster than we are told to run.
     * If we're faster, sleep a while *before* doing the fread() here.
     * Also, make no larger fread() than should be sent this second!
     */

    time_t timediff;
    time_t now;

    now = time(NULL);
    timediff = now - config->lastsendtime;
    if( config->lastsendsize > config->sendpersecond*timediff) {
      /* figure out how many milliseconds to rest */
      go_sleep ( config->lastsendsize*1000/config->sendpersecond -
                 timediff*1000 );
      now = time(NULL);
    }
    config->lastsendtime = now;

    if(size*nmemb > config->sendpersecond) {
      /* lower the size to actually read */
      nmemb = config->sendpersecond;
      size = 1;
    }
    config->lastsendsize = size*nmemb;    
  }


  return fread(buffer, size, nmemb, in->stream);
}

struct ProgressData {
  int calls;
  double total;
  double prev;
  double point;
  int width;
  FILE *out; /* where to write everything to */
};

int myprogress (void *clientp,
                double dltotal,
                double dlnow,
                double ultotal,
                double ulnow)
{
  /* The original progress-bar source code was written for curl by Lars Aas,
     and this new edition inherites some of his concepts. */
  
  char line[256];
  char outline[256];
  char format[40];
  double frac;
  double percent;
  int barwidth;
  int num;
  int i;

  struct ProgressData *bar = (struct ProgressData *)clientp;
  double total = dltotal + ultotal;

  bar->point = dlnow + ulnow; /* we've come this far */

  bar->calls++; /* simply count invokes */

  if(0 == total) {
    int prevblock = (int)bar->prev / 1024;
    int thisblock = (int)bar->point / 1024;
    while ( thisblock > prevblock ) {
      fprintf( bar->out, "#" );
      prevblock++;
    }
  }
  else {
    frac = bar->point / total;
    percent = frac * 100.0f;
    barwidth = bar->width - 7;
    num = (int) (((double)barwidth) * frac);
    i = 0;
    for ( i = 0; i < num; i++ ) {
      line[i] = '#';
    }
    line[i] = '\0';
    sprintf( format, "%%-%ds %%5.1f%%%%", barwidth );
    sprintf( outline, format, line, percent );
    fprintf( bar->out, "\r%s", outline );
  }
  bar->prev = bar->point;

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

/* TODO: get terminal width through ansi escapes or something similar.
         try to update width when xterm is resized... - 19990617 larsa */
#ifndef __EMX__
  /* 20000318 mgs
   * OS/2 users most likely won't have this env var set, and besides that
   * we're using our own way to determine screen width */
  colp = curl_getenv("COLUMNS");
  if (colp != NULL) {
    bar->width = atoi(colp);
    free(colp);
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
void dump(const char *text,
          FILE *stream, unsigned char *ptr, size_t size,
          bool nohex)
{
  size_t i;
  size_t c;

  unsigned int width=0x10;

  if(nohex)
    /* without the hex output, we can fit more on screen */
    width = 0x40;

  fprintf(stream, "%s, %d bytes (0x%x)\n", text, size, size);

  for(i=0; i<size; i+= width) {

    fprintf(stream, "%04x: ", i);

    if(!nohex) {
      /* hex not disabled, show it */
      for(c = 0; c < width; c++)
        if(i+c < size)
          fprintf(stream, "%02x ", ptr[i+c]);
        else
          fputs("   ", stream);
    }

    for(c = 0; (c < width) && (i+c < size); c++) {
      /* check for 0D0A; if found, skip past and start a new line of output */
      if (nohex && (i+c+1 < size) && ptr[i+c]==0x0D && ptr[i+c+1]==0x0A) {
        i+=(c+2-width);
        break;
      }
      fprintf(stream, "%c",
              (ptr[i+c]>=0x20) && (ptr[i+c]<0x80)?ptr[i+c]:'.');
      /* check again for 0D0A, to avoid an extra \n if it's at width */
      if (nohex && (i+c+2 < size) && ptr[i+c+1]==0x0D && ptr[i+c+2]==0x0A) {
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

  (void)handle; /* prevent compiler warning */

  if(!config->trace_stream) {
    /* open for append */
    if(strequal("-", config->trace_dump))
      config->trace_stream = stdout;
    else {
      config->trace_stream = fopen(config->trace_dump, "w");
      config->trace_fopened = TRUE;
    }
  }

  if(config->trace_stream)
    output = config->trace_stream;

  switch (type) {
  case CURLINFO_TEXT:
    fprintf(output, "== Info: %s", data);
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
  }

  dump(text, output, data, size, config->trace_ascii);
  return 0;
}

void free_config_fields(struct Configurable *config)
{
  if(config->random_file)
    free(config->random_file);
  if(config->egd_file)
    free(config->egd_file);
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
  if(config->infile)
    free(config->infile);
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

  curl_slist_free_all(config->quote); /* checks for config->quote == NULL */
  curl_slist_free_all(config->postquote); /*  */
  curl_slist_free_all(config->headers); /*  */
}

#if defined(WIN32) && !defined(__CYGWIN32__)

/* Function to find CACert bundle on a Win32 platform using SearchPath.
 * (SearchPath is defined in windows.h, which is #included into libcurl)
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
  curl_version_info_data *info;
  info = curl_version_info(CURLVERSION_NOW);

  /* only check for cert file if "we" support SSL */
  if(info->features & CURL_VERSION_SSL) {
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
  int urlnum;
  char *outfiles;
  int separator = 0;
  
  FILE *infd = stdin;
  FILE *headerfilep = NULL;
  char *urlbuffer=NULL;
  int infilesize=-1; /* -1 means unknown */
  bool stillflags=TRUE;

  bool allocuseragent=FALSE;

  char *httpgetfields=NULL;

  CURL *curl;
  int res = 0;
  int i;

  char *env;
#ifdef MALLOCDEBUG
  /* this sends all memory debug messages to a logfile named memdump */
  env = curl_getenv("CURL_MEMDEBUG");
  if(env) {
    free(env);
    curl_memdebug("memdump");
  }
#endif

  errorbuffer[0]=0; /* prevent junk from being output */

  main_init(); /* inits */

  config->showerror=TRUE;
  config->conf=CONF_DEFAULT;
  config->use_httpget=FALSE;
  config->create_dirs=FALSE;

  if(argc>1 &&
     (!strnequal("--", argv[1], 2) && (argv[1][0] == '-')) &&
     strchr(argv[1], 'q')) {
    /*
     * The first flag, that is not a verbose name, but a shortname
     * and it includes the 'q' flag!
     */
    ;
  }
  else {
    res = parseconfig(NULL, config);
    if(res)
      return res;
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

      if(strequal("--", argv[i]))
	/* this indicates the end of the flags and thus enables the
	   following (URL) argument to start with -. */
	stillflags=FALSE;
      else {
	nextarg= (i < argc - 1)? argv[i+1]: NULL;

	res = getparameter(flag, nextarg, &passarg, config);
	if(res) {
          switch(res) {
          case PARAM_OPTION_AMBIGUOUS:
            helpf("option %s is ambiguous\n", origopt);
            break;
          case PARAM_OPTION_UNKNOWN:
            helpf("option %s is unknown\n", origopt);
            break;
          case PARAM_REQUIRES_PARAMETER:
            helpf("option %s requires an extra argument!\n", origopt);
            break;
          case PARAM_BAD_USE:
            helpf("option %s was wrongly used!\n", origopt);
            break;
          case PARAM_HELP_REQUESTED:
            /* no text */
            break;
          }
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

  if(!config->url_list) {
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
  if (! config->cacert) {
    env = curl_getenv("CURL_CA_BUNDLE");
    if(env) {
      GetStr(&config->cacert, env);
      free(env);
    }
  }
#if defined(WIN32) && !defined(__CYGWIN32__)
  if (! config->cacert)
    FindWin32CACert(config, "curl-ca-bundle.crt");
#endif

  if (config->postfields) {
    if (config->use_httpget) {
      /* Use the postfields data for a http get */
      httpgetfields = strdup(config->postfields);
      free(config->postfields);
      config->postfields = NULL;
      if(SetHTTPrequest((config->conf&CONF_NOBODY?HTTPREQ_HEAD:HTTPREQ_GET),
                        &config->httpreq)) {
        free(httpgetfields);
        return PARAM_BAD_USE;
      }
    }
    else {
      if(SetHTTPrequest(HTTPREQ_SIMPLEPOST, &config->httpreq))
        return PARAM_BAD_USE;
    }
  }

  /*
   * Get a curl handle to use for all forthcoming curl transfers.  Cleanup
   * when all transfers are done. This is supported with libcurl 7.7 and
   * should not be attempted on previous versions.
   */
  curl = curl_easy_init();
  if(!curl)
    return CURLE_FAILED_INIT;

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

    /* get the full URL (it might be NULL) */
    url=urlnode->url;

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

    if(!config->globoff) {
      /* Unless explicitly shut off, we expand '{...}' and '[...]' expressions
         and return total number of URLs in pattern set */
      res = glob_url(&urls, url, &urlnum);
      if(res != CURLE_OK)
        return res;
    }


    /* save outfile pattern before expansion */
    outfiles = urlnode->outfile?strdup(urlnode->outfile):NULL;

    if ((!outfiles || strequal(outfiles, "-")) && urlnum > 1) {
      /* multiple files extracted to stdout, insert separators! */
      separator = 1;
    }
    for(i = 0;
        (url = urls?next_url(urls):(i?NULL:strdup(url)));
        i++) {
      char *outfile;
      outfile = outfiles?strdup(outfiles):NULL;
 
      if((urlnode->flags&GETOUT_USEREMOTE) ||
         (outfile && !strequal("-", outfile)) ) {

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
          outfile = (char *) NULL == pc ? NULL : strdup(pc+1) ;
          if(!outfile) {
            helpf("Remote file name has no length!\n");
            return CURLE_WRITE_ERROR;
          }
        }
        else if(urls) {
          /* fill '#1' ... '#9' terms from URL pattern */
          char *storefile = outfile;
          outfile = match_url(storefile, urls);
          free(storefile);
        }
      
        /* Create the directory hierarchy, if not pre-existant to a multiple
           file output call */
        
        if(config->create_dirs)
          if (-1 == create_dir_hierarchy(outfile))
            return CURLE_WRITE_ERROR;
        
        if(config->resume_from_current) {
          /* We're told to continue from where we are now. Get the
             size of the file as it is now and open it for append instead */
          
          struct stat fileinfo;

          /*VMS?? -- Danger, the filesize is only valid for stream files */
          if(0 == stat(outfile, &fileinfo))
            /* set offset to current file size: */
            config->resume_from = fileinfo.st_size;
          else
            /* let offset be 0 */
            config->resume_from = 0;
        }
        
        if(config->resume_from) {
          /* open file for output: */
          outs.stream=(FILE *) fopen(outfile, config->resume_from?"ab":"wb");
          if (!outs.stream) {
            helpf("Can't open '%s'!\n", outfile);
            return CURLE_WRITE_ERROR;
          }
        }
        else {
          outs.filename = outfile;
          outs.stream = NULL; /* open when needed */
        }
      }
      if(config->infile) {
        /*
         * We have specified a file to upload
         */
        struct stat fileinfo;

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
          char *filep = strrchr(config->infile, '/');
          char *file2 = strrchr(filep?filep:config->infile, '\\');

          if(file2)
            filep = file2+1;
          else if(filep)
            filep++;
          else
            filep = config->infile;

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
          
          url = urlbuffer; /* use our new URL instead! */
        }
/*VMS??-- Reading binary from files can be a problem... */
/*VMS??   Only FIXED, VAR etc WITHOUT implied CC will work */
/*VMS??   Others need a \n appended to a line */
/*VMS??-- Stat gives a size but this is UNRELIABLE in VMS */
/*VMS??   As a f.e. a fixed file with implied CC needs to have a byte added */
/*VMS??   for every record processed, this can by derived from Filesize & recordsize */
/*VMS??   for VARiable record files the records need to be counted! */
/*VMS??   for every record add 1 for linefeed and subtract 2 for the record header */
/*VMS??   for VARIABLE header files only the bare record data needs to be considered with one appended if implied CC */

        infd=(FILE *) fopen(config->infile, "rb");
        if (!infd || stat(config->infile, &fileinfo)) {
          helpf("Can't open '%s'!\n", config->infile);
          return CURLE_READ_ERROR;
        }
        infilesize=fileinfo.st_size;
      
      }
      if((config->conf&CONF_UPLOAD) &&
         config->resume_from_current) {
        config->resume_from = -1; /* -1 will then force get-it-yourself */
      }
      if(outs.stream && isatty(fileno(outs.stream)) &&
         !(config->conf&(CONF_UPLOAD|CONF_HTTPPOST)))
        /* we send the output to a tty and it isn't an upload operation,
           therefore we switch off the progress meter */
        config->conf |= CONF_NOPROGRESS;
    

      if (urlnum > 1 && !(config->conf&CONF_MUTE)) {
        fprintf(stderr, "\n[%d/%d]: %s --> %s\n",
                i+1, urlnum, url, outfile ? outfile : "<stdout>");
        if (separator)
          printf("%s%s\n", CURLseparator, url);
      }
      if (httpgetfields) {
        /* Find out whether the url contains a file name */
        char *pc =strstr(url, "://");
        char separator='?';
        if(pc)
          pc+=3;
        else
          pc=url;

        pc = strrchr(pc, '/'); /* check for a slash */

        if(pc) {
          /* there is a slash present in the URL */

          if(strchr(pc, '?'))
          /* Ouch, there's already a question mark in the URL string, we
             then appead the data with an amperand separator instead! */
            separator='&';
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
          sprintf(urlbuffer, "%s%c%s", url, separator, httpgetfields);
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

#if defined(WIN32) && !defined(__CYGWIN32__)
      if(!outfile && !(config->conf & CONF_GETTEXT)) {
        /* We get the output to stdout and we have not got the ASCII/text flag,
           then set stdout to be binary */
        setmode( 1, O_BINARY );
      }
#endif

      curl_easy_setopt(curl, CURLOPT_SSLENGINE, config->engine);
      curl_easy_setopt(curl, CURLOPT_SSLENGINE_DEFAULT, 1);

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

      if(config->recvpersecond) {
        /* tell libcurl to use a smaller sized buffer as it allows us to
           make better sleeps! 7.9.9 stuff! */
        curl_easy_setopt(curl, CURLOPT_BUFFERSIZE, config->recvpersecond);
      }

      /* size of uploaded file: */
      curl_easy_setopt(curl, CURLOPT_INFILESIZE, infilesize);
      curl_easy_setopt(curl, CURLOPT_URL, url);     /* what to fetch */
      curl_easy_setopt(curl, CURLOPT_PROXY, config->proxy); /* proxy to use */
      curl_easy_setopt(curl, CURLOPT_HEADER, config->conf&CONF_HEADER);
      curl_easy_setopt(curl, CURLOPT_NOPROGRESS, config->conf&CONF_NOPROGRESS);
      curl_easy_setopt(curl, CURLOPT_NOBODY, config->conf&CONF_NOBODY);
      curl_easy_setopt(curl, CURLOPT_FAILONERROR,
                       config->conf&CONF_FAILONERROR);
      curl_easy_setopt(curl, CURLOPT_UPLOAD, config->conf&CONF_UPLOAD);
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
      curl_easy_setopt(curl, CURLOPT_TRANSFERTEXT, config->conf&CONF_GETTEXT);
      curl_easy_setopt(curl, CURLOPT_MUTE, config->conf&CONF_MUTE);
      curl_easy_setopt(curl, CURLOPT_USERPWD, config->userpwd);
      curl_easy_setopt(curl, CURLOPT_PROXYUSERPWD, config->proxyuserpwd);
      curl_easy_setopt(curl, CURLOPT_RANGE, config->range);
      curl_easy_setopt(curl, CURLOPT_ERRORBUFFER, errorbuffer);
      curl_easy_setopt(curl, CURLOPT_TIMEOUT, config->timeout);
      curl_easy_setopt(curl, CURLOPT_POSTFIELDS, config->postfields);

      /* new in libcurl 7.2: */
      curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, config->postfieldsize);
        
      curl_easy_setopt(curl, CURLOPT_REFERER, config->referer);
      curl_easy_setopt(curl, CURLOPT_AUTOREFERER,
                       config->conf&CONF_AUTO_REFERER);
      curl_easy_setopt(curl, CURLOPT_USERAGENT, config->useragent);
      curl_easy_setopt(curl, CURLOPT_FTPPORT, config->ftpport);
      curl_easy_setopt(curl, CURLOPT_LOW_SPEED_LIMIT, config->low_speed_limit);
      curl_easy_setopt(curl, CURLOPT_LOW_SPEED_TIME, config->low_speed_time);
      curl_easy_setopt(curl, CURLOPT_RESUME_FROM,
                       config->use_resume?config->resume_from:0);
      curl_easy_setopt(curl, CURLOPT_COOKIE, config->cookie);
      curl_easy_setopt(curl, CURLOPT_HTTPHEADER, config->headers);
      curl_easy_setopt(curl, CURLOPT_HTTPPOST, config->httppost);
      curl_easy_setopt(curl, CURLOPT_SSLCERT, config->cert);
      curl_easy_setopt(curl, CURLOPT_SSLCERTTYPE, config->cert_type);
      curl_easy_setopt(curl, CURLOPT_SSLKEY, config->key);
      curl_easy_setopt(curl, CURLOPT_SSLKEYTYPE, config->key_type);
      curl_easy_setopt(curl, CURLOPT_SSLKEYPASSWD, config->key_passwd);

      if(config->cacert || config->capath) {
        if (config->cacert)
          curl_easy_setopt(curl, CURLOPT_CAINFO, config->cacert);

        if (config->capath)
          curl_easy_setopt(curl, CURLOPT_CAPATH, config->capath);
        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, TRUE);
        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 2);
      }
      else {
        if(config->insecure_ok)
          /* new stuff needed for libcurl 7.10 */
          curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, FALSE);

        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 1);
      }
      
      if((config->conf&CONF_NOBODY) ||
         config->remote_time) {
        /* no body or use remote time */
        curl_easy_setopt(curl, CURLOPT_FILETIME, TRUE);
      }
      
      if (config->maxredirs) 
        curl_easy_setopt(curl, CURLOPT_MAXREDIRS, config->maxredirs); 
      else 
        curl_easy_setopt(curl, CURLOPT_MAXREDIRS, DEFAULT_MAXREDIRS); 
 
      curl_easy_setopt(curl, CURLOPT_CRLF, config->crlf);
      curl_easy_setopt(curl, CURLOPT_QUOTE, config->quote);
      curl_easy_setopt(curl, CURLOPT_POSTQUOTE, config->postquote);
      curl_easy_setopt(curl, CURLOPT_WRITEHEADER,
                       config->headerfile?&heads:NULL);
      curl_easy_setopt(curl, CURLOPT_COOKIEFILE, config->cookiefile);
      /* cookie jar was added in 7.9 */
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
      
      if((config->progressmode == CURL_PROGRESS_BAR) &&
         !(config->conf&(CONF_NOPROGRESS|CONF_MUTE))) {
        /* we want the alternative style, then we have to implement it
           ourselves! */
        progressbarinit(&progressbar, config);
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

      /* new in curl 7.9.7 */
      if(config->trace_dump) {
        curl_easy_setopt(curl, CURLOPT_DEBUGFUNCTION, my_trace);
        curl_easy_setopt(curl, CURLOPT_DEBUGDATA, config);
        config->conf |= CONF_VERBOSE; /* force verbose */
      }
      curl_easy_setopt(curl, CURLOPT_VERBOSE, config->conf&CONF_VERBOSE);

      /* new in curl 7.10 */
      curl_easy_setopt(curl, CURLOPT_ENCODING, 
                       (config->encoding) ? "deflate" : NULL);

      res = curl_easy_perform(curl);
        
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

#ifdef	VMS
      if (!config->showerror)  {
        vms_show = VMSSTS_HIDE;
      }
#else
      if((res!=CURLE_OK) && config->showerror)
        fprintf(config->errors, "curl: (%d) %s\n", res, errorbuffer);
#endif

      if (outfile && !strequal(outfile, "-") && outs.stream)
        fclose(outs.stream);

#ifdef HAVE_UTIME
      /* Important that we set the time _after_ the file has been 
         closed, as is done above here */
      if(config->remote_time && outs.filename) {
        /* as libcurl if we got a time. Pretty please */
        long filetime;
        curl_easy_getinfo(curl, CURLINFO_FILETIME, &filetime);
        if(filetime >= 0) {
          struct utimbuf times;
          times.actime = filetime;
          times.modtime = filetime;
          utime(outs.filename, &times); /* set the time we got */
        }
      }
#endif

      if (config->infile)
        fclose(infd);
      if(headerfilep)
        fclose(headerfilep);
      
      if (httpgetfields)
        free(httpgetfields);

      if(url)
        free(url);

      if(outfile)
        free(outfile);
    }
    if(outfiles)
      free(outfiles);

    if(urls)
      /* cleanup memory used for URL globbing patterns */
      glob_cleanup(urls);

    /* empty this urlnode struct */
    if(urlnode->url)
      free(urlnode->url);
    if(urlnode->outfile)
      free(urlnode->outfile);
    
    /* move on to the next URL */
    nextnode=urlnode->next;
    free(urlnode); /* free the node */
    urlnode = nextnode;

  } /* while-loop through all URLs */

  if(config->headerfile && !headerfilep && heads.stream)
    fclose(heads.stream);

  if(config->trace_fopened)
    fclose(config->trace_stream);

  if(allocuseragent)
    free(config->useragent);

  /* cleanup the curl handle! */
  curl_easy_cleanup(curl);

  if(config->errors_fopened)
    fclose(config->errors);

  main_free(); /* cleanup */

  return res;
}


int main(int argc, char *argv[])
{
  int res;
  struct Configurable config;
  memset(&config, 0, sizeof(struct Configurable));
  
  res = operate(&config, argc, argv);
  free_config_fields(&config);

#ifdef	VMS
  if (res > 52) res = 53;		/* MAXMSG, porting helper */
  return (vms_cond[res]|vms_show);
#else
  return res;
#endif
}

static char *my_get_line(FILE *fp)
{
   char buf[4096];
   char *nl = NULL;
   char *retval = NULL;

   do
   {
      if (NULL == fgets(buf, sizeof(buf), fp))
         break;
      if (NULL == retval)
         retval = strdup(buf);
      else
      {
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
      if (access(dirbuildup,F_OK) == -1) {
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

