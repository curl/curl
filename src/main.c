/*****************************************************************************
 *                                  _   _ ____  _     
 *  Project                     ___| | | |  _ \| |    
 *                             / __| | | | |_) | |    
 *                            | (__| |_| |  _ <| |___ 
 *                             \___|\___/|_| \_\_____|
 *
 *  The contents of this file are subject to the Mozilla Public License
 *  Version 1.0 (the "License"); you may not use this file except in
 *  compliance with the License. You may obtain a copy of the License at
 *  http://www.mozilla.org/MPL/
 *
 *  Software distributed under the License is distributed on an "AS IS"
 *  basis, WITHOUT WARRANTY OF ANY KIND, either express or implied. See the
 *  License for the specific language governing rights and limitations
 *  under the License.
 *
 *  The Original Code is Curl.
 *
 *  The Initial Developer of the Original Code is Daniel Stenberg.
 *
 *  Portions created by the Initial Developer are Copyright (C) 1998.
 *  All Rights Reserved.
 *
 * ------------------------------------------------------------
 * Main author:
 * - Daniel Stenberg <Daniel.Stenberg@haxx.nu>
 *
 * 	http://curl.haxx.nu
 *
 * $Source$
 * $Revision$
 * $Date$
 * $Author$
 * $State$
 * $Locker$
 *
 * ------------------------------------------------------------
 ****************************************************************************/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <sys/stat.h>
#include <ctype.h>

#include <curl/curl.h>
#include <curl/mprintf.h>
#include "../lib/getdate.h"
#ifdef GLOBURL
#include "urlglob.h"
#define CURLseparator	"--_curl_--"
#define MIMEseparator	"_curl_"
#endif

/* This is now designed to have its own local setup.h */
#include "setup.h"

#include "version.h"

#ifdef HAVE_IO_H /* typical win32 habit */
#include <io.h>
#endif

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif

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

extern void hugehelp(void);

static void helpf(char *fmt, ...)
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

static void help(void)
{
  printf(CURL_ID "%s\n"
       "Usage: curl [options...] <url>\n"
       "Options: (H) means HTTP/HTTPS only, (F) means FTP only\n"
       " -a/--append        Append to target file when uploading (F)\n"
       " -A/--user-agent <string> User-Agent to send to server (H)\n"
       " -b/--cookie <name=string/file> Cookie string or file to read cookies from (H)\n"
       " -B/--ftp-ascii     Use ASCII transfer (F)\n"
       " -c/--continue      Resume a previous transfer where we left it\n"
       " -C/--continue-at <offset> Specify absolute resume offset\n"
       " -d/--data          POST data (H)\n"
       " -D/--dump-header <file> Write the headers to this file\n"
       " -e/--referer       Referer page (H)\n"
       " -E/--cert <cert:passwd> Specifies your certificate file and password (HTTPS)\n"
       " -f/--fail          Fail silently (no output at all) on errors (H)\n"
       " -F/--form <name=content> Specify HTTP POST data (H)\n"

       " -h/--help          This help text\n"
       " -H/--header <line> Custom header to pass to server. (H)\n"
       " -i/--include       Include the HTTP-header in the output (H)\n"
       " -I/--head          Fetch document info only (HTTP HEAD/FTP SIZE)\n"
       " -K/--config        Specify which config file to read\n"
       " -l/--list-only     List only names of an FTP directory (F)\n"
       " -L/--location      Follow Location: hints (H)\n"
       " -m/--max-time <seconds> Maximum time allowed for the transfer\n"
       " -M/--manual        Display huge help text\n"
       " -n/--netrc         Read .netrc for user name and password\n"
       " -N/--no-buffer     Disables the buffering of the output stream\n"
       " -o/--output <file> Write output to <file> instead of stdout\n"
       " -O/--remote-name   Write output to a file named as the remote file\n"
#if 0
       " -p/--port <port>   Use port other than default for current protocol.\n"
#endif
       " -P/--ftpport <address> Use PORT with address instead of PASV when ftping (F)\n"
       " -q                 When used as the first parameter disables .curlrc\n"
       " -Q/--quote <cmd>   Send QUOTE command to FTP before file transfer (F)\n"
       " -r/--range <range> Retrieve a byte range from a HTTP/1.1 or FTP server\n"
       " -s/--silent        Silent mode. Don't output anything\n"
       " -S/--show-error    Show error. With -s, make curl show errors when they occur\n"
       " -t/--upload        Transfer/upload stdin to remote site\n"
       " -T/--upload-file <file> Transfer/upload <file> to remote site\n"
       " -u/--user <user:password> Specify user and password to use\n"
       " -U/--proxy-user <user:password> Specify Proxy authentication\n"
       " -v/--verbose       Makes the operation more talkative\n"
       " -V/--version       Outputs version number then quits\n"
       " -w/--write-out [format] What to output after completion\n"
       " -x/--proxy <host>  Use proxy. (Default port is 1080)\n"
       " -X/--request <command> Specific request command to use\n"
       " -y/--speed-time    Time needed to trig speed-limit abort. Defaults to 30\n"
       " -Y/--speed-limit   Stop transfer if below speed-limit for 'speed-time' secs\n"
       " -z/--time-cond <time> Includes a time condition to the server (H)\n"
       " -2/--sslv2         Force usage of SSLv2 (H)\n"
       " -3/--sslv3         Force usage of SSLv3 (H)\n"
       " -#/--progress-bar  Display transfer progress as a progress bar\n"
       "    --crlf          Convert LF to CRLF in upload. Useful for MVS (OS/390)\n"
       "    --stderr <file> Where to redirect stderr. - means stdout.\n",
         curl_version()
         );
}

struct LongShort {
  char *letter;
  char *lname;
  bool extraparam;
};

struct Configurable {
  char *useragent;
  char *cookie;
  bool use_resume;
  int resume_from;
  char *postfields;
  char *referer;
  long timeout;
  char *outfile;
  char *headerfile;
  char remotefile;
  char *ftpport;
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
  long conf;
  char *url;
  char *cert;
  char *cert_passwd;
  bool crlf;
  char *cookiefile;
  char *customrequest;
  bool progressmode;
  bool nobuffer;

  char *writeout; /* %-styled format string to output */

  FILE *errors; /* if stderr redirect is requested */

  struct curl_slist *quote;
  struct curl_slist *postquote;

  long ssl_version;
  TimeCond timecond;
  time_t condtime;

  struct HttpHeader *headers;
  struct HttpHeader *last_header;

  struct HttpPost *httppost;
  struct HttpPost *last_post;
};

static int parseconfig(char *filename,
		       struct Configurable *config);
static char *my_get_line(FILE *fp);
static char *my_get_token(const char *line);

static void GetStr(char **string,
		   char *value)
{
  if(*string)
    free(*string);
  *string = strdup(value);
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

static int getparameter(char *flag, /* f or -long-flag */
			char *nextarg, /* NULL if unset */
			bool *usedarg, /* set to TRUE if the arg has been
					  used */
			struct Configurable *config)
{
  char letter;
  char *parse=NULL;
  int res;
  struct HttpHeader *head;
  int j;
  time_t now;
  int hit=-1;

  /* single-letter,
     long-name,
     boolean whether it takes an additional argument
     */
  struct LongShort aliases[]= {
    {"9", "crlf",        FALSE},
    {"8", "stderr",      TRUE},

    {"2", "sslv2",       FALSE},
    {"3", "sslv3",       FALSE},
    {"a", "append",      FALSE},
    {"A", "user-agent",  TRUE},
    {"b", "cookie",      TRUE},
    {"B", "ftp-ascii",   FALSE},
    {"c", "continue",    FALSE},
    {"C", "continue-at", TRUE},
    {"d", "data",        TRUE},
    {"D", "dump-header", TRUE},
    {"e", "referer",     TRUE},
    {"E", "cert",        TRUE},
    {"f", "fail",        FALSE},
    {"F", "form",        TRUE},

    {"h", "help",        FALSE},
    {"H", "header",      TRUE},
    {"i", "include",     FALSE},
    {"I", "head",        FALSE},
    {"K", "config",      TRUE},
    {"l", "list-only",   FALSE},
    {"L", "location",    FALSE},
    {"m", "max-time",    TRUE},
    {"M", "manual",      FALSE},
    {"n", "netrc",       FALSE},
    {"N", "no-buffer",   FALSE},
    {"o", "output",      TRUE},
    {"O", "remote-name", FALSE},
#if 0
    {"p", "port",        TRUE},
#endif
    {"P", "ftpport",     TRUE},
    {"q", "disable",     FALSE},
    {"Q", "quote",       TRUE},
    {"r", "range",       TRUE},
    {"s", "silent",      FALSE},
    {"S", "show-error",  FALSE},
    {"t", "upload",      FALSE},
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

  if('-' == flag[0]) {
    /* try a long name */
    int fnam=strlen(&flag[1]);
    for(j=0; j< sizeof(aliases)/sizeof(aliases[0]); j++) {
      if(strnequal(aliases[j].lname, &flag[1], fnam)) {
        if(strequal(aliases[j].lname, &flag[1])) {
          parse = aliases[j].letter;
          hit = j;
          break;
        }
	if(parse) {
	  /* this is the second match, we can't continue! */
	  helpf("option --%s is ambiguous\n", &flag[1]);
	  return URG_FAILED_INIT;
	}
	parse = aliases[j].letter;
	hit = j;
      }
    }
    if(hit < 0) {
      helpf("unknown option -%s.\n", flag);
      return URG_FAILED_INIT;
    }    
  }
  else {
    hit=-1;
    parse = flag;
  }

  do {
    /* we can loop here if we have multiple single-letters */

    letter = parse?*parse:'\0';
    *usedarg = FALSE; /* default is that we don't use the arg */

#if 0
    fprintf(stderr, "OPTION: %c %s\n", letter, nextarg?nextarg:"<null>");
#endif
    if(hit < 0) {
      for(j=0; j< sizeof(aliases)/sizeof(aliases[0]); j++) {
	if(letter == *aliases[j].letter) {
	  hit = j;
	  break;
	}
      }
      if(hit < 0) {
	helpf("unknown option -%c.\n", letter);
	return URG_FAILED_INIT;      
      }
    }
    if(hit < 0) {
      helpf("unknown option -%c.\n", letter);
      return URG_FAILED_INIT;
    }    
    if(!nextarg && aliases[hit].extraparam) {
      helpf("option -%s/--%s requires an extra argument!\n",
	    aliases[hit].letter,
	    aliases[hit].lname);
      return URG_FAILED_INIT;
    }
    else if(nextarg && aliases[hit].extraparam)
      *usedarg = TRUE; /* mark it as used */

    switch(letter) {
    case 'z': /* time condition coming up */
      switch(*nextarg) {
      case '+':
        nextarg++;
      default:
        /* If-Modified-Since: (section 14.28 in RFC2068) */
        config->timecond = TIMECOND_IFMODSINCE;
        break;
      case '-':
        /* If-Unmodified-Since:  (section 14.24 in RFC2068) */
        config->timecond = TIMECOND_IFUNMODSINCE;
        nextarg++;
        break;
      case '=':
        /* Last-Modified:  (section 14.29 in RFC2068) */
        config->timecond = TIMECOND_LASTMOD;
        nextarg++;
        break;
      }
      now=time(NULL);
      config->condtime=get_date(nextarg, &now);
      if(-1 == config->condtime) {
        /* now let's see if it is a file name to get the time from instead! */
        struct stat statbuf;
        if(-1 == stat(nextarg, &statbuf)) {
          /* failed, remove time condition */
          config->timecond = TIMECOND_NONE;
        }
        else {
          /* pull the time out from the file */
          config->condtime = statbuf.st_mtime;
        }
      }
      break;
    case '9': /* there is no short letter for this */
      /* LF -> CRLF conversinon? */
      config->crlf = TRUE;
      break;
    case '8': /* there is no short letter for this */
      if(strcmp(nextarg, "-"))
        config->errors = fopen(nextarg, "wt");
      else
        config->errors = stdout;
      break;
    case '#': /* added 19990617 larsa */
      config->progressmode ^= CURL_PROGRESS_BAR;
      break;
    case '2': 
      /* SSL version 2 */
      config->ssl_version = 2;
      break;
    case '3': 
      /* SSL version 2 */
      config->ssl_version = 3;
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
      /* use type ASCII when transfering ftp files */
      config->conf ^= CONF_FTPASCII;
      break;
    case 'c':
      /* This makes us continue an ftp transfer */
      config->use_resume^=TRUE;
      break;
    case 'C':
      /* This makes us continue an ftp transfer at given position */
      config->resume_from= atoi(nextarg);
      config->use_resume=TRUE;
      break;
    case 'd':
      /* postfield data */
      if('@' == *nextarg) {
        /* the data begins with a '@' letter, it means that a file name
           or - (stdin) follows */
        FILE *file;
        nextarg++; /* pass the @ */
        if(strequal("-", nextarg))
          file = stdin;
        else 
          file = fopen(nextarg, "r");
        config->postfields = file2string(file);
        if(file && (file != stdin))
          fclose(stdin);
      }
      else {
        GetStr(&config->postfields, nextarg);
      }
      if(config->postfields)
        config->conf |= CONF_POST;
      break;
    case 'D':
      /* dump-header to given file name */
      GetStr(&config->headerfile, nextarg);
      break;
    case 'e':
      GetStr(&config->referer, nextarg);
      config->conf |= CONF_REFERER;
      break;
    case 'E':
      {
	char *ptr = strchr(nextarg, ':');
	if(ptr) {
	  /* we have a password too */
	  *ptr=0;
	  ptr++;
	  GetStr(&config->cert_passwd, ptr);
	}
	GetStr(&config->cert, nextarg);
      }
      break;
    case 'f':
      /* fail hard on errors  */
      config->conf ^= CONF_FAILONERROR;
      break;
    case 'F':
      /* "form data" simulation, this is a little advanced so lets do our best
	 to sort this out slowly and carefully */
      if(curl_FormParse(nextarg,
                        &config->httppost,
                        &config->last_post))
	return URG_FAILED_INIT;    
      config->conf |= CONF_HTTPPOST; /* no toggle, OR! */
      break;

    case 'h': /* h for help */
      help();
      return URG_FAILED_INIT;
    case 'H':
      head = (struct HttpHeader *)malloc(sizeof(struct HttpHeader));
      if(head) {
	head->next = NULL;
	head->header = NULL; /* first zero this */
	GetStr(&head->header, nextarg); /* now get the header line */

	/* point on our new one */
	if(config->last_header)
	  config->last_header->next = head;
	else {
	  config->headers = head;
	}

	config->last_header = head;
      }
      break;
    case 'i':
      config->conf ^= CONF_HEADER; /* include the HTTP header as well */
      break;
    case 'I':
      config->conf ^= CONF_HEADER; /* include the HTTP header in the output */
      config->conf ^= CONF_NOBODY; /* don't fetch the body at all */
      break;
    case 'K':
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
      return URG_FAILED_INIT;
    case 'n':
      /* pick info from .netrc, if this is used for http, curl will
	 automatically enfore user+password with the request */
      config->conf ^= CONF_NETRC;
      break;
    case 'N':
      /* disable the output I/O buffering */
      config->nobuffer ^= 1;
      break;
    case 'o':
      /* output file */
      GetStr(&config->outfile, nextarg); /* write to this file */
      break;
    case 'O':
      /* output file */
      config->remotefile ^= TRUE;
      break;
    case 'P':
      /* This makes the FTP sessions use PORT instead of PASV */
      /* use <eth0> or <192.168.10.10> style addresses. Anything except
	 this will make us try to get the "default" address.
	 NOTE: this is a changed behaviour since the released 4.1!
	 */
      config->conf |= CONF_FTPPORT;
      GetStr(&config->ftpport, nextarg);
      break;
#if 0
    case 'p':
      /* specified port */
      fputs("You've used the -p option, it will be removed in a future version\n",
	    stderr);
      config->porttouse = atoi(nextarg);
      config->conf |= CONF_PORT; /* changed port */
      break;
#endif
    case 'q': /* if used first, already taken care of, we do it like
		 this so we don't cause an error! */
      break;
    case 'Q':
      /* QUOTE command to send to FTP server */
      if(nextarg[0] == '-') {
        /* prefixed with a dash makes it a POST TRANSFER one */
        nextarg++;
        config->postquote = curl_slist_append(config->postquote, nextarg);
      }
      else {
        config->quote = curl_slist_append(config->quote, nextarg);
      }
      break;
    case 'r':
      /* byte range requested */
      GetStr(&config->range, nextarg);
      config->conf |= CONF_RANGE;
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
      /* we are uploading */
      config->conf ^= CONF_UPLOAD;
      break;
    case 'T':
      /* we are uploading */
      config->conf |= CONF_UPLOAD;
      GetStr(&config->infile, nextarg);
      break;
    case 'u':
      /* user:password  */
      GetStr(&config->userpwd, nextarg);
      config->conf |= CONF_USERPWD;
      break;
    case 'U':
      /* Proxy user:password  */
      GetStr(&config->proxyuserpwd, nextarg);
      config->conf |= CONF_PROXYUSERPWD;
      break;
    case 'v':
      config->conf ^= CONF_VERBOSE; /* talk a lot */
      break;
    case 'V':
      printf(CURL_ID "%s\n", curl_version());
      return URG_FAILED_INIT;
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
          fclose(stdin);
      }
      else 
        GetStr(&config->writeout, nextarg);
      break;
    case 'x':
      /* proxy */
      if(!*nextarg) {
	/* disable proxy when no proxy is given */
	config->conf &= ~CONF_PROXY;
      }
      else { 
	config->conf |= CONF_PROXY;
	GetStr(&config->proxy, nextarg);
      }
      break;
    case 'X':
      /* HTTP request */
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

    default: /* unknown flag */
      if(letter)	
	helpf("Unknown option '%c'\n", letter);
      else
	helpf("Unknown option\n"); /* short help blurb */
      return URG_FAILED_INIT;
    }
    hit = -1;

  } while(*++parse && !*usedarg);

  return URG_OK;
}


static int parseconfig(char *filename,
		       struct Configurable *config)
{
  int res;
  FILE *file;
  char configbuffer[4096];
  char filebuffer[256];
  bool usedarg;
  
  if(!filename || !*filename) {
    /* NULL or no file name attempts to load .curlrc from the homedir! */

#define CURLRC DOT_CHAR "curlrc"

    char *home = curl_GetEnv("HOME"); /* portable environment reader */

    if(!home || (strlen(home)>(sizeof(filebuffer)-strlen(CURLRC))))
      return URG_OK;

    sprintf(filebuffer, "%s%s%s", home, DIR_CHAR, CURLRC);

    filename = filebuffer;
  }

  if(strcmp(filename,"-"))
    file = fopen(filename, "r");
  else
    file = stdin;
  
  if(file)
  {
    char *line;
    char *tok1;
    char *tok2;

    while (NULL != (line = my_get_line(file)))
    {
      /* lines with # in the fist column is a comment! */
      if ('#' == line[0])
      {
        free(line);
        continue;
      }

      if (NULL == (tok1 = my_get_token(line)))
      {
        free(line);
        continue;
      }
      if ('-' != tok1[0])
      {
        if (config->url)
          free(config->url);
        config->url = tok1;
      }

      while ((NULL != tok1) && ('-' == tok1[0]))
      {
        tok2 = my_get_token(NULL);
        while (NULL == tok2)
        {
          free(line);
          if (NULL == (line = my_get_line(file)))
            break;
          if ('#' == line[0])
            continue;
          tok2 = my_get_token(line);
        }

        res = getparameter(tok1 + 1, tok2, &usedarg, config);
        free(tok1);
        if (!usedarg)
          tok1 = tok2;
        else
        {
          free(tok2);
          break;
        }
      }

      free(line);
    }
    if(file != stdin)
      fclose(file);
  }
  return URG_OK;
}

struct OutStruct {
  char *filename;
  FILE *stream;
};

/* having this global is a bit dirty, but hey, who said we weren't? ;-) */
struct Configurable config;

int my_fwrite(void *buffer, size_t size, size_t nmemb, FILE *stream)
{
  struct OutStruct *out=(struct OutStruct *)stream;
  if(out && !out->stream) {
    /* open file for writing */
    out->stream=fopen(out->filename, "wb");
    if(!out->stream)
      return -1; /* failure */
    if(config.nobuffer) {
      /* disable output buffering */
#ifdef HAVE_SETVBUF
      setvbuf(out->stream, NULL, _IONBF, 0);
#endif
    }
  }
  return fwrite(buffer, size, nmemb, out->stream);
}


int main(int argc, char *argv[])
{
  char errorbuffer[URLGET_ERROR_SIZE];

  struct OutStruct outs;

  char *url = NULL;
#ifdef GLOBURL
  URLGlob *urls;
  int urlnum;
  char *outfiles = NULL;
  int separator = 0;
#endif
  
  FILE *infd = stdin;
  FILE *headerfilep = NULL;
  char *urlbuffer=NULL;
  int infilesize=-1; /* -1 means unknown */
  bool stillflags=TRUE;

  int res=URG_OK;
  int i;

  outs.stream = stdout;

  memset(&config, 0, sizeof(struct Configurable));
  
  /* set non-zero default values: */
  config.useragent= maprintf(CURL_NAME "/" CURL_VERSION " (" OS ") "
                             "%s", curl_version());
  config.showerror=TRUE;
  config.conf=CONF_DEFAULT;
#if 0
  config.crlf=FALSE;
  config.quote=NULL;
#endif

  if(argc>1 &&
     (!strnequal("--", argv[1], 2) && (argv[1][0] == '-')) &&
     strchr(argv[1], 'q')) {
    /*
     * The first flag, that is not a verbose name, but a shortname
     * and it includes the 'q' flag!
     */
#if 0
    fprintf(stderr, "I TURNED OFF THE CRAP\n");
#endif
    ;
  }
  else {
    res = parseconfig(NULL, &config);
    if(res)
      return res;
  }

  if ((argc < 2)  && !config.url) {
    helpf(NULL);
    return URG_FAILED_INIT;
  }

  /* Parse options */
  for (i = 1; i < argc; i++) {
    if(stillflags &&
       ('-' == argv[i][0])) {
      char *nextarg;
      bool passarg;
      
      char *flag = &argv[i][1];

      if(strequal("--", argv[i]))
	/* this indicates the end of the flags and thus enables the
	   following (URL) argument to start with -. */
	stillflags=FALSE;
      else {
	nextarg= (i < argc - 1)? argv[i+1]: NULL;

	res = getparameter ( flag,
			     nextarg,
			     &passarg,
			   &config );
	if(res)
	  return res;

	if(passarg) /* we're supposed to skip this */
	  i++;
      }
    }
    else {
      if(url) {
	helpf("only one URL is supported!\n");
	return URG_FAILED_INIT;
      }
      url = argv[i];
    }
  }

  /* if no URL was specified and there was one in the config file, get that
     one */
  if(!url && config.url)
    url = config.url;
  
  if(!url) {
    helpf("no URL specified!\n");
    return URG_FAILED_INIT;
  }
#if 0
    fprintf(stderr, "URL: %s PROXY: %s\n", url, config.proxy?config.proxy:"none");
#endif

#ifdef GLOBURL
  urlnum = glob_url(&urls, url);	/* expand '{...}' and '[...]' expressions and return
					   total number of URLs in pattern set */
  outfiles = config.outfile;		/* save outfile pattern befor expansion */
  if (!outfiles && !config.remotefile && urlnum > 1) {
#ifdef CURL_SEPARATORS
    /* multiple files extracted to stdout, insert separators! */
    separator = 1;
#endif
#ifdef MIME_SEPARATORS
    /* multiple files extracted to stdout, insert MIME separators! */
    separator = 1;
    printf("MIME-Version: 1.0\n");
    printf("Content-Type: multipart/mixed; boundary=%s\n\n", MIMEseparator);
#endif
  }
  for (i = 0; (url = next_url(urls)); ++i) {
    if (outfiles)
      config.outfile = strdup(outfiles);
#endif

  if(config.outfile && config.infile) {
    helpf("you can't both upload and download!\n");
    return URG_FAILED_INIT;
  }
 
  if (config.outfile || config.remotefile) {
    /* 
     * We have specified a file name to store the result in, or we have
     * decided we want to use the remote file name.
     */

    if(config.remotefile) {
      /* Find and get the remote file name */
      config.outfile=strstr(url, "://");
      if(config.outfile)
        config.outfile+=3;
      else
        config.outfile=url;
      config.outfile = strrchr(config.outfile, '/');
      if(!config.outfile || !strlen(++config.outfile)) {
        helpf("Remote file name has no length!\n");
        return URG_WRITE_ERROR;
      }
    }
#ifdef GLOBURL
    else	/* fill '#1' ... '#9' terms from URL pattern */
      config.outfile = match_url(config.outfile, *urls);
#endif

    if((0 == config.resume_from) && config.use_resume) {
      /* we're told to continue where we are now, then we get the size of the
	 file as it is now and open it for append instead */
      struct stat fileinfo;

      if(0 == stat(config.outfile, &fileinfo)) {
	/* set offset to current file size: */
	config.resume_from = fileinfo.st_size;
      }
      /* else let offset remain 0 */
    }

    if(config.resume_from) {
      /* open file for output: */
      outs.stream=(FILE *) fopen(config.outfile, config.resume_from?"ab":"wb");
      if (!outs.stream) {
        helpf("Can't open '%s'!\n", config.outfile);
        return URG_WRITE_ERROR;
      }
    }
    else {
      outs.filename = config.outfile;
      outs.stream = NULL; /* open when needed */
    }
  }
  if (config.infile) {
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
         to be able to do so, we have to create a new URL in another buffer.*/
      urlbuffer=(char *)malloc(strlen(url) + strlen(config.infile) + 3);
      if(!urlbuffer) {
        helpf("out of memory\n");
        return URG_OUT_OF_MEMORY;
      }
      if(ptr)
        /* there is a trailing slash on the URL */
        sprintf(urlbuffer, "%s%s", url, config.infile);
      else
        /* thers is no trailing slash on the URL */
        sprintf(urlbuffer, "%s/%s", url, config.infile);

      url = urlbuffer; /* use our new URL instead! */
    }

    infd=(FILE *) fopen(config.infile, "rb");
    if (!infd || stat(config.infile, &fileinfo)) {
      helpf("Can't open '%s'!\n", config.infile);
      return URG_READ_ERROR;
    }
    infilesize=fileinfo.st_size;

  }
  if((config.conf&CONF_UPLOAD) &&
     config.use_resume &&
     (0==config.resume_from)) {
    config.resume_from = -1; /* -1 will then force get-it-yourself */
  }
  if(config.headerfile) {
    /* open file for output: */
    if(strcmp(config.headerfile,"-"))
    {
      headerfilep=(FILE *) fopen(config.headerfile, "wb");
      if (!headerfilep) {
	helpf("Can't open '%s'!\n", config.headerfile);
	return URG_WRITE_ERROR;
      }
    }
    else
      headerfilep=stdout;
  }

  if(outs.stream && isatty(fileno(outs.stream)) &&
     !(config.conf&(CONF_UPLOAD|CONF_HTTPPOST)))
    /* we send the output to a tty and it isn't an upload operation, therefore
       we switch off the progress meter */
    config.conf |= CONF_NOPROGRESS;

#ifdef GLOBURL
  if (urlnum > 1) {
    fprintf(stderr, "\n[%d/%d]: %s --> %s\n", i+1, urlnum, url, config.outfile ? config.outfile : "<stdout>");
    if (separator) {
#ifdef CURL_SEPARATORS
      printf("%s%s\n", CURLseparator, url);
#endif
#ifdef MIME_SEPARATORS
      printf("--%s\n", MIMEseparator);
      printf("Content-ID: %s\n\n", url); 
#endif
    }
  }
#endif

  if(!config.errors)
    config.errors = stderr;

  res = curl_urlget(URGTAG_FILE, (FILE *)&outs,  /* where to store */
                    URGTAG_WRITEFUNCTION, my_fwrite, /* what call to write */
                    URGTAG_INFILE, infd, /* for uploads */
                    URGTAG_INFILESIZE, infilesize, /* size of uploaded file */
                    URGTAG_URL, url,     /* what to fetch */
                    URGTAG_PROXY, config.proxy, /* proxy to use */
                    URGTAG_FLAGS, config.conf, /* flags */
                    URGTAG_USERPWD, config.userpwd, /* user + passwd */
                    URGTAG_PROXYUSERPWD, config.proxyuserpwd, /* Proxy user + passwd */
                    URGTAG_RANGE, config.range, /* range of document */
                    URGTAG_ERRORBUFFER, errorbuffer,
                    URGTAG_TIMEOUT, config.timeout,
                    URGTAG_POSTFIELDS, config.postfields,
                    URGTAG_REFERER, config.referer,
                    URGTAG_USERAGENT, config.useragent,
                    URGTAG_FTPPORT, config.ftpport,
                    URGTAG_LOW_SPEED_LIMIT, config.low_speed_limit,
                    URGTAG_LOW_SPEED_TIME, config.low_speed_time,
                    URGTAG_RESUME_FROM, config.use_resume?config.resume_from:0,
                    URGTAG_COOKIE, config.cookie,
                    URGTAG_HTTPHEADER, config.headers,
                    URGTAG_HTTPPOST, config.httppost,
                    URGTAG_SSLCERT, config.cert,
                    URGTAG_SSLCERTPASSWD, config.cert_passwd,
                    URGTAG_CRLF, config.crlf,
                    URGTAG_QUOTE, config.quote,
                    URGTAG_POSTQUOTE, config.postquote,
                    URGTAG_WRITEHEADER, headerfilep,
                    URGTAG_COOKIEFILE, config.cookiefile,
                    URGTAG_SSLVERSION, config.ssl_version,
                    URGTAG_TIMECONDITION, config.timecond,
                    URGTAG_TIMEVALUE, config.condtime,
                    URGTAG_CUSTOMREQUEST, config.customrequest,
                    URGTAG_STDERR, config.errors,
                    URGTAG_PROGRESSMODE, config.progressmode,
                    URGTAG_WRITEINFO, config.writeout,
                    URGTAG_DONE); /* always terminate the list of tags */
  if((res!=URG_OK) && config.showerror)
    fprintf(config.errors, "curl: (%d) %s\n", res, errorbuffer);

  if((config.errors != stderr) &&
     (config.errors != stdout))
    /* it wasn't directed to stdout or stderr so close the file! */
    fclose(config.errors);

  if(urlbuffer)
    free(urlbuffer);
  if (config.outfile && outs.stream)
    fclose(outs.stream);
  if (config.infile)
    fclose(infd);
  if(headerfilep)
    fclose(headerfilep);

  if(config.url)
    free(config.url);

#ifdef GLOBURL
  if(url)
    free(url);
  if(config.outfile && !config.remotefile)
    free(config.outfile);
  }
#ifdef MIME_SEPARATORS
  if (separator)
    printf("--%s--\n", MIMEseparator);
#endif
#endif

  curl_slist_free_all(config.quote); /* the checks for config.quote == NULL */

  return(res);
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

static char *my_get_token(const char *line)
{
  static const char *save = NULL;
  const char *first = NULL;
  const char *last = NULL;
  char *retval = NULL;
  size_t size;

  if (NULL == line)
    line = save;
  if (NULL == line)
    return NULL;

  while (('\0' != *line) && (isspace(*line)))
    line++;
  first = line;
  while (('\0' != *line) && (!isspace(*line)))
    line++;
  save = line;
  while ('\0' != *line)
    line++;
  last = line;

  size = last - first;
  if (0 == size)
    return NULL;
  if (NULL == (retval = malloc(size + 1)))
    return NULL;
  memcpy(retval, first, size);
  retval[size] = '\0';
  return retval;
}
