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

/*
 * SSL code intially written by
 * Linas Vepstas <linas@linas.org> and Sampo Kellomaki <sampo@iki.fi>
 */

/* -- WIN32 approved -- */
#include <stdio.h>
#include <string.h>
#include <stdarg.h>
#include <stdlib.h>
#include <ctype.h>
#include <sys/types.h>
#include <sys/stat.h>

#include <errno.h>

#include "setup.h"

#if defined(WIN32) && !defined(__GNUC__) || defined(__MINGW32__)
#include <winsock.h>
#include <time.h>
#include <io.h>
#else
#ifdef HAVE_SYS_SOCKET_H
#include <sys/socket.h>
#endif
#include <netinet/in.h>
#include <sys/time.h>
#include <sys/resource.h>
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#include <netdb.h>
#ifdef HAVE_ARPA_INET_H
#include <arpa/inet.h>
#endif
#ifdef HAVE_NET_IF_H
#include <net/if.h>
#endif
#include <sys/ioctl.h>
#include <signal.h>

#ifdef HAVE_SYS_PARAM_H
#include <sys/param.h>
#endif

#ifdef HAVE_SYS_SELECT_H
#include <sys/select.h>
#endif

#ifndef HAVE_VPRINTF
#error "We can't compile without vprintf() support!"
#endif
#ifndef HAVE_SELECT
#error "We can't compile without select() support!"
#endif
#ifndef HAVE_SOCKET
#error "We can't compile without socket() support!"
#endif

#endif

#include "urldata.h"
#include <curl/curl.h>
#include "netrc.h"

#include "formdata.h"
#include "getenv.h"
#include "base64.h"
#include "ssluse.h"
#include "hostip.h"
#include "if2ip.h"
#include "download.h"
#include "sendf.h"
#include "speedcheck.h"
#include "getpass.h"
#include "progress.h"
#include "cookie.h"

/* And now for the protocols */
#include "ftp.h"
#include "dict.h"
#include "telnet.h"
#include "http.h"
#include "file.h"
#include "ldap.h"

#define _MPRINTF_REPLACE /* use our functions only */
#include <curl/mprintf.h>

/* -- -- */

/***********************************************************************
 * Start with some silly functions to make win32-systems survive
 ***********************************************************************/
#if defined(WIN32) && !defined(__GNUC__) || defined(__MINGW32__)
static void cleanup(void)
{
  WSACleanup();
}

static int init(void)
{
  WORD wVersionRequested;  
  WSADATA wsaData; 
  int err; 
  wVersionRequested = MAKEWORD(1, 1); 
    
  err = WSAStartup(wVersionRequested, &wsaData); 
    
  if (err != 0) 
    /* Tell the user that we couldn't find a useable */ 
    /* winsock.dll.     */ 
    return 1; 
    
  /* Confirm that the Windows Sockets DLL supports 1.1.*/ 
  /* Note that if the DLL supports versions greater */ 
  /* than 1.1 in addition to 1.1, it will still return */ 
  /* 1.1 in wVersion since that is the version we */ 
  /* requested. */ 
    
  if ( LOBYTE( wsaData.wVersion ) != 1 || 
       HIBYTE( wsaData.wVersion ) != 1 ) { 
    /* Tell the user that we couldn't find a useable */ 

    /* winsock.dll. */ 
    WSACleanup(); 
    return 1; 
  }
  return 0;
}
/* The Windows Sockets DLL is acceptable. Proceed. */ 
#else
static int init(void) { return 0; }
static void cleanup(void) {}
#endif

static UrgError _urlget(struct UrlData *data);


void urlfree(struct UrlData *data, bool totally)
{
#ifdef USE_SSLEAY
  if (data->use_ssl) {
    if(data->ssl) {
      SSL_shutdown(data->ssl);
      SSL_set_connect_state(data->ssl);

      SSL_free (data->ssl);
      data->ssl = NULL;
    }
    if(data->ctx) {
      SSL_CTX_free (data->ctx);
      data->ctx = NULL;
    }
    data->use_ssl = FALSE; /* get back to ordinary socket usage */
  }
#endif /* USE_SSLEAY */

  /* close possibly still open sockets */
  if(-1 != data->secondarysocket) {
    sclose(data->secondarysocket);
    data->secondarysocket = -1;	
  }
  if(-1 != data->firstsocket) {
    sclose(data->firstsocket);
    data->firstsocket=-1;
  }


  if(data->ptr_proxyuserpwd) {
    free(data->ptr_proxyuserpwd);
    data->ptr_proxyuserpwd=NULL;
  }
  if(data->ptr_uagent) {
    free(data->ptr_uagent);
    data->ptr_uagent=NULL;
  }
  if(data->ptr_userpwd) {
    free(data->ptr_userpwd);
    data->ptr_userpwd=NULL;
  }
  if(data->ptr_rangeline) {
    free(data->ptr_rangeline);
    data->ptr_rangeline=NULL;
  }
  if(data->ptr_ref) {
    free(data->ptr_ref);
    data->ptr_ref=NULL;
  }
  if(data->ptr_cookie) {
    free(data->ptr_cookie);
    data->ptr_cookie=NULL;
  }
  if(data->ptr_host) {
    free(data->ptr_host);
    data->ptr_host=NULL;
  }

  if(totally) {
    /* we let the switch decide whether we're doing a part or total
       cleanup */

    /* check for allocated [URL] memory to free: */
    if(data->freethis)
      free(data->freethis);

    if(data->headerbuff)
      free(data->headerbuff);

    cookie_cleanup(data->cookies);

    free(data);

    /* winsock crap cleanup */
    cleanup();
  }
}

typedef int (*func_T)(void);

UrgError curl_urlget(UrgTag tag, ...)
{
  va_list arg;
  func_T param_func = (func_T)0;
  long param_long = 0;
  void *param_obj = NULL;
  UrgError res;
  char *cookiefile;

  struct UrlData *data;

  /* this is for the lame win32 socket crap */
  if(init())
    return URG_FAILED_INIT;

  data = (struct UrlData *)malloc(sizeof(struct UrlData));
  if(data) {

    memset(data, 0, sizeof(struct UrlData));

    /* Let's set some default values: */
    data->out = stdout; /* default output to stdout */
    data->in  = stdin;  /* default input from stdin */
    data->err  = stderr;  /* default stderr to stderr */
    data->firstsocket = -1; /* no file descriptor */
    data->secondarysocket = -1; /* no file descriptor */

    /* use fwrite as default function to store output */
    data->fwrite = (size_t (*)(char *, size_t, size_t, FILE *))fwrite;

    /* use fread as default function to read input */
    data->fread = (size_t (*)(char *, size_t, size_t, FILE *))fread;

    data->infilesize = -1; /* we don't know any size */

    data->current_speed = -1; /* init to negative == impossible */

    va_start(arg, tag);

    while(tag != URGTAG_DONE) {
      /* PORTING NOTE:
	 Ojbect pointers can't necessarily be casted to function pointers and
	 therefore we need to know what type it is and read the correct type
	 at once. This should also correct problems with different sizes of
	 the types.
         */

      if(tag < URGTYPE_OBJECTPOINT) {
	/* This is a LONG type */
	param_long = va_arg(arg, long);
      }
      else if(tag < URGTYPE_FUNCTIONPOINT) {
	/* This is a object pointer type */
	param_obj = va_arg(arg, void *);
      }
      else
	param_func = va_arg(arg, func_T );

      /* printf("tag: %d\n", tag); */
     

      switch(tag) {
#ifdef MULTIDOC
      case URGTAG_MOREDOCS:
        data->moredoc = (struct MoreDoc *)param_obj;
        break;
#endif
      case URGTAG_TIMECONDITION:
        data->timecondition = (long)param_long;
        break;

      case URGTAG_TIMEVALUE:
        data->timevalue = (long)param_long;
        break;

      case URGTAG_SSLVERSION:
        data->ssl_version = (int)param_long;
        break;

      case URGTAG_COOKIEFILE:
        cookiefile = (char *)param_obj;
        if(cookiefile) {
          data->cookies = cookie_init(cookiefile);
        }
        break;
      case URGTAG_WRITEHEADER:
	data->writeheader = (FILE *)param_obj;
	break;
      case URGTAG_COOKIE:
	data->cookie = (char *)param_obj;
	break;
      case URGTAG_ERRORBUFFER:
        data->errorbuffer = (char *)param_obj;
        break;
      case URGTAG_FILE:
        data->out = (FILE *)param_obj;
        break;
      case URGTAG_FTPPORT:
        data->ftpport = (char *)param_obj;
        break;
      case URGTAG_HTTPHEADER:
	data->headers = (struct HttpHeader *)param_obj;
	break;
      case URGTAG_CUSTOMREQUEST:
	data->customrequest = (char *)param_obj;
	break;
      case URGTAG_HTTPPOST:
	data->httppost = (struct HttpPost *)param_obj;
	break;
      case URGTAG_INFILE:
        data->in = (FILE *)param_obj;
        break;
      case URGTAG_INFILESIZE:
        data->infilesize = (long)param_long;
        break;
      case URGTAG_LOW_SPEED_LIMIT:
	data->low_speed_limit=(long)param_long;
	break;
      case URGTAG_LOW_SPEED_TIME:
	data->low_speed_time=(long)param_long;
	break;
      case URGTAG_URL:
        data->url = (char *)param_obj;
        break;
      case URGTAG_PORT:
        /* this typecast is used to fool the compiler to NOT warn for a
           "cast from pointer to integer of different size" */
        data->port = (unsigned short)((long)param_long);
        break;
      case URGTAG_POSTFIELDS:
        data->postfields = (char *)param_obj;
        break;
      case URGTAG_PROGRESSMODE:
        data->progress.mode = (long)param_long;
        break;
      case URGTAG_REFERER:
        data->referer = (char *)param_obj;
        break;
      case URGTAG_PROXY:
        data->proxy = (char *)param_obj;
        break;
      case URGTAG_FLAGS:
        data->conf = (long)param_long;
        break;
      case URGTAG_TIMEOUT:
        data->timeout = (long)param_long;
        break;
      case URGTAG_USERAGENT:
        data->useragent = (char *)param_obj;
        break;
      case URGTAG_USERPWD:
        data->userpwd = (char *)param_obj;
        break;
      case URGTAG_POSTQUOTE:
        data->postquote = (struct curl_slist *)param_obj;
        break;
      case URGTAG_PROXYUSERPWD:
        data->proxyuserpwd = (char *)param_obj;
        break;
      case URGTAG_RANGE:
        data->range = (char *)param_obj;
        break;
      case URGTAG_RESUME_FROM:
	data->resume_from = (long)param_long;
	break;
      case URGTAG_STDERR:
	data->err = (FILE *)param_obj;
	break;
      case URGTAG_WRITEFUNCTION:
        data->fwrite = (size_t (*)(char *, size_t, size_t, FILE *))param_func;
        break;
      case URGTAG_WRITEINFO:
        data->writeinfo = (char *)param_obj;
        break;
      case URGTAG_READFUNCTION:
        data->fread = (size_t (*)(char *, size_t, size_t, FILE *))param_func;
        break;
      case URGTAG_SSLCERT:
	data->cert = (char *)param_obj;
	break;
      case URGTAG_SSLCERTPASSWD:
	data->cert_passwd = (char *)param_obj;
	break;
      case URGTAG_CRLF:
	data->crlf = (long)param_long;
	break;
      case URGTAG_QUOTE:
        data->quote = (struct curl_slist *)param_obj;
        break;
      case URGTAG_DONE: /* done with the parsing, fall through */
        continue;
      default:
        /* unknown tag and its companion, just ignore: */
        break;
      }
      tag = va_arg(arg, UrgTag);
    }

    va_end(arg);

    pgrsMode(data, data->progress.mode);
    pgrsStartNow(data);

    data-> headerbuff=(char*)malloc(HEADERSIZE);
    if(!data->headerbuff)
      return URG_FAILED_INIT;

    data-> headersize=HEADERSIZE;

    res = _urlget(data); /* fetch the URL please */

    while((res == URG_OK) && data->newurl) {
      /* Location: redirect */
      char prot[16];
      char path[URL_MAX_LENGTH];

      if(2 != sscanf(data->newurl, "%15[^:]://%" URL_MAX_LENGTH_TXT
                     "s", prot, path)) {
	/***
	 *DANG* this is an RFC 2068 violation. The URL is supposed
	 to be absolute and this doesn't seem to be that!
	 ***
	 Instead, we have to TRY to append this new path to the old URL
	 to the right of the host part. Oh crap, this is doomed to cause
	 problems in the future...
	 */
	char *protsep;
	char *pathsep;
	char *newest;

	/* protsep points to the start of the host name */
	protsep=strstr(data->url, "//");
	if(!protsep)
	  protsep=data->url;
	else {
          data->port=0; /* we got a full URL and then we should reset the
                           port number here to re-initiate it later */
	  protsep+=2; /* pass the // */
        }

        if('/' != data->newurl[0]) {
          /* First we need to find out if there's a ?-letter in the URL, and
             cut it and the right-side of that off */
          pathsep = strrchr(protsep, '?');
          if(pathsep)
            *pathsep=0;

          /* we have a relative path to append to the last slash if
             there's one available */
          pathsep = strrchr(protsep, '/');
          if(pathsep)
            *pathsep=0;
        }
        else {
          /* We got a new absolute path for this server, cut off from the
             first slash */
          pathsep = strchr(protsep, '/');
          if(pathsep)
            *pathsep=0;
        }

        newest=(char *)malloc( strlen(data->url) +
                               1 + /* possible slash */
                               strlen(data->newurl) + 1/* zero byte */);

	if(!newest)
	  return URG_OUT_OF_MEMORY;
        sprintf(newest, "%s%s%s", data->url, ('/' == data->newurl[0])?"":"/",
                data->newurl);
	free(data->newurl);
	data->newurl = newest;
      }

      data->url = data->newurl;
      data->newurl = NULL; /* don't show! */

      infof(data, "Follows Location: to new URL: '%s'\n", data->url);

      /* clean up the sockets and SSL stuff from the previous "round" */
      urlfree(data, FALSE);

      res = _urlget(data);
    }
    if(data->newurl)
      free(data->newurl);

  }
  else
    res = URG_FAILED_INIT; /* failed */

  if((URG_OK == res) && data->writeinfo) {
    /* Time to output some info to stdout */
    WriteOut(data);
  }


  /* total cleanup */
  urlfree(data, TRUE);

  return res;
}


/*
 * Read everything until a newline.
 */

static int GetLine(int sockfd, char *buf,
		   struct UrlData *data)
{
  int nread;
  int read_rc=1;
  char *ptr;
  ptr=buf;

  /* get us a full line, terminated with a newline */
  for(nread=0;
      (nread<BUFSIZE) && read_rc;
      nread++, ptr++) {
#ifdef USE_SSLEAY
    if (data->use_ssl) {
      read_rc = SSL_read(data->ssl, ptr, 1);
    }
    else {
#endif
      read_rc = sread(sockfd, ptr, 1);
#ifdef USE_SSLEAY
    }
#endif /* USE_SSLEAY */
    if (*ptr == '\n')
      break;
  }
  *ptr=0; /* zero terminate */

  if(data->conf & CONF_VERBOSE) {
    fputs("< ", data->err);
    fwrite(buf, 1, nread, data->err);
    fputs("\n", data->err);
  }
  return nread;
}



#ifndef WIN32
#ifndef RETSIGTYPE
#define RETSIGTYPE void
#endif
RETSIGTYPE alarmfunc(int signal)
{
  /* this is for "-ansi -Wall -pedantic" to stop complaining!   (rabe) */
  (void)signal;
  return;
}
#endif

/* ====================================================== */
/*
 * urlget <url>
 * (result put on stdout)
 *
 * <url> ::= <proto> "://" <host> [ ":" <port> ] "/" <path>
 *
 * <proto> = "HTTP" | "HTTPS" | "GOPHER" | "FTP"
 *
 * When FTP:
 *
 * <host> ::= [ <user> ":" <password> "@" ] <host>
 */

static UrgError _urlget(struct UrlData *data)
{
  struct hostent *hp=NULL;
  struct sockaddr_in serv_addr;
  char *buf;
  char proto[64];
  char gname[256]="default.com";
  char *name;
  char path[URL_MAX_LENGTH]="/";
  char *ppath, *tmp;
  long bytecount;
  struct timeval now;

  UrgError result;
  char resumerange[12]="";

  buf = data->buffer; /* this is our buffer */

#if 0
  signal(SIGALRM, alarmfunc);
#endif

  /* Parse <url> */
  /* We need to parse the url, even when using the proxy, because
   * we will need the hostname and port in case we are trying
   * to SSL connect through the proxy -- and we don't know if we
   * will need to use SSL until we parse the url ...
   */
  if((1 == sscanf(data->url, "file://%" URL_MAX_LENGTH_TXT "[^\n]",
                  path))) {
    /* we deal with file://<host>/<path> differently since it
       supports no hostname other than "localhost" and "127.0.0.1",
       which ist unique among the protocols specified in RFC 1738 */
    if (strstr(path, "localhost/") || strstr(path, "127.0.0.1/"))
      strcpy(path, &path[10]);		/* ... since coincidentally
					   both host strings are of
					   equal length */
    /* otherwise, <host>/ is quietly ommitted */


    /* that's it, no more fiddling with proxies, redirections,
       or SSL for files, go directly to the file reading function */
    result = file(data, path, &bytecount);
    if(result)
      return result;
  
    return URG_OK;
  }
  else if (2 > sscanf(data->url, "%64[^\n:]://%256[^\n/]%" URL_MAX_LENGTH_TXT "[^\n]",
                 proto, gname, path)) {
    
      
    /* badly formatted, let's try the browser-style _without_ 'http://' */
    if((1 > sscanf(data->url, "%256[^\n/]%" URL_MAX_LENGTH_TXT "[^\n]", gname,
                   path)) ) {
      failf(data, "<url> malformed");
      return URG_URL_MALFORMAT;
    }
    if(strnequal(gname, "FTP", 3)) {
      strcpy(proto, "ftp");
    }
    else if(strnequal(gname, "GOPHER", 6))
      strcpy(proto, "gopher");
#ifdef USE_SSLEAY
    else if(strnequal(gname, "HTTPS", 5))
      strcpy(proto, "https");
#endif /* USE_SSLEAY */
    else if(strnequal(gname, "TELNET", 6))
      strcpy(proto, "telnet");
    else if (strnequal(gname, "DICT", sizeof("DICT")-1))
      strcpy(proto, "DICT");
    else if (strnequal(gname, "LDAP", sizeof("LDAP")-1))
      strcpy(proto, "LDAP");
    else
      strcpy(proto, "http");

    data->conf |= CONF_NOPROT;
  }


  if((data->conf & CONF_USERPWD) && ! (data->conf & CONF_NETRC)) {
    if(':' != *data->userpwd) {
      if((1 <= sscanf(data->userpwd, "%127[^:]:%127s",
                      data->user, data->passwd))) {
        /* check for password, if no ask for one */
        if( !data->passwd[0] )
        {
          strncpy(data->passwd, getpass("password: "), sizeof(data->passwd));
        }
      }
    }
    if(!data->user[0]) {
      failf(data, "USER malformat: user name can't be zero length");
      return URG_MALFORMAT_USER;
    }
  }

  if(data->conf & CONF_PROXYUSERPWD) {
    if(':' != *data->proxyuserpwd) {
      if((1 <= sscanf(data->proxyuserpwd, "%127[^:]:%127s",
                      data->proxyuser, data->proxypasswd))) {
        /* check for password, if no ask for one */
        if( !data->proxypasswd[0] )
        {
          strncpy(data->proxypasswd, getpass("proxy password: "), sizeof(data->proxypasswd));
        }
      }
    }
    if(!data->proxyuser[0]) {
      failf(data, " Proxy USER malformat: user name can't be zero length");
      return URG_MALFORMAT_USER;
    }
  }

  name = gname;
  ppath = path;
  data->hostname = name;


  if(!(data->conf & CONF_PROXY)) {
    /* If proxy was not specified, we check for default proxy environment
       variables, to enable i.e Lynx compliance:

       HTTP_PROXY http://some.server.dom:port/
       HTTPS_PROXY http://some.server.dom:port/
       FTP_PROXY http://some.server.dom:port/
       GOPHER_PROXY http://some.server.dom:port/
       NO_PROXY host.domain.dom  (a comma-separated list of hosts which should
       not be proxied, or an asterisk to override all proxy variables)
       ALL_PROXY seems to exist for the CERN www lib. Probably the first to
       check for.
 
       */
    char *no_proxy=GetEnv("NO_PROXY");
    char *proxy=NULL;
    char proxy_env[128];

    if(!no_proxy || !strequal("*", no_proxy)) {
      /* NO_PROXY wasn't specified or it wasn't just an asterisk */
      char *nope;

      nope=no_proxy?strtok(no_proxy, ", "):NULL;
      while(nope) {
        if(strlen(nope) <= strlen(name)) {
          char *checkn=
            name + strlen(name) - strlen(nope);
          if(strnequal(nope, checkn, strlen(nope))) {
            /* no proxy for this host! */
            break;
          }
        }
	nope=strtok(NULL, ", ");
      }
      if(!nope) {
	/* It was not listed as without proxy */
	char *protop = proto;
	char *envp = proxy_env;
	char *prox;

	/* Now, build <PROTOCOL>_PROXY and check for such a one to use */
	while(*protop) {
	  *envp++ = toupper(*protop++);
	}
	/* append _PROXY */
	strcpy(envp, "_PROXY");
#if 0
	infof(data, "DEBUG: checks the environment variable %s\n", proxy_env);
#endif
	/* read the protocol proxy: */
	prox=GetEnv(proxy_env);

	if(prox && *prox) { /* don't count "" strings */
	  proxy = prox; /* use this */
        }
        else
          proxy = GetEnv("ALL_PROXY"); /* default proxy to use */

        if(proxy && *proxy) {
          /* we have a proxy here to set */
          data->proxy = proxy;
          data->conf |= CONF_PROXY;
        }
      } /* if (!nope) - it wasn't specfied non-proxy */
    } /* NO_PROXY wasn't specified or '*' */
  } /* if not using proxy */

  if((data->conf & (CONF_PROXY|CONF_NOPROT)) == (CONF_PROXY|CONF_NOPROT) ) {
    /* We're guessing prefixes here and since we're told to use a proxy, we
       need to add the protocol prefix to the URL string before we continue!
       */
    char *reurl;

    reurl = maprintf("%s://%s", proto, data->url);

    if(!reurl)
      return URG_OUT_OF_MEMORY;

    data->url = reurl;
    if(data->freethis)
      free(data->freethis);
    data->freethis = reurl;

    data->conf &= ~CONF_NOPROT; /* switch that one off again */
  }

  /* RESUME on a HTTP page is a tricky business. First, let's just check that
     'range' isn't used, then set the range parameter and leave the resume as
     it is to inform about this situation for later use. We will then
     "attempt" to resume, and if we're talking to a HTTP/1.1 (or later)
     server, we will get the document resumed. If we talk to a HTTP/1.0
     server, we just fail since we can't rewind the file writing from within
     this function. */
  if(data->resume_from) {
    if(!(data->conf & CONF_RANGE)) {
      /* if it already was in use, we just skip this */
      sprintf(resumerange, "%d-", data->resume_from);
      data->range=resumerange; /* tell ourselves to fetch this range */
      data->conf |= CONF_RANGE; /* switch on range usage */
    }
  }


  if(data->timeout) {
    /* We set the timeout on the connection/resolving phase first, separately
       from the download/upload part to allow a maximum time on everything */
    myalarm(data->timeout); /* this sends a signal when the timeout fires
			       off, and that will abort system calls */
  }

  /*
   * Hmm, if we are using a proxy, then we can skip the GOPHER and the
   * FTP steps, although we cannot skip the HTTPS step (since the proxy
   * works differently, depending on whether its SSL or not).
   */

  if (strequal(proto, "HTTP")) {
    if(!data->port)
      data->port = PORT_HTTP;
    data->remote_port = PORT_HTTP;
    data->conf |= CONF_HTTP;
  }
  else if (strequal(proto, "HTTPS")) {
#ifdef USE_SSLEAY
    if(!data->port)
      data->port = PORT_HTTPS;
    data->remote_port = PORT_HTTPS;
    data->conf |= CONF_HTTP;
    data->conf |= CONF_HTTPS;
#else /* USE_SSLEAY */
    failf(data, "SSL is disabled, https: not supported!");
    return URG_UNSUPPORTED_PROTOCOL;
#endif /* !USE_SSLEAY */
  }
  else if (strequal(proto, "GOPHER")) {
    if(!data->port)
      data->port = PORT_GOPHER;
    data->remote_port = PORT_GOPHER;
    /* Skip /<item-type>/ in path if present */
    if (isdigit((int)path[1])) {
      ppath = strchr(&path[1], '/');
      if (ppath == NULL)
	ppath = path;
      }
    data->conf |= CONF_GOPHER;
  }
  else if(strequal(proto, "FTP")) {
    char *type;
    if(!data->port)
      data->port = PORT_FTP;
    data->remote_port = PORT_FTP;
    data->conf |= CONF_FTP;

    ppath++; /* don't include the initial slash */

    /* FTP URLs support an extension like ";type=<typecode>" that
       we'll try to get now! */
    type=strstr(ppath, ";type=");
    if(!type) {
      type=strstr(gname, ";type=");
    }
    if(type) {
      char command;
      *type=0;
      command = toupper(type[6]);
      switch(command) {
      case 'A': /* ASCII mode */
	data->conf |= CONF_FTPASCII;
	break;
      case 'D': /* directory mode */
	data->conf |= CONF_FTPLISTONLY;
	break;
      case 'I': /* binary mode */
      default:
	/* switch off ASCII */
	data->conf &= ~CONF_FTPASCII; 
	break;
      }
    }
  }
  else if(strequal(proto, "TELNET")) {
    /* telnet testing factory */
    data->conf |= CONF_TELNET;
    if(!data->port)
      data->port = PORT_TELNET;
    data->remote_port = PORT_TELNET;
  }
  else if (strequal(proto, "DICT")) {
    data->conf |= CONF_DICT;
    if(!data->port)
      data->port = PORT_DICT;
    data->remote_port = PORT_DICT;
  }
  else if (strequal(proto, "LDAP")) {
    data->conf |= CONF_LDAP;
    if(!data->port)
      data->port = PORT_LDAP;
    data->remote_port = PORT_LDAP;
  }
  /* file:// is handled above */
  /*  else if (strequal(proto, "FILE")) {
    data->conf |= CONF_FILE;

    result = file(data, path, &bytecount);
    if(result)
      return result;

    return URG_OK;
    }*/
  else {
    failf(data, "Unsupported protocol: %s", proto);
    return URG_UNSUPPORTED_PROTOCOL;
  }

  if(data->conf & CONF_NETRC) {
    if(ParseNetrc(data->hostname, data->user, data->passwd)) {
      infof(data, "Couldn't find host %s in the .netrc file, using defaults",
            data->hostname);
    }
    /* weather we failed or not, we don't know which fields that were filled
       in anyway */
    if(!data->user[0])
      strcpy(data->user, CURL_DEFAULT_USER);
    if(!data->passwd[0])
      strcpy(data->passwd, CURL_DEFAULT_PASSWORD);
    if(data->conf & CONF_HTTP) {
      data->conf |= CONF_USERPWD;
    }
  }
  else if(!(data->conf & CONF_USERPWD) &&
	  (data->conf & (CONF_FTP|CONF_HTTP)) ) {
    /* This is a FTP or HTTP URL, and we haven't got the user+password in
       the extra parameter, we will now try to extract the possible
       user+password pair in a string like:
       ftp://user:password@ftp.my.site:8021/README */
    char *ptr=NULL; /* assign to remove possible warnings */
    if(':' == *name) {
      failf(data, "URL malformat: user can't be zero length");
      return URG_URL_MALFORMAT_USER;
    }
    if((1 <= sscanf(name, "%127[^:]:%127[^@]",
		    data->user, data->passwd)) && (ptr=strchr(name, '@'))) {
      name = ++ptr;
      data->conf |= CONF_USERPWD;
    }
    else {
      strcpy(data->user, CURL_DEFAULT_USER);
      strcpy(data->passwd, CURL_DEFAULT_PASSWORD);
    }
  }

  if(!(data->conf & CONF_PROXY)) {
    /* If not connecting via a proxy, extract the port from the URL, if it is
     * there, thus overriding any defaults that might have been set above. */
    tmp = strchr(name, ':');
    if (tmp) {
      *tmp++ = '\0';
      data->port = atoi(tmp);
    }
    
    /* Connect to target host right on */
    if(!(hp = GetHost(data, name))) {
      failf(data, "Couldn't resolv host '%s'", name);
      return URG_COULDNT_RESOLVE_HOST;
    }
  }
  else {
    char *prox_portno;
    char *endofprot;

    /* we use proxy all right, but we wanna know the remote port for SSL
       reasons */
    tmp = strchr(name, ':');
    if (tmp) {
      *tmp++ = '\0'; /* cut off the name there */
      data->remote_port = atoi(tmp);
    }

    /* Daniel Dec 10, 1998:
       We do the proxy host string parsing here. We want the host name and the
       port name. Accept a protocol:// prefix, even though it should just be
       ignored. */

    /* 1. skip the protocol part if present */
    endofprot=strstr(data->proxy, "://");
    if(endofprot) {
      data->proxy = endofprot+3;
    }

    /* allow user to specify proxy.server.com:1080 if desired */
    prox_portno = strchr (data->proxy, ':');
    if (prox_portno) {
      *prox_portno = 0x0; /* cut off number from host name */
      prox_portno ++;
      /* now set the local port number */
      data->port = atoi(prox_portno);
    }

    /* connect to proxy */
    if(!(hp = GetHost(data, data->proxy))) {
      failf(data, "Couldn't resolv proxy '%s'", data->proxy);
      return URG_COULDNT_RESOLVE_PROXY;
    }
  }
  pgrsTime(data, TIMER_NAMELOOKUP);

  data->firstsocket = socket(AF_INET, SOCK_STREAM, 0);

  memset((char *) &serv_addr, '\0', sizeof(serv_addr));
  memcpy((char *)&(serv_addr.sin_addr), hp->h_addr, hp->h_length);
  serv_addr.sin_family = hp->h_addrtype;

  serv_addr.sin_port = htons(data->port);

  if (connect(data->firstsocket, (struct sockaddr *) &serv_addr,
	      sizeof(serv_addr)) < 0) {
    switch(errno) {
#ifdef ECONNREFUSED
      /* this should be made nicer */
    case ECONNREFUSED:
      failf(data, "Connection refused");
      break;
#endif
#ifdef EINTR
    case EINTR:
      failf(data, "Connection timeouted");
      break;
#endif
    default:
      failf(data, "Can't connect to server: %d", errno);
      break;
    }
    return URG_COULDNT_CONNECT;
  }

  if(data->conf & CONF_PROXYUSERPWD) {
    char authorization[512];
    sprintf(data->buffer, "%s:%s", data->proxyuser, data->proxypasswd);
    base64Encode(data->buffer, authorization);

    data->ptr_proxyuserpwd = maprintf("Proxy-authorization: Basic %s\015\012",
				      authorization);
  }
  if(data->conf & (CONF_HTTPS|CONF_HTTP)) {
    if(data->useragent) {
      data->ptr_uagent = maprintf("User-Agent: %s\015\012", data->useragent);
    }
  }


  /* If we are not using a proxy and we want a secure connection,
   * perform SSL initialization & connection now.
   * If using a proxy with https, then we must tell the proxy to CONNECT
   * us to the host we want to talk to.  Only after the connect
   * has occured, can we start talking SSL
   */
   if (data->conf & CONF_HTTPS) {
     if (data->conf & CONF_PROXY) {

        /* OK, now send the connect statment */
        sendf(data->firstsocket, data,
              "CONNECT %s:%d HTTP/1.0\015\012"
              "%s"
	      "%s"
              "\r\n",
              data->hostname, data->remote_port,
              (data->conf&CONF_PROXYUSERPWD)?data->ptr_proxyuserpwd:"",
	      (data->useragent?data->ptr_uagent:"")
              );

        /* wait for the proxy to send us a HTTP/1.0 200 OK header */
	/* Daniel rewrote this part Nov 5 1998 to make it more obvious */
	{
	  int httperror=0;
	  int subversion=0;
	  while(GetLine(data->firstsocket, data->buffer, data)) {
	    if('\r' == data->buffer[0])
	      break; /* end of headers */
	    if(2 == sscanf(data->buffer, "HTTP/1.%d %d",
			   &subversion,
			   &httperror)) {
	      ;
	    }
	  }
	  if(200 != httperror) {
	    if(407 == httperror)
	      /* Added Nov 6 1998 */
	      failf(data, "Proxy requires authorization!");
	    else 
	      failf(data, "Received error code %d from proxy", httperror);
	    return URG_READ_ERROR;
	  }
	}
        infof (data, "Proxy has replied to CONNECT request\n");
     }

      /* now, perform the SSL initialization for this socket */
     if(UrgSSLConnect (data)) {
       return URG_SSL_CONNECT_ERROR;
     }
  }
  pgrsTime(data, TIMER_CONNECT);

  now = tvnow(); /* time this *after* the connect is done */
  bytecount = 0;
  
  /* Figure out the ip-number and the first host name it shows: */
  {
    struct in_addr in;
    (void) memcpy(&in.s_addr, *hp->h_addr_list, sizeof (in.s_addr));
    infof(data, "Connected to %s (%s)\n", hp->h_name, inet_ntoa(in));
  }

  if((data->conf&(CONF_FTP|CONF_PROXY)) == CONF_FTP) {
    result = ftp(data, &bytecount, data->user, data->passwd, ppath);
    if(result)
      return result;
  }
  else if(data->conf & CONF_TELNET) {
    result=telnet(data);
    if(result)
      return result;
  }
  else if (data->conf & CONF_LDAP) {
    result = ldap(data, path, &bytecount);
    if (result)
      return result;
  }
  else if (data->conf & CONF_DICT) {
    result = dict(data, path, &bytecount);
    if(result)
      return result;
  }
  else {
    result = http(data, ppath, name, &bytecount);
    if(result)
      return result;
  }
  if(bytecount) {
    double ittook = tvdiff (tvnow(), now);
    infof(data, "%i bytes transfered in %.3lf seconds (%.0lf bytes/sec).\n",
          bytecount, ittook, (double)bytecount/(ittook!=0.0?ittook:1));
  }
  return URG_OK;
}

