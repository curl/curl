#ifndef __URLDATA_H
#define __URLDATA_H
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

/* This file is for lib internal stuff */

#include "setup.h"

#ifndef MAXHOSTNAMELEN
#define MAXHOSTNAMELEN 256
#endif

#define PORT_FTP 21
#define PORT_TELNET 23
#define PORT_GOPHER 70
#define PORT_HTTP 80
#define PORT_HTTPS 443
#define PORT_DICT 2628
#define PORT_LDAP 389

#define DICT_MATCH "/MATCH:"
#define DICT_MATCH2 "/M:"
#define DICT_MATCH3 "/FIND:"
#define DICT_DEFINE "/DEFINE:"
#define DICT_DEFINE2 "/D:"
#define DICT_DEFINE3 "/LOOKUP:"

#define CURL_DEFAULT_USER "anonymous"
#define CURL_DEFAULT_PASSWORD "curl_by_Daniel.Stenberg@haxx.nu"

#include "cookie.h"
    
#ifdef USE_SSLEAY
/* SSLeay stuff usually in /usr/local/ssl/include */
#ifdef USE_OPENSSL
#include "openssl/rsa.h"
#include "openssl/crypto.h"
#include "openssl/x509.h"
#include "openssl/pem.h"
#include "openssl/ssl.h"
#include "openssl/err.h"
#else
#include "rsa.h"
#include "crypto.h"
#include "x509.h"
#include "pem.h"
#include "ssl.h"
#include "err.h"
#endif
#endif

#include "timeval.h"

/* Download buffer size, keep it fairly big for speed reasons */
#define BUFSIZE (1024*50)

/* Initial size of the buffer to store headers in, it'll be enlarged in case
   of need. */
#define HEADERSIZE 256

struct Progress {
  long lastshow; /* time() of the last displayed progress meter or NULL to
                    force redraw at next call */
  double size_dl;
  double size_ul;
  double downloaded;
  double uploaded;

  double current_speed; /* uses the currently fastest transfer */

  int mode;  /* what kind of progress meter to display */
  int width; /* screen width at download start */
  int flags; /* see progress.h */
  double timespent;
  double dlspeed;
  double ulspeed;

  struct timeval start;
  /* various data stored for possible later report */
  struct timeval t_nslookup;
  struct timeval t_connect;
  struct timeval t_pretransfer;
  int httpcode;
};

struct UrlData {
  FILE *out;    /* the fetched file goes here */
  FILE *in;     /* the uploaded file is read from here */
  FILE *err;    /* the stderr writes goes here */
  FILE *writeheader; /* write the header to this is non-NULL */
  char *url;   /* what to get */
  char *freethis; /* if non-NULL, an allocated string for the URL */
  char *hostname; /* hostname to contect, as parsed from url */
  unsigned short port; /* which port to use (if non-protocol bind) set
                          CONF_PORT to use this */
  unsigned short remote_port; /* what remote port to connect to, not the proxy
				 port! */
  char *proxy; /* if proxy, set it here, set CONF_PROXY to use this */
  long conf;   /* configure flags */
  char *userpwd;  /* <user:password>, if used */
  char *proxyuserpwd;  /* Proxy <user:password>, if used */
  char *range; /* range, if used. See README for detailed specification on
                  this syntax. */
  char *postfields; /* if POST, set the fields' values here */
  char *referer;
  char *errorbuffer; /* store failure messages in here */
  char *useragent;   /* User-Agent string */

  char *ftpport; /* port to send with the PORT command */

 /* function that stores the output:*/
  size_t (*fwrite)(char *buffer,
                   size_t size,
                   size_t nitems,
                   FILE *outstream);

  /* function that reads the input:*/
  size_t (*fread)(char *buffer,
                  size_t size,
                  size_t nitems,
                  FILE *outstream);

  long timeout; /* in seconds, 0 means no timeout */
  long infilesize; /* size of file to upload, -1 means unknown */

  long maxdownload; /* in bytes, the maximum amount of data to fetch, 0
                       means unlimited */
  
  /* fields only set and used within _urlget() */
  int firstsocket;     /* the main socket to use */
  int secondarysocket; /* for i.e ftp transfers */

  char buffer[BUFSIZE+1]; /* buffer with size BUFSIZE */

  double current_speed;  /* the ProgressShow() funcion sets this */

  long low_speed_limit; /* bytes/second */
  long low_speed_time;  /* number of seconds */

  int resume_from;    /* continue [ftp] transfer from here */

  char *cookie;       /* HTTP cookie string to send */

  short    use_ssl;   /* use ssl encrypted communications */

  char *newurl; /* This can only be set if a Location: was in the
		   document headers */

  struct HttpHeader *headers; /* linked list of extra headers */
  struct HttpPost *httppost;  /* linked list of POST data */

  char *cert; /* PEM-formatted certificate */
  char *cert_passwd; /* plain text certificate password */

  struct CookieInfo *cookies;

  long ssl_version; /* what version the client wants to use */
#ifdef USE_SSLEAY
  SSL_CTX* ctx;
  SSL*     ssl;
  X509*    server_cert;
#endif /* USE_SSLEAY */
  long crlf;
  struct curl_slist *quote;     /* before the transfer */
  struct curl_slist *postquote; /* after the transfer */

  TimeCond timecondition;
  time_t timevalue;

  char *customrequest; /* http/ftp request to use */

  char *headerbuff; /* allocated buffer to store headers in */
  int headersize;   /* size of the allocation */

  char *writeinfo;  /* if non-NULL describes what to output on a successful
                       completion */

  struct Progress progress;

#define MAX_CURL_USER_LENGTH 128
#define MAX_CURL_PASSWORD_LENGTH 128

  char user[MAX_CURL_USER_LENGTH];
  char passwd[MAX_CURL_PASSWORD_LENGTH];
  char proxyuser[MAX_CURL_USER_LENGTH];
  char proxypasswd[MAX_CURL_PASSWORD_LENGTH];

  /**** Dynamicly allocated strings, may need to be freed on return ****/
  char *ptr_proxyuserpwd; /* free later if not NULL! */
  char *ptr_uagent; /* free later if not NULL! */
  char *ptr_userpwd; /* free later if not NULL! */
  char *ptr_rangeline; /* free later if not NULL! */
  char *ptr_ref; /* free later if not NULL! */
  char *ptr_cookie; /* free later if not NULL! */
  char *ptr_host; /* free later if not NULL */
};

#define LIBCURL_NAME "libcurl"
#define LIBCURL_ID LIBCURL_NAME " " LIBCURL_VERSION " " SSL_ID


#endif
