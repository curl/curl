#ifndef __CURL_H
#define __CURL_H
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
#ifndef TRUE
#define TRUE 1
#endif
#ifndef FALSE
#define FALSE 0
#endif


#define CONF_DEFAULT 0
#define CONF_PROXY   (1<<0) /* set if proxy is in use */
#define CONF_PORT    (1<<1) /* set if different port than protcol-defines is
                               used */
#define CONF_HTTP    (1<<2) /* http get */
#define CONF_GOPHER  (1<<3) /* gopher get */
#define CONF_FTP     (1<<4) /* ftp get (binary mode) */
#define CONF_VERBOSE (1<<5) /* talk a lot */

#define CONF_TELNET  (1<<6)

#define CONF_HEADER  (1<<8) /* throw the header out too */
#define CONF_USERPWD (1<<9) /* user+passwd has been specified */
#define CONF_NOPROGRESS (1<<10) /* shut off the progress meter (auto)
                                   see also _MUTE */
#define CONF_NOBODY  (1<<11) /* use HEAD to get http document */
#define CONF_FAILONERROR (1<<12) /* Makes urlget() fail with a return code
                                    WITHOUT writing anything to the output if
                                    a return code >=300 is returned from the
                                    server. */
#define CONF_RANGE (1<<13) /* Byte-range request, specified parameter is set */
#define CONF_UPLOAD (1<<14) /* this is an upload, only supported for ftp
                               currently */

#define CONF_POST (1<<15) /* HTTP POST method */

/* When getting an FTP directory, this switch makes the listing only show file
   names and nothing else. Makes machine parsing of the output possible. This
   enforces the NLST command to the ftp server, compared to the otherwise
   used: LIST. */
#define CONF_FTPLISTONLY (1<<16)

/* Set the referer string */
#define CONF_REFERER (1<<17)
#define CONF_PROXYUSERPWD (1<<18) /* Proxy user+passwd has been specified */

/* For FTP, use PORT instead of PASV! */
#define CONF_FTPPORT (1<<19)

/* FTP: Append instead of overwrite on upload! */
#define CONF_FTPAPPEND (1<<20)

#define CONF_HTTPS (1<<21)  /* Use SSLeay for encrypted communication */

#define CONF_NETRC (1<<22)  /* read user+password from .netrc */

#define CONF_FOLLOWLOCATION (1<<23) /* get the page that the Location: tells
				       us to get */

#define CONF_FTPASCII (1<<24) /* use TYPE A for transfer */

#define CONF_HTTPPOST (1<<25) /* this causes a multipart/form-data
				 HTTP POST */
#define CONF_NOPROT   (1<<26) /* host name specified without protocol */

#define CONF_PUT      (1<<27) /* PUT the input file */

#define CONF_MUTE     (1<<28) /* force NOPROGRESS */

#define CONF_DICT     (1<<29) /* DICT:// protocol */

#define CONF_FILE     (1<<30) /* FILE:// protocol */

#define CONF_LDAP     (1<<31) /* LDAP:// protocol */

struct HttpHeader {
  struct HttpHeader *next; /* next entry in the list */
  char *header; /* pointer to allocated line without newline */
};

struct HttpPost {
  struct HttpPost *next; /* next entry in the list */
  char *name;     /* pointer to allocated name */
  char *contents; /* pointer to allocated data contents */
  char *contenttype; /* Content-Type */
  struct HttpPost *more; /* if one field name has more than one file, this
			    link should link to following files */
  long flags;     /* as defined below */
#define HTTPPOST_FILENAME (1<<0) /* specified content is a file name */
};

/* All possible error codes from this version of urlget(). Future versions
   may return other values, stay prepared. */

typedef enum {
  URG_OK = 0,
  URG_UNSUPPORTED_PROTOCOL,
  URG_FAILED_INIT,
  URG_URL_MALFORMAT,
  URG_URL_MALFORMAT_USER,
  URG_COULDNT_RESOLVE_PROXY,
  URG_COULDNT_RESOLVE_HOST,
  URG_COULDNT_CONNECT,
  URG_FTP_WEIRD_SERVER_REPLY,
  URG_FTP_ACCESS_DENIED,
  URG_FTP_USER_PASSWORD_INCORRECT,
  URG_FTP_WEIRD_PASS_REPLY,
  URG_FTP_WEIRD_USER_REPLY,
  URG_FTP_WEIRD_PASV_REPLY,
  URG_FTP_WEIRD_227_FORMAT,
  URG_FTP_CANT_GET_HOST,
  URG_FTP_CANT_RECONNECT,
  URG_FTP_COULDNT_SET_BINARY,
  URG_PARTIAL_FILE,
  URG_FTP_COULDNT_RETR_FILE,
  URG_FTP_WRITE_ERROR,
  URG_FTP_QUOTE_ERROR,
  URG_HTTP_NOT_FOUND,
  URG_WRITE_ERROR,

  URG_MALFORMAT_USER, /* the user name is illegally specified */
  URG_FTP_COULDNT_STOR_FILE, /* failed FTP upload */
  URG_READ_ERROR, /* could open/read from file */

  URG_OUT_OF_MEMORY,
  URG_OPERATION_TIMEOUTED, /* the timeout time was reached */
  URG_FTP_COULDNT_SET_ASCII, /* TYPE A failed */

  URG_FTP_PORT_FAILED, /* FTP PORT operation failed */

  URG_FTP_COULDNT_USE_REST, /* the REST command failed */
  URG_FTP_COULDNT_GET_SIZE, /* the SIZE command failed */

  URG_HTTP_RANGE_ERROR, /* The RANGE "command" didn't seem to work */

  URG_HTTP_POST_ERROR,

  URG_SSL_CONNECT_ERROR, /* something was wrong when connecting with SSL */

  URG_FTP_BAD_DOWNLOAD_RESUME, /* couldn't resume download */

  URG_FILE_COULDNT_READ_FILE,

  URG_LDAP_CANNOT_BIND,
  URG_LDAP_SEARCH_FAILED,
  URG_LIBRARY_NOT_FOUND,
  URG_FUNCTION_NOT_FOUND,

  URL_LAST
} UrgError;

/* This is just to make older programs not break: */
#define URG_FTP_PARTIAL_FILE URG_PARTIAL_FILE

#define URGTAG_DONE -1
#define URGTAG_LAST -1
#define URGTAG_END -1

#define URLGET_ERROR_SIZE 256

/* maximum URL length we deal with */
#define URL_MAX_LENGTH 4096 
#define URL_MAX_LENGTH_TXT "4095"

/* name is uppercase URGTAG_<name>,
   type is one of the defined URGTYPE_<type>
   number is unique identifier */
#define T(name,type,number) URGTAG_ ## name = URGTYPE_ ## type + number

/* long may be 32 or 64 bits, but we should never depend on anything else
   but 32 */
#define URGTYPE_LONG          0
#define URGTYPE_OBJECTPOINT   10000
#define URGTYPE_FUNCTIONPOINT 20000

typedef enum {
  URGTAG_NOTHING, /* the first unused */
  
  /* This is the FILE * the regular output should be written to. */
  T(FILE, OBJECTPOINT, 1),

  /* The full URL to get/put */
  T(URL,  OBJECTPOINT, 2),

  /* Port number to connect to, if other than default. Specify the CONF_PORT
     flag in the URGTAG_FLAGS to activate this */
  T(PORT, LONG, 3),

  /* Name of proxy to use. Specify the CONF_PROXY flag in the URGTAG_FLAGS to
     activate this */
  T(PROXY, OBJECTPOINT, 4),
  
  /* Name and password to use when fetching. Specify the CONF_USERPWD flag in
     the URGTAG_FLAGS to activate this */
  T(USERPWD, OBJECTPOINT, 5),

  /* Name and password to use with Proxy. Specify the CONF_PROXYUSERPWD 
     flag in the URGTAG_FLAGS to activate this */
  T(PROXYUSERPWD, OBJECTPOINT, 6),

  /* Range to get, specified as an ASCII string. Specify the CONF_RANGE flag
     in the URGTAG_FLAGS to activate this */
  T(RANGE, OBJECTPOINT, 7),

  /* Configuration flags */
  T(FLAGS, LONG, 8),

  /* Specified file stream to upload from (use as input): */
  T(INFILE, OBJECTPOINT, 9),

  /* Buffer to receive error messages in, must be at least URLGET_ERROR_SIZE
     bytes big. If this is not used, error messages go to stderr instead: */
  T(ERRORBUFFER, OBJECTPOINT, 10),

  /* Function that will be called to store the output (instead of fwrite). The
     parameters will use fwrite() syntax, make sure to follow them. */
  T(WRITEFUNCTION, FUNCTIONPOINT, 11),

  /* Function that will be called to read the input (instead of fread). The
     parameters will use fread() syntax, make sure to follow them. */
  T(READFUNCTION, FUNCTIONPOINT, 12),

  /* Time-out the read operation after this amount of seconds */
  T(TIMEOUT, LONG, 13),

  /* If the URGTAG_INFILE is used, this can be used to inform urlget about how
     large the file being sent really is. That allows better error checking
     and better verifies that the upload was succcessful. -1 means unknown
     size. */
  T(INFILESIZE, LONG, 14),

  /* POST input fields. */
  T(POSTFIELDS, OBJECTPOINT, 15),

  /* Set the referer page (needed by some CGIs) */
  T(REFERER, OBJECTPOINT, 16),

  /* Set the FTP PORT string (interface name, named or numerical IP address)
     Use i.e '-' to use default address. */
  T(FTPPORT, OBJECTPOINT, 17),

  /* Set the User-Agent string (examined by some CGIs) */
  T(USERAGENT, OBJECTPOINT, 18),

  /* If the download receives less than "low speed limit" bytes/second
   * during "low speed time" seconds, the operations is aborted.
   * You could i.e if you have a pretty high speed connection, abort if
   * it is less than 2000 bytes/sec during 20 seconds.   
   */

  /* Set the "low speed limit" */
  T(LOW_SPEED_LIMIT, LONG , 19),

  /* Set the "low speed time" */
  T(LOW_SPEED_TIME, LONG, 20),

  /* Set the continuation offset */
  T(RESUME_FROM, LONG, 21),

  /* Set cookie in request: */
  T(COOKIE, OBJECTPOINT, 22),

  /* This points to a linked list of headers, struct HttpHeader kind */
  T(HTTPHEADER, OBJECTPOINT, 23),

  /* This points to a linked list of post entries, struct HttpPost */
  T(HTTPPOST, OBJECTPOINT, 24),

  /* name of the file keeping your private SSL-certificate */
  T(SSLCERT, OBJECTPOINT, 25),

  /* password for the SSL-certificate */
  T(SSLCERTPASSWD, OBJECTPOINT, 26),
  
  /* send TYPE parameter? */
  T(CRLF, LONG, 27),

  /* send linked-list of QUOTE commands */
  T(QUOTE, OBJECTPOINT, 28),

  /* send FILE * to store headers to */
  T(WRITEHEADER, OBJECTPOINT, 29),

#ifdef MULTIDOC
  /* send linked list of MoreDoc structs */
  T(MOREDOCS, OBJECTPOINT, 30),
#endif

  /* point to a file to read the initial cookies from, also enables
     "cookie awareness" */
  T(COOKIEFILE, OBJECTPOINT, 31),

  /* What version to specifly try to use.
     3 = SSLv3, 2 = SSLv2, all else makes it try v3 first then v2 */
  T(SSLVERSION, LONG, 32),

  /* What kind of HTTP time condition to use, see defines */
  T(TIMECONDITION, LONG, 33),

  /* Time to use with the above condition. Specified in number of seconds
     since 1 Jan 1970 */
  T(TIMEVALUE, LONG, 34),

  /* HTTP request, for odd commands like DELETE, TRACE and others */
  /* OBSOLETE DEFINE, left for tradition only */
  T(HTTPREQUEST, OBJECTPOINT, 35),

  /* Custom request, for customizing the get command like
     HTTP: DELETE, TRACE and others
     FTP: to use a different list command
     */
  T(CUSTOMREQUEST, OBJECTPOINT, 36),

  /* HTTP request, for odd commands like DELETE, TRACE and others */
  T(STDERR, OBJECTPOINT, 37),

  /* Progress mode sets alternative progress mode displays, the only
     one defined today is 1 which makes the #-style progress bar. */
  T(PROGRESSMODE, LONG, 38),

  /* send linked-list of post-transfer QUOTE commands */
  T(POSTQUOTE, OBJECTPOINT, 39),

  /* Pass a pointer to string of the output using full variable-replacement
     as described elsewhere. */
  T(WRITEINFO, OBJECTPOINT, 40),

  URGTAG_LASTENTRY /* the last unusued */
} UrgTag;

#define CURL_PROGRESS_STATS 0 /* default progress display */
#define CURL_PROGRESS_BAR   1

typedef enum {
  TIMECOND_NONE,

  TIMECOND_IFMODSINCE,
  TIMECOND_IFUNMODSINCE,
  TIMECOND_LASTMOD,

  TIMECOND_LAST
} TimeCond;

#ifdef __BEOS__
#include <support/SupportDefs.h>
#else
#ifndef __cplusplus        /* (rabe) */
typedef char bool;
#endif                     /* (rabe) */
#endif

/**********************************************************************
 *
 * >>> urlget() interface #defines changed in v5! <<<
 *
 * You enter parameters as tags. Tags are specified as a pair of parameters.
 * The first parameter in a pair is the tag identifier, telling urlget what
 * kind of tag it is, and the second is the data. The tags may come in any
 * order but MUST ALWAYS BE TERMINATED with an ending URGTAG_DONE (which
 * needs no data).
 *
 * _Very_ simple example:
 *
 * curl_urlget(URGTAG_URL, "http://www.fts.frontec.se/~dast/", URGTAG_DONE);
 *
 ***********************************************************************/

UrgError curl_urlget(UrgTag, ...);

/* external form function */
int curl_FormParse(char *string,
                   struct HttpPost **httppost,
                   struct HttpPost **last_post);

/* Unix and Win32 getenv function call */
char *curl_GetEnv(char *variable);

/* returns ascii string of the libcurl version */
char *curl_version(void);

/* This is the version number */
#define LIBCURL_VERSION "6.5"

/* linked-list structure for QUOTE */
struct curl_slist {
	char			*data;
	struct curl_slist	*next;
};

struct curl_slist *curl_slist_append(struct curl_slist *list, char *data);
void curl_slist_free_all(struct curl_slist *list);

#endif /* __URLGET_H */
