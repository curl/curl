#ifndef __CURL_CURL_H
#define __CURL_CURL_H
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

/* The include stuff here is mainly for time_t! */
#ifdef vms
# include <types.h>
# include <time.h>
#else
# include <sys/types.h>
# if TIME_WITH_SYS_TIME
#  include <sys/time.h>
#  include <time.h>
# else
#  if HAVE_SYS_TIME_H
#   include <sys/time.h>
#  else
#   include <time.h>
#  endif
# endif
#endif /* defined (vms) */

#ifndef TRUE
#define TRUE 1
#endif
#ifndef FALSE
#define FALSE 0
#endif

#include <curl/types.h>

#ifdef  __cplusplus
extern "C" {
#endif

struct HttpPost {
  struct HttpPost *next; /* next entry in the list */
  char *name;     /* pointer to allocated name */
  char *contents; /* pointer to allocated data contents */
  char *contenttype; /* Content-Type */
  struct HttpPost *more; /* if one field name has more than one file, this
			    link should link to following files */
  long flags;     /* as defined below */
#define HTTPPOST_FILENAME (1<<0) /* specified content is a file name */
#define HTTPPOST_READFILE (1<<1) /* specified content is a file name */
};

typedef int (*curl_progress_callback)(void *clientp,
                                      size_t dltotal,
                                      size_t dlnow,
                                      size_t ultotal,
                                      size_t ulnow);

typedef size_t (*curl_write_callback)(char *buffer,
                                      size_t size,
                                      size_t nitems,
                                      FILE *outstream);

typedef size_t (*curl_read_callback)(char *buffer,
                                     size_t size,
                                     size_t nitems,
                                     FILE *instream);

/* All possible error codes from this version of urlget(). Future versions
   may return other values, stay prepared. */

typedef enum {
  CURLE_OK = 0,
  CURLE_UNSUPPORTED_PROTOCOL,
  CURLE_FAILED_INIT,
  CURLE_URL_MALFORMAT,
  CURLE_URL_MALFORMAT_USER,
  CURLE_COULDNT_RESOLVE_PROXY,
  CURLE_COULDNT_RESOLVE_HOST,
  CURLE_COULDNT_CONNECT,
  CURLE_FTP_WEIRD_SERVER_REPLY,
  CURLE_FTP_ACCESS_DENIED,
  CURLE_FTP_USER_PASSWORD_INCORRECT,
  CURLE_FTP_WEIRD_PASS_REPLY,
  CURLE_FTP_WEIRD_USER_REPLY,
  CURLE_FTP_WEIRD_PASV_REPLY,
  CURLE_FTP_WEIRD_227_FORMAT,
  CURLE_FTP_CANT_GET_HOST,
  CURLE_FTP_CANT_RECONNECT,
  CURLE_FTP_COULDNT_SET_BINARY,
  CURLE_PARTIAL_FILE,
  CURLE_FTP_COULDNT_RETR_FILE,
  CURLE_FTP_WRITE_ERROR,
  CURLE_FTP_QUOTE_ERROR,
  CURLE_HTTP_NOT_FOUND,
  CURLE_WRITE_ERROR,

  CURLE_MALFORMAT_USER, /* the user name is illegally specified */
  CURLE_FTP_COULDNT_STOR_FILE, /* failed FTP upload */
  CURLE_READ_ERROR, /* could open/read from file */

  CURLE_OUT_OF_MEMORY,
  CURLE_OPERATION_TIMEOUTED, /* the timeout time was reached */
  CURLE_FTP_COULDNT_SET_ASCII, /* TYPE A failed */

  CURLE_FTP_PORT_FAILED, /* FTP PORT operation failed */

  CURLE_FTP_COULDNT_USE_REST, /* the REST command failed */
  CURLE_FTP_COULDNT_GET_SIZE, /* the SIZE command failed */

  CURLE_HTTP_RANGE_ERROR, /* The RANGE "command" didn't seem to work */

  CURLE_HTTP_POST_ERROR,

  CURLE_HTTP_PORT_FAILED, /* HTTP Interface operation failed */

  CURLE_SSL_CONNECT_ERROR, /* something was wrong when connecting with SSL */

  CURLE_FTP_BAD_DOWNLOAD_RESUME, /* couldn't resume download */

  CURLE_FILE_COULDNT_READ_FILE,

  CURLE_LDAP_CANNOT_BIND,
  CURLE_LDAP_SEARCH_FAILED,
  CURLE_LIBRARY_NOT_FOUND,
  CURLE_FUNCTION_NOT_FOUND,
  
  CURLE_ABORTED_BY_CALLBACK,

  CURLE_BAD_FUNCTION_ARGUMENT,
  CURLE_BAD_CALLING_ORDER,

  CURL_LAST
} CURLcode;

/* This is just to make older programs not break: */
#define CURLE_FTP_PARTIAL_FILE CURLE_PARTIAL_FILE

#define CURL_ERROR_SIZE 256

/* maximum URL length we deal with */
#define URL_MAX_LENGTH 4096 
#define URL_MAX_LENGTH_TXT "4095"

/* name is uppercase CURLOPT_<name>,
   type is one of the defined CURLOPTTYPE_<type>
   number is unique identifier */
#ifdef CINIT
#undef CINIT
#endif
#define CINIT(name,type,number) CURLOPT_ ## name = CURLOPTTYPE_ ## type + number

/* long may be 32 or 64 bits, but we should never depend on anything else
   but 32 */
#define CURLOPTTYPE_LONG          0
#define CURLOPTTYPE_OBJECTPOINT   10000
#define CURLOPTTYPE_FUNCTIONPOINT 20000

typedef enum {
  CINIT(NOTHING, LONG, 0), /********* the first one is unused ************/
  
  /* This is the FILE * the regular output should be written to. */
  CINIT(FILE, OBJECTPOINT, 1),

  /* The full URL to get/put */
  CINIT(URL,  OBJECTPOINT, 2),

  /* Port number to connect to, if other than default. Specify the CONF_PORT
     flag in the CURLOPT_FLAGS to activate this */
  CINIT(PORT, LONG, 3),

  /* Name of proxy to use. Specify the CONF_PROXY flag in the CURLOPT_FLAGS to
     activate this */
  CINIT(PROXY, OBJECTPOINT, 4),
  
  /* Name and password to use when fetching. Specify the CONF_USERPWD flag in
     the CURLOPT_FLAGS to activate this */
  CINIT(USERPWD, OBJECTPOINT, 5),

  /* Name and password to use with Proxy. Specify the CONF_PROXYUSERPWD 
     flag in the CURLOPT_FLAGS to activate this */
  CINIT(PROXYUSERPWD, OBJECTPOINT, 6),

  /* Range to get, specified as an ASCII string. Specify the CONF_RANGE flag
     in the CURLOPT_FLAGS to activate this */
  CINIT(RANGE, OBJECTPOINT, 7),

#if 0
  /* Configuration flags */
  CINIT(FLAGS, LONG, 8),
#endif
  /* Specified file stream to upload from (use as input): */
  CINIT(INFILE, OBJECTPOINT, 9),

  /* Buffer to receive error messages in, must be at least CURL_ERROR_SIZE
   * bytes big. If this is not used, error messages go to stderr instead: */
  CINIT(ERRORBUFFER, OBJECTPOINT, 10),

  /* Function that will be called to store the output (instead of fwrite). The
   * parameters will use fwrite() syntax, make sure to follow them. */
  CINIT(WRITEFUNCTION, FUNCTIONPOINT, 11),

  /* Function that will be called to read the input (instead of fread). The
   * parameters will use fread() syntax, make sure to follow them. */
  CINIT(READFUNCTION, FUNCTIONPOINT, 12),

  /* Time-out the read operation after this amount of seconds */
  CINIT(TIMEOUT, LONG, 13),

  /* If the CURLOPT_INFILE is used, this can be used to inform libcurl about
   * how large the file being sent really is. That allows better error
   * checking and better verifies that the upload was succcessful. -1 means
   * unknown size. */
  CINIT(INFILESIZE, LONG, 14),

  /* POST input fields. */
  CINIT(POSTFIELDS, OBJECTPOINT, 15),

  /* Set the referer page (needed by some CGIs) */
  CINIT(REFERER, OBJECTPOINT, 16),

  /* Set the FTP PORT string (interface name, named or numerical IP address)
     Use i.e '-' to use default address. */
  CINIT(FTPPORT, OBJECTPOINT, 17),

  /* Set the User-Agent string (examined by some CGIs) */
  CINIT(USERAGENT, OBJECTPOINT, 18),

  /* If the download receives less than "low speed limit" bytes/second
   * during "low speed time" seconds, the operations is aborted.
   * You could i.e if you have a pretty high speed connection, abort if
   * it is less than 2000 bytes/sec during 20 seconds.   
   */

  /* Set the "low speed limit" */
  CINIT(LOW_SPEED_LIMIT, LONG , 19),

  /* Set the "low speed time" */
  CINIT(LOW_SPEED_TIME, LONG, 20),

  /* Set the continuation offset */
  CINIT(RESUME_FROM, LONG, 21),

  /* Set cookie in request: */
  CINIT(COOKIE, OBJECTPOINT, 22),

  /* This points to a linked list of headers, struct HttpHeader kind */
  CINIT(HTTPHEADER, OBJECTPOINT, 23),

  /* This points to a linked list of post entries, struct HttpPost */
  CINIT(HTTPPOST, OBJECTPOINT, 24),

  /* name of the file keeping your private SSL-certificate */
  CINIT(SSLCERT, OBJECTPOINT, 25),

  /* password for the SSL-certificate */
  CINIT(SSLCERTPASSWD, OBJECTPOINT, 26),
  
  /* send TYPE parameter? */
  CINIT(CRLF, LONG, 27),

  /* send linked-list of QUOTE commands */
  CINIT(QUOTE, OBJECTPOINT, 28),

  /* send FILE * to store headers to */
  CINIT(WRITEHEADER, OBJECTPOINT, 29),

#ifdef MULTIDOC
  /* send linked list of MoreDoc structs */
  CINIT(MOREDOCS, OBJECTPOINT, 30),
#endif

  /* point to a file to read the initial cookies from, also enables
     "cookie awareness" */
  CINIT(COOKIEFILE, OBJECTPOINT, 31),

  /* What version to specifly try to use.
     3 = SSLv3, 2 = SSLv2, all else makes it try v3 first then v2 */
  CINIT(SSLVERSION, LONG, 32),

  /* What kind of HTTP time condition to use, see defines */
  CINIT(TIMECONDITION, LONG, 33),

  /* Time to use with the above condition. Specified in number of seconds
     since 1 Jan 1970 */
  CINIT(TIMEVALUE, LONG, 34),

  /* HTTP request, for odd commands like DELETE, TRACE and others */
  /* OBSOLETE DEFINE, left for tradition only */
  CINIT(HTTPREQUEST, OBJECTPOINT, 35),

  /* Custom request, for customizing the get command like
     HTTP: DELETE, TRACE and others
     FTP: to use a different list command
     */
  CINIT(CUSTOMREQUEST, OBJECTPOINT, 36),

  /* HTTP request, for odd commands like DELETE, TRACE and others */
  CINIT(STDERR, OBJECTPOINT, 37),

#if 0
  /* Progress mode set alternative progress mode displays. Alternative
     ones should now be made by the client, not the lib! */     
  CINIT(PROGRESSMODE, LONG, 38),
#endif
  /* send linked-list of post-transfer QUOTE commands */
  CINIT(POSTQUOTE, OBJECTPOINT, 39),

  /* Pass a pointer to string of the output using full variable-replacement
     as described elsewhere. */
  CINIT(WRITEINFO, OBJECTPOINT, 40),

  /* Previous FLAG bits */
  CINIT(VERBOSE, LONG, 41),      /* talk a lot */
  CINIT(HEADER, LONG, 42),       /* throw the header out too */
  CINIT(NOPROGRESS, LONG, 43),   /* shut off the progress meter */
  CINIT(NOBODY, LONG, 44),       /* use HEAD to get http document */
  CINIT(FAILONERROR, LONG, 45),  /* no output on http error codes >= 300 */
  CINIT(UPLOAD, LONG, 46),       /* this is an upload */
  CINIT(POST, LONG, 47),         /* HTTP POST method */
  CINIT(FTPLISTONLY, LONG, 48),  /* Use NLST when listing ftp dir */

  CINIT(FTPAPPEND, LONG, 50),    /* Append instead of overwrite on upload! */
  CINIT(NETRC, LONG, 51),        /* read user+password from .netrc */
  CINIT(FOLLOWLOCATION, LONG, 52),  /* use Location: Luke! */

  /* This FTPASCII name is now obsolete, to be removed, use the TRANSFERTEXT
     instead. It goes for more protocols than just ftp... */
  CINIT(FTPASCII, LONG, 53),     /* use TYPE A for transfer */

  CINIT(TRANSFERTEXT, LONG, 53), /* transfer data in text/ASCII format */
  CINIT(PUT, LONG, 54),          /* PUT the input file */
  CINIT(MUTE, LONG, 55),         /* force NOPROGRESS */

  /* Function that will be called instead of the internal progress display
   * function. This function should be defined as the curl_progress_callback
   * prototype defines. */
  CINIT(PROGRESSFUNCTION, FUNCTIONPOINT, 56),

  /* Data passed to the progress callback */
  CINIT(PROGRESSDATA, OBJECTPOINT, 57),

  /* We want the referer field set automatically when following locations */
  CINIT(AUTOREFERER, LONG, 58),

  /* Port of the proxy, can be set in the proxy string as well with:
     "[host]:[port]" */
  CINIT(PROXYPORT, LONG, 59),

  /* size of the POST input data, if strlen() is not good to use */
  CINIT(POSTFIELDSIZE, LONG, 60),

  /* tunnel non-http operations through a HTTP proxy */
  CINIT(HTTPPROXYTUNNEL, LONG, 61),

  /* Set the interface string to use as outgoing network interface */
  CINIT(INTERFACE, OBJECTPOINT, 62),

  /* Set the krb4 security level, this also enables krb4 awareness.  This is a
   * string, 'clear', 'safe', 'confidential' or 'private'.  If the string is
   * set but doesn't match one of these, 'private' will be used.  */
  CINIT(KRB4LEVEL, OBJECTPOINT, 63),

  CURLOPT_LASTENTRY /* the last unusued */
} CURLoption;

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


/* These functions are in the libcurl, they're here for portable reasons and
   they are used by the 'curl' client. They really should be moved to some kind
   of "portability library" since it has nothing to do with file transfers and
   might be usable to other programs...

   NOTE: they return TRUE if the strings match *case insensitively*.
 */
extern int (strequal)(const char *s1, const char *s2);
extern int (strnequal)(const char *s1, const char *s2, size_t n);

/* external form function */
int curl_formparse(char *string,
                   struct HttpPost **httppost,
                   struct HttpPost **last_post);

/* Unix and Win32 getenv function call, this returns a malloc()'ed string that
   MUST be free()ed after usage is complete. */
char *curl_getenv(char *variable);

/* returns ascii string of the libcurl version */
char *curl_version(void);

/* This is the version number */
#define LIBCURL_VERSION "7.3"
#define LIBCURL_VERSION_NUM 0x070300

/* linked-list structure for the CURLOPT_QUOTE option */
struct curl_slist {
	char			*data;
	struct curl_slist	*next;
};

struct curl_slist *curl_slist_append(struct curl_slist *list, char *data);
void curl_slist_free_all(struct curl_slist *list);

/*
 * NAME	curl_init()
 *
 * DESCRIPTION
 *
 * Inits libcurl globally. This must be used before any libcurl calls can
 * be used. This may install global plug-ins or whatever. (This does not
 * do winsock inits in Windows.)
 *
 * EXAMPLE
 *
 * curl_init();
 *
 */
CURLcode curl_init(void);

/*
 * NAME	curl_init()
 *
 * DESCRIPTION
 *
 * Frees libcurl globally. This must be used after all libcurl calls have
 * been used. This may remove global plug-ins or whatever. (This does not
 * do winsock cleanups in Windows.)
 *
 * EXAMPLE
 *
 * curl_free(curl);
 *
 */
void curl_free(void);

/*
 * NAME curl_open()
 *
 * DESCRIPTION
 *
 * Opens a general curl session. It does not try to connect or do anything
 * on the network because of this call. The specified URL is only required
 * to enable curl to figure out what protocol to "activate".
 *
 * A session should be looked upon as a series of requests to a single host.  A
 * session interacts with one host only, using one single protocol.
 *
 * The URL is not required. If set to "" or NULL, it can still be set later
 * using the curl_setopt() function. If the curl_connect() function is called
 * without the URL being known, it will return error.
 *
 * EXAMPLE
 *
 * CURLcode result;
 * CURL *curl;
 * result = curl_open(&curl, "http://curl.haxx.nu/libcurl/");
 * if(result != CURL_OK) {
 *   return result;
 * }
 * */
CURLcode curl_open(CURL **curl, char *url);

/*
 * NAME curl_setopt()
 *
 * DESCRIPTION
 *
 * Sets a particular option to the specified value.
 *
 * EXAMPLE
 *
 * CURL curl;
 * curl_setopt(curl, CURL_HTTP_FOLLOW_LOCATION, TRUE);
 */
CURLcode curl_setopt(CURL *handle, CURLoption option, ...);

/*
 * NAME curl_close()
 *
 * DESCRIPTION
 *
 * Closes a session previously opened with curl_open()
 *
 * EXAMPLE
 *
 * CURL *curl;
 * CURLcode result;
 *
 * result = curl_close(curl);
 */
CURLcode curl_close(CURL *curl); /* the opposite of curl_open() */

CURLcode curl_read(CURLconnect *c_conn, char *buf, size_t buffersize,
                   size_t *n);
CURLcode curl_write(CURLconnect *c_conn, char *buf, size_t amount,
                    size_t *n);

/*
 * NAME curl_connect()
 *
 * DESCRIPTION
 *
 * Connects to the peer server and performs the initial setup. This function
 * writes a connect handle to its second argument that is a unique handle for
 * this connect. This allows multiple connects from the same handle returned
 * by curl_open().
 *
 * EXAMPLE
 *
 * CURLCode result;
 * CURL curl;
 * CURLconnect connect;
 * result = curl_connect(curl, &connect);
 */

CURLcode curl_connect(CURL *curl, CURLconnect **in_connect);

/*
 * NAME curl_do()
 *
 * DESCRIPTION
 *
 * (Note: May 3rd 2000: this function does not currently allow you to
 * specify a document, it will use the one set previously)
 *
 * This function asks for the particular document, file or resource that
 * resides on the server we have connected to. You may specify a full URL,
 * just an absolute path or even a relative path. That means, if you're just
 * getting one file from the remote site, you can use the same URL as input
 * for both curl_open() as well as for this function.
 *
 * In the even there is a host name, port number, user name or password parts
 * in the URL, you can use the 'flags' argument to ignore them completely, or
 * at your choice, make the function fail if you're trying to get a URL from
 * different host than you connected to with curl_connect().
 *
 * You can only get one document at a time using the same connection. When one
 * document has been received you can although request again.
 *
 * When the transfer is done, curl_done() MUST be called.
 *
 * EXAMPLE
 *
 * CURLCode result;
 * char *url;
 * CURLconnect *connect;
 * result = curl_do(connect, url, CURL_DO_NONE); */
CURLcode curl_do(CURLconnect *in_conn);

/*
 * NAME curl_done()
 *
 * DESCRIPTION
 *
 * When the transfer following a curl_do() call is done, this function should
 * get called.
 *
 * EXAMPLE
 *
 * CURLCode result;
 * char *url;
 * CURLconnect *connect;
 * result = curl_done(connect); */
CURLcode curl_done(CURLconnect *connect);

/*
 * NAME curl_disconnect()
 *
 * DESCRIPTION
 *
 * Disconnects from the peer server and performs connection cleanup.
 *
 * EXAMPLE
 *
 * CURLcode result;
 * CURLconnect *connect;
 * result = curl_disconnect(connect); */
CURLcode curl_disconnect(CURLconnect *connect);

/*
 * NAME curl_getdate()
 *
 * DESCRIPTION
 *
 * Returns the time, in seconds since 1 Jan 1970 of the time string given in
 * the first argument. The time argument in the second parameter is for cases
 * where the specified time is relative now, like 'two weeks' or 'tomorrow'
 * etc.
 */
time_t curl_getdate(const char *p, const time_t *now);

#ifdef  __cplusplus
}
#endif

#endif /* __CURL_CURL_H */
