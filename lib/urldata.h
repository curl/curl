#ifndef __URLDATA_H
#define __URLDATA_H
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

/* This file is for lib internal stuff */

#include "setup.h"

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
#define CURL_DEFAULT_PASSWORD "curl_by_daniel@haxx.se"

#include "cookie.h"
#include "formdata.h"
    
#ifdef USE_SSLEAY
/* SSLeay stuff usually in /usr/local/ssl/include */
#ifdef USE_OPENSSL
#include "openssl/rsa.h"
#include "openssl/crypto.h"
#include "openssl/x509.h"
#include "openssl/pem.h"
#include "openssl/ssl.h"
#include "openssl/err.h"
#ifdef HAVE_OPENSSL_ENGINE_H
#include <openssl/engine.h>
#endif
#else
#include "rsa.h"
#include "crypto.h"
#include "x509.h"
#include "pem.h"
#include "ssl.h"
#include "err.h"
#endif
#endif

#ifdef HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif

#include "timeval.h"

#include <curl/curl.h>

#include "http_chunks.h" /* for the structs and enum stuff */
#include "hostip.h"
#include "hash.h"

#ifdef HAVE_ZLIB_H
#include <zlib.h> 		/* for content-encoding 08/28/02 jhrg */
#endif

/* Download buffer size, keep it fairly big for speed reasons */
#define BUFSIZE CURL_MAX_WRITE_SIZE

/* Initial size of the buffer to store headers in, it'll be enlarged in case
   of need. */
#define HEADERSIZE 256

/* Just a convenience macro to get the larger value out of two given */
#ifndef MAX
#define MAX(x,y) ((x)>(y)?(x):(y))
#endif

#ifdef KRB4
/* Types needed for krb4-ftp connections */
struct krb4buffer {
  void *data;
  size_t size;
  size_t index;
  int eof_flag;
};
enum protection_level { 
    prot_clear, 
    prot_safe, 
    prot_confidential, 
    prot_private 
};
#endif

#ifndef HAVE_OPENSSL_ENGINE_H
typedef void ENGINE;
#endif
/* struct for data related to SSL and SSL connections */
struct ssl_connect_data {
  bool use;              /* use ssl encrypted communications TRUE/FALSE */
#ifdef USE_SSLEAY
  /* these ones requires specific SSL-types */
  SSL_CTX* ctx;
  SSL*     handle;
  X509*    server_cert;
#endif /* USE_SSLEAY */
};

/* information about one single SSL session */
struct curl_ssl_session {
  char *name;       /* host name for which this ID was used */
  void *sessionid;  /* as returned from the SSL layer */
  long age;         /* just a number, the higher the more recent */
  unsigned short remote_port; /* remote port to connect to */
};

struct ssl_config_data {
  long version;          /* what version the client wants to use */
  long certverifyresult; /* result from the certificate verification */
  long verifypeer;       /* set TRUE if this is desired */
  long verifyhost;       /* 0: no verify
                            1: check that CN exists
                            2: CN must match hostname */
  char *CApath;          /* DOES NOT WORK ON WINDOWS */
  char *CAfile;          /* cerficate to verify peer against */
  char *random_file;     /* path to file containing "random" data */
  char *egdsocket;       /* path to file containing the EGD daemon socket */
  char *cipher_list;     /* list of ciphers to use */
  long numsessions;      /* SSL session id cache size */
};

/****************************************************************************
 * HTTP unique setup
 ***************************************************************************/
struct HTTP {
  struct FormData *sendit;
  int postsize;
  const char *p_pragma;      /* Pragma: string */
  const char *p_accept;      /* Accept: string */
  long readbytecount; 
  long writebytecount;

  /* For FORM posting */
  struct Form form;
  curl_read_callback storefread;
  FILE *in;

  struct Curl_chunker chunk;
};

/****************************************************************************
 * FTP unique setup
 ***************************************************************************/
struct FTP {
  long *bytecountp;
  char *user;    /* user name string */
  char *passwd;  /* password string */
  char *urlpath; /* the originally given path part of the URL */
  char *dir;     /* decoded directory */
  char *file;    /* decoded file */

  char *entrypath; /* the PWD reply when we logged on */

  char *cache;       /* data cache between getresponse()-calls */
  size_t cache_size; /* size of cache in bytes */
  bool dont_check;  /* Set to TRUE to prevent the final (post-transfer)
                       file size and 226/250 status check. It should still
                       read the line, just ignore the result. */
  bool no_transfer; /* nothing was transfered, (possibly because a resumed
                       transfer already was complete) */

};

/****************************************************************************
 * FILE unique setup
 ***************************************************************************/
struct FILE {
  int fd; /* open file descriptor to read from! */
};

/*
 * Boolean values that concerns this connection.
 */
struct ConnectBits {
  bool close; /* if set, we close the connection after this request */
  bool reuse; /* if set, this is a re-used connection */
  bool chunk; /* if set, this is a chunked transfer-encoding */
  bool httpproxy;    /* if set, this transfer is done through a http proxy */
  bool user_passwd;    /* do we use user+password for this connection? */
  bool proxy_user_passwd; /* user+password for the proxy? */
  bool ipv6_ip; /* we communicate with a remove site specified with pure IPv6
                   IP address */
  bool use_range;
  bool rangestringalloc; /* the range string is malloc()'ed */

  bool do_more; /* this is set TRUE if the ->curl_do_more() function is
                   supposed to be called, after ->curl_do() */

  bool upload_chunky; /* set TRUE if we are doing chunked transfer-encoding
                         on upload */

  bool getheader;	 /* TRUE if header parsing is wanted */
};

/*
 * This struct is all the previously local variables from Curl_perform() moved
 * to struct to allow the function to return and get re-invoked better without
 * losing state.
 */

struct Curl_transfer_keeper {
  int bytecount;                /* total number of bytes read */
  int writebytecount;           /* number of bytes written */
  long contentlength;           /* size of incoming data */
  struct timeval start;         /* transfer started at this time */
  struct timeval now;           /* current time */
  bool header;	                /* incoming data has HTTP header */
  enum {
    HEADER_NORMAL,      /* no bad header at all */
    HEADER_PARTHEADER,  /* part of the chunk is a bad header, the rest is
                           normal data */
    HEADER_ALLBAD       /* all was believed to be header */
  } badheader;		        /* the header was deemed bad and will be
                                   written as body */
  int headerline;		/* counts header lines to better track the
                                   first one */
  char *hbufp;			/* points at *end* of header line */
  int hbuflen;
  char *str;			/* within buf */
  char *str_start;		/* within buf */
  char *end_ptr;		/* within buf */
  char *p;			/* within headerbuff */
  bool content_range;      	/* set TRUE if Content-Range: was found */
  int offset;	                /* possible resume offset read from the
                                   Content-Range: header */
  int httpcode;		        /* error code from the 'HTTP/1.? XXX' line */
  int httpversion;		/* the HTTP version*10 */
  bool write_after_100_header;  /* should we enable the write after
                                   we received a 100-continue/timeout
                                   or directly */
  int content_encoding;  	/* What content encoding. sec 3.5, RFC2616. */

#define IDENTITY 0		/* No encoding */
#define DEFLATE 1		/* zlib delfate [RFC 1950 & 1951] */
#define GZIP 2			/* gzip algorithm [RFC 1952] */
#define COMPRESS 3		/* Not handled, added for completeness */

#ifdef HAVE_LIBZ
  bool zlib_init;		/* True if zlib already initialized;
				   undefined if Content-Encdoing header. */
  z_stream z;			/* State structure for zlib. */
#endif

  /* for the low speed checks: */
  time_t timeofdoc;
  long bodywrites;
  int writetype;

  char *buf;
  char *uploadbuf;
  int maxfd;

  /* pointers to the actual descriptors we check */
  fd_set *readfdp;
  fd_set *writefdp;

  /* the file descriptors to play with */
  fd_set readfd;
  fd_set writefd;
  fd_set rkeepfd;
  fd_set wkeepfd;
  int keepon;

  bool upload_done; /* set to TRUE when doing chunked transfer-encoding upload
                       and we're uploading the last chunk */
};


/*
 * The connectdata struct contains all fields and variables that should be
 * unique for an entire connection.
 */
struct connectdata {
  /**** Fields set when inited and not modified again */
  struct SessionHandle *data; /* link to the root CURL struct */
  int connectindex; /* what index in the connects index this particular
                       struct has */

  long protocol; /* PROT_* flags concerning the protocol set */
#define PROT_MISSING (1<<0)
#define PROT_GOPHER  (1<<1)
#define PROT_HTTP    (1<<2)
#define PROT_HTTPS   (1<<3)
#define PROT_FTP     (1<<4)
#define PROT_TELNET  (1<<5)
#define PROT_DICT    (1<<6)
#define PROT_LDAP    (1<<7)
#define PROT_FILE    (1<<8)
#define PROT_FTPS    (1<<9)
#define PROT_SSL     (1<<10) /* protocol requires SSL */

  /* the particular host we use, in two different ways */
  struct Curl_dns_entry *connect_addr;

#ifdef ENABLE_IPV6
  struct addrinfo *serv_addr;
#else
  struct sockaddr_in serv_addr;
#endif
  char protostr[64];  /* store the protocol string in this buffer */
  char gname[513]; /* store the hostname in this buffer */
  char *name;      /* host name pointer to fool around with */
  char *path;      /* allocated buffer to store the URL's path part in */
  char *hostname;  /* hostname to connect, as parsed from url */
  long port;       /* which port to use locally */
  unsigned short remote_port; /* what remote port to connect to,
                                 not the proxy port! */
  char *ppath;
  long bytecount;
  long headerbytecount;  /* only count received headers */

  char *range; /* range, if used. See README for detailed specification on
                  this syntax. */
  ssize_t resume_from; /* continue [ftp] transfer from here */

  char *proxyhost; /* name of the http proxy host */

  struct timeval now;     /* "current" time */
  struct timeval created; /* creation time */
  int firstsocket;     /* the main socket to use */
  int secondarysocket; /* for i.e ftp transfers */
  long maxdownload; /* in bytes, the maximum amount of data to fetch, 0
                       means unlimited */
  
  struct ssl_connect_data ssl; /* this is for ssl-stuff */

  struct ConnectBits bits;    /* various state-flags for this connection */

  /* These two functions MUST be set by the curl_connect() function to be
     be protocol dependent */
  CURLcode (*curl_do)(struct connectdata *connect);
  CURLcode (*curl_done)(struct connectdata *connect);

  /* If the curl_do() function is better made in two halves, this
   * curl_do_more() function will be called afterwards, if set. For example
   * for doing the FTP stuff after the PASV/PORT command.
   */
  CURLcode (*curl_do_more)(struct connectdata *connect);

  /* This function *MAY* be set to a protocol-dependent function that is run
   * after the connect() and everything is done, as a step in the connection.
   */ 
  CURLcode (*curl_connect)(struct connectdata *connect);

  /* This function *MAY* be set to a protocol-dependent function that is run
   * by the curl_disconnect(), as a step in the disconnection.
   */ 
  CURLcode (*curl_disconnect)(struct connectdata *connect);

  /* This function *MAY* be set to a protocol-dependent function that is run
   * in the curl_close() function if protocol-specific cleanups are required.
   */ 
  CURLcode (*curl_close)(struct connectdata *connect);

  /**** curl_get() phase fields */

  /* READ stuff */
  int sockfd;		 /* socket to read from or -1 */
  int size;		 /* -1 if unknown at this point */
  long *bytecountp;	 /* return number of bytes read or NULL */
          
  /* WRITE stuff */
  int writesockfd;       /* socket to write to, it may very well be
                            the same we read from. -1 disables */
  long *writebytecountp; /* return number of bytes written or NULL */

  /** Dynamicly allocated strings, may need to be freed before this **/
  /** struct is killed.                                             **/
  struct dynamically_allocated_data {
    char *proxyuserpwd; /* free later if not NULL! */
    char *uagent; /* free later if not NULL! */
    char *accept_encoding; /* free later if not NULL! 08/28/02 jhrg */
    char *userpwd; /* free later if not NULL! */
    char *rangeline; /* free later if not NULL! */
    char *ref; /* free later if not NULL! */
    char *cookie; /* free later if not NULL! */
    char *host; /* free later if not NULL */
  } allocptr;

  char *newurl; /* This can only be set if a Location: was in the
		   document headers */

#ifdef KRB4
  enum protection_level command_prot;
  enum protection_level data_prot;
  enum protection_level request_data_prot;

  size_t buffer_size;

  struct krb4buffer in_buffer, out_buffer;
  int sec_complete;
  void *app_data;

  struct Curl_sec_client_mech *mech;
  struct sockaddr_in local_addr;

#endif

  /*************** Request - specific items ************/
  /* previously this was in the urldata struct */
  union {
    struct HTTP *http;
    struct HTTP *gopher; /* alias, just for the sake of being more readable */
    struct HTTP *https;  /* alias, just for the sake of being more readable */
    struct FTP *ftp;
    struct FILE *file;
    void *telnet;        /* private for telnet.c-eyes only */
#if 0 /* no need for special ones for these: */
    struct LDAP *ldap;
    struct DICT *dict;
#endif
    void *generic;
  } proto;

  /* This struct is inited when needed */
  struct Curl_transfer_keeper keep;

  /* 'upload_present' is used to keep a byte counter of how much data there is
     still left in the buffer, aimed for upload. */
  int upload_present;

   /* 'upload_fromhere' is used as a read-pointer when we uploaded parts of a
      buffer, so the next read should read from where this pointer points to,
      and the 'upload_present' contains the number of bytes available at this
      position */
  char *upload_fromhere;
};

/* The end of connectdata. 08/27/02 jhrg */

/*
 * Struct to keep statistical and informational data.
 */
struct PureInfo {
  int httpcode;
  int httpversion;
  long filetime; /* If requested, this is might get set. Set to -1 if
                    the time was unretrievable */
  long header_size;  /* size of read header(s) in bytes */
  long request_size; /* the amount of bytes sent in the request(s) */

  char *contenttype; /* the content type of the object */
};


struct Progress {
  long lastshow; /* time() of the last displayed progress meter or NULL to
                    force redraw at next call */
  double size_dl;
  double size_ul;
  double downloaded;
  double uploaded;

  double current_speed; /* uses the currently fastest transfer */

  bool callback;  /* set when progress callback is used */
  int width; /* screen width at download start */
  int flags; /* see progress.h */

  double timespent;

  double dlspeed;
  double ulspeed;

  double t_nslookup;
  double t_connect;
  double t_pretransfer;
  double t_starttransfer;
  double t_redirect;

  struct timeval start;
  struct timeval t_startsingle;
#define CURR_TIME (5+1) /* 6 entries for 5 seconds */

  double speeder[ CURR_TIME ];
  struct timeval speeder_time[ CURR_TIME ];
  int speeder_c;
};

typedef enum {
  HTTPREQ_NONE, /* first in list */
  HTTPREQ_GET,
  HTTPREQ_POST,
  HTTPREQ_POST_FORM, /* we make a difference internally */
  HTTPREQ_PUT,
  HTTPREQ_CUSTOM,
  HTTPREQ_LAST /* last in list */
} Curl_HttpReq;

/*
 * Values that are generated, temporary or calculated internally for a
 * "session handle" must be defined within the 'struct urlstate'.  This struct
 * will be used within the SessionHandle struct. When the 'SessionHandle'
 * struct is cloned, this data MUST NOT be copied.
 *
 * Remember that any "state" information goes globally for the curl handle.
 * Session-data MUST be put in the connectdata struct and here.  */
#define MAX_CURL_USER_LENGTH 256
#define MAX_CURL_PASSWORD_LENGTH 256

struct UrlState {
  enum {
    Curl_if_none,
    Curl_if_easy,
    Curl_if_multi
  } used_interface;

  /* buffers to store authentication data in, as parsed from input options */
  char user[MAX_CURL_USER_LENGTH];
  char passwd[MAX_CURL_PASSWORD_LENGTH];
  char proxyuser[MAX_CURL_USER_LENGTH];
  char proxypasswd[MAX_CURL_PASSWORD_LENGTH];

  struct timeval keeps_speed; /* for the progress meter really */

  /* 'connects' will be an allocated array with pointers. If the pointer is
     set, it holds an allocated connection. */
  struct connectdata **connects;
  long numconnects; /* size of the 'connects' array */

  char *headerbuff; /* allocated buffer to store headers in */
  int headersize;   /* size of the allocation */

  char buffer[BUFSIZE+1]; /* download buffer */
  char uploadbuffer[BUFSIZE+1]; /* upload buffer */
  double current_speed;  /* the ProgressShow() funcion sets this */

  bool this_is_a_follow; /* this is a followed Location: request */

  char *auth_host; /* if set, this should be the host name that we will
                      sent authorization to, no else. Used to make Location:
                      following not keep sending user+password... This is
                      strdup() data.
                    */

  struct curl_ssl_session *session; /* array of 'numsessions' size */
  long sessionage;                  /* number of the most recent session */

  char scratch[BUFSIZE*2]; /* huge buffer when doing upload CRLF replacing */
  bool errorbuf; /* Set to TRUE if the error buffer is already filled in.
                    This must be set to FALSE every time _easy_perform() is
                    called. */

#ifdef HAVE_SIGNAL
  /* storage for the previous bag^H^H^HSIGPIPE signal handler :-) */
  void (*prev_signal)(int sig);
#endif
  bool allow_port; /* Is set.use_port allowed to take effect or not. This
                      is always set TRUE when curl_easy_perform() is called. */
};


/*
 * This 'DynamicStatic' struct defines dynamic states that actually change
 * values in the 'UserDefined' area, which MUST be taken into consideration
 * if the UserDefined struct is cloned or similar. You can probably just
 * copy these, but each one indicate a special action on other data.
 */

struct DynamicStatic {
  char *url;        /* work URL, copied from UserDefined */
  bool url_alloc;   /* URL string is malloc()'ed */
  char *proxy;      /* work proxy, copied from UserDefined */
  bool proxy_alloc; /* http proxy string is malloc()'ed */
  char *referer;    /* referer string */
  bool referer_alloc; /* referer sting is malloc()ed */
  struct curl_slist *cookielist; /* list of cookie files set by
                                    curl_easy_setopt(COOKIEFILE) calls */
};

/*
 * This 'UserDefined' struct must only contain data that is set once to go
 * for many (perhaps) independent connections. Values that are generated or
 * calculated internally for the "session handle" MUST be defined within the
 * 'struct urlstate' instead. The only exceptions MUST note the changes in
 * the 'DynamicStatic' struct.
 */

struct UserDefined {
  FILE *err;         /* the stderr user data goes here */
  void *debugdata;   /* the data that will be passed to fdebug */
  char *errorbuffer; /* store failure messages in here */
  char *proxyuserpwd;  /* Proxy <user:password>, if used */
  long proxyport; /* If non-zero, use this port number by default. If the
                     proxy string features a ":[port]" that one will override
                     this. */  
  void *out;         /* the fetched file goes here */
  void *in;          /* the uploaded file is read from here */
  void *writeheader; /* write the header to this is non-NULL */
  char *set_url;     /* what original URL to work on */
  char *set_proxy;   /* proxy to use */
  long use_port;     /* which port to use (when not using default) */
  char *userpwd;     /* <user:password>, if used */
  char *set_range;   /* range, if used. See README for detailed specification
                        on this syntax. */
  long followlocation; /* as in HTTP Location: */
  long maxredirs;    /* maximum no. of http(s) redirects to follow */
  char *set_referer; /* custom string */
  bool free_referer; /* set TRUE if 'referer' points to a string we
                        allocated */
  char *useragent;   /* User-Agent string */
  char *encoding;    /* Accept-Encoding string 08/28/02 jhrg */
  char *postfields;  /* if POST, set the fields' values here */
  size_t postfieldsize; /* if POST, this might have a size to use instead of
                           strlen(), and then the data *may* be binary (contain
                           zero bytes) */
  char *ftpport;     /* port to send with the FTP PORT command */
  char *device;      /* network interface to use */
  curl_write_callback fwrite;        /* function that stores the output */
  curl_write_callback fwrite_header; /* function that stores headers */
  curl_read_callback fread;          /* function that reads the input */
  curl_progress_callback fprogress;  /* function for progress information */
  curl_debug_callback fdebug;      /* function that write informational data */
  void *progress_client; /* pointer to pass to the progress callback */
  curl_passwd_callback fpasswd;      /* call for password */
  void *passwd_client;               /* pass to the passwd callback */
  long timeout;         /* in seconds, 0 means no timeout */
  long connecttimeout;  /* in seconds, 0 means no timeout */
  long infilesize;      /* size of file to upload, -1 means unknown */
  long low_speed_limit; /* bytes/second */
  long low_speed_time;  /* number of seconds */
  int set_resume_from;  /* continue [ftp] transfer from here */
  char *cookie;         /* HTTP cookie string to send */
  struct curl_slist *headers; /* linked list of extra headers */
  struct HttpPost *httppost;  /* linked list of POST data */
  char *cert;           /* certificate */
  char *cert_type;      /* format for certificate (default: PEM) */
  char *key;            /* private key */
  char *key_type;       /* format for private key (default: PEM) */
  char *key_passwd;     /* plain text private key password */
  char *crypto_engine;  /* name of the crypto engine to use */
  char *cookiejar;      /* dump all cookies to this file */
  bool cookiesession;   /* new cookie session? */
  bool crlf;            /* convert crlf on ftp upload(?) */
  struct curl_slist *quote;     /* after connection is established */
  struct curl_slist *postquote; /* after the transfer */
  struct curl_slist *prequote; /* before the transfer, after type (Wesley Laxton)*/
  struct curl_slist *telnet_options; /* linked list of telnet options */
  curl_TimeCond timecondition; /* kind of time/date comparison */
  time_t timevalue;       /* what time to compare with */
  curl_closepolicy closepolicy; /* connection cache close concept */
  Curl_HttpReq httpreq;   /* what kind of HTTP request (if any) is this */
  char *customrequest;    /* HTTP/FTP request to use */
  long httpversion; /* when non-zero, a specific HTTP version requested to
                       be used in the library's request(s) */
  char *auth_host; /* if set, this is the allocated string to the host name
                    * to which to send the authorization data to, and no other
                    * host (which location-following otherwise could lead to)
                    */
  char *krb4_level; /* what security level */
  struct ssl_config_data ssl;  /* user defined SSL stuff */

  curl_proxytype proxytype; /* what kind of proxy that is in use */

  int dns_cache_timeout; /* DNS cache timeout */
  long buffer_size;      /* size of receive buffer to use */
  
/* Here follows boolean settings that define how to behave during
   this session. They are STATIC, set by libcurl users or at least initially
   and they don't change during operations. */

  bool get_filetime;
  bool tunnel_thru_httpproxy;
  bool ftp_append;
  bool ftp_ascii;
  bool ftp_list_only;
  bool ftp_use_port;
  bool hide_progress;
  bool http_fail_on_error;
  bool http_follow_location;
  bool include_header;
#define http_include_header include_header /* former name */

  bool http_set_referer;
  bool http_auto_referer; /* set "correct" referer when following location: */
  bool no_body;
  bool set_port;
  bool upload;
  enum CURL_NETRC_OPTION
       use_netrc;        /* defined in include/curl.h */
  bool verbose;
  bool krb4;             /* kerberos4 connection requested */
  bool reuse_forbid;     /* forbidden to be reused, close after use */
  bool reuse_fresh;      /* do not re-use an existing connection  */
  bool expect100header;  /* TRUE if we added Expect: 100-continue */
  bool ftp_use_epsv;     /* if EPSV is to be attempted or not */
  bool no_signal;        /* do not use any signal/alarm handler */

  bool global_dns_cache;
};

/*
 * In August 2001, this struct was redesigned and is since stricter than
 * before. The 'connectdata' struct MUST have all the connection oriented
 * stuff as we may now have several simultaneous connections and connection
 * structs in memory.
 *
 * From now on, the 'SessionHandle' must only contain data that is set once to
 * go for many (perhaps) independent connections. Values that are generated or
 * calculated internally for the "session handle" must be defined within the
 * 'struct urlstate' instead.  */

struct SessionHandle {
  curl_hash *hostcache;
  curl_share *share;           /* Share, handles global variable mutexing */
  struct UserDefined set;      /* values set by the libcurl user */
  struct DynamicStatic change; /* possibly modified userdefined data */

  struct CookieInfo *cookies;  /* the cookies, read from files and servers */
  struct Progress progress;    /* for all the progress meter data */
  struct UrlState state;       /* struct for fields used for state info and
                                  other dynamic purposes */
  struct PureInfo info;        /* stats, reports and info data */
#ifdef USE_SSLEAY
  ENGINE*  engine;
#endif /* USE_SSLEAY */
};

#define LIBCURL_NAME "libcurl"

#endif
