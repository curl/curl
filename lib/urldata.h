#ifndef __URLDATA_H
#define __URLDATA_H
/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) 1998 - 2004, Daniel Stenberg, <daniel@haxx.se>, et al.
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
#define PORT_FTPS 990
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

#ifdef HAVE_ZLIB_H
#include <zlib.h>               /* for content-encoding */
#endif

#ifdef USE_ARES
#include <ares.h>
#endif

#include <curl/curl.h>

#include "http_chunks.h" /* for the structs and enum stuff */
#include "hostip.h"
#include "hash.h"

#ifdef HAVE_GSSAPI
#ifdef HAVE_GSSMIT
#include <gssapi/gssapi.h>
#include <gssapi/gssapi_generic.h>
#else
#include <gssapi.h>
#endif
#endif

/* Download buffer size, keep it fairly big for speed reasons */
#define BUFSIZE CURL_MAX_WRITE_SIZE

/* Initial size of the buffer to store headers in, it'll be enlarged in case
   of need. */
#define HEADERSIZE 256

/* Just a convenience macro to get the larger value out of two given.
   We prefix with CURL to prevent name collisions. */
#define CURLMAX(x,y) ((x)>(y)?(x):(y))

#ifdef HAVE_KRB4
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

/* struct for data related to each SSL connection */
struct ssl_connect_data {
  bool use;        /* use ssl encrypted communications TRUE/FALSE */
#ifdef USE_SSLEAY
  /* these ones requires specific SSL-types */
  SSL_CTX* ctx;
  SSL*     handle;
  X509*    server_cert;
#endif /* USE_SSLEAY */
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
  curl_ssl_ctx_callback fsslctx;        /* function to initialize ssl ctx */
  void *fsslctxp;       /*parameter for call back */
};

/* information stored about one single SSL session */
struct curl_ssl_session {
  char *name;       /* host name for which this ID was used */
  void *sessionid;  /* as returned from the SSL layer */
  long age;         /* just a number, the higher the more recent */
  unsigned short remote_port; /* remote port to connect to */
  struct ssl_config_data ssl_config; /* setup for this session */
};

/* Struct used for Digest challenge-response authentication */
struct digestdata {
  char *nonce;
  char *cnonce;
  char *realm;
  int algo;
  bool stale; /* set true for re-negotiation */
  char *opaque;
  char *qop;
  char *algorithm;
  int nc; /* nounce count */
};

typedef enum {
  NTLMSTATE_NONE,
  NTLMSTATE_TYPE1,
  NTLMSTATE_TYPE2,
  NTLMSTATE_TYPE3,
  NTLMSTATE_LAST
} curlntlm;

/* for 3rd party transfers to decide which side that issues PASV */
typedef enum {
  CURL_TARGET_PASV,
  CURL_SOURCE_PASV
} curl_pasv_side;

/* Struct used for NTLM challenge-response authentication */
struct ntlmdata {
  curlntlm state;
  unsigned char nonce[8];
};

#ifdef HAVE_GSSAPI
struct negotiatedata {
  bool gss; /* Whether we're processing GSS-Negotiate or Negotiate */
  const char* protocol; /* "GSS-Negotiate" or "Negotiate" */
  OM_uint32 status;
  gss_ctx_id_t context;
  gss_name_t server_name;
  gss_buffer_desc output_token;
};
#endif

/****************************************************************************
 * HTTP unique setup
 ***************************************************************************/
struct HTTP {
  struct FormData *sendit;
  curl_off_t postsize; /* off_t to handle large file sizes */
  char *postdata;

  const char *p_pragma;      /* Pragma: string */
  const char *p_accept;      /* Accept: string */
  curl_off_t readbytecount;
  curl_off_t writebytecount;

  /* For FORM posting */
  struct Form form;
  struct Curl_chunker chunk;

  struct back {
    curl_read_callback fread; /* backup storage for fread pointer */
    void *fread_in;           /* backup storage for fread_in pointer */
    char *postdata;
    curl_off_t postsize;
  } backup;

  enum {
    HTTPSEND_NADA,    /* init */
    HTTPSEND_REQUEST, /* sending a request */
    HTTPSEND_BODY,    /* sending body */
    HTTPSEND_LAST     /* never use this */
  } sending;

  void *send_buffer; /* used if the request couldn't be sent in one chunk,
                        points to an allocated send_buffer struct */
};

/****************************************************************************
 * FTP unique setup
 ***************************************************************************/
struct FTP {
  curl_off_t *bytecountp;
  char *user;    /* user name string */
  char *passwd;  /* password string */
  char *urlpath; /* the originally given path part of the URL */
  char **dirs;   /* realloc()ed array for path components */
  int dirdepth;  /* number of entries used in the 'dirs' array */
  int diralloc;  /* number of entries allocated for the 'dirs' array */
  char *file;    /* decoded file */

  char *entrypath; /* the PWD reply when we logged on */

  char *cache;       /* data cache between getresponse()-calls */
  curl_off_t cache_size; /* size of cache in bytes */
  bool dont_check;  /* Set to TRUE to prevent the final (post-transfer)
                       file size and 226/250 status check. It should still
                       read the line, just ignore the result. */
  bool no_transfer; /* nothing was transfered, (possibly because a resumed
                       transfer already was complete) */
  long response_time; /* When no timeout is given, this is the amount of
                         seconds we await for an FTP response. Initialized
                         in Curl_ftp_connect() */
  bool ctl_valid;   /* Tells Curl_ftp_quit() whether or not to do anything. If
                       the connection has timed out or been closed, this
                       should be FALSE when it gets to Curl_ftp_quit() */
  bool cwddone;     /* if it has been determined that the proper CWD combo
                       already has been done */
  char *prevpath;   /* conn->path from the previous transfer */
};

/****************************************************************************
 * FILE unique setup
 ***************************************************************************/
struct FILEPROTO {
  char *path; /* the path we operate on */
  char *freepath; /* pointer to the allocated block we must free, this might
                     differ from the 'path' pointer */
  int fd;     /* open file descriptor to read from! */
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
  bool getheader;     /* TRUE if header parsing is wanted */

  bool forbidchunk;   /* used only to explicitly forbid chunk-upload for
                         specific upload buffers. See readmoredata() in
                         http.c for details. */
  bool tcpconnect;    /* the tcp stream (or simimlar) is connected, this
                         is set the first time on the first connect function
                         call */
  bool retry;         /* this connection is about to get closed and then
                         re-attempted at another connection. */
  bool no_body;       /* CURLOPT_NO_BODY (or similar) was set */
  bool tunnel_proxy;  /* if CONNECT is used to "tunnel" through the proxy.
                         This is implicit when SSL-protocols are used through
                         proxies, but can also be enabled explicitly by
                         apps */
  bool authneg;       /* TRUE when the auth phase has started, which means
                         that we are creating a request with an auth header,
                         but it is not the final request in the auth
                         negotiation. */
  bool rewindaftersend;/* TRUE when the sending couldn't be stopped even
                          though it will be discarded. When the whole send
                          operation is done, we must call the data rewind
                          callback. */
  bool ftp_use_epsv;  /* As set with CURLOPT_FTP_USE_EPSV, but if we find out
                         EPSV doesn't work we disable it for the forthcoming
                         requests */

  bool ftp_use_eprt;  /* As set with CURLOPT_FTP_USE_EPRT, but if we find out
                         EPRT doesn't work we disable it for the forthcoming
                         requests */
  bool ftp_use_lprt;  /* As set with CURLOPT_FTP_USE_EPRT, but if we find out
                         LPRT doesn't work we disable it for the forthcoming
                         requests */
};

struct hostname {
  char *rawalloc; /* allocated "raw" version of the name */
  char *encalloc; /* allocated IDN-encoded version of the name */
  char *name;     /* name to use internally, might be encoded, might be raw */
  char *dispname; /* name to display, as 'name' might be encoded */
};

/*
 * This struct is all the previously local variables from Curl_perform() moved
 * to struct to allow the function to return and get re-invoked better without
 * losing state.
 */

struct Curl_transfer_keeper {
  curl_off_t bytecount;         /* total number of bytes read */
  curl_off_t writebytecount;    /* number of bytes written */
  struct timeval start;         /* transfer started at this time */
  struct timeval now;           /* current time */
  bool header;                  /* incoming data has HTTP header */
  enum {
    HEADER_NORMAL,              /* no bad header at all */
    HEADER_PARTHEADER,          /* part of the chunk is a bad header, the rest
                                   is normal data */
    HEADER_ALLBAD               /* all was believed to be header */
  } badheader;                  /* the header was deemed bad and will be
                                   written as body */
  int headerline;               /* counts header lines to better track the
                                   first one */
  char *hbufp;                  /* points at *end* of header line */
  size_t hbuflen;
  char *str;                    /* within buf */
  char *str_start;              /* within buf */
  char *end_ptr;                /* within buf */
  char *p;                      /* within headerbuff */
  bool content_range;           /* set TRUE if Content-Range: was found */
  curl_off_t offset;            /* possible resume offset read from the
                                   Content-Range: header */
  int httpcode;                 /* error code from the 'HTTP/1.? XXX' line */
  int httpversion;              /* the HTTP version*10 */
  struct timeval start100;      /* time stamp to wait for the 100 code from */
  bool write_after_100_header;  /* TRUE = we enable the write after we
                                   received a 100-continue/timeout or
                                   FALSE = directly */
  bool wait100_after_headers;   /* TRUE = after the request-headers have been
                                   sent off properly, we go into the wait100
                                   state, FALSE = don't */
  int content_encoding;         /* What content encoding. sec 3.5, RFC2616. */

#define IDENTITY 0              /* No encoding */
#define DEFLATE 1               /* zlib delfate [RFC 1950 & 1951] */
#define GZIP 2                  /* gzip algorithm [RFC 1952] */
#define COMPRESS 3              /* Not handled, added for completeness */

#ifdef HAVE_LIBZ
  bool zlib_init;               /* True if zlib already initialized;
                                   undefined if Content-Encoding header. */
  z_stream z;                   /* State structure for zlib. */
#endif

  time_t timeofdoc;
  long bodywrites;

  char *buf;
  char *uploadbuf;
  curl_socket_t maxfd;

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

  bool ignorebody;  /* we read a response-body but we ignore it! */
};

#if defined(USE_ARES) || defined(USE_THREADING_GETHOSTBYNAME) || \
    defined(USE_THREADING_GETADDRINFO)
struct Curl_async {
  char *hostname;
  int port;
  struct Curl_dns_entry *dns;
  bool done;  /* set TRUE when the lookup is complete */
  int status; /* if done is TRUE, this is the status from the callback */
  void *os_specific;  /* 'struct thread_data' for Windows */
};
#endif

#define FIRSTSOCKET     0
#define SECONDARYSOCKET 1

/*
 * The connectdata struct contains all fields and variables that should be
 * unique for an entire connection.
 */
struct connectdata {
  /**** Fields set when inited and not modified again */
  struct SessionHandle *data; /* link to the root CURL struct */
  long connectindex; /* what index in the connects index this particular
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
  struct Curl_dns_entry *dns_entry;
  Curl_addrinfo *ip_addr; /* the particular IP we connected to */

  char protostr[16];  /* store the protocol string in this buffer */

  struct hostname host;
  struct hostname proxy;

  char *pathbuffer;/* allocated buffer to store the URL's path part in */
  char *path;      /* path to use, points to somewhere within the pathbuffer
                      area */
  long port;       /* which port to use locally */
  unsigned short remote_port; /* what remote port to connect to,
                                 not the proxy port! */
  curl_off_t bytecount;
  long headerbytecount;  /* only count received headers */
  long deductheadercount; /* this amount of bytes doesn't count when we check
                             if anything has been transfered at the end of
                             a connection. We use this counter to make only
                             a 100 reply (without a following second response
                             code) result in a CURLE_GOT_NOTHING error code */

  char *range; /* range, if used. See README for detailed specification on
                  this syntax. */
  curl_off_t resume_from; /* continue [ftp] transfer from here */

  char *user;    /* user name string, allocated */
  char *passwd;  /* password string, allocated */

  char *proxyuser;    /* proxy user name string, allocated */
  char *proxypasswd;  /* proxy password string, allocated */

  struct timeval now;     /* "current" time */
  struct timeval created; /* creation time */
  curl_socket_t sock[2]; /* two sockets, the second is used for the data
                            transfer when doing FTP */
  curl_off_t maxdownload; /* in bytes, the maximum amount of data to fetch, 0
                             means unlimited */

  struct ssl_connect_data ssl[2]; /* this is for ssl-stuff */
  struct ssl_config_data ssl_config;

  struct ConnectBits bits;    /* various state-flags for this connection */

  /* These two functions MUST be set by the curl_connect() function to be
     be protocol dependent */
  CURLcode (*curl_do)(struct connectdata *);
  CURLcode (*curl_done)(struct connectdata *, CURLcode);

  /* If the curl_do() function is better made in two halves, this
   * curl_do_more() function will be called afterwards, if set. For example
   * for doing the FTP stuff after the PASV/PORT command.
   */
  CURLcode (*curl_do_more)(struct connectdata *);

  /* This function *MAY* be set to a protocol-dependent function that is run
   * after the connect() and everything is done, as a step in the connection.
   */
  CURLcode (*curl_connect)(struct connectdata *);

  /* This function *MAY* be set to a protocol-dependent function that is run
   * by the curl_disconnect(), as a step in the disconnection.
   */
  CURLcode (*curl_disconnect)(struct connectdata *);

  /* This function *MAY* be set to a protocol-dependent function that is run
   * in the curl_close() function if protocol-specific cleanups are required.
   */
  CURLcode (*curl_close)(struct connectdata *);

  /**** curl_get() phase fields */

  /* READ stuff */
  curl_socket_t sockfd;   /* socket to read from or CURL_SOCKET_BAD */
  curl_off_t size;        /* -1 if unknown at this point */
  curl_off_t *bytecountp; /* return number of bytes read or NULL */

  /* WRITE stuff */
  curl_socket_t writesockfd; /* socket to write to, it may very
                                well be the same we read from.
                                CURL_SOCKET_BAD disables */
  curl_off_t *writebytecountp; /* return number of bytes written or NULL */

  /** Dynamicly allocated strings, may need to be freed before this **/
  /** struct is killed.                                             **/
  struct dynamically_allocated_data {
    char *proxyuserpwd; /* free later if not NULL! */
    char *uagent; /* free later if not NULL! */
    char *accept_encoding; /* free later if not NULL! */
    char *userpwd; /* free later if not NULL! */
    char *rangeline; /* free later if not NULL! */
    char *ref; /* free later if not NULL! */
    char *host; /* free later if not NULL */
    char *cookiehost; /* free later if not NULL */
  } allocptr;

  char *newurl; /* This can only be set if a Location: was in the
                   document headers */

#ifdef HAVE_KRB4
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
    struct FILEPROTO *file;
    void *telnet;        /* private for telnet.c-eyes only */
    void *generic;
  } proto;

  /* This struct is inited when needed */
  struct Curl_transfer_keeper keep;

  /* 'upload_present' is used to keep a byte counter of how much data there is
     still left in the buffer, aimed for upload. */
  ssize_t upload_present;

   /* 'upload_fromhere' is used as a read-pointer when we uploaded parts of a
      buffer, so the next read should read from where this pointer points to,
      and the 'upload_present' contains the number of bytes available at this
      position */
  char *upload_fromhere;

  curl_read_callback fread; /* function that reads the input */
  void *fread_in;           /* pointer to pass to the fread() above */

  struct ntlmdata ntlm;     /* NTLM differs from other authentication schemes
                               because it authenticates connections, not
                               single requests! */
  struct ntlmdata proxyntlm; /* NTLM data for proxy */

  char syserr_buf [256]; /* buffer for Curl_strerror() */

#if defined(USE_ARES) || defined(USE_THREADING_GETHOSTBYNAME) || \
    defined(USE_THREADING_GETADDRINFO)
  /* data used for the asynch name resolve callback */
  struct Curl_async async;
#endif
  struct connectdata *sec_conn;   /* secondary connection for 3rd party
                                     transfer */
};

/* The end of connectdata. */

/*
 * Struct to keep statistical and informational data.
 */
struct PureInfo {
  int httpcode;  /* Recent HTTP or FTP response code */
  int httpproxycode;
  int httpversion;
  long filetime; /* If requested, this is might get set. Set to -1 if the time
                    was unretrievable. We cannot have this of type time_t,
                    since time_t is unsigned on several platforms such as
                    OpenVMS. */
  long header_size;  /* size of read header(s) in bytes */
  long request_size; /* the amount of bytes sent in the request(s) */

  long proxyauthavail;
  long httpauthavail;

  long numconnects; /* how many new connection did libcurl created */

  char *contenttype; /* the content type of the object */
};


struct Progress {
  long lastshow; /* time() of the last displayed progress meter or NULL to
                    force redraw at next call */
  curl_off_t size_dl; /* total expected size */
  curl_off_t size_ul; /* total expected size */
  curl_off_t downloaded; /* transfered so far */
  curl_off_t uploaded; /* transfered so far */

  curl_off_t current_speed; /* uses the currently fastest transfer */

  bool callback;  /* set when progress callback is used */
  int width; /* screen width at download start */
  int flags; /* see progress.h */

  double timespent;

  curl_off_t dlspeed;
  curl_off_t ulspeed;

  double t_nslookup;
  double t_connect;
  double t_pretransfer;
  double t_starttransfer;
  double t_redirect;

  struct timeval start;
  struct timeval t_startsingle;
#define CURR_TIME (5+1) /* 6 entries for 5 seconds */

  curl_off_t speeder[ CURR_TIME ];
  struct timeval speeder_time[ CURR_TIME ];
  int speeder_c;
};

typedef enum {
  HTTPREQ_NONE, /* first in list */
  HTTPREQ_GET,
  HTTPREQ_POST,
  HTTPREQ_POST_FORM, /* we make a difference internally */
  HTTPREQ_PUT,
  HTTPREQ_HEAD,
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
#define MAX_CURL_USER_LENGTH_TXT "255"
#define MAX_CURL_PASSWORD_LENGTH_TXT "255"

struct auth {
  long want;  /* Bitmask set to the authentication methods wanted by the app
                 (with CURLOPT_HTTPAUTH or CURLOPT_PROXYAUTH). */
  long picked;
  long avail; /* bitmask for what the server reports to support for this
                 resource */
  bool done;  /* TRUE when the auth phase is done and ready to do the *actual*
                 request */
  bool multi; /* TRUE if this is not yet authenticated but within the auth
                 multipass negotiation */

};

struct UrlState {
  enum {
    Curl_if_none,
    Curl_if_easy,
    Curl_if_multi
  } used_interface;

  /* buffers to store authentication data in, as parsed from input options */
  struct timeval keeps_speed; /* for the progress meter really */

  /* 'connects' will be an allocated array with pointers. If the pointer is
     set, it holds an allocated connection. */
  struct connectdata **connects;
  long numconnects; /* size of the 'connects' array */

  char *headerbuff; /* allocated buffer to store headers in */
  size_t headersize;   /* size of the allocation */

  char buffer[BUFSIZE+1]; /* download buffer */
  char uploadbuffer[BUFSIZE+1]; /* upload buffer */
  curl_off_t current_speed;  /* the ProgressShow() funcion sets this,
                                bytes / second */
  bool this_is_a_follow; /* this is a followed Location: request */

  char *first_host; /* if set, this should be the host name that we will
                       sent authorization to, no else. Used to make Location:
                       following not keep sending user+password... This is
                       strdup() data.
                    */

  struct curl_ssl_session *session; /* array of 'numsessions' size */
  long sessionage;                  /* number of the most recent session */

  char *scratch; /* huge buffer[BUFSIZE*2] when doing upload CRLF replacing */
  bool errorbuf; /* Set to TRUE if the error buffer is already filled in.
                    This must be set to FALSE every time _easy_perform() is
                    called. */
  int os_errno;  /* filled in with errno whenever an error occurs */
#ifdef HAVE_SIGNAL
  /* storage for the previous bag^H^H^HSIGPIPE signal handler :-) */
  void (*prev_signal)(int sig);
#endif
  bool allow_port; /* Is set.use_port allowed to take effect or not. This
                      is always set TRUE when curl_easy_perform() is called. */

  struct digestdata digest;
  struct digestdata proxydigest;

#ifdef HAVE_GSSAPI
  struct negotiatedata negotiate;
#endif

  struct auth authhost;
  struct auth authproxy;

  bool authproblem; /* TRUE if there's some problem authenticating */
#ifdef USE_ARES
  ares_channel areschannel; /* for name resolves */
#endif
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
  bool url_changed; /* set on CURL_OPT_URL, used to detect if the URL was
                       changed after the connect phase, as we allow callback
                       to change it and if so, we reconnect to use the new
                       URL instead */
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
  long httpauth;     /* what kind of HTTP authentication to use (bitmask) */
  long proxyauth;    /* what kind of proxy authentication to use (bitmask) */
  char *set_range;   /* range, if used. See README for detailed specification
                        on this syntax. */
  long followlocation; /* as in HTTP Location: */
  long maxredirs;    /* maximum no. of http(s) redirects to follow */
  char *set_referer; /* custom string */
  bool free_referer; /* set TRUE if 'referer' points to a string we
                        allocated */
  char *useragent;   /* User-Agent string */
  char *encoding;    /* Accept-Encoding string */
  char *postfields;  /* if POST, set the fields' values here */
  curl_off_t postfieldsize; /* if POST, this might have a size to use instead
                               of strlen(), and then the data *may* be binary
                               (contain zero bytes) */
  char *ftpport;     /* port to send with the FTP PORT command */
  char *device;      /* network interface to use */
  curl_write_callback fwrite;        /* function that stores the output */
  curl_write_callback fwrite_header; /* function that stores headers */
  curl_read_callback fread;          /* function that reads the input */
  curl_progress_callback fprogress;  /* function for progress information */
  curl_debug_callback fdebug;      /* function that write informational data */
  curl_ioctl_callback ioctrl;      /* function for I/O control */
  void *progress_client; /* pointer to pass to the progress callback */
  void *ioctrl_client;  /* pointer to pass to the ioctrl callback */
  long timeout;         /* in seconds, 0 means no timeout */
  long connecttimeout;  /* in seconds, 0 means no timeout */
  long ftp_response_timeout; /* in seconds, 0 means no timeout */
  curl_off_t infilesize;      /* size of file to upload, -1 means unknown */
  long low_speed_limit; /* bytes/second */
  long low_speed_time;  /* number of seconds */
  curl_off_t set_resume_from;  /* continue [ftp] transfer from here */
  char *cookie;         /* HTTP cookie string to send */
  struct curl_slist *headers; /* linked list of extra headers */
  struct curl_httppost *httppost;  /* linked list of POST data */
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
  struct curl_slist *prequote; /* before the transfer, after type */
  struct curl_slist *source_prequote;  /* in 3rd party transfer mode - before
                                          the transfer on source host */
  struct curl_slist *source_postquote; /* in 3rd party transfer mode - after
                                          the transfer on source host */
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

  char *private; /* Private data */

  struct curl_slist *http200aliases; /* linked list of aliases for http200 */

  long ip_version;

  curl_off_t max_filesize; /* Maximum file size to download */

  char *source_host;     /* for 3rd party transfer */
  char *source_port;     /* for 3rd party transfer */
  char *source_userpwd;  /* for 3rd party transfer */
  char *source_path;     /* for 3rd party transfer */
  curl_pasv_side pasvHost; /* for 3rd party transfer indicates passive host */

/* Here follows boolean settings that define how to behave during
   this session. They are STATIC, set by libcurl users or at least initially
   and they don't change during operations. */

  bool printhost;       /* printing host name in debug info */
  bool get_filetime;
  bool tunnel_thru_httpproxy;
  bool ftp_append;
  bool ftp_ascii;
  bool ftp_list_only;
  bool ftp_create_missing_dirs;
  bool ftp_use_port;
  bool hide_progress;
  bool http_fail_on_error;
  bool http_follow_location;
  bool http_disable_hostname_check_before_authentication;
  bool include_header;   /* include received protocol headers in data output */
  bool http_set_referer;
  bool http_auto_referer; /* set "correct" referer when following location: */
  bool opt_no_body;      /* as set with CURLOPT_NO_BODY */
  bool set_port;
  bool upload;
  enum CURL_NETRC_OPTION
       use_netrc;        /* defined in include/curl.h */
  char *netrc_file;      /* if not NULL, use this instead of trying to find
                            $HOME/.netrc */
  bool verbose;
  bool krb4;             /* kerberos4 connection requested */
  bool reuse_forbid;     /* forbidden to be reused, close after use */
  bool reuse_fresh;      /* do not re-use an existing connection  */
  bool expect100header;  /* TRUE if we added Expect: 100-continue */
  bool ftp_use_epsv;     /* if EPSV is to be attempted or not */
  bool ftp_use_eprt;     /* if EPRT is to be attempted or not */
  bool ftp_use_lprt;     /* if LPRT is to be attempted or not */
  curl_ftpssl ftp_ssl;   /* if AUTH TLS is to be attempted etc */
  curl_ftpauth ftpsslauth; /* what AUTH XXX to be attempted */
  bool no_signal;        /* do not use any signal/alarm handler */
  bool global_dns_cache; /* subject for future removal */
  bool tcp_nodelay;      /* whether to enable TCP_NODELAY or not */

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
  struct Curl_share *share;    /* Share, handles global variable mutexing */
  struct UserDefined set;      /* values set by the libcurl user */
  struct DynamicStatic change; /* possibly modified userdefined data */

  struct CookieInfo *cookies;  /* the cookies, read from files and servers */
  struct Progress progress;    /* for all the progress meter data */
  struct UrlState state;       /* struct for fields used for state info and
                                  other dynamic purposes */
  struct PureInfo info;        /* stats, reports and info data */
#if defined(USE_SSLEAY) && defined(HAVE_OPENSSL_ENGINE_H)
  ENGINE*  engine;
#endif /* USE_SSLEAY */
};

#define LIBCURL_NAME "libcurl"

#endif
