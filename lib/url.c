/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) 1998 - 2013, Daniel Stenberg, <daniel@haxx.se>, et al.
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

#include "curl_setup.h"

#ifdef HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif
#ifdef HAVE_NETDB_H
#include <netdb.h>
#endif
#ifdef HAVE_ARPA_INET_H
#include <arpa/inet.h>
#endif
#ifdef HAVE_NET_IF_H
#include <net/if.h>
#endif
#ifdef HAVE_SYS_IOCTL_H
#include <sys/ioctl.h>
#endif

#ifdef HAVE_SYS_PARAM_H
#include <sys/param.h>
#endif

#ifdef __VMS
#include <in.h>
#include <inet.h>
#endif

#ifndef HAVE_SOCKET
#error "We can't compile without socket() support!"
#endif

#ifdef HAVE_LIMITS_H
#include <limits.h>
#endif

#ifdef USE_LIBIDN
#include <idna.h>
#include <tld.h>
#include <stringprep.h>
#ifdef HAVE_IDN_FREE_H
#include <idn-free.h>
#else
/* prototype from idn-free.h, not provided by libidn 0.4.5's make install! */
void idn_free (void *ptr);
#endif
#ifndef HAVE_IDN_FREE
/* if idn_free() was not found in this version of libidn use free() instead */
#define idn_free(x) (free)(x)
#endif
#elif defined(USE_WIN32_IDN)
/* prototype for curl_win32_idn_to_ascii() */
int curl_win32_idn_to_ascii(const char *in, char **out);
#endif  /* USE_LIBIDN */

#include "urldata.h"
#include "netrc.h"

#include "formdata.h"
#include "sslgen.h"
#include "hostip.h"
#include "transfer.h"
#include "sendf.h"
#include "progress.h"
#include "cookie.h"
#include "strequal.h"
#include "strerror.h"
#include "escape.h"
#include "strtok.h"
#include "share.h"
#include "content_encoding.h"
#include "http_digest.h"
#include "http_negotiate.h"
#include "select.h"
#include "multiif.h"
#include "easyif.h"
#include "speedcheck.h"
#include "rawstr.h"
#include "warnless.h"
#include "non-ascii.h"
#include "inet_pton.h"

/* And now for the protocols */
#include "ftp.h"
#include "dict.h"
#include "telnet.h"
#include "tftp.h"
#include "http.h"
#include "file.h"
#include "curl_ldap.h"
#include "ssh.h"
#include "imap.h"
#include "url.h"
#include "connect.h"
#include "inet_ntop.h"
#include "curl_ntlm.h"
#include "curl_ntlm_wb.h"
#include "socks.h"
#include "curl_rtmp.h"
#include "gopher.h"
#include "http_proxy.h"
#include "bundles.h"
#include "conncache.h"
#include "multihandle.h"
#include "pipeline.h"

#define _MPRINTF_REPLACE /* use our functions only */
#include <curl/mprintf.h>

#include "curl_memory.h"
/* The last #include file should be: */
#include "memdebug.h"

/* Local static prototypes */
static struct connectdata *
find_oldest_idle_connection(struct SessionHandle *data);
static struct connectdata *
find_oldest_idle_connection_in_bundle(struct SessionHandle *data,
                                      struct connectbundle *bundle);
static void conn_free(struct connectdata *conn);
static void signalPipeClose(struct curl_llist *pipeline, bool pipe_broke);
static CURLcode do_init(struct connectdata *conn);
static CURLcode parse_url_login(struct SessionHandle *data,
                                struct connectdata *conn,
                                char *user, char *passwd, char *options);
static CURLcode parse_login_details(const char *login, const size_t len,
                                    char **userptr, char **passwdptr,
                                    char **optionsptr);
/*
 * Protocol table.
 */

static const struct Curl_handler * const protocols[] = {

#ifndef CURL_DISABLE_HTTP
  &Curl_handler_http,
#endif

#if defined(USE_SSL) && !defined(CURL_DISABLE_HTTP)
  &Curl_handler_https,
#endif

#ifndef CURL_DISABLE_FTP
  &Curl_handler_ftp,
#endif

#if defined(USE_SSL) && !defined(CURL_DISABLE_FTP)
  &Curl_handler_ftps,
#endif

#ifndef CURL_DISABLE_TELNET
  &Curl_handler_telnet,
#endif

#ifndef CURL_DISABLE_DICT
  &Curl_handler_dict,
#endif

#ifndef CURL_DISABLE_LDAP
  &Curl_handler_ldap,
#if !defined(CURL_DISABLE_LDAPS) && \
    ((defined(USE_OPENLDAP) && defined(USE_SSL)) || \
     (!defined(USE_OPENLDAP) && defined(HAVE_LDAP_SSL)))
  &Curl_handler_ldaps,
#endif
#endif

#ifndef CURL_DISABLE_FILE
  &Curl_handler_file,
#endif

#ifndef CURL_DISABLE_TFTP
  &Curl_handler_tftp,
#endif

#ifdef USE_LIBSSH2
  &Curl_handler_scp,
  &Curl_handler_sftp,
#endif

#ifndef CURL_DISABLE_IMAP
  &Curl_handler_imap,
#ifdef USE_SSL
  &Curl_handler_imaps,
#endif
#endif

#ifndef CURL_DISABLE_POP3
  &Curl_handler_pop3,
#ifdef USE_SSL
  &Curl_handler_pop3s,
#endif
#endif

#ifndef CURL_DISABLE_SMTP
  &Curl_handler_smtp,
#ifdef USE_SSL
  &Curl_handler_smtps,
#endif
#endif

#ifndef CURL_DISABLE_RTSP
  &Curl_handler_rtsp,
#endif

#ifndef CURL_DISABLE_GOPHER
  &Curl_handler_gopher,
#endif

#ifdef USE_LIBRTMP
  &Curl_handler_rtmp,
  &Curl_handler_rtmpt,
  &Curl_handler_rtmpe,
  &Curl_handler_rtmpte,
  &Curl_handler_rtmps,
  &Curl_handler_rtmpts,
#endif

  (struct Curl_handler *) NULL
};

/*
 * Dummy handler for undefined protocol schemes.
 */

static const struct Curl_handler Curl_handler_dummy = {
  "<no protocol>",                      /* scheme */
  ZERO_NULL,                            /* setup_connection */
  ZERO_NULL,                            /* do_it */
  ZERO_NULL,                            /* done */
  ZERO_NULL,                            /* do_more */
  ZERO_NULL,                            /* connect_it */
  ZERO_NULL,                            /* connecting */
  ZERO_NULL,                            /* doing */
  ZERO_NULL,                            /* proto_getsock */
  ZERO_NULL,                            /* doing_getsock */
  ZERO_NULL,                            /* domore_getsock */
  ZERO_NULL,                            /* perform_getsock */
  ZERO_NULL,                            /* disconnect */
  ZERO_NULL,                            /* readwrite */
  0,                                    /* defport */
  0,                                    /* protocol */
  PROTOPT_NONE                          /* flags */
};

void Curl_freeset(struct SessionHandle *data)
{
  /* Free all dynamic strings stored in the data->set substructure. */
  enum dupstring i;
  for(i=(enum dupstring)0; i < STRING_LAST; i++)
    Curl_safefree(data->set.str[i]);

  if(data->change.referer_alloc) {
    Curl_safefree(data->change.referer);
    data->change.referer_alloc = FALSE;
  }
  data->change.referer = NULL;
}

static CURLcode setstropt(char **charp, char *s)
{
  /* Release the previous storage at `charp' and replace by a dynamic storage
     copy of `s'. Return CURLE_OK or CURLE_OUT_OF_MEMORY. */

  Curl_safefree(*charp);

  if(s) {
    s = strdup(s);

    if(!s)
      return CURLE_OUT_OF_MEMORY;

    *charp = s;
  }

  return CURLE_OK;
}

static CURLcode setstropt_userpwd(char *option, char **userp, char **passwdp,
                                  char **optionsp)
{
  CURLcode result = CURLE_OK;
  char *user = NULL;
  char *passwd = NULL;
  char *options = NULL;

  /* Parse the login details if specified. It not then we treat NULL as a hint
     to clear the existing data */
  if(option) {
    result = parse_login_details(option, strlen(option),
                                 (userp ? &user : NULL),
                                 (passwdp ? &passwd : NULL),
                                 (optionsp ? &options : NULL));
  }

  if(!result) {
    /* Store the username part of option if required */
    if(userp) {
      Curl_safefree(*userp);
      *userp = user;
    }

    /* Store the password part of option if required */
    if(passwdp) {
      Curl_safefree(*passwdp);
      *passwdp = passwd;
    }

    /* Store the options part of option if required */
    if(optionsp) {
      Curl_safefree(*optionsp);
      *optionsp = options;
    }
  }

  return result;
}

CURLcode Curl_dupset(struct SessionHandle *dst, struct SessionHandle *src)
{
  CURLcode r = CURLE_OK;
  enum dupstring i;

  /* Copy src->set into dst->set first, then deal with the strings
     afterwards */
  dst->set = src->set;

  /* clear all string pointers first */
  memset(dst->set.str, 0, STRING_LAST * sizeof(char *));

  /* duplicate all strings */
  for(i=(enum dupstring)0; i< STRING_LAST; i++) {
    r = setstropt(&dst->set.str[i], src->set.str[i]);
    if(r != CURLE_OK)
      break;
  }

  /* If a failure occurred, freeing has to be performed externally. */
  return r;
}

/*
 * This is the internal function curl_easy_cleanup() calls. This should
 * cleanup and free all resources associated with this sessionhandle.
 *
 * NOTE: if we ever add something that attempts to write to a socket or
 * similar here, we must ignore SIGPIPE first. It is currently only done
 * when curl_easy_perform() is invoked.
 */

CURLcode Curl_close(struct SessionHandle *data)
{
  struct Curl_multi *m;

  if(!data)
    return CURLE_OK;

  Curl_expire(data, 0); /* shut off timers */

  m = data->multi;

  if(m)
    /* This handle is still part of a multi handle, take care of this first
       and detach this handle from there. */
    curl_multi_remove_handle(data->multi, data);

  if(data->multi_easy)
    /* when curl_easy_perform() is used, it creates its own multi handle to
       use and this is the one */
    curl_multi_cleanup(data->multi_easy);

  /* Destroy the timeout list that is held in the easy handle. It is
     /normally/ done by curl_multi_remove_handle() but this is "just in
     case" */
  if(data->state.timeoutlist) {
    Curl_llist_destroy(data->state.timeoutlist, NULL);
    data->state.timeoutlist = NULL;
  }

  data->magic = 0; /* force a clear AFTER the possibly enforced removal from
                      the multi handle, since that function uses the magic
                      field! */

  if(data->state.rangestringalloc)
    free(data->state.range);

  /* Free the pathbuffer */
  Curl_safefree(data->state.pathbuffer);
  data->state.path = NULL;

  Curl_safefree(data->state.proto.generic);

  /* Close down all open SSL info and sessions */
  Curl_ssl_close_all(data);
  Curl_safefree(data->state.first_host);
  Curl_safefree(data->state.scratch);
  Curl_ssl_free_certinfo(data);

  if(data->change.referer_alloc) {
    Curl_safefree(data->change.referer);
    data->change.referer_alloc = FALSE;
  }
  data->change.referer = NULL;

  if(data->change.url_alloc) {
    Curl_safefree(data->change.url);
    data->change.url_alloc = FALSE;
  }
  data->change.url = NULL;

  Curl_safefree(data->state.headerbuff);

  Curl_flush_cookies(data, 1);

  Curl_digest_cleanup(data);

  Curl_safefree(data->info.contenttype);
  Curl_safefree(data->info.wouldredirect);

  /* this destroys the channel and we cannot use it anymore after this */
  Curl_resolver_cleanup(data->state.resolver);

  Curl_convert_close(data);

  /* No longer a dirty share, if it exists */
  if(data->share) {
    Curl_share_lock(data, CURL_LOCK_DATA_SHARE, CURL_LOCK_ACCESS_SINGLE);
    data->share->dirty--;
    Curl_share_unlock(data, CURL_LOCK_DATA_SHARE);
  }

  Curl_freeset(data);
  free(data);
  return CURLE_OK;
}

/*
 * Initialize the UserDefined fields within a SessionHandle.
 * This may be safely called on a new or existing SessionHandle.
 */
CURLcode Curl_init_userdefined(struct UserDefined *set)
{
  CURLcode res = CURLE_OK;

  set->out = stdout; /* default output to stdout */
  set->in  = stdin;  /* default input from stdin */
  set->err  = stderr;  /* default stderr to stderr */

  /* use fwrite as default function to store output */
  set->fwrite_func = (curl_write_callback)fwrite;

  /* use fread as default function to read input */
  set->fread_func = (curl_read_callback)fread;
  set->is_fread_set = 0;
  set->is_fwrite_set = 0;

  set->seek_func = ZERO_NULL;
  set->seek_client = ZERO_NULL;

  /* conversion callbacks for non-ASCII hosts */
  set->convfromnetwork = ZERO_NULL;
  set->convtonetwork   = ZERO_NULL;
  set->convfromutf8    = ZERO_NULL;

  set->infilesize = -1;      /* we don't know any size */
  set->postfieldsize = -1;   /* unknown size */
  set->maxredirs = -1;       /* allow any amount by default */

  set->httpreq = HTTPREQ_GET; /* Default HTTP request */
  set->rtspreq = RTSPREQ_OPTIONS; /* Default RTSP request */
  set->ftp_use_epsv = TRUE;   /* FTP defaults to EPSV operations */
  set->ftp_use_eprt = TRUE;   /* FTP defaults to EPRT operations */
  set->ftp_use_pret = FALSE;  /* mainly useful for drftpd servers */
  set->ftp_filemethod = FTPFILE_MULTICWD;

  set->dns_cache_timeout = 60; /* Timeout every 60 seconds by default */

  /* Set the default size of the SSL session ID cache */
  set->ssl.max_ssl_sessions = 5;

  set->proxyport = CURL_DEFAULT_PROXY_PORT; /* from url.h */
  set->proxytype = CURLPROXY_HTTP; /* defaults to HTTP proxy */
  set->httpauth = CURLAUTH_BASIC;  /* defaults to basic */
  set->proxyauth = CURLAUTH_BASIC; /* defaults to basic */

  /* make libcurl quiet by default: */
  set->hide_progress = TRUE;  /* CURLOPT_NOPROGRESS changes these */

  /*
   * libcurl 7.10 introduced SSL verification *by default*! This needs to be
   * switched off unless wanted.
   */
  set->ssl.verifypeer = TRUE;
  set->ssl.verifyhost = TRUE;
#ifdef USE_TLS_SRP
  set->ssl.authtype = CURL_TLSAUTH_NONE;
#endif
  set->ssh_auth_types = CURLSSH_AUTH_DEFAULT; /* defaults to any auth
                                                      type */
  set->ssl.sessionid = TRUE; /* session ID caching enabled by default */

  set->new_file_perms = 0644;    /* Default permissions */
  set->new_directory_perms = 0755; /* Default permissions */

  /* for the *protocols fields we don't use the CURLPROTO_ALL convenience
     define since we internally only use the lower 16 bits for the passed
     in bitmask to not conflict with the private bits */
  set->allowed_protocols = CURLPROTO_ALL;
  set->redir_protocols =
    CURLPROTO_ALL & ~(CURLPROTO_FILE|CURLPROTO_SCP); /* not FILE or SCP */

#if defined(HAVE_GSSAPI) || defined(USE_WINDOWS_SSPI)
  /*
   * disallow unprotected protection negotiation NEC reference implementation
   * seem not to follow rfc1961 section 4.3/4.4
   */
  set->socks5_gssapi_nec = FALSE;
  /* set default gssapi service name */
  res = setstropt(&set->str[STRING_SOCKS5_GSSAPI_SERVICE],
                  (char *) CURL_DEFAULT_SOCKS5_GSSAPI_SERVICE);
  if(res != CURLE_OK)
    return res;
#endif

  /* This is our preferred CA cert bundle/path since install time */
#if defined(CURL_CA_BUNDLE)
  res = setstropt(&set->str[STRING_SSL_CAFILE], (char *) CURL_CA_BUNDLE);
#elif defined(CURL_CA_PATH)
  res = setstropt(&set->str[STRING_SSL_CAPATH], (char *) CURL_CA_PATH);
#endif

  set->wildcardmatch  = FALSE;
  set->chunk_bgn      = ZERO_NULL;
  set->chunk_end      = ZERO_NULL;

  /* tcp keepalives are disabled by default, but provide reasonable values for
   * the interval and idle times.
   */
  set->tcp_keepalive = FALSE;
  set->tcp_keepintvl = 60;
  set->tcp_keepidle = 60;

  return res;
}

/**
 * Curl_open()
 *
 * @param curl is a pointer to a sessionhandle pointer that gets set by this
 * function.
 * @return CURLcode
 */

CURLcode Curl_open(struct SessionHandle **curl)
{
  CURLcode res = CURLE_OK;
  struct SessionHandle *data;
  CURLcode status;

  /* Very simple start-up: alloc the struct, init it with zeroes and return */
  data = calloc(1, sizeof(struct SessionHandle));
  if(!data) {
    /* this is a very serious error */
    DEBUGF(fprintf(stderr, "Error: calloc of SessionHandle failed\n"));
    return CURLE_OUT_OF_MEMORY;
  }

  data->magic = CURLEASY_MAGIC_NUMBER;

  status = Curl_resolver_init(&data->state.resolver);
  if(status) {
    DEBUGF(fprintf(stderr, "Error: resolver_init failed\n"));
    free(data);
    return status;
  }

  /* We do some initial setup here, all those fields that can't be just 0 */

  data->state.headerbuff = malloc(HEADERSIZE);
  if(!data->state.headerbuff) {
    DEBUGF(fprintf(stderr, "Error: malloc of headerbuff failed\n"));
    res = CURLE_OUT_OF_MEMORY;
  }
  else {
    Curl_easy_initHandleData(data);
    res = Curl_init_userdefined(&data->set);

    data->state.headersize=HEADERSIZE;

    Curl_convert_init(data);

    /* most recent connection is not yet defined */
    data->state.lastconnect = NULL;

    data->progress.flags |= PGRS_HIDE;
    data->state.current_speed = -1; /* init to negative == impossible */

    data->wildcard.state = CURLWC_INIT;
    data->wildcard.filelist = NULL;
    data->set.fnmatch = ZERO_NULL;
    data->set.maxconnects = DEFAULT_CONNCACHE_SIZE; /* for easy handles */
  }

  if(res) {
    Curl_resolver_cleanup(data->state.resolver);
    if(data->state.headerbuff)
      free(data->state.headerbuff);
    Curl_freeset(data);
    free(data);
    data = NULL;
  }
  else
    *curl = data;

  return res;
}

CURLcode Curl_setopt(struct SessionHandle *data, CURLoption option,
                     va_list param)
{
  char *argptr;
  CURLcode result = CURLE_OK;
  long arg;
#ifndef CURL_DISABLE_HTTP
  curl_off_t bigsize;
#endif

  switch(option) {
  case CURLOPT_DNS_CACHE_TIMEOUT:
    data->set.dns_cache_timeout = va_arg(param, long);
    break;
  case CURLOPT_DNS_USE_GLOBAL_CACHE:
    /* remember we want this enabled */
    arg = va_arg(param, long);
    data->set.global_dns_cache = (0 != arg)?TRUE:FALSE;
    break;
  case CURLOPT_SSL_CIPHER_LIST:
    /* set a list of cipher we want to use in the SSL connection */
    result = setstropt(&data->set.str[STRING_SSL_CIPHER_LIST],
                       va_arg(param, char *));
    break;

  case CURLOPT_RANDOM_FILE:
    /*
     * This is the path name to a file that contains random data to seed
     * the random SSL stuff with. The file is only used for reading.
     */
    result = setstropt(&data->set.str[STRING_SSL_RANDOM_FILE],
                       va_arg(param, char *));
    break;
  case CURLOPT_EGDSOCKET:
    /*
     * The Entropy Gathering Daemon socket pathname
     */
    result = setstropt(&data->set.str[STRING_SSL_EGDSOCKET],
                       va_arg(param, char *));
    break;
  case CURLOPT_MAXCONNECTS:
    /*
     * Set the absolute number of maximum simultaneous alive connection that
     * libcurl is allowed to have.
     */
    data->set.maxconnects = va_arg(param, long);
    break;
  case CURLOPT_FORBID_REUSE:
    /*
     * When this transfer is done, it must not be left to be reused by a
     * subsequent transfer but shall be closed immediately.
     */
    data->set.reuse_forbid = (0 != va_arg(param, long))?TRUE:FALSE;
    break;
  case CURLOPT_FRESH_CONNECT:
    /*
     * This transfer shall not use a previously cached connection but
     * should be made with a fresh new connect!
     */
    data->set.reuse_fresh = (0 != va_arg(param, long))?TRUE:FALSE;
    break;
  case CURLOPT_VERBOSE:
    /*
     * Verbose means infof() calls that give a lot of information about
     * the connection and transfer procedures as well as internal choices.
     */
    data->set.verbose = (0 != va_arg(param, long))?TRUE:FALSE;
    break;
  case CURLOPT_HEADER:
    /*
     * Set to include the header in the general data output stream.
     */
    data->set.include_header = (0 != va_arg(param, long))?TRUE:FALSE;
    break;
  case CURLOPT_NOPROGRESS:
    /*
     * Shut off the internal supported progress meter
     */
    data->set.hide_progress = (0 != va_arg(param, long))?TRUE:FALSE;
    if(data->set.hide_progress)
      data->progress.flags |= PGRS_HIDE;
    else
      data->progress.flags &= ~PGRS_HIDE;
    break;
  case CURLOPT_NOBODY:
    /*
     * Do not include the body part in the output data stream.
     */
    data->set.opt_no_body = (0 != va_arg(param, long))?TRUE:FALSE;
    break;
  case CURLOPT_FAILONERROR:
    /*
     * Don't output the >=300 error code HTML-page, but instead only
     * return error.
     */
    data->set.http_fail_on_error = (0 != va_arg(param, long))?TRUE:FALSE;
    break;
  case CURLOPT_UPLOAD:
  case CURLOPT_PUT:
    /*
     * We want to sent data to the remote host. If this is HTTP, that equals
     * using the PUT request.
     */
    data->set.upload = (0 != va_arg(param, long))?TRUE:FALSE;
    if(data->set.upload) {
      /* If this is HTTP, PUT is what's needed to "upload" */
      data->set.httpreq = HTTPREQ_PUT;
      data->set.opt_no_body = FALSE; /* this is implied */
    }
    else
      /* In HTTP, the opposite of upload is GET (unless NOBODY is true as
         then this can be changed to HEAD later on) */
      data->set.httpreq = HTTPREQ_GET;
    break;
  case CURLOPT_FILETIME:
    /*
     * Try to get the file time of the remote document. The time will
     * later (possibly) become available using curl_easy_getinfo().
     */
    data->set.get_filetime = (0 != va_arg(param, long))?TRUE:FALSE;
    break;
  case CURLOPT_FTP_CREATE_MISSING_DIRS:
    /*
     * An FTP option that modifies an upload to create missing directories on
     * the server.
     */
    switch(va_arg(param, long)) {
    case 0:
      data->set.ftp_create_missing_dirs = 0;
      break;
    case 1:
      data->set.ftp_create_missing_dirs = 1;
      break;
    case 2:
      data->set.ftp_create_missing_dirs = 2;
      break;
    default:
      /* reserve other values for future use */
      result = CURLE_UNKNOWN_OPTION;
      break;
    }
    break;
  case CURLOPT_SERVER_RESPONSE_TIMEOUT:
    /*
     * Option that specifies how quickly an server response must be obtained
     * before it is considered failure. For pingpong protocols.
     */
    data->set.server_response_timeout = va_arg( param , long ) * 1000;
    break;
  case CURLOPT_TFTP_BLKSIZE:
    /*
     * TFTP option that specifies the block size to use for data transmission
     */
    data->set.tftp_blksize = va_arg(param, long);
    break;
  case CURLOPT_DIRLISTONLY:
    /*
     * An option that changes the command to one that asks for a list
     * only, no file info details.
     */
    data->set.ftp_list_only = (0 != va_arg(param, long))?TRUE:FALSE;
    break;
  case CURLOPT_APPEND:
    /*
     * We want to upload and append to an existing file.
     */
    data->set.ftp_append = (0 != va_arg(param, long))?TRUE:FALSE;
    break;
  case CURLOPT_FTP_FILEMETHOD:
    /*
     * How do access files over FTP.
     */
    data->set.ftp_filemethod = (curl_ftpfile)va_arg(param, long);
    break;
  case CURLOPT_NETRC:
    /*
     * Parse the $HOME/.netrc file
     */
    data->set.use_netrc = (enum CURL_NETRC_OPTION)va_arg(param, long);
    break;
  case CURLOPT_NETRC_FILE:
    /*
     * Use this file instead of the $HOME/.netrc file
     */
    result = setstropt(&data->set.str[STRING_NETRC_FILE],
                       va_arg(param, char *));
    break;
  case CURLOPT_TRANSFERTEXT:
    /*
     * This option was previously named 'FTPASCII'. Renamed to work with
     * more protocols than merely FTP.
     *
     * Transfer using ASCII (instead of BINARY).
     */
    data->set.prefer_ascii = (0 != va_arg(param, long))?TRUE:FALSE;
    break;
  case CURLOPT_TIMECONDITION:
    /*
     * Set HTTP time condition. This must be one of the defines in the
     * curl/curl.h header file.
     */
    data->set.timecondition = (curl_TimeCond)va_arg(param, long);
    break;
  case CURLOPT_TIMEVALUE:
    /*
     * This is the value to compare with the remote document with the
     * method set with CURLOPT_TIMECONDITION
     */
    data->set.timevalue = (time_t)va_arg(param, long);
    break;
  case CURLOPT_SSLVERSION:
    /*
     * Set explicit SSL version to try to connect with, as some SSL
     * implementations are lame.
     */
    data->set.ssl.version = va_arg(param, long);
    break;

#ifndef CURL_DISABLE_HTTP
  case CURLOPT_AUTOREFERER:
    /*
     * Switch on automatic referer that gets set if curl follows locations.
     */
    data->set.http_auto_referer = (0 != va_arg(param, long))?TRUE:FALSE;
    break;

  case CURLOPT_ACCEPT_ENCODING:
    /*
     * String to use at the value of Accept-Encoding header.
     *
     * If the encoding is set to "" we use an Accept-Encoding header that
     * encompasses all the encodings we support.
     * If the encoding is set to NULL we don't send an Accept-Encoding header
     * and ignore an received Content-Encoding header.
     *
     */
    argptr = va_arg(param, char *);
    result = setstropt(&data->set.str[STRING_ENCODING],
                       (argptr && !*argptr)?
                       (char *) ALL_CONTENT_ENCODINGS: argptr);
    break;

  case CURLOPT_TRANSFER_ENCODING:
    data->set.http_transfer_encoding = (0 != va_arg(param, long))?TRUE:FALSE;
    break;

  case CURLOPT_FOLLOWLOCATION:
    /*
     * Follow Location: header hints on a HTTP-server.
     */
    data->set.http_follow_location = (0 != va_arg(param, long))?TRUE:FALSE;
    break;

  case CURLOPT_UNRESTRICTED_AUTH:
    /*
     * Send authentication (user+password) when following locations, even when
     * hostname changed.
     */
    data->set.http_disable_hostname_check_before_authentication =
      (0 != va_arg(param, long))?TRUE:FALSE;
    break;

  case CURLOPT_MAXREDIRS:
    /*
     * The maximum amount of hops you allow curl to follow Location:
     * headers. This should mostly be used to detect never-ending loops.
     */
    data->set.maxredirs = va_arg(param, long);
    break;

  case CURLOPT_POSTREDIR:
  {
    /*
     * Set the behaviour of POST when redirecting
     * CURL_REDIR_GET_ALL - POST is changed to GET after 301 and 302
     * CURL_REDIR_POST_301 - POST is kept as POST after 301
     * CURL_REDIR_POST_302 - POST is kept as POST after 302
     * CURL_REDIR_POST_303 - POST is kept as POST after 303
     * CURL_REDIR_POST_ALL - POST is kept as POST after 301, 302 and 303
     * other - POST is kept as POST after 301 and 302
     */
    int postRedir = curlx_sltosi(va_arg(param, long));
    data->set.keep_post = postRedir & CURL_REDIR_POST_ALL;
  }
  break;

  case CURLOPT_POST:
    /* Does this option serve a purpose anymore? Yes it does, when
       CURLOPT_POSTFIELDS isn't used and the POST data is read off the
       callback! */
    if(va_arg(param, long)) {
      data->set.httpreq = HTTPREQ_POST;
      data->set.opt_no_body = FALSE; /* this is implied */
    }
    else
      data->set.httpreq = HTTPREQ_GET;
    break;

  case CURLOPT_COPYPOSTFIELDS:
    /*
     * A string with POST data. Makes curl HTTP POST. Even if it is NULL.
     * If needed, CURLOPT_POSTFIELDSIZE must have been set prior to
     *  CURLOPT_COPYPOSTFIELDS and not altered later.
     */
    argptr = va_arg(param, char *);

    if(!argptr || data->set.postfieldsize == -1)
      result = setstropt(&data->set.str[STRING_COPYPOSTFIELDS], argptr);
    else {
      /*
       *  Check that requested length does not overflow the size_t type.
       */

      if((data->set.postfieldsize < 0) ||
         ((sizeof(curl_off_t) != sizeof(size_t)) &&
          (data->set.postfieldsize > (curl_off_t)((size_t)-1))))
        result = CURLE_OUT_OF_MEMORY;
      else {
        char * p;

        (void) setstropt(&data->set.str[STRING_COPYPOSTFIELDS], NULL);

        /* Allocate even when size == 0. This satisfies the need of possible
           later address compare to detect the COPYPOSTFIELDS mode, and
           to mark that postfields is used rather than read function or
           form data.
        */
        p = malloc((size_t)(data->set.postfieldsize?
                            data->set.postfieldsize:1));

        if(!p)
          result = CURLE_OUT_OF_MEMORY;
        else {
          if(data->set.postfieldsize)
            memcpy(p, argptr, (size_t)data->set.postfieldsize);

          data->set.str[STRING_COPYPOSTFIELDS] = p;
        }
      }
    }

    data->set.postfields = data->set.str[STRING_COPYPOSTFIELDS];
    data->set.httpreq = HTTPREQ_POST;
    break;

  case CURLOPT_POSTFIELDS:
    /*
     * Like above, but use static data instead of copying it.
     */
    data->set.postfields = va_arg(param, void *);
    /* Release old copied data. */
    (void) setstropt(&data->set.str[STRING_COPYPOSTFIELDS], NULL);
    data->set.httpreq = HTTPREQ_POST;
    break;

  case CURLOPT_POSTFIELDSIZE:
    /*
     * The size of the POSTFIELD data to prevent libcurl to do strlen() to
     * figure it out. Enables binary posts.
     */
    bigsize = va_arg(param, long);

    if(data->set.postfieldsize < bigsize &&
       data->set.postfields == data->set.str[STRING_COPYPOSTFIELDS]) {
      /* Previous CURLOPT_COPYPOSTFIELDS is no longer valid. */
      (void) setstropt(&data->set.str[STRING_COPYPOSTFIELDS], NULL);
      data->set.postfields = NULL;
    }

    data->set.postfieldsize = bigsize;
    break;

  case CURLOPT_POSTFIELDSIZE_LARGE:
    /*
     * The size of the POSTFIELD data to prevent libcurl to do strlen() to
     * figure it out. Enables binary posts.
     */
    bigsize = va_arg(param, curl_off_t);

    if(data->set.postfieldsize < bigsize &&
       data->set.postfields == data->set.str[STRING_COPYPOSTFIELDS]) {
      /* Previous CURLOPT_COPYPOSTFIELDS is no longer valid. */
      (void) setstropt(&data->set.str[STRING_COPYPOSTFIELDS], NULL);
      data->set.postfields = NULL;
    }

    data->set.postfieldsize = bigsize;
    break;

  case CURLOPT_HTTPPOST:
    /*
     * Set to make us do HTTP POST
     */
    data->set.httppost = va_arg(param, struct curl_httppost *);
    data->set.httpreq = HTTPREQ_POST_FORM;
    data->set.opt_no_body = FALSE; /* this is implied */
    break;

  case CURLOPT_REFERER:
    /*
     * String to set in the HTTP Referer: field.
     */
    if(data->change.referer_alloc) {
      Curl_safefree(data->change.referer);
      data->change.referer_alloc = FALSE;
    }
    result = setstropt(&data->set.str[STRING_SET_REFERER],
                       va_arg(param, char *));
    data->change.referer = data->set.str[STRING_SET_REFERER];
    break;

  case CURLOPT_USERAGENT:
    /*
     * String to use in the HTTP User-Agent field
     */
    result = setstropt(&data->set.str[STRING_USERAGENT],
                       va_arg(param, char *));
    break;

  case CURLOPT_HTTPHEADER:
    /*
     * Set a list with HTTP headers to use (or replace internals with)
     */
    data->set.headers = va_arg(param, struct curl_slist *);
    break;

  case CURLOPT_HTTP200ALIASES:
    /*
     * Set a list of aliases for HTTP 200 in response header
     */
    data->set.http200aliases = va_arg(param, struct curl_slist *);
    break;

#if !defined(CURL_DISABLE_COOKIES)
  case CURLOPT_COOKIE:
    /*
     * Cookie string to send to the remote server in the request.
     */
    result = setstropt(&data->set.str[STRING_COOKIE],
                       va_arg(param, char *));
    break;

  case CURLOPT_COOKIEFILE:
    /*
     * Set cookie file to read and parse. Can be used multiple times.
     */
    argptr = (char *)va_arg(param, void *);
    if(argptr) {
      struct curl_slist *cl;
      /* append the cookie file name to the list of file names, and deal with
         them later */
      cl = curl_slist_append(data->change.cookielist, argptr);
      if(!cl) {
        curl_slist_free_all(data->change.cookielist);
        data->change.cookielist = NULL;
        return CURLE_OUT_OF_MEMORY;
      }
      data->change.cookielist = cl; /* store the list for later use */
    }
    break;

  case CURLOPT_COOKIEJAR:
    /*
     * Set cookie file name to dump all cookies to when we're done.
     */
    result = setstropt(&data->set.str[STRING_COOKIEJAR],
                       va_arg(param, char *));

    /*
     * Activate the cookie parser. This may or may not already
     * have been made.
     */
    data->cookies = Curl_cookie_init(data, NULL, data->cookies,
                                     data->set.cookiesession);
    break;

  case CURLOPT_COOKIESESSION:
    /*
     * Set this option to TRUE to start a new "cookie session". It will
     * prevent the forthcoming read-cookies-from-file actions to accept
     * cookies that are marked as being session cookies, as they belong to a
     * previous session.
     *
     * In the original Netscape cookie spec, "session cookies" are cookies
     * with no expire date set. RFC2109 describes the same action if no
     * 'Max-Age' is set and RFC2965 includes the RFC2109 description and adds
     * a 'Discard' action that can enforce the discard even for cookies that
     * have a Max-Age.
     *
     * We run mostly with the original cookie spec, as hardly anyone implements
     * anything else.
     */
    data->set.cookiesession = (0 != va_arg(param, long))?TRUE:FALSE;
    break;

  case CURLOPT_COOKIELIST:
    argptr = va_arg(param, char *);

    if(argptr == NULL)
      break;

    if(Curl_raw_equal(argptr, "ALL")) {
      /* clear all cookies */
      Curl_cookie_clearall(data->cookies);
      break;
    }
    else if(Curl_raw_equal(argptr, "SESS")) {
      /* clear session cookies */
      Curl_cookie_clearsess(data->cookies);
      break;
    }
    else if(Curl_raw_equal(argptr, "FLUSH")) {
      /* flush cookies to file */
      Curl_flush_cookies(data, 0);
      break;
    }

    if(!data->cookies)
      /* if cookie engine was not running, activate it */
      data->cookies = Curl_cookie_init(data, NULL, NULL, TRUE);

    argptr = strdup(argptr);
    if(!argptr) {
      result = CURLE_OUT_OF_MEMORY;
      break;
    }

    if(checkprefix("Set-Cookie:", argptr))
      /* HTTP Header format line */
      Curl_cookie_add(data, data->cookies, TRUE, argptr + 11, NULL, NULL);

    else
      /* Netscape format line */
      Curl_cookie_add(data, data->cookies, FALSE, argptr, NULL, NULL);

    free(argptr);
    break;
#endif /* CURL_DISABLE_COOKIES */

  case CURLOPT_HTTPGET:
    /*
     * Set to force us do HTTP GET
     */
    if(va_arg(param, long)) {
      data->set.httpreq = HTTPREQ_GET;
      data->set.upload = FALSE; /* switch off upload */
      data->set.opt_no_body = FALSE; /* this is implied */
    }
    break;

  case CURLOPT_HTTP_VERSION:
    /*
     * This sets a requested HTTP version to be used. The value is one of
     * the listed enums in curl/curl.h.
     */
    data->set.httpversion = va_arg(param, long);
    break;

  case CURLOPT_HTTPAUTH:
    /*
     * Set HTTP Authentication type BITMASK.
     */
  {
    int bitcheck;
    bool authbits;
    unsigned long auth = va_arg(param, unsigned long);

    if(auth == CURLAUTH_NONE) {
      data->set.httpauth = auth;
      break;
    }

    /* the DIGEST_IE bit is only used to set a special marker, for all the
       rest we need to handle it as normal DIGEST */
    data->state.authhost.iestyle = (auth & CURLAUTH_DIGEST_IE)?TRUE:FALSE;

    if(auth & CURLAUTH_DIGEST_IE) {
      auth |= CURLAUTH_DIGEST; /* set standard digest bit */
      auth &= ~CURLAUTH_DIGEST_IE; /* unset ie digest bit */
    }

    /* switch off bits we can't support */
#ifndef USE_NTLM
    auth &= ~CURLAUTH_NTLM;    /* no NTLM support */
    auth &= ~CURLAUTH_NTLM_WB; /* no NTLM_WB support */
#elif !defined(NTLM_WB_ENABLED)
    auth &= ~CURLAUTH_NTLM_WB; /* no NTLM_WB support */
#endif
#ifndef USE_HTTP_NEGOTIATE
    auth &= ~CURLAUTH_GSSNEGOTIATE; /* no GSS-Negotiate without GSSAPI or
                                       WINDOWS_SSPI */
#endif

    /* check if any auth bit lower than CURLAUTH_ONLY is still set */
    bitcheck = 0;
    authbits = FALSE;
    while(bitcheck < 31) {
      if(auth & (1UL << bitcheck++)) {
        authbits = TRUE;
        break;
      }
    }
    if(!authbits)
      return CURLE_NOT_BUILT_IN; /* no supported types left! */

    data->set.httpauth = auth;
  }
  break;

#endif   /* CURL_DISABLE_HTTP */

  case CURLOPT_CUSTOMREQUEST:
    /*
     * Set a custom string to use as request
     */
    result = setstropt(&data->set.str[STRING_CUSTOMREQUEST],
                       va_arg(param, char *));

    /* we don't set
       data->set.httpreq = HTTPREQ_CUSTOM;
       here, we continue as if we were using the already set type
       and this just changes the actual request keyword */
    break;

#ifndef CURL_DISABLE_PROXY
  case CURLOPT_HTTPPROXYTUNNEL:
    /*
     * Tunnel operations through the proxy instead of normal proxy use
     */
    data->set.tunnel_thru_httpproxy = (0 != va_arg(param, long))?TRUE:FALSE;
    break;

  case CURLOPT_PROXYPORT:
    /*
     * Explicitly set HTTP proxy port number.
     */
    data->set.proxyport = va_arg(param, long);
    break;

  case CURLOPT_PROXYAUTH:
    /*
     * Set HTTP Authentication type BITMASK.
     */
  {
    int bitcheck;
    bool authbits;
    unsigned long auth = va_arg(param, unsigned long);

    if(auth == CURLAUTH_NONE) {
      data->set.proxyauth = auth;
      break;
    }

    /* the DIGEST_IE bit is only used to set a special marker, for all the
       rest we need to handle it as normal DIGEST */
    data->state.authproxy.iestyle = (auth & CURLAUTH_DIGEST_IE)?TRUE:FALSE;

    if(auth & CURLAUTH_DIGEST_IE) {
      auth |= CURLAUTH_DIGEST; /* set standard digest bit */
      auth &= ~CURLAUTH_DIGEST_IE; /* unset ie digest bit */
    }
    /* switch off bits we can't support */
#ifndef USE_NTLM
    auth &= ~CURLAUTH_NTLM;    /* no NTLM support */
    auth &= ~CURLAUTH_NTLM_WB; /* no NTLM_WB support */
#elif !defined(NTLM_WB_ENABLED)
    auth &= ~CURLAUTH_NTLM_WB; /* no NTLM_WB support */
#endif
#ifndef USE_HTTP_NEGOTIATE
    auth &= ~CURLAUTH_GSSNEGOTIATE; /* no GSS-Negotiate without GSSAPI or
                                       WINDOWS_SSPI */
#endif

    /* check if any auth bit lower than CURLAUTH_ONLY is still set */
    bitcheck = 0;
    authbits = FALSE;
    while(bitcheck < 31) {
      if(auth & (1UL << bitcheck++)) {
        authbits = TRUE;
        break;
      }
    }
    if(!authbits)
      return CURLE_NOT_BUILT_IN; /* no supported types left! */

    data->set.proxyauth = auth;
  }
  break;

  case CURLOPT_PROXY:
    /*
     * Set proxy server:port to use as HTTP proxy.
     *
     * If the proxy is set to "" we explicitly say that we don't want to use a
     * proxy (even though there might be environment variables saying so).
     *
     * Setting it to NULL, means no proxy but allows the environment variables
     * to decide for us.
     */
    result = setstropt(&data->set.str[STRING_PROXY],
                       va_arg(param, char *));
    break;

  case CURLOPT_PROXYTYPE:
    /*
     * Set proxy type. HTTP/HTTP_1_0/SOCKS4/SOCKS4a/SOCKS5/SOCKS5_HOSTNAME
     */
    data->set.proxytype = (curl_proxytype)va_arg(param, long);
    break;

  case CURLOPT_PROXY_TRANSFER_MODE:
    /*
     * set transfer mode (;type=<a|i>) when doing FTP via an HTTP proxy
     */
    switch (va_arg(param, long)) {
    case 0:
      data->set.proxy_transfer_mode = FALSE;
      break;
    case 1:
      data->set.proxy_transfer_mode = TRUE;
      break;
    default:
      /* reserve other values for future use */
      result = CURLE_UNKNOWN_OPTION;
      break;
    }
    break;
#endif   /* CURL_DISABLE_PROXY */

#if defined(HAVE_GSSAPI) || defined(USE_WINDOWS_SSPI)
  case CURLOPT_SOCKS5_GSSAPI_SERVICE:
    /*
     * Set gssapi service name
     */
    result = setstropt(&data->set.str[STRING_SOCKS5_GSSAPI_SERVICE],
                       va_arg(param, char *));
    break;

  case CURLOPT_SOCKS5_GSSAPI_NEC:
    /*
     * set flag for nec socks5 support
     */
    data->set.socks5_gssapi_nec = (0 != va_arg(param, long))?TRUE:FALSE;
    break;
#endif

  case CURLOPT_WRITEHEADER:
    /*
     * Custom pointer to pass the header write callback function
     */
    data->set.writeheader = (void *)va_arg(param, void *);
    break;
  case CURLOPT_ERRORBUFFER:
    /*
     * Error buffer provided by the caller to get the human readable
     * error string in.
     */
    data->set.errorbuffer = va_arg(param, char *);
    break;
  case CURLOPT_FILE:
    /*
     * FILE pointer to write to. Or possibly
     * used as argument to the write callback.
     */
    data->set.out = va_arg(param, void *);
    break;
  case CURLOPT_FTPPORT:
    /*
     * Use FTP PORT, this also specifies which IP address to use
     */
    result = setstropt(&data->set.str[STRING_FTPPORT],
                       va_arg(param, char *));
    data->set.ftp_use_port = (NULL != data->set.str[STRING_FTPPORT]) ?
                             TRUE:FALSE;
    break;

  case CURLOPT_FTP_USE_EPRT:
    data->set.ftp_use_eprt = (0 != va_arg(param, long))?TRUE:FALSE;
    break;

  case CURLOPT_FTP_USE_EPSV:
    data->set.ftp_use_epsv = (0 != va_arg(param, long))?TRUE:FALSE;
    break;

  case CURLOPT_FTP_USE_PRET:
    data->set.ftp_use_pret = (0 != va_arg(param, long))?TRUE:FALSE;
    break;

  case CURLOPT_FTP_SSL_CCC:
    data->set.ftp_ccc = (curl_ftpccc)va_arg(param, long);
    break;

  case CURLOPT_FTP_SKIP_PASV_IP:
    /*
     * Enable or disable FTP_SKIP_PASV_IP, which will disable/enable the
     * bypass of the IP address in PASV responses.
     */
    data->set.ftp_skip_ip = (0 != va_arg(param, long))?TRUE:FALSE;
    break;

  case CURLOPT_INFILE:
    /*
     * FILE pointer to read the file to be uploaded from. Or possibly
     * used as argument to the read callback.
     */
    data->set.in = va_arg(param, void *);
    break;
  case CURLOPT_INFILESIZE:
    /*
     * If known, this should inform curl about the file size of the
     * to-be-uploaded file.
     */
    data->set.infilesize = va_arg(param, long);
    break;
  case CURLOPT_INFILESIZE_LARGE:
    /*
     * If known, this should inform curl about the file size of the
     * to-be-uploaded file.
     */
    data->set.infilesize = va_arg(param, curl_off_t);
    break;
  case CURLOPT_LOW_SPEED_LIMIT:
    /*
     * The low speed limit that if transfers are below this for
     * CURLOPT_LOW_SPEED_TIME, the transfer is aborted.
     */
    data->set.low_speed_limit=va_arg(param, long);
    break;
  case CURLOPT_MAX_SEND_SPEED_LARGE:
    /*
     * When transfer uploads are faster then CURLOPT_MAX_SEND_SPEED_LARGE
     * bytes per second the transfer is throttled..
     */
    data->set.max_send_speed=va_arg(param, curl_off_t);
    break;
  case CURLOPT_MAX_RECV_SPEED_LARGE:
    /*
     * When receiving data faster than CURLOPT_MAX_RECV_SPEED_LARGE bytes per
     * second the transfer is throttled..
     */
    data->set.max_recv_speed=va_arg(param, curl_off_t);
    break;
  case CURLOPT_LOW_SPEED_TIME:
    /*
     * The low speed time that if transfers are below the set
     * CURLOPT_LOW_SPEED_LIMIT during this time, the transfer is aborted.
     */
    data->set.low_speed_time=va_arg(param, long);
    break;
  case CURLOPT_URL:
    /*
     * The URL to fetch.
     */
    if(data->change.url_alloc) {
      /* the already set URL is allocated, free it first! */
      Curl_safefree(data->change.url);
      data->change.url_alloc = FALSE;
    }
    result = setstropt(&data->set.str[STRING_SET_URL],
                       va_arg(param, char *));
    data->change.url = data->set.str[STRING_SET_URL];
    break;
  case CURLOPT_PORT:
    /*
     * The port number to use when getting the URL
     */
    data->set.use_port = va_arg(param, long);
    break;
  case CURLOPT_TIMEOUT:
    /*
     * The maximum time you allow curl to use for a single transfer
     * operation.
     */
    data->set.timeout = va_arg(param, long) * 1000L;
    break;

  case CURLOPT_TIMEOUT_MS:
    data->set.timeout = va_arg(param, long);
    break;

  case CURLOPT_CONNECTTIMEOUT:
    /*
     * The maximum time you allow curl to use to connect.
     */
    data->set.connecttimeout = va_arg(param, long) * 1000L;
    break;

  case CURLOPT_CONNECTTIMEOUT_MS:
    data->set.connecttimeout = va_arg(param, long);
    break;

  case CURLOPT_ACCEPTTIMEOUT_MS:
    /*
     * The maximum time you allow curl to wait for server connect
     */
    data->set.accepttimeout = va_arg(param, long);
    break;

  case CURLOPT_USERPWD:
    /*
     * user:password;options to use in the operation
     */
    result = setstropt_userpwd(va_arg(param, char *),
                               &data->set.str[STRING_USERNAME],
                               &data->set.str[STRING_PASSWORD],
                               &data->set.str[STRING_OPTIONS]);
    break;
  case CURLOPT_USERNAME:
    /*
     * authentication user name to use in the operation
     */
    result = setstropt(&data->set.str[STRING_USERNAME],
                       va_arg(param, char *));
    break;
  case CURLOPT_PASSWORD:
    /*
     * authentication password to use in the operation
     */
    result = setstropt(&data->set.str[STRING_PASSWORD],
                       va_arg(param, char *));
    break;
  case CURLOPT_POSTQUOTE:
    /*
     * List of RAW FTP commands to use after a transfer
     */
    data->set.postquote = va_arg(param, struct curl_slist *);
    break;
  case CURLOPT_PREQUOTE:
    /*
     * List of RAW FTP commands to use prior to RETR (Wesley Laxton)
     */
    data->set.prequote = va_arg(param, struct curl_slist *);
    break;
  case CURLOPT_QUOTE:
    /*
     * List of RAW FTP commands to use before a transfer
     */
    data->set.quote = va_arg(param, struct curl_slist *);
    break;
  case CURLOPT_RESOLVE:
    /*
     * List of NAME:[address] names to populate the DNS cache with
     * Prefix the NAME with dash (-) to _remove_ the name from the cache.
     *
     * Names added with this API will remain in the cache until explicitly
     * removed or the handle is cleaned up.
     *
     * This API can remove any name from the DNS cache, but only entries
     * that aren't actually in use right now will be pruned immediately.
     */
    data->set.resolve = va_arg(param, struct curl_slist *);
    data->change.resolve = data->set.resolve;
    break;
  case CURLOPT_PROGRESSFUNCTION:
    /*
     * Progress callback function
     */
    data->set.fprogress = va_arg(param, curl_progress_callback);
    if(data->set.fprogress)
      data->progress.callback = TRUE; /* no longer internal */
    else
      data->progress.callback = FALSE; /* NULL enforces internal */

    break;
  case CURLOPT_PROGRESSDATA:
    /*
     * Custom client data to pass to the progress callback
     */
    data->set.progress_client = va_arg(param, void *);
    break;

#ifndef CURL_DISABLE_PROXY
  case CURLOPT_PROXYUSERPWD:
    /*
     * user:password needed to use the proxy
     */
    result = setstropt_userpwd(va_arg(param, char *),
                               &data->set.str[STRING_PROXYUSERNAME],
                               &data->set.str[STRING_PROXYPASSWORD], NULL);
    break;
  case CURLOPT_PROXYUSERNAME:
    /*
     * authentication user name to use in the operation
     */
    result = setstropt(&data->set.str[STRING_PROXYUSERNAME],
                       va_arg(param, char *));
    break;
  case CURLOPT_PROXYPASSWORD:
    /*
     * authentication password to use in the operation
     */
    result = setstropt(&data->set.str[STRING_PROXYPASSWORD],
                       va_arg(param, char *));
    break;
  case CURLOPT_NOPROXY:
    /*
     * proxy exception list
     */
    result = setstropt(&data->set.str[STRING_NOPROXY],
                       va_arg(param, char *));
    break;
#endif

  case CURLOPT_RANGE:
    /*
     * What range of the file you want to transfer
     */
    result = setstropt(&data->set.str[STRING_SET_RANGE],
                       va_arg(param, char *));
    break;
  case CURLOPT_RESUME_FROM:
    /*
     * Resume transfer at the give file position
     */
    data->set.set_resume_from = va_arg(param, long);
    break;
  case CURLOPT_RESUME_FROM_LARGE:
    /*
     * Resume transfer at the give file position
     */
    data->set.set_resume_from = va_arg(param, curl_off_t);
    break;
  case CURLOPT_DEBUGFUNCTION:
    /*
     * stderr write callback.
     */
    data->set.fdebug = va_arg(param, curl_debug_callback);
    /*
     * if the callback provided is NULL, it'll use the default callback
     */
    break;
  case CURLOPT_DEBUGDATA:
    /*
     * Set to a void * that should receive all error writes. This
     * defaults to CURLOPT_STDERR for normal operations.
     */
    data->set.debugdata = va_arg(param, void *);
    break;
  case CURLOPT_STDERR:
    /*
     * Set to a FILE * that should receive all error writes. This
     * defaults to stderr for normal operations.
     */
    data->set.err = va_arg(param, FILE *);
    if(!data->set.err)
      data->set.err = stderr;
    break;
  case CURLOPT_HEADERFUNCTION:
    /*
     * Set header write callback
     */
    data->set.fwrite_header = va_arg(param, curl_write_callback);
    break;
  case CURLOPT_WRITEFUNCTION:
    /*
     * Set data write callback
     */
    data->set.fwrite_func = va_arg(param, curl_write_callback);
    if(!data->set.fwrite_func) {
      data->set.is_fwrite_set = 0;
      /* When set to NULL, reset to our internal default function */
      data->set.fwrite_func = (curl_write_callback)fwrite;
    }
    else
      data->set.is_fwrite_set = 1;
    break;
  case CURLOPT_READFUNCTION:
    /*
     * Read data callback
     */
    data->set.fread_func = va_arg(param, curl_read_callback);
    if(!data->set.fread_func) {
      data->set.is_fread_set = 0;
      /* When set to NULL, reset to our internal default function */
      data->set.fread_func = (curl_read_callback)fread;
    }
    else
      data->set.is_fread_set = 1;
    break;
  case CURLOPT_SEEKFUNCTION:
    /*
     * Seek callback. Might be NULL.
     */
    data->set.seek_func = va_arg(param, curl_seek_callback);
    break;
  case CURLOPT_SEEKDATA:
    /*
     * Seek control callback. Might be NULL.
     */
    data->set.seek_client = va_arg(param, void *);
    break;
  case CURLOPT_CONV_FROM_NETWORK_FUNCTION:
    /*
     * "Convert from network encoding" callback
     */
    data->set.convfromnetwork = va_arg(param, curl_conv_callback);
    break;
  case CURLOPT_CONV_TO_NETWORK_FUNCTION:
    /*
     * "Convert to network encoding" callback
     */
    data->set.convtonetwork = va_arg(param, curl_conv_callback);
    break;
  case CURLOPT_CONV_FROM_UTF8_FUNCTION:
    /*
     * "Convert from UTF-8 encoding" callback
     */
    data->set.convfromutf8 = va_arg(param, curl_conv_callback);
    break;
  case CURLOPT_IOCTLFUNCTION:
    /*
     * I/O control callback. Might be NULL.
     */
    data->set.ioctl_func = va_arg(param, curl_ioctl_callback);
    break;
  case CURLOPT_IOCTLDATA:
    /*
     * I/O control data pointer. Might be NULL.
     */
    data->set.ioctl_client = va_arg(param, void *);
    break;
  case CURLOPT_SSLCERT:
    /*
     * String that holds file name of the SSL certificate to use
     */
    result = setstropt(&data->set.str[STRING_CERT],
                       va_arg(param, char *));
    break;
  case CURLOPT_SSLCERTTYPE:
    /*
     * String that holds file type of the SSL certificate to use
     */
    result = setstropt(&data->set.str[STRING_CERT_TYPE],
                       va_arg(param, char *));
    break;
  case CURLOPT_SSLKEY:
    /*
     * String that holds file name of the SSL key to use
     */
    result = setstropt(&data->set.str[STRING_KEY],
                       va_arg(param, char *));
    break;
  case CURLOPT_SSLKEYTYPE:
    /*
     * String that holds file type of the SSL key to use
     */
    result = setstropt(&data->set.str[STRING_KEY_TYPE],
                       va_arg(param, char *));
    break;
  case CURLOPT_KEYPASSWD:
    /*
     * String that holds the SSL or SSH private key password.
     */
    result = setstropt(&data->set.str[STRING_KEY_PASSWD],
                       va_arg(param, char *));
    break;
  case CURLOPT_SSLENGINE:
    /*
     * String that holds the SSL crypto engine.
     */
    argptr = va_arg(param, char *);
    if(argptr && argptr[0])
      result = Curl_ssl_set_engine(data, argptr);
    break;

  case CURLOPT_SSLENGINE_DEFAULT:
    /*
     * flag to set engine as default.
     */
    result = Curl_ssl_set_engine_default(data);
    break;
  case CURLOPT_CRLF:
    /*
     * Kludgy option to enable CRLF conversions. Subject for removal.
     */
    data->set.crlf = (0 != va_arg(param, long))?TRUE:FALSE;
    break;

  case CURLOPT_INTERFACE:
    /*
     * Set what interface or address/hostname to bind the socket to when
     * performing an operation and thus what from-IP your connection will use.
     */
    result = setstropt(&data->set.str[STRING_DEVICE],
                       va_arg(param, char *));
    break;
  case CURLOPT_LOCALPORT:
    /*
     * Set what local port to bind the socket to when performing an operation.
     */
    data->set.localport = curlx_sltous(va_arg(param, long));
    break;
  case CURLOPT_LOCALPORTRANGE:
    /*
     * Set number of local ports to try, starting with CURLOPT_LOCALPORT.
     */
    data->set.localportrange = curlx_sltosi(va_arg(param, long));
    break;
  case CURLOPT_KRBLEVEL:
    /*
     * A string that defines the kerberos security level.
     */
    result = setstropt(&data->set.str[STRING_KRB_LEVEL],
                       va_arg(param, char *));
    data->set.krb = (NULL != data->set.str[STRING_KRB_LEVEL])?TRUE:FALSE;
    break;
  case CURLOPT_GSSAPI_DELEGATION:
    /*
     * GSSAPI credential delegation
     */
    data->set.gssapi_delegation = va_arg(param, long);
    break;
  case CURLOPT_SSL_VERIFYPEER:
    /*
     * Enable peer SSL verifying.
     */
    data->set.ssl.verifypeer = (0 != va_arg(param, long))?TRUE:FALSE;
    break;
  case CURLOPT_SSL_VERIFYHOST:
    /*
     * Enable verification of the host name in the peer certificate
     */
    arg = va_arg(param, long);

    /* Obviously people are not reading documentation and too many thought
       this argument took a boolean when it wasn't and misused it. We thus ban
       1 as a sensible input and we warn about its use. Then we only have the
       2 action internally stored as TRUE. */

    if(1 == arg) {
      failf(data, "CURLOPT_SSL_VERIFYHOST no longer supports 1 as value!");
      return CURLE_BAD_FUNCTION_ARGUMENT;
    }

    data->set.ssl.verifyhost = (0 != arg)?TRUE:FALSE;
    break;
#ifdef USE_SSLEAY
    /* since these two options are only possible to use on an OpenSSL-
       powered libcurl we #ifdef them on this condition so that libcurls
       built against other SSL libs will return a proper error when trying
       to set this option! */
  case CURLOPT_SSL_CTX_FUNCTION:
    /*
     * Set a SSL_CTX callback
     */
    data->set.ssl.fsslctx = va_arg(param, curl_ssl_ctx_callback);
    break;
  case CURLOPT_SSL_CTX_DATA:
    /*
     * Set a SSL_CTX callback parameter pointer
     */
    data->set.ssl.fsslctxp = va_arg(param, void *);
    break;
  case CURLOPT_CERTINFO:
    data->set.ssl.certinfo = (0 != va_arg(param, long))?TRUE:FALSE;
    break;
#endif
  case CURLOPT_CAINFO:
    /*
     * Set CA info for SSL connection. Specify file name of the CA certificate
     */
    result = setstropt(&data->set.str[STRING_SSL_CAFILE],
                       va_arg(param, char *));
    break;
  case CURLOPT_CAPATH:
    /*
     * Set CA path info for SSL connection. Specify directory name of the CA
     * certificates which have been prepared using openssl c_rehash utility.
     */
    /* This does not work on windows. */
    result = setstropt(&data->set.str[STRING_SSL_CAPATH],
                       va_arg(param, char *));
    break;
  case CURLOPT_CRLFILE:
    /*
     * Set CRL file info for SSL connection. Specify file name of the CRL
     * to check certificates revocation
     */
    result = setstropt(&data->set.str[STRING_SSL_CRLFILE],
                       va_arg(param, char *));
    break;
  case CURLOPT_ISSUERCERT:
    /*
     * Set Issuer certificate file
     * to check certificates issuer
     */
    result = setstropt(&data->set.str[STRING_SSL_ISSUERCERT],
                       va_arg(param, char *));
    break;
  case CURLOPT_TELNETOPTIONS:
    /*
     * Set a linked list of telnet options
     */
    data->set.telnet_options = va_arg(param, struct curl_slist *);
    break;

  case CURLOPT_BUFFERSIZE:
    /*
     * The application kindly asks for a differently sized receive buffer.
     * If it seems reasonable, we'll use it.
     */
    data->set.buffer_size = va_arg(param, long);

    if((data->set.buffer_size> (BUFSIZE -1 )) ||
       (data->set.buffer_size < 1))
      data->set.buffer_size = 0; /* huge internal default */

    break;

  case CURLOPT_NOSIGNAL:
    /*
     * The application asks not to set any signal() or alarm() handlers,
     * even when using a timeout.
     */
    data->set.no_signal = (0 != va_arg(param, long))?TRUE:FALSE;
    break;

  case CURLOPT_SHARE:
  {
    struct Curl_share *set;
    set = va_arg(param, struct Curl_share *);

    /* disconnect from old share, if any */
    if(data->share) {
      Curl_share_lock(data, CURL_LOCK_DATA_SHARE, CURL_LOCK_ACCESS_SINGLE);

      if(data->dns.hostcachetype == HCACHE_SHARED) {
        data->dns.hostcache = NULL;
        data->dns.hostcachetype = HCACHE_NONE;
      }

#if !defined(CURL_DISABLE_HTTP) && !defined(CURL_DISABLE_COOKIES)
      if(data->share->cookies == data->cookies)
        data->cookies = NULL;
#endif

      if(data->share->sslsession == data->state.session)
        data->state.session = NULL;

      data->share->dirty--;

      Curl_share_unlock(data, CURL_LOCK_DATA_SHARE);
      data->share = NULL;
    }

    /* use new share if it set */
    data->share = set;
    if(data->share) {

      Curl_share_lock(data, CURL_LOCK_DATA_SHARE, CURL_LOCK_ACCESS_SINGLE);

      data->share->dirty++;

      if(data->share->hostcache) {
        /* use shared host cache */
        data->dns.hostcache = data->share->hostcache;
        data->dns.hostcachetype = HCACHE_SHARED;
      }
#if !defined(CURL_DISABLE_HTTP) && !defined(CURL_DISABLE_COOKIES)
      if(data->share->cookies) {
        /* use shared cookie list, first free own one if any */
        if(data->cookies)
          Curl_cookie_cleanup(data->cookies);
        /* enable cookies since we now use a share that uses cookies! */
        data->cookies = data->share->cookies;
      }
#endif   /* CURL_DISABLE_HTTP */
      if(data->share->sslsession) {
        data->set.ssl.max_ssl_sessions = data->share->max_ssl_sessions;
        data->state.session = data->share->sslsession;
      }
      Curl_share_unlock(data, CURL_LOCK_DATA_SHARE);

    }
    /* check for host cache not needed,
     * it will be done by curl_easy_perform */
  }
  break;

  case CURLOPT_PRIVATE:
    /*
     * Set private data pointer.
     */
    data->set.private_data = va_arg(param, void *);
    break;

  case CURLOPT_MAXFILESIZE:
    /*
     * Set the maximum size of a file to download.
     */
    data->set.max_filesize = va_arg(param, long);
    break;

#ifdef USE_SSL
  case CURLOPT_USE_SSL:
    /*
     * Make transfers attempt to use SSL/TLS.
     */
    data->set.use_ssl = (curl_usessl)va_arg(param, long);
    break;

  case CURLOPT_SSL_OPTIONS:
    arg = va_arg(param, long);
    data->set.ssl_enable_beast = arg&CURLSSLOPT_ALLOW_BEAST?TRUE:FALSE;
    break;

#endif
  case CURLOPT_FTPSSLAUTH:
    /*
     * Set a specific auth for FTP-SSL transfers.
     */
    data->set.ftpsslauth = (curl_ftpauth)va_arg(param, long);
    break;

  case CURLOPT_IPRESOLVE:
    data->set.ipver = va_arg(param, long);
    break;

  case CURLOPT_MAXFILESIZE_LARGE:
    /*
     * Set the maximum size of a file to download.
     */
    data->set.max_filesize = va_arg(param, curl_off_t);
    break;

  case CURLOPT_TCP_NODELAY:
    /*
     * Enable or disable TCP_NODELAY, which will disable/enable the Nagle
     * algorithm
     */
    data->set.tcp_nodelay = (0 != va_arg(param, long))?TRUE:FALSE;
    break;

  case CURLOPT_FTP_ACCOUNT:
    result = setstropt(&data->set.str[STRING_FTP_ACCOUNT],
                       va_arg(param, char *));
    break;

  case CURLOPT_IGNORE_CONTENT_LENGTH:
    data->set.ignorecl = (0 != va_arg(param, long))?TRUE:FALSE;
    break;

  case CURLOPT_CONNECT_ONLY:
    /*
     * No data transfer, set up connection and let application use the socket
     */
    data->set.connect_only = (0 != va_arg(param, long))?TRUE:FALSE;
    break;

  case CURLOPT_FTP_ALTERNATIVE_TO_USER:
    result = setstropt(&data->set.str[STRING_FTP_ALTERNATIVE_TO_USER],
                       va_arg(param, char *));
    break;

  case CURLOPT_SOCKOPTFUNCTION:
    /*
     * socket callback function: called after socket() but before connect()
     */
    data->set.fsockopt = va_arg(param, curl_sockopt_callback);
    break;

  case CURLOPT_SOCKOPTDATA:
    /*
     * socket callback data pointer. Might be NULL.
     */
    data->set.sockopt_client = va_arg(param, void *);
    break;

  case CURLOPT_OPENSOCKETFUNCTION:
    /*
     * open/create socket callback function: called instead of socket(),
     * before connect()
     */
    data->set.fopensocket = va_arg(param, curl_opensocket_callback);
    break;

  case CURLOPT_OPENSOCKETDATA:
    /*
     * socket callback data pointer. Might be NULL.
     */
    data->set.opensocket_client = va_arg(param, void *);
    break;

  case CURLOPT_CLOSESOCKETFUNCTION:
    /*
     * close socket callback function: called instead of close()
     * when shutting down a connection
     */
    data->set.fclosesocket = va_arg(param, curl_closesocket_callback);
    break;

  case CURLOPT_CLOSESOCKETDATA:
    /*
     * socket callback data pointer. Might be NULL.
     */
    data->set.closesocket_client = va_arg(param, void *);
    break;

  case CURLOPT_SSL_SESSIONID_CACHE:
    data->set.ssl.sessionid = (0 != va_arg(param, long))?TRUE:FALSE;
    break;

#ifdef USE_LIBSSH2
    /* we only include SSH options if explicitly built to support SSH */
  case CURLOPT_SSH_AUTH_TYPES:
    data->set.ssh_auth_types = va_arg(param, long);
    break;

  case CURLOPT_SSH_PUBLIC_KEYFILE:
    /*
     * Use this file instead of the $HOME/.ssh/id_dsa.pub file
     */
    result = setstropt(&data->set.str[STRING_SSH_PUBLIC_KEY],
                       va_arg(param, char *));
    break;

  case CURLOPT_SSH_PRIVATE_KEYFILE:
    /*
     * Use this file instead of the $HOME/.ssh/id_dsa file
     */
    result = setstropt(&data->set.str[STRING_SSH_PRIVATE_KEY],
                       va_arg(param, char *));
    break;
  case CURLOPT_SSH_HOST_PUBLIC_KEY_MD5:
    /*
     * Option to allow for the MD5 of the host public key to be checked
     * for validation purposes.
     */
    result = setstropt(&data->set.str[STRING_SSH_HOST_PUBLIC_KEY_MD5],
                       va_arg(param, char *));
    break;
#ifdef HAVE_LIBSSH2_KNOWNHOST_API
  case CURLOPT_SSH_KNOWNHOSTS:
    /*
     * Store the file name to read known hosts from.
     */
    result = setstropt(&data->set.str[STRING_SSH_KNOWNHOSTS],
                       va_arg(param, char *));
    break;

  case CURLOPT_SSH_KEYFUNCTION:
    /* setting to NULL is fine since the ssh.c functions themselves will
       then rever to use the internal default */
    data->set.ssh_keyfunc = va_arg(param, curl_sshkeycallback);
    break;

  case CURLOPT_SSH_KEYDATA:
    /*
     * Custom client data to pass to the SSH keyfunc callback
     */
    data->set.ssh_keyfunc_userp = va_arg(param, void *);
    break;
#endif /* HAVE_LIBSSH2_KNOWNHOST_API */

#endif /* USE_LIBSSH2 */

  case CURLOPT_HTTP_TRANSFER_DECODING:
    /*
     * disable libcurl transfer encoding is used
     */
    data->set.http_te_skip = (0 == va_arg(param, long))?TRUE:FALSE;
    break;

  case CURLOPT_HTTP_CONTENT_DECODING:
    /*
     * raw data passed to the application when content encoding is used
     */
    data->set.http_ce_skip = (0 == va_arg(param, long))?TRUE:FALSE;
    break;

  case CURLOPT_NEW_FILE_PERMS:
    /*
     * Uses these permissions instead of 0644
     */
    data->set.new_file_perms = va_arg(param, long);
    break;

  case CURLOPT_NEW_DIRECTORY_PERMS:
    /*
     * Uses these permissions instead of 0755
     */
    data->set.new_directory_perms = va_arg(param, long);
    break;

  case CURLOPT_ADDRESS_SCOPE:
    /*
     * We always get longs when passed plain numericals, but for this value we
     * know that an unsigned int will always hold the value so we blindly
     * typecast to this type
     */
    data->set.scope = curlx_sltoui(va_arg(param, long));
    break;

  case CURLOPT_PROTOCOLS:
    /* set the bitmask for the protocols that are allowed to be used for the
       transfer, which thus helps the app which takes URLs from users or other
       external inputs and want to restrict what protocol(s) to deal
       with. Defaults to CURLPROTO_ALL. */
    data->set.allowed_protocols = va_arg(param, long);
    break;

  case CURLOPT_REDIR_PROTOCOLS:
    /* set the bitmask for the protocols that libcurl is allowed to follow to,
       as a subset of the CURLOPT_PROTOCOLS ones. That means the protocol needs
       to be set in both bitmasks to be allowed to get redirected to. Defaults
       to all protocols except FILE and SCP. */
    data->set.redir_protocols = va_arg(param, long);
    break;

  case CURLOPT_MAIL_FROM:
    result = setstropt(&data->set.str[STRING_MAIL_FROM],
                       va_arg(param, char *));
    break;

  case CURLOPT_MAIL_AUTH:
    result = setstropt(&data->set.str[STRING_MAIL_AUTH],
                       va_arg(param, char *));
    break;

  case CURLOPT_MAIL_RCPT:
    /* get a list of mail recipients */
    data->set.mail_rcpt = va_arg(param, struct curl_slist *);
    break;

  case CURLOPT_RTSP_REQUEST:
    {
      /*
       * Set the RTSP request method (OPTIONS, SETUP, PLAY, etc...)
       * Would this be better if the RTSPREQ_* were just moved into here?
       */
      long curl_rtspreq = va_arg(param, long);
      Curl_RtspReq rtspreq = RTSPREQ_NONE;
      switch(curl_rtspreq) {
        case CURL_RTSPREQ_OPTIONS:
          rtspreq = RTSPREQ_OPTIONS;
          break;

        case CURL_RTSPREQ_DESCRIBE:
          rtspreq = RTSPREQ_DESCRIBE;
          break;

        case CURL_RTSPREQ_ANNOUNCE:
          rtspreq = RTSPREQ_ANNOUNCE;
          break;

        case CURL_RTSPREQ_SETUP:
          rtspreq = RTSPREQ_SETUP;
          break;

        case CURL_RTSPREQ_PLAY:
          rtspreq = RTSPREQ_PLAY;
          break;

        case CURL_RTSPREQ_PAUSE:
          rtspreq = RTSPREQ_PAUSE;
          break;

        case CURL_RTSPREQ_TEARDOWN:
          rtspreq = RTSPREQ_TEARDOWN;
          break;

        case CURL_RTSPREQ_GET_PARAMETER:
          rtspreq = RTSPREQ_GET_PARAMETER;
          break;

        case CURL_RTSPREQ_SET_PARAMETER:
          rtspreq = RTSPREQ_SET_PARAMETER;
          break;

        case CURL_RTSPREQ_RECORD:
          rtspreq = RTSPREQ_RECORD;
          break;

        case CURL_RTSPREQ_RECEIVE:
          rtspreq = RTSPREQ_RECEIVE;
          break;
        default:
          rtspreq = RTSPREQ_NONE;
      }

      data->set.rtspreq = rtspreq;
    break;
    }


  case CURLOPT_RTSP_SESSION_ID:
    /*
     * Set the RTSP Session ID manually. Useful if the application is
     * resuming a previously established RTSP session
     */
    result = setstropt(&data->set.str[STRING_RTSP_SESSION_ID],
                       va_arg(param, char *));
    break;

  case CURLOPT_RTSP_STREAM_URI:
    /*
     * Set the Stream URI for the RTSP request. Unless the request is
     * for generic server options, the application will need to set this.
     */
    result = setstropt(&data->set.str[STRING_RTSP_STREAM_URI],
                       va_arg(param, char *));
    break;

  case CURLOPT_RTSP_TRANSPORT:
    /*
     * The content of the Transport: header for the RTSP request
     */
    result = setstropt(&data->set.str[STRING_RTSP_TRANSPORT],
                       va_arg(param, char *));
    break;

  case CURLOPT_RTSP_CLIENT_CSEQ:
    /*
     * Set the CSEQ number to issue for the next RTSP request. Useful if the
     * application is resuming a previously broken connection. The CSEQ
     * will increment from this new number henceforth.
     */
    data->state.rtsp_next_client_CSeq = va_arg(param, long);
    break;

  case CURLOPT_RTSP_SERVER_CSEQ:
    /* Same as the above, but for server-initiated requests */
    data->state.rtsp_next_client_CSeq = va_arg(param, long);
    break;

  case CURLOPT_INTERLEAVEDATA:
    data->set.rtp_out = va_arg(param, void *);
    break;
  case CURLOPT_INTERLEAVEFUNCTION:
    /* Set the user defined RTP write function */
    data->set.fwrite_rtp = va_arg(param, curl_write_callback);
    break;

  case CURLOPT_WILDCARDMATCH:
    data->set.wildcardmatch = (0 != va_arg(param, long))?TRUE:FALSE;
    break;
  case CURLOPT_CHUNK_BGN_FUNCTION:
    data->set.chunk_bgn = va_arg(param, curl_chunk_bgn_callback);
    break;
  case CURLOPT_CHUNK_END_FUNCTION:
    data->set.chunk_end = va_arg(param, curl_chunk_end_callback);
    break;
  case CURLOPT_FNMATCH_FUNCTION:
    data->set.fnmatch = va_arg(param, curl_fnmatch_callback);
    break;
  case CURLOPT_CHUNK_DATA:
    data->wildcard.customptr = va_arg(param, void *);
    break;
  case CURLOPT_FNMATCH_DATA:
    data->set.fnmatch_data = va_arg(param, void *);
    break;
#ifdef USE_TLS_SRP
  case CURLOPT_TLSAUTH_USERNAME:
    result = setstropt(&data->set.str[STRING_TLSAUTH_USERNAME],
                       va_arg(param, char *));
    if(data->set.str[STRING_TLSAUTH_USERNAME] && !data->set.ssl.authtype)
      data->set.ssl.authtype = CURL_TLSAUTH_SRP; /* default to SRP */
    break;
  case CURLOPT_TLSAUTH_PASSWORD:
    result = setstropt(&data->set.str[STRING_TLSAUTH_PASSWORD],
                       va_arg(param, char *));
    if(data->set.str[STRING_TLSAUTH_USERNAME] && !data->set.ssl.authtype)
      data->set.ssl.authtype = CURL_TLSAUTH_SRP; /* default to SRP */
    break;
  case CURLOPT_TLSAUTH_TYPE:
    if(strnequal((char *)va_arg(param, char *), "SRP", strlen("SRP")))
      data->set.ssl.authtype = CURL_TLSAUTH_SRP;
    else
      data->set.ssl.authtype = CURL_TLSAUTH_NONE;
    break;
#endif
  case CURLOPT_DNS_SERVERS:
    result = Curl_set_dns_servers(data, va_arg(param, char *));
    break;

  case CURLOPT_TCP_KEEPALIVE:
    data->set.tcp_keepalive = (0 != va_arg(param, long))?TRUE:FALSE;
    break;
  case CURLOPT_TCP_KEEPIDLE:
    data->set.tcp_keepidle = va_arg(param, long);
    break;
  case CURLOPT_TCP_KEEPINTVL:
    data->set.tcp_keepintvl = va_arg(param, long);
    break;

  default:
    /* unknown tag and its companion, just ignore: */
    result = CURLE_UNKNOWN_OPTION;
    break;
  }

  return result;
}

static void conn_free(struct connectdata *conn)
{
  if(!conn)
    return;

  /* possible left-overs from the async name resolvers */
  Curl_resolver_cancel(conn);

  /* close the SSL stuff before we close any sockets since they will/may
     write to the sockets */
  Curl_ssl_close(conn, FIRSTSOCKET);
  Curl_ssl_close(conn, SECONDARYSOCKET);

  /* close possibly still open sockets */
  if(CURL_SOCKET_BAD != conn->sock[SECONDARYSOCKET])
    Curl_closesocket(conn, conn->sock[SECONDARYSOCKET]);
  if(CURL_SOCKET_BAD != conn->sock[FIRSTSOCKET])
    Curl_closesocket(conn, conn->sock[FIRSTSOCKET]);

#if defined(USE_NTLM) && defined(NTLM_WB_ENABLED)
  Curl_ntlm_wb_cleanup(conn);
#endif

  Curl_safefree(conn->user);
  Curl_safefree(conn->passwd);
  Curl_safefree(conn->options);
  Curl_safefree(conn->proxyuser);
  Curl_safefree(conn->proxypasswd);
  Curl_safefree(conn->allocptr.proxyuserpwd);
  Curl_safefree(conn->allocptr.uagent);
  Curl_safefree(conn->allocptr.userpwd);
  Curl_safefree(conn->allocptr.accept_encoding);
  Curl_safefree(conn->allocptr.te);
  Curl_safefree(conn->allocptr.rangeline);
  Curl_safefree(conn->allocptr.ref);
  Curl_safefree(conn->allocptr.host);
  Curl_safefree(conn->allocptr.cookiehost);
  Curl_safefree(conn->allocptr.rtsp_transport);
  Curl_safefree(conn->trailer);
  Curl_safefree(conn->host.rawalloc); /* host name buffer */
  Curl_safefree(conn->proxy.rawalloc); /* proxy name buffer */
  Curl_safefree(conn->master_buffer);

  Curl_llist_destroy(conn->send_pipe, NULL);
  Curl_llist_destroy(conn->recv_pipe, NULL);

  conn->send_pipe = NULL;
  conn->recv_pipe = NULL;

  Curl_safefree(conn->localdev);
  Curl_free_ssl_config(&conn->ssl_config);

  free(conn); /* free all the connection oriented data */
}

CURLcode Curl_disconnect(struct connectdata *conn, bool dead_connection)
{
  struct SessionHandle *data;
  if(!conn)
    return CURLE_OK; /* this is closed and fine already */
  data = conn->data;

  if(!data) {
    DEBUGF(fprintf(stderr, "DISCONNECT without easy handle, ignoring\n"));
    return CURLE_OK;
  }

  if(conn->dns_entry != NULL) {
    Curl_resolv_unlock(data, conn->dns_entry);
    conn->dns_entry = NULL;
  }

  Curl_hostcache_prune(data); /* kill old DNS cache entries */

  {
    int has_host_ntlm = (conn->ntlm.state != NTLMSTATE_NONE);
    int has_proxy_ntlm = (conn->proxyntlm.state != NTLMSTATE_NONE);

    /* Authentication data is a mix of connection-related and sessionhandle-
       related stuff. NTLM is connection-related so when we close the shop
       we shall forget. */

    if(has_host_ntlm) {
      data->state.authhost.done = FALSE;
      data->state.authhost.picked =
        data->state.authhost.want;
    }

    if(has_proxy_ntlm) {
      data->state.authproxy.done = FALSE;
      data->state.authproxy.picked =
        data->state.authproxy.want;
    }

    if(has_host_ntlm || has_proxy_ntlm)
      data->state.authproblem = FALSE;
  }

  /* Cleanup NTLM connection-related data */
  Curl_http_ntlm_cleanup(conn);

  /* Cleanup possible redirect junk */
  if(data->req.newurl) {
    free(data->req.newurl);
    data->req.newurl = NULL;
  }

  if(conn->handler->disconnect)
    /* This is set if protocol-specific cleanups should be made */
    conn->handler->disconnect(conn, dead_connection);

    /* unlink ourselves! */
  infof(data, "Closing connection %d\n", conn->connection_id);
  Curl_conncache_remove_conn(data->state.conn_cache, conn);

#if defined(USE_LIBIDN)
  if(conn->host.encalloc)
    idn_free(conn->host.encalloc); /* encoded host name buffer, must be freed
                                      with idn_free() since this was allocated
                                      by libidn */
  if(conn->proxy.encalloc)
    idn_free(conn->proxy.encalloc); /* encoded proxy name buffer, must be
                                       freed with idn_free() since this was
                                       allocated by libidn */
#elif defined(USE_WIN32_IDN)
  free(conn->host.encalloc); /* encoded host name buffer, must be freed with
                                idn_free() since this was allocated by
                                curl_win32_idn_to_ascii */
  if(conn->proxy.encalloc)
    free(conn->proxy.encalloc); /* encoded proxy name buffer, must be freed
                                   with idn_free() since this was allocated by
                                   curl_win32_idn_to_ascii */
#endif

  Curl_ssl_close(conn, FIRSTSOCKET);

  /* Indicate to all handles on the pipe that we're dead */
  if(Curl_multi_pipeline_enabled(data->multi)) {
    signalPipeClose(conn->send_pipe, TRUE);
    signalPipeClose(conn->recv_pipe, TRUE);
  }

  conn_free(conn);
  data->state.current_conn = NULL;
  Curl_speedinit(data);

  return CURLE_OK;
}

/*
 * This function should return TRUE if the socket is to be assumed to
 * be dead. Most commonly this happens when the server has closed the
 * connection due to inactivity.
 */
static bool SocketIsDead(curl_socket_t sock)
{
  int sval;
  bool ret_val = TRUE;

  sval = Curl_socket_ready(sock, CURL_SOCKET_BAD, 0);
  if(sval == 0)
    /* timeout */
    ret_val = FALSE;

  return ret_val;
}

static bool IsPipeliningPossible(const struct SessionHandle *handle,
                                 const struct connectdata *conn)
{
  if((conn->handler->protocol & CURLPROTO_HTTP) &&
     Curl_multi_pipeline_enabled(handle->multi) &&
     (handle->set.httpreq == HTTPREQ_GET ||
      handle->set.httpreq == HTTPREQ_HEAD) &&
     handle->set.httpversion != CURL_HTTP_VERSION_1_0)
    return TRUE;

  return FALSE;
}

bool Curl_isPipeliningEnabled(const struct SessionHandle *handle)
{
  return Curl_multi_pipeline_enabled(handle->multi);
}

CURLcode Curl_addHandleToPipeline(struct SessionHandle *data,
                                  struct curl_llist *pipeline)
{
  if(!Curl_llist_insert_next(pipeline, pipeline->tail, data))
    return CURLE_OUT_OF_MEMORY;
  infof(data, "Curl_addHandleToPipeline: length: %d\n", pipeline->size);
  return CURLE_OK;
}

int Curl_removeHandleFromPipeline(struct SessionHandle *handle,
                                  struct curl_llist *pipeline)
{
  struct curl_llist_element *curr;

  curr = pipeline->head;
  while(curr) {
    if(curr->ptr == handle) {
      Curl_llist_remove(pipeline, curr, NULL);
      return 1; /* we removed a handle */
    }
    curr = curr->next;
  }

  return 0;
}

#if 0 /* this code is saved here as it is useful for debugging purposes */
static void Curl_printPipeline(struct curl_llist *pipeline)
{
  struct curl_llist_element *curr;

  curr = pipeline->head;
  while(curr) {
    struct SessionHandle *data = (struct SessionHandle *) curr->ptr;
    infof(data, "Handle in pipeline: %s\n", data->state.path);
    curr = curr->next;
  }
}
#endif

static struct SessionHandle* gethandleathead(struct curl_llist *pipeline)
{
  struct curl_llist_element *curr = pipeline->head;
  if(curr) {
    return (struct SessionHandle *) curr->ptr;
  }

  return NULL;
}

/* remove the specified connection from all (possible) pipelines and related
   queues */
void Curl_getoff_all_pipelines(struct SessionHandle *data,
                               struct connectdata *conn)
{
  bool recv_head = (conn->readchannel_inuse &&
    (gethandleathead(conn->recv_pipe) == data)) ? TRUE : FALSE;

  bool send_head = (conn->writechannel_inuse &&
    (gethandleathead(conn->send_pipe) == data)) ? TRUE : FALSE;

  if(Curl_removeHandleFromPipeline(data, conn->recv_pipe) && recv_head)
    conn->readchannel_inuse = FALSE;
  if(Curl_removeHandleFromPipeline(data, conn->send_pipe) && send_head)
    conn->writechannel_inuse = FALSE;
}

static void signalPipeClose(struct curl_llist *pipeline, bool pipe_broke)
{
  struct curl_llist_element *curr;

  if(!pipeline)
    return;

  curr = pipeline->head;
  while(curr) {
    struct curl_llist_element *next = curr->next;
    struct SessionHandle *data = (struct SessionHandle *) curr->ptr;

#ifdef DEBUGBUILD /* debug-only code */
    if(data->magic != CURLEASY_MAGIC_NUMBER) {
      /* MAJOR BADNESS */
      infof(data, "signalPipeClose() found BAAD easy handle\n");
    }
#endif

    if(pipe_broke)
      data->state.pipe_broke = TRUE;
    Curl_multi_handlePipeBreak(data);
    Curl_llist_remove(pipeline, curr, NULL);
    curr = next;
  }
}

/*
 * This function finds the connection in the connection
 * cache that has been unused for the longest time.
 *
 * Returns the pointer to the oldest idle connection, or NULL if none was
 * found.
 */
static struct connectdata *
find_oldest_idle_connection(struct SessionHandle *data)
{
  struct conncache *bc = data->state.conn_cache;
  struct curl_hash_iterator iter;
  struct curl_llist_element *curr;
  struct curl_hash_element *he;
  long highscore=-1;
  long score;
  struct timeval now;
  struct connectdata *conn_candidate = NULL;
  struct connectbundle *bundle;

  now = Curl_tvnow();

  Curl_hash_start_iterate(bc->hash, &iter);

  he = Curl_hash_next_element(&iter);
  while(he) {
    struct connectdata *conn;

    bundle = he->ptr;

    curr = bundle->conn_list->head;
    while(curr) {
      conn = curr->ptr;

      if(!conn->inuse) {
        /* Set higher score for the age passed since the connection was used */
        score = Curl_tvdiff(now, conn->now);

        if(score > highscore) {
          highscore = score;
          conn_candidate = conn;
        }
      }
      curr = curr->next;
    }

    he = Curl_hash_next_element(&iter);
  }

  return conn_candidate;
}

/*
 * This function finds the connection in the connection
 * bundle that has been unused for the longest time.
 *
 * Returns the pointer to the oldest idle connection, or NULL if none was
 * found.
 */
static struct connectdata *
find_oldest_idle_connection_in_bundle(struct SessionHandle *data,
                                      struct connectbundle *bundle)
{
  struct curl_llist_element *curr;
  long highscore=-1;
  long score;
  struct timeval now;
  struct connectdata *conn_candidate = NULL;
  struct connectdata *conn;

  (void)data;

  now = Curl_tvnow();

  curr = bundle->conn_list->head;
  while(curr) {
    conn = curr->ptr;

    if(!conn->inuse) {
      /* Set higher score for the age passed since the connection was used */
      score = Curl_tvdiff(now, conn->now);

      if(score > highscore) {
        highscore = score;
        conn_candidate = conn;
      }
    }
    curr = curr->next;
  }

  return conn_candidate;
}

/*
 * Given one filled in connection struct (named needle), this function should
 * detect if there already is one that has all the significant details
 * exactly the same and thus should be used instead.
 *
 * If there is a match, this function returns TRUE - and has marked the
 * connection as 'in-use'. It must later be called with ConnectionDone() to
 * return back to 'idle' (unused) state.
 *
 * The force_reuse flag is set if the connection must be used, even if
 * the pipelining strategy wants to open a new connection instead of reusing.
 */
static bool
ConnectionExists(struct SessionHandle *data,
                 struct connectdata *needle,
                 struct connectdata **usethis,
                 bool *force_reuse)
{
  struct connectdata *check;
  struct connectdata *chosen = 0;
  bool canPipeline = IsPipeliningPossible(data, needle);
  bool wantNTLM = (data->state.authhost.want==CURLAUTH_NTLM) ||
                  (data->state.authhost.want==CURLAUTH_NTLM_WB) ? TRUE : FALSE;
  struct connectbundle *bundle;

  *force_reuse = FALSE;

  /* We can't pipe if the site is blacklisted */
  if(canPipeline && Curl_pipeline_site_blacklisted(data, needle)) {
    canPipeline = FALSE;
  }

  /* Look up the bundle with all the connections to this
     particular host */
  bundle = Curl_conncache_find_bundle(data->state.conn_cache,
                                      needle->host.name);
  if(bundle) {
    size_t max_pipe_len = Curl_multi_max_pipeline_length(data->multi);
    size_t best_pipe_len = max_pipe_len;
    struct curl_llist_element *curr;

    infof(data, "Found bundle for host %s: %p\n", needle->host.name, bundle);

    /* We can't pipe if we don't know anything about the server */
    if(canPipeline && !bundle->server_supports_pipelining) {
      infof(data, "Server doesn't support pipelining\n");
      canPipeline = FALSE;
    }

    curr = bundle->conn_list->head;
    while(curr) {
      bool match = FALSE;
      bool credentialsMatch = FALSE;
      size_t pipeLen;

      /*
       * Note that if we use a HTTP proxy, we check connections to that
       * proxy and not to the actual remote server.
       */
      check = curr->ptr;
      curr = curr->next;

      pipeLen = check->send_pipe->size + check->recv_pipe->size;

      if(!pipeLen && !check->inuse) {
        /* The check for a dead socket makes sense only if there are no
           handles in pipeline and the connection isn't already marked in
           use */
        bool dead;
        if(check->handler->protocol & CURLPROTO_RTSP)
          /* RTSP is a special case due to RTP interleaving */
          dead = Curl_rtsp_connisdead(check);
        else
          dead = SocketIsDead(check->sock[FIRSTSOCKET]);

        if(dead) {
          check->data = data;
          infof(data, "Connection %d seems to be dead!\n",
                check->connection_id);

          /* disconnect resources */
          Curl_disconnect(check, /* dead_connection */ TRUE);
          continue;
        }
      }

      if(canPipeline) {
        /* Make sure the pipe has only GET requests */
        struct SessionHandle* sh = gethandleathead(check->send_pipe);
        struct SessionHandle* rh = gethandleathead(check->recv_pipe);
        if(sh) {
          if(!IsPipeliningPossible(sh, check))
            continue;
        }
        else if(rh) {
          if(!IsPipeliningPossible(rh, check))
            continue;
        }
      }
      else {
        if(pipeLen > 0) {
          /* can only happen within multi handles, and means that another easy
             handle is using this connection */
          continue;
        }

        if(Curl_resolver_asynch()) {
          /* ip_addr_str[0] is NUL only if the resolving of the name hasn't
             completed yet and until then we don't re-use this connection */
          if(!check->ip_addr_str[0]) {
            infof(data,
                  "Connection #%ld is still name resolving, can't reuse\n",
                  check->connection_id);
            continue;
          }
        }

        if((check->sock[FIRSTSOCKET] == CURL_SOCKET_BAD) ||
           check->bits.close) {
          /* Don't pick a connection that hasn't connected yet or that is going
             to get closed. */
          infof(data, "Connection #%ld isn't open enough, can't reuse\n",
                check->connection_id);
#ifdef DEBUGBUILD
          if(check->recv_pipe->size > 0) {
            infof(data,
                  "BAD! Unconnected #%ld has a non-empty recv pipeline!\n",
                  check->connection_id);
          }
#endif
          continue;
        }
      }

      if((needle->handler->flags&PROTOPT_SSL) !=
         (check->handler->flags&PROTOPT_SSL))
        /* don't do mixed SSL and non-SSL connections */
        if(!(needle->handler->protocol & check->handler->protocol))
          /* except protocols that have been upgraded via TLS */
          continue;

      if(needle->handler->flags&PROTOPT_SSL) {
        if((data->set.ssl.verifypeer != check->verifypeer) ||
           (data->set.ssl.verifyhost != check->verifyhost))
          continue;
      }

      if(needle->bits.proxy != check->bits.proxy)
        /* don't do mixed proxy and non-proxy connections */
        continue;

      if(!canPipeline && check->inuse)
        /* this request can't be pipelined but the checked connection is
           already in use so we skip it */
        continue;

      if(needle->localdev || needle->localport) {
        /* If we are bound to a specific local end (IP+port), we must not
           re-use a random other one, although if we didn't ask for a
           particular one we can reuse one that was bound.

           This comparison is a bit rough and too strict. Since the input
           parameters can be specified in numerous ways and still end up the
           same it would take a lot of processing to make it really accurate.
           Instead, this matching will assume that re-uses of bound connections
           will most likely also re-use the exact same binding parameters and
           missing out a few edge cases shouldn't hurt anyone very much.
        */
        if((check->localport != needle->localport) ||
           (check->localportrange != needle->localportrange) ||
           !check->localdev ||
           !needle->localdev ||
           strcmp(check->localdev, needle->localdev))
          continue;
      }

      if((needle->handler->protocol & CURLPROTO_FTP) ||
         ((needle->handler->protocol & CURLPROTO_HTTP) && wantNTLM)) {
         /* This is FTP or HTTP+NTLM, verify that we're using the same name
            and password as well */
         if(!strequal(needle->user, check->user) ||
            !strequal(needle->passwd, check->passwd)) {
            /* one of them was different */
            continue;
         }
         credentialsMatch = TRUE;
      }

      if(!needle->bits.httpproxy || needle->handler->flags&PROTOPT_SSL ||
         (needle->bits.httpproxy && check->bits.httpproxy &&
          needle->bits.tunnel_proxy && check->bits.tunnel_proxy &&
          Curl_raw_equal(needle->proxy.name, check->proxy.name) &&
          (needle->port == check->port))) {
        /* The requested connection does not use a HTTP proxy or it uses SSL or
           it is a non-SSL protocol tunneled over the same http proxy name and
           port number or it is a non-SSL protocol which is allowed to be
           upgraded via TLS */

        if((Curl_raw_equal(needle->handler->scheme, check->handler->scheme) ||
            needle->handler->protocol & check->handler->protocol) &&
           Curl_raw_equal(needle->host.name, check->host.name) &&
           needle->remote_port == check->remote_port) {
          if(needle->handler->flags & PROTOPT_SSL) {
            /* This is a SSL connection so verify that we're using the same
               SSL options as well */
            if(!Curl_ssl_config_matches(&needle->ssl_config,
                                        &check->ssl_config)) {
              DEBUGF(infof(data,
                           "Connection #%ld has different SSL parameters, "
                           "can't reuse\n",
                           check->connection_id));
              continue;
            }
            else if(check->ssl[FIRSTSOCKET].state != ssl_connection_complete) {
              DEBUGF(infof(data,
                           "Connection #%ld has not started SSL connect, "
                           "can't reuse\n",
                           check->connection_id));
              continue;
            }
          }
          match = TRUE;
        }
      }
      else { /* The requested needle connection is using a proxy,
                is the checked one using the same host, port and type? */
        if(check->bits.proxy &&
           (needle->proxytype == check->proxytype) &&
           (needle->bits.tunnel_proxy == check->bits.tunnel_proxy) &&
           Curl_raw_equal(needle->proxy.name, check->proxy.name) &&
           needle->port == check->port) {
          /* This is the same proxy connection, use it! */
          match = TRUE;
        }
      }

      if(match) {
        /* If we are looking for an NTLM connection, check if this is already
           authenticating with the right credentials. If not, keep looking so
           that we can reuse NTLM connections if possible. (Especially we
           must not reuse the same connection if partway through
           a handshake!) */
        if(wantNTLM) {
          if(credentialsMatch && check->ntlm.state != NTLMSTATE_NONE) {
            chosen = check;

            /* We must use this connection, no other */
            *force_reuse = TRUE;
            break;
          }
          else
            continue;
        }

        if(canPipeline) {
          /* We can pipeline if we want to. Let's continue looking for
             the optimal connection to use, i.e the shortest pipe that is not
             blacklisted. */

          if(pipeLen == 0) {
            /* We have the optimal connection. Let's stop looking. */
            chosen = check;
            break;
          }

          /* We can't use the connection if the pipe is full */
          if(pipeLen >= max_pipe_len)
            continue;

          /* We can't use the connection if the pipe is penalized */
          if(Curl_pipeline_penalized(data, check))
            continue;

          if(pipeLen < best_pipe_len) {
            /* This connection has a shorter pipe so far. We'll pick this
               and continue searching */
            chosen = check;
            best_pipe_len = pipeLen;
            continue;
          }
        }
        else {
          /* We have found a connection. Let's stop searching. */
          chosen = check;
          break;
        }
      }
    }
  }

  if(chosen) {
    *usethis = chosen;
    return TRUE; /* yes, we found one to use! */
  }

  return FALSE; /* no matching connecting exists */
}

/* Mark the connection as 'idle', or close it if the cache is full.
   Returns TRUE if the connection is kept, or FALSE if it was closed. */
static bool
ConnectionDone(struct SessionHandle *data, struct connectdata *conn)
{
  /* data->multi->maxconnects can be negative, deal with it. */
  size_t maxconnects =
    (data->multi->maxconnects < 0) ? 0 : data->multi->maxconnects;
  struct connectdata *conn_candidate = NULL;

  /* Mark the current connection as 'unused' */
  conn->inuse = FALSE;

  if(maxconnects > 0 &&
     data->state.conn_cache->num_connections > maxconnects) {
    infof(data, "Connection cache is full, closing the oldest one.\n");

    conn_candidate = find_oldest_idle_connection(data);

    if(conn_candidate) {
      /* Set the connection's owner correctly */
      conn_candidate->data = data;

      /* the winner gets the honour of being disconnected */
      (void)Curl_disconnect(conn_candidate, /* dead_connection */ FALSE);
    }
  }

  return (conn_candidate == conn) ? FALSE : TRUE;
}

/*
 * The given input connection struct pointer is to be stored in the connection
 * cache. If the cache is already full, least interesting existing connection
 * (if any) gets closed.
 *
 * The given connection should be unique. That must've been checked prior to
 * this call.
 */
static CURLcode ConnectionStore(struct SessionHandle *data,
                                struct connectdata *conn)
{
  static int connection_id_counter = 0;

  CURLcode result;

  /* Assign a number to the connection for easier tracking in the log
     output */
  conn->connection_id = connection_id_counter++;

  result = Curl_conncache_add_conn(data->state.conn_cache, conn);
  if(result != CURLE_OK)
    conn->connection_id = -1;

  return result;
}

/* after a TCP connection to the proxy has been verified, this function does
   the next magic step.

   Note: this function's sub-functions call failf()

*/
CURLcode Curl_connected_proxy(struct connectdata *conn)
{
  if(!conn->bits.proxy)
    return CURLE_OK;

  switch(conn->proxytype) {
#ifndef CURL_DISABLE_PROXY
  case CURLPROXY_SOCKS5:
  case CURLPROXY_SOCKS5_HOSTNAME:
    return Curl_SOCKS5(conn->proxyuser, conn->proxypasswd,
                       conn->host.name, conn->remote_port,
                       FIRSTSOCKET, conn);

  case CURLPROXY_SOCKS4:
    return Curl_SOCKS4(conn->proxyuser, conn->host.name,
                       conn->remote_port, FIRSTSOCKET, conn, FALSE);

  case CURLPROXY_SOCKS4A:
    return Curl_SOCKS4(conn->proxyuser, conn->host.name,
                       conn->remote_port, FIRSTSOCKET, conn, TRUE);

#endif /* CURL_DISABLE_PROXY */
  case CURLPROXY_HTTP:
  case CURLPROXY_HTTP_1_0:
    /* do nothing here. handled later. */
    break;
  default:
    break;
  } /* switch proxytype */

  return CURLE_OK;
}

static CURLcode ConnectPlease(struct SessionHandle *data,
                              struct connectdata *conn,
                              bool *connected)
{
  CURLcode result;
  Curl_addrinfo *addr;
#ifndef CURL_DISABLE_VERBOSE_STRINGS
  char *hostname = conn->bits.proxy?conn->proxy.name:conn->host.name;

  infof(data, "About to connect() to %s%s port %ld (#%ld)\n",
        conn->bits.proxy?"proxy ":"",
        hostname, conn->port, conn->connection_id);
#else
  (void)data;
#endif

  /*************************************************************
   * Connect to server/proxy
   *************************************************************/
  result= Curl_connecthost(conn,
                           conn->dns_entry,
                           &conn->sock[FIRSTSOCKET],
                           &addr,
                           connected);
  if(CURLE_OK == result) {
    /* All is cool, we store the current information */
    conn->ip_addr = addr;

    if(*connected) {
      result = Curl_connected_proxy(conn);
      if(!result) {
        conn->bits.tcpconnect[FIRSTSOCKET] = TRUE;
        Curl_pgrsTime(data, TIMER_CONNECT); /* connect done */
      }
    }
  }

  if(result)
    *connected = FALSE; /* mark it as not connected */

  return result;
}

/*
 * verboseconnect() displays verbose information after a connect
 */
#ifndef CURL_DISABLE_VERBOSE_STRINGS
void Curl_verboseconnect(struct connectdata *conn)
{
  if(conn->data->set.verbose)
    infof(conn->data, "Connected to %s (%s) port %ld (#%ld)\n",
          conn->bits.proxy ? conn->proxy.dispname : conn->host.dispname,
          conn->ip_addr_str, conn->port, conn->connection_id);
}
#endif

int Curl_protocol_getsock(struct connectdata *conn,
                          curl_socket_t *socks,
                          int numsocks)
{
  if(conn->handler->proto_getsock)
    return conn->handler->proto_getsock(conn, socks, numsocks);
  return GETSOCK_BLANK;
}

int Curl_doing_getsock(struct connectdata *conn,
                       curl_socket_t *socks,
                       int numsocks)
{
  if(conn && conn->handler->doing_getsock)
    return conn->handler->doing_getsock(conn, socks, numsocks);
  return GETSOCK_BLANK;
}

/*
 * We are doing protocol-specific connecting and this is being called over and
 * over from the multi interface until the connection phase is done on
 * protocol layer.
 */

CURLcode Curl_protocol_connecting(struct connectdata *conn,
                                  bool *done)
{
  CURLcode result=CURLE_OK;

  if(conn && conn->handler->connecting) {
    *done = FALSE;
    result = conn->handler->connecting(conn, done);
  }
  else
    *done = TRUE;

  return result;
}

/*
 * We are DOING this is being called over and over from the multi interface
 * until the DOING phase is done on protocol layer.
 */

CURLcode Curl_protocol_doing(struct connectdata *conn, bool *done)
{
  CURLcode result=CURLE_OK;

  if(conn && conn->handler->doing) {
    *done = FALSE;
    result = conn->handler->doing(conn, done);
  }
  else
    *done = TRUE;

  return result;
}

/*
 * We have discovered that the TCP connection has been successful, we can now
 * proceed with some action.
 *
 */
CURLcode Curl_protocol_connect(struct connectdata *conn,
                               bool *protocol_done)
{
  CURLcode result=CURLE_OK;

  *protocol_done = FALSE;

  if(conn->bits.tcpconnect[FIRSTSOCKET] && conn->bits.protoconnstart) {
    /* We already are connected, get back. This may happen when the connect
       worked fine in the first call, like when we connect to a local server
       or proxy. Note that we don't know if the protocol is actually done.

       Unless this protocol doesn't have any protocol-connect callback, as
       then we know we're done. */
    if(!conn->handler->connecting)
      *protocol_done = TRUE;

    return CURLE_OK;
  }

  if(!conn->bits.protoconnstart) {

    result = Curl_proxy_connect(conn);
    if(result)
      return result;

    if(conn->bits.tunnel_proxy && conn->bits.httpproxy &&
       (conn->tunnel_state[FIRSTSOCKET] != TUNNEL_COMPLETE))
      /* when using an HTTP tunnel proxy, await complete tunnel establishment
         before proceeding further. Return CURLE_OK so we'll be called again */
      return CURLE_OK;

    if(conn->handler->connect_it) {
      /* is there a protocol-specific connect() procedure? */

      /* Call the protocol-specific connect function */
      result = conn->handler->connect_it(conn, protocol_done);
    }
    else
      *protocol_done = TRUE;

    /* it has started, possibly even completed but that knowledge isn't stored
       in this bit! */
    if(!result)
      conn->bits.protoconnstart = TRUE;
  }

  return result; /* pass back status */
}

/*
 * Helpers for IDNA convertions.
 */
static bool is_ASCII_name(const char *hostname)
{
  const unsigned char *ch = (const unsigned char*)hostname;

  while(*ch) {
    if(*ch++ & 0x80)
      return FALSE;
  }
  return TRUE;
}

#ifdef USE_LIBIDN
/*
 * Check if characters in hostname is allowed in Top Level Domain.
 */
static bool tld_check_name(struct SessionHandle *data,
                           const char *ace_hostname)
{
  size_t err_pos;
  char *uc_name = NULL;
  int rc;
#ifndef CURL_DISABLE_VERBOSE_STRINGS
  const char *tld_errmsg = "<no msg>";
#else
  (void)data;
#endif

  /* Convert (and downcase) ACE-name back into locale's character set */
  rc = idna_to_unicode_lzlz(ace_hostname, &uc_name, 0);
  if(rc != IDNA_SUCCESS)
    return FALSE;

  rc = tld_check_lz(uc_name, &err_pos, NULL);
#ifndef CURL_DISABLE_VERBOSE_STRINGS
#ifdef HAVE_TLD_STRERROR
  if(rc != TLD_SUCCESS)
    tld_errmsg = tld_strerror((Tld_rc)rc);
#endif
  if(rc == TLD_INVALID)
    infof(data, "WARNING: %s; pos %u = `%c'/0x%02X\n",
          tld_errmsg, err_pos, uc_name[err_pos],
          uc_name[err_pos] & 255);
  else if(rc != TLD_SUCCESS)
    infof(data, "WARNING: TLD check for %s failed; %s\n",
          uc_name, tld_errmsg);
#endif /* CURL_DISABLE_VERBOSE_STRINGS */
  if(uc_name)
     idn_free(uc_name);
  if(rc != TLD_SUCCESS)
    return FALSE;

  return TRUE;
}
#endif

/*
 * Perform any necessary IDN conversion of hostname
 */
static void fix_hostname(struct SessionHandle *data,
                         struct connectdata *conn, struct hostname *host)
{
#ifndef USE_LIBIDN
  (void)data;
  (void)conn;
#elif defined(CURL_DISABLE_VERBOSE_STRINGS)
  (void)conn;
#endif

  /* set the name we use to display the host name */
  host->dispname = host->name;
  if(!is_ASCII_name(host->name)) {
#ifdef USE_LIBIDN
  /*************************************************************
   * Check name for non-ASCII and convert hostname to ACE form.
   *************************************************************/
  if(stringprep_check_version(LIBIDN_REQUIRED_VERSION)) {
    char *ace_hostname = NULL;
    int rc = idna_to_ascii_lz(host->name, &ace_hostname, 0);
    infof (data, "Input domain encoded as `%s'\n",
           stringprep_locale_charset ());
    if(rc != IDNA_SUCCESS)
      infof(data, "Failed to convert %s to ACE; %s\n",
            host->name, Curl_idn_strerror(conn,rc));
    else {
      /* tld_check_name() displays a warning if the host name contains
         "illegal" characters for this TLD */
      (void)tld_check_name(data, ace_hostname);

      host->encalloc = ace_hostname;
      /* change the name pointer to point to the encoded hostname */
      host->name = host->encalloc;
    }
  }
#elif defined(USE_WIN32_IDN)
  /*************************************************************
   * Check name for non-ASCII and convert hostname to ACE form.
   *************************************************************/
    char *ace_hostname = NULL;
    int rc = curl_win32_idn_to_ascii(host->name, &ace_hostname);
    if(rc == 0)
      infof(data, "Failed to convert %s to ACE;\n",
            host->name);
    else {
      host->encalloc = ace_hostname;
      /* change the name pointer to point to the encoded hostname */
      host->name = host->encalloc;
    }
#else
    infof(data, "IDN support not present, can't parse Unicode domains\n");
#endif
  }
}

static void llist_dtor(void *user, void *element)
{
  (void)user;
  (void)element;
  /* Do nothing */
}

/*
 * Allocate and initialize a new connectdata object.
 */
static struct connectdata *allocate_conn(struct SessionHandle *data)
{
  struct connectdata *conn = calloc(1, sizeof(struct connectdata));
  if(!conn)
    return NULL;

  conn->handler = &Curl_handler_dummy;  /* Be sure we have a handler defined
                                           already from start to avoid NULL
                                           situations and checks */

  /* and we setup a few fields in case we end up actually using this struct */

  conn->sock[FIRSTSOCKET] = CURL_SOCKET_BAD;     /* no file descriptor */
  conn->sock[SECONDARYSOCKET] = CURL_SOCKET_BAD; /* no file descriptor */
  conn->connection_id = -1;    /* no ID */
  conn->port = -1; /* unknown at this point */

  /* Default protocol-independent behavior doesn't support persistent
     connections, so we set this to force-close. Protocols that support
     this need to set this to FALSE in their "curl_do" functions. */
  conn->bits.close = TRUE;

  /* Store creation time to help future close decision making */
  conn->created = Curl_tvnow();

  conn->data = data; /* Setup the association between this connection
                        and the SessionHandle */

  conn->proxytype = data->set.proxytype; /* type */

#ifdef CURL_DISABLE_PROXY

  conn->bits.proxy = FALSE;
  conn->bits.httpproxy = FALSE;
  conn->bits.proxy_user_passwd = FALSE;
  conn->bits.tunnel_proxy = FALSE;

#else /* CURL_DISABLE_PROXY */

  /* note that these two proxy bits are now just on what looks to be
     requested, they may be altered down the road */
  conn->bits.proxy = (data->set.str[STRING_PROXY] &&
                      *data->set.str[STRING_PROXY])?TRUE:FALSE;
  conn->bits.httpproxy = (conn->bits.proxy &&
                          (conn->proxytype == CURLPROXY_HTTP ||
                           conn->proxytype == CURLPROXY_HTTP_1_0))?TRUE:FALSE;
  conn->bits.proxy_user_passwd =
    (NULL != data->set.str[STRING_PROXYUSERNAME])?TRUE:FALSE;
  conn->bits.tunnel_proxy = data->set.tunnel_thru_httpproxy;

#endif /* CURL_DISABLE_PROXY */

  conn->bits.user_passwd = (NULL != data->set.str[STRING_USERNAME])?TRUE:FALSE;
  conn->bits.ftp_use_epsv = data->set.ftp_use_epsv;
  conn->bits.ftp_use_eprt = data->set.ftp_use_eprt;

  conn->verifypeer = data->set.ssl.verifypeer;
  conn->verifyhost = data->set.ssl.verifyhost;

  conn->ip_version = data->set.ipver;

#if defined(USE_NTLM) && defined(NTLM_WB_ENABLED)
  conn->ntlm_auth_hlpr_socket = CURL_SOCKET_BAD;
  conn->ntlm_auth_hlpr_pid = 0;
  conn->challenge_header = NULL;
  conn->response_header = NULL;
#endif

  if(Curl_multi_pipeline_enabled(data->multi) &&
      !conn->master_buffer) {
    /* Allocate master_buffer to be used for pipelining */
    conn->master_buffer = calloc(BUFSIZE, sizeof (char));
    if(!conn->master_buffer)
      goto error;
  }

  /* Initialize the pipeline lists */
  conn->send_pipe = Curl_llist_alloc((curl_llist_dtor) llist_dtor);
  conn->recv_pipe = Curl_llist_alloc((curl_llist_dtor) llist_dtor);
  if(!conn->send_pipe || !conn->recv_pipe)
    goto error;

#if defined(HAVE_KRB4) || defined(HAVE_GSSAPI)
  conn->data_prot = PROT_CLEAR;
#endif

  /* Store the local bind parameters that will be used for this connection */
  if(data->set.str[STRING_DEVICE]) {
    conn->localdev = strdup(data->set.str[STRING_DEVICE]);
    if(!conn->localdev)
      goto error;
  }
  conn->localportrange = data->set.localportrange;
  conn->localport = data->set.localport;

  /* the close socket stuff needs to be copied to the connection struct as
     it may live on without (this specific) SessionHandle */
  conn->fclosesocket = data->set.fclosesocket;
  conn->closesocket_client = data->set.closesocket_client;

  return conn;
  error:

  Curl_llist_destroy(conn->send_pipe, NULL);
  Curl_llist_destroy(conn->recv_pipe, NULL);

  conn->send_pipe = NULL;
  conn->recv_pipe = NULL;

  Curl_safefree(conn->master_buffer);
  Curl_safefree(conn->localdev);
  Curl_safefree(conn);
  return NULL;
}

static CURLcode findprotocol(struct SessionHandle *data,
                             struct connectdata *conn,
                             const char *protostr)
{
  const struct Curl_handler * const *pp;
  const struct Curl_handler *p;

  /* Scan protocol handler table and match against 'protostr' to set a few
     variables based on the URL. Now that the handler may be changed later
     when the protocol specific setup function is called. */
  for(pp = protocols; (p = *pp) != NULL; pp++) {
    if(Curl_raw_equal(p->scheme, protostr)) {
      /* Protocol found in table. Check if allowed */
      if(!(data->set.allowed_protocols & p->protocol))
        /* nope, get out */
        break;

      /* it is allowed for "normal" request, now do an extra check if this is
         the result of a redirect */
      if(data->state.this_is_a_follow &&
         !(data->set.redir_protocols & p->protocol))
        /* nope, get out */
        break;

      /* Perform setup complement if some. */
      conn->handler = conn->given = p;

      /* 'port' and 'remote_port' are set in setup_connection_internals() */
      return CURLE_OK;
    }
  }


  /* The protocol was not found in the table, but we don't have to assign it
     to anything since it is already assigned to a dummy-struct in the
     create_conn() function when the connectdata struct is allocated. */
  failf(data, "Protocol %s not supported or disabled in " LIBCURL_NAME,
        protostr);

  return CURLE_UNSUPPORTED_PROTOCOL;
}

/*
 * Parse URL and fill in the relevant members of the connection struct.
 */
static CURLcode parseurlandfillconn(struct SessionHandle *data,
                                    struct connectdata *conn,
                                    bool *prot_missing,
                                    char *user, char *passwd, char *options)
{
  char *at;
  char *fragment;
  char *path = data->state.path;
  char *query;
  int rc;
  char protobuf[16];
  const char *protop;
  CURLcode result;
  bool fix_slash = FALSE;

  *prot_missing = FALSE;

  /*************************************************************
   * Parse the URL.
   *
   * We need to parse the url even when using the proxy, because we will need
   * the hostname and port in case we are trying to SSL connect through the
   * proxy -- and we don't know if we will need to use SSL until we parse the
   * url ...
   ************************************************************/
  if((2 == sscanf(data->change.url, "%15[^:]:%[^\n]",
                  protobuf, path)) &&
     Curl_raw_equal(protobuf, "file")) {
    if(path[0] == '/' && path[1] == '/') {
      /* Allow omitted hostname (e.g. file:/<path>).  This is not strictly
       * speaking a valid file: URL by RFC 1738, but treating file:/<path> as
       * file://localhost/<path> is similar to how other schemes treat missing
       * hostnames.  See RFC 1808. */

      /* This cannot be done with strcpy() in a portable manner, since the
         memory areas overlap! */
      memmove(path, path + 2, strlen(path + 2)+1);
    }
    /*
     * we deal with file://<host>/<path> differently since it supports no
     * hostname other than "localhost" and "127.0.0.1", which is unique among
     * the URL protocols specified in RFC 1738
     */
    if(path[0] != '/') {
      /* the URL included a host name, we ignore host names in file:// URLs
         as the standards don't define what to do with them */
      char *ptr=strchr(path, '/');
      if(ptr) {
        /* there was a slash present

           RFC1738 (section 3.1, page 5) says:

           The rest of the locator consists of data specific to the scheme,
           and is known as the "url-path". It supplies the details of how the
           specified resource can be accessed. Note that the "/" between the
           host (or port) and the url-path is NOT part of the url-path.

           As most agents use file://localhost/foo to get '/foo' although the
           slash preceding foo is a separator and not a slash for the path,
           a URL as file://localhost//foo must be valid as well, to refer to
           the same file with an absolute path.
        */

        if(ptr[1] && ('/' == ptr[1]))
          /* if there was two slashes, we skip the first one as that is then
             used truly as a separator */
          ptr++;

        /* This cannot be made with strcpy, as the memory chunks overlap! */
        memmove(path, ptr, strlen(ptr)+1);
      }
    }

    protop = "file"; /* protocol string */
  }
  else {
    /* clear path */
    path[0]=0;

    if(2 > sscanf(data->change.url,
                   "%15[^\n:]://%[^\n/?]%[^\n]",
                   protobuf,
                   conn->host.name, path)) {

      /*
       * The URL was badly formatted, let's try the browser-style _without_
       * protocol specified like 'http://'.
       */
      rc = sscanf(data->change.url, "%[^\n/?]%[^\n]", conn->host.name, path);
      if(1 > rc) {
        /*
         * We couldn't even get this format.
         * djgpp 2.04 has a sscanf() bug where 'conn->host.name' is
         * assigned, but the return value is EOF!
         */
#if defined(__DJGPP__) && (DJGPP_MINOR == 4)
        if(!(rc == -1 && *conn->host.name))
#endif
        {
          failf(data, "<url> malformed");
          return CURLE_URL_MALFORMAT;
        }
      }

      /*
       * Since there was no protocol part specified, we guess what protocol it
       * is based on the first letters of the server name.
       */

      /* Note: if you add a new protocol, please update the list in
       * lib/version.c too! */

      if(checkprefix("FTP.", conn->host.name))
        protop = "ftp";
      else if(checkprefix("DICT.", conn->host.name))
        protop = "DICT";
      else if(checkprefix("LDAP.", conn->host.name))
        protop = "LDAP";
      else if(checkprefix("IMAP.", conn->host.name))
        protop = "IMAP";
      else {
        protop = "http";
      }

      *prot_missing = TRUE; /* not given in URL */
    }
    else
      protop = protobuf;
  }

  /* We search for '?' in the host name (but only on the right side of a
   * @-letter to allow ?-letters in username and password) to handle things
   * like http://example.com?param= (notice the missing '/').
   */
  at = strchr(conn->host.name, '@');
  if(at)
    query = strchr(at+1, '?');
  else
    query = strchr(conn->host.name, '?');

  if(query) {
    /* We must insert a slash before the '?'-letter in the URL. If the URL had
       a slash after the '?', that is where the path currently begins and the
       '?string' is still part of the host name.

       We must move the trailing part from the host name and put it first in
       the path. And have it all prefixed with a slash.
    */

    size_t hostlen = strlen(query);
    size_t pathlen = strlen(path);

    /* move the existing path plus the zero byte forward, to make room for
       the host-name part */
    memmove(path+hostlen+1, path, pathlen+1);

     /* now copy the trailing host part in front of the existing path */
    memcpy(path+1, query, hostlen);

    path[0]='/'; /* prepend the missing slash */
    fix_slash = TRUE;

    *query=0; /* now cut off the hostname at the ? */
  }
  else if(!path[0]) {
    /* if there's no path set, use a single slash */
    strcpy(path, "/");
    fix_slash = TRUE;
  }

  /* If the URL is malformatted (missing a '/' after hostname before path) we
   * insert a slash here. The only letter except '/' we accept to start a path
   * is '?'.
   */
  if(path[0] == '?') {
    /* We need this function to deal with overlapping memory areas. We know
       that the memory area 'path' points to is 'urllen' bytes big and that
       is bigger than the path. Use +1 to move the zero byte too. */
    memmove(&path[1], path, strlen(path)+1);
    path[0] = '/';
    fix_slash = TRUE;
  }


  /*
   * "fix_slash" means that the URL was malformatted so we need to generate an
   * updated version with the new slash inserted at the right place!  We need
   * the corrected URL when communicating over HTTP proxy and we don't know at
   * this point if we're using a proxy or not.
   */
  if(fix_slash) {
    char *reurl;

    size_t plen = strlen(path); /* new path, should be 1 byte longer than
                                   the original */
    size_t urllen = strlen(data->change.url); /* original URL length */

    reurl = malloc(urllen + 2); /* 2 for zerobyte + slash */
    if(!reurl)
      return CURLE_OUT_OF_MEMORY;

    /* copy the prefix */
    memcpy(reurl, data->change.url, urllen - (plen-1));

    /* append the trailing piece + zerobyte */
    memcpy(&reurl[urllen - (plen-1)], path, plen + 1);

    /* possible free the old one */
    if(data->change.url_alloc) {
      Curl_safefree(data->change.url);
      data->change.url_alloc = FALSE;
    }

    data->change.url = reurl;
    data->change.url_alloc = TRUE; /* free this later */
  }

  /*
   * Parse the login details from the URL and strip them out of
   * the host name
   */
  result = parse_url_login(data, conn, user, passwd, options);
  if(result != CURLE_OK)
    return result;

  if(conn->host.name[0] == '[') {
    /* This looks like an IPv6 address literal.  See if there is an address
       scope.  */
    char *percent = strstr (conn->host.name, "%25");
    if(percent) {
      char *endp;
      unsigned long scope = strtoul (percent + 3, &endp, 10);
      if(*endp == ']') {
        /* The address scope was well formed.  Knock it out of the
           hostname. */
        memmove(percent, endp, strlen(endp)+1);
        if(!data->state.this_is_a_follow)
          /* Don't honour a scope given in a Location: header */
          conn->scope = (unsigned int)scope;
      }
      else
        infof(data, "Invalid IPv6 address format\n");
    }
  }

  if(data->set.scope)
    /* Override any scope that was set above.  */
    conn->scope = data->set.scope;

  /* Remove the fragment part of the path. Per RFC 2396, this is always the
     last part of the URI. We are looking for the first '#' so that we deal
     gracefully with non conformant URI such as http://example.com#foo#bar. */
  fragment = strchr(path, '#');
  if(fragment) {
    *fragment = 0;

    /* we know the path part ended with a fragment, so we know the full URL
       string does too and we need to cut it off from there so it isn't used
       over proxy */
    fragment = strchr(data->change.url, '#');
    if(fragment)
      *fragment = 0;
  }

  /*
   * So if the URL was A://B/C#D,
   *   protop is A
   *   conn->host.name is B
   *   data->state.path is /C
   */

  return findprotocol(data, conn, protop);
}

/*
 * If we're doing a resumed transfer, we need to setup our stuff
 * properly.
 */
static CURLcode setup_range(struct SessionHandle *data)
{
  struct UrlState *s = &data->state;
  s->resume_from = data->set.set_resume_from;
  if(s->resume_from || data->set.str[STRING_SET_RANGE]) {
    if(s->rangestringalloc)
      free(s->range);

    if(s->resume_from)
      s->range = aprintf("%" FORMAT_OFF_TU "-", s->resume_from);
    else
      s->range = strdup(data->set.str[STRING_SET_RANGE]);

    s->rangestringalloc = (s->range)?TRUE:FALSE;

    if(!s->range)
      return CURLE_OUT_OF_MEMORY;

    /* tell ourselves to fetch this range */
    s->use_range = TRUE;        /* enable range download */
  }
  else
    s->use_range = FALSE; /* disable range download */

  return CURLE_OK;
}


/***************************************************************
* Setup connection internals specific to the requested protocol.
* This MUST get called after proxy magic has been figured out.
***************************************************************/
static CURLcode setup_connection_internals(struct connectdata *conn)
{
  const struct Curl_handler * p;
  CURLcode result;

  conn->socktype = SOCK_STREAM; /* most of them are TCP streams */

  /* Scan protocol handler table. */

  /* Perform setup complement if some. */
  p = conn->handler;

  if(p->setup_connection) {
    result = (*p->setup_connection)(conn);

    if(result != CURLE_OK)
      return result;

    p = conn->handler;              /* May have changed. */
  }

  if(conn->port < 0)
    /* we check for -1 here since if proxy was detected already, this
       was very likely already set to the proxy port */
    conn->port = p->defport;
  conn->remote_port = (unsigned short)conn->given->defport;

  return CURLE_OK;
}

#ifndef CURL_DISABLE_PROXY
/****************************************************************
* Checks if the host is in the noproxy list. returns true if it matches
* and therefore the proxy should NOT be used.
****************************************************************/
static bool check_noproxy(const char* name, const char* no_proxy)
{
  /* no_proxy=domain1.dom,host.domain2.dom
   *   (a comma-separated list of hosts which should
   *   not be proxied, or an asterisk to override
   *   all proxy variables)
   */
  size_t tok_start;
  size_t tok_end;
  const char* separator = ", ";
  size_t no_proxy_len;
  size_t namelen;
  char *endptr;

  if(no_proxy && no_proxy[0]) {
    if(Curl_raw_equal("*", no_proxy)) {
      return TRUE;
    }

    /* NO_PROXY was specified and it wasn't just an asterisk */

    no_proxy_len = strlen(no_proxy);
    endptr = strchr(name, ':');
    if(endptr)
      namelen = endptr - name;
    else
      namelen = strlen(name);

    for(tok_start = 0; tok_start < no_proxy_len; tok_start = tok_end + 1) {
      while(tok_start < no_proxy_len &&
            strchr(separator, no_proxy[tok_start]) != NULL) {
        /* Look for the beginning of the token. */
        ++tok_start;
      }

      if(tok_start == no_proxy_len)
        break; /* It was all trailing separator chars, no more tokens. */

      for(tok_end = tok_start; tok_end < no_proxy_len &&
            strchr(separator, no_proxy[tok_end]) == NULL; ++tok_end)
        /* Look for the end of the token. */
        ;

      /* To match previous behaviour, where it was necessary to specify
       * ".local.com" to prevent matching "notlocal.com", we will leave
       * the '.' off.
       */
      if(no_proxy[tok_start] == '.')
        ++tok_start;

      if((tok_end - tok_start) <= namelen) {
        /* Match the last part of the name to the domain we are checking. */
        const char *checkn = name + namelen - (tok_end - tok_start);
        if(Curl_raw_nequal(no_proxy + tok_start, checkn,
                           tok_end - tok_start)) {
          if((tok_end - tok_start) == namelen || *(checkn - 1) == '.') {
            /* We either have an exact match, or the previous character is a .
             * so it is within the same domain, so no proxy for this host.
             */
            return TRUE;
          }
        }
      } /* if((tok_end - tok_start) <= namelen) */
    } /* for(tok_start = 0; tok_start < no_proxy_len;
         tok_start = tok_end + 1) */
  } /* NO_PROXY was specified and it wasn't just an asterisk */

  return FALSE;
}

/****************************************************************
* Detect what (if any) proxy to use. Remember that this selects a host
* name and is not limited to HTTP proxies only.
* The returned pointer must be freed by the caller (unless NULL)
****************************************************************/
static char *detect_proxy(struct connectdata *conn)
{
  char *proxy = NULL;

#ifndef CURL_DISABLE_HTTP
  /* If proxy was not specified, we check for default proxy environment
   * variables, to enable i.e Lynx compliance:
   *
   * http_proxy=http://some.server.dom:port/
   * https_proxy=http://some.server.dom:port/
   * ftp_proxy=http://some.server.dom:port/
   * no_proxy=domain1.dom,host.domain2.dom
   *   (a comma-separated list of hosts which should
   *   not be proxied, or an asterisk to override
   *   all proxy variables)
   * all_proxy=http://some.server.dom:port/
   *   (seems to exist for the CERN www lib. Probably
   *   the first to check for.)
   *
   * For compatibility, the all-uppercase versions of these variables are
   * checked if the lowercase versions don't exist.
   */
  char *no_proxy=NULL;
  char proxy_env[128];

  no_proxy=curl_getenv("no_proxy");
  if(!no_proxy)
    no_proxy=curl_getenv("NO_PROXY");

  if(!check_noproxy(conn->host.name, no_proxy)) {
    /* It was not listed as without proxy */
    const char *protop = conn->handler->scheme;
    char *envp = proxy_env;
    char *prox;

    /* Now, build <protocol>_proxy and check for such a one to use */
    while(*protop)
      *envp++ = (char)tolower((int)*protop++);

    /* append _proxy */
    strcpy(envp, "_proxy");

    /* read the protocol proxy: */
    prox=curl_getenv(proxy_env);

    /*
     * We don't try the uppercase version of HTTP_PROXY because of
     * security reasons:
     *
     * When curl is used in a webserver application
     * environment (cgi or php), this environment variable can
     * be controlled by the web server user by setting the
     * http header 'Proxy:' to some value.
     *
     * This can cause 'internal' http/ftp requests to be
     * arbitrarily redirected by any external attacker.
     */
    if(!prox && !Curl_raw_equal("http_proxy", proxy_env)) {
      /* There was no lowercase variable, try the uppercase version: */
      Curl_strntoupper(proxy_env, proxy_env, sizeof(proxy_env));
      prox=curl_getenv(proxy_env);
    }

    if(prox && *prox) { /* don't count "" strings */
      proxy = prox; /* use this */
    }
    else {
      proxy = curl_getenv("all_proxy"); /* default proxy to use */
      if(!proxy)
        proxy=curl_getenv("ALL_PROXY");
    }
  } /* if(!check_noproxy(conn->host.name, no_proxy)) - it wasn't specified
       non-proxy */
  if(no_proxy)
    free(no_proxy);

#else /* !CURL_DISABLE_HTTP */

  (void)conn;
#endif /* CURL_DISABLE_HTTP */

  return proxy;
}

/*
 * If this is supposed to use a proxy, we need to figure out the proxy
 * host name, so that we can re-use an existing connection
 * that may exist registered to the same proxy host.
 * proxy will be freed before this function returns.
 */
static CURLcode parse_proxy(struct SessionHandle *data,
                            struct connectdata *conn, char *proxy)
{
  char *prox_portno;
  char *endofprot;

  /* We use 'proxyptr' to point to the proxy name from now on... */
  char *proxyptr;
  char *portptr;
  char *atsign;

  /* We do the proxy host string parsing here. We want the host name and the
   * port name. Accept a protocol:// prefix
   */

  /* Parse the protocol part if present */
  endofprot = strstr(proxy, "://");
  if(endofprot) {
    proxyptr = endofprot+3;
    if(checkprefix("socks5h", proxy))
      conn->proxytype = CURLPROXY_SOCKS5_HOSTNAME;
    else if(checkprefix("socks5", proxy))
      conn->proxytype = CURLPROXY_SOCKS5;
    else if(checkprefix("socks4a", proxy))
      conn->proxytype = CURLPROXY_SOCKS4A;
    else if(checkprefix("socks4", proxy) || checkprefix("socks", proxy))
      conn->proxytype = CURLPROXY_SOCKS4;
    /* Any other xxx:// : change to http proxy */
  }
  else
    proxyptr = proxy; /* No xxx:// head: It's a HTTP proxy */

  /* Is there a username and password given in this proxy url? */
  atsign = strchr(proxyptr, '@');
  if(atsign) {
    CURLcode res = CURLE_OK;
    char *proxyuser = NULL;
    char *proxypasswd = NULL;

    res = parse_login_details(proxyptr, atsign - proxyptr,
                              &proxyuser, &proxypasswd, NULL);
    if(!res) {
      /* found user and password, rip them out.  note that we are
         unescaping them, as there is otherwise no way to have a
         username or password with reserved characters like ':' in
         them. */
      Curl_safefree(conn->proxyuser);
      if(proxyuser && strlen(proxyuser) < MAX_CURL_USER_LENGTH)
        conn->proxyuser = curl_easy_unescape(data, proxyuser, 0, NULL);
      else
        conn->proxyuser = strdup("");

      if(!conn->proxyuser)
        res = CURLE_OUT_OF_MEMORY;
      else {
        Curl_safefree(conn->proxypasswd);
        if(proxypasswd && strlen(proxypasswd) < MAX_CURL_PASSWORD_LENGTH)
          conn->proxypasswd = curl_easy_unescape(data, proxypasswd, 0, NULL);
        else
          conn->proxypasswd = strdup("");

        if(!conn->proxypasswd)
          res = CURLE_OUT_OF_MEMORY;
      }

      if(!res) {
        conn->bits.proxy_user_passwd = TRUE; /* enable it */
        atsign++; /* the right side of the @-letter */

        if(atsign)
          proxyptr = atsign; /* now use this instead */
        else
          res = CURLE_OUT_OF_MEMORY;
      }
    }

    Curl_safefree(proxyuser);
    Curl_safefree(proxypasswd);

    if(res)
      return res;
  }

  /* start scanning for port number at this point */
  portptr = proxyptr;

  /* detect and extract RFC2732-style IPv6-addresses */
  if(*proxyptr == '[') {
    char *ptr = ++proxyptr; /* advance beyond the initial bracket */
    while(*ptr && (ISXDIGIT(*ptr) || (*ptr == ':') || (*ptr == '%') ||
                   (*ptr == '.')))
      ptr++;
    if(*ptr == ']')
      /* yeps, it ended nicely with a bracket as well */
      *ptr++ = 0;
    else
      infof(data, "Invalid IPv6 address format\n");
    portptr = ptr;
    /* Note that if this didn't end with a bracket, we still advanced the
     * proxyptr first, but I can't see anything wrong with that as no host
     * name nor a numeric can legally start with a bracket.
     */
  }

  /* Get port number off proxy.server.com:1080 */
  prox_portno = strchr(portptr, ':');
  if(prox_portno) {
    *prox_portno = 0x0; /* cut off number from host name */
    prox_portno ++;
    /* now set the local port number */
    conn->port = strtol(prox_portno, NULL, 10);
  }
  else {
    if(proxyptr[0]=='/')
      /* If the first character in the proxy string is a slash, fail
         immediately. The following code will otherwise clear the string which
         will lead to code running as if no proxy was set! */
      return CURLE_COULDNT_RESOLVE_PROXY;

    /* without a port number after the host name, some people seem to use
       a slash so we strip everything from the first slash */
    atsign = strchr(proxyptr, '/');
    if(atsign)
      *atsign = 0x0; /* cut off path part from host name */

    if(data->set.proxyport)
      /* None given in the proxy string, then get the default one if it is
         given */
      conn->port = data->set.proxyport;
  }

  /* now, clone the cleaned proxy host name */
  conn->proxy.rawalloc = strdup(proxyptr);
  conn->proxy.name = conn->proxy.rawalloc;

  if(!conn->proxy.rawalloc)
    return CURLE_OUT_OF_MEMORY;

  return CURLE_OK;
}

/*
 * Extract the user and password from the authentication string
 */
static CURLcode parse_proxy_auth(struct SessionHandle *data,
                                 struct connectdata *conn)
{
  char proxyuser[MAX_CURL_USER_LENGTH]="";
  char proxypasswd[MAX_CURL_PASSWORD_LENGTH]="";

  if(data->set.str[STRING_PROXYUSERNAME] != NULL) {
    strncpy(proxyuser, data->set.str[STRING_PROXYUSERNAME],
            MAX_CURL_USER_LENGTH);
    proxyuser[MAX_CURL_USER_LENGTH-1] = '\0';   /*To be on safe side*/
  }
  if(data->set.str[STRING_PROXYPASSWORD] != NULL) {
    strncpy(proxypasswd, data->set.str[STRING_PROXYPASSWORD],
            MAX_CURL_PASSWORD_LENGTH);
    proxypasswd[MAX_CURL_PASSWORD_LENGTH-1] = '\0'; /*To be on safe side*/
  }

  conn->proxyuser = curl_easy_unescape(data, proxyuser, 0, NULL);
  if(!conn->proxyuser)
    return CURLE_OUT_OF_MEMORY;

  conn->proxypasswd = curl_easy_unescape(data, proxypasswd, 0, NULL);
  if(!conn->proxypasswd)
    return CURLE_OUT_OF_MEMORY;

  return CURLE_OK;
}
#endif /* CURL_DISABLE_PROXY */

/*
 * parse_url_login()
 *
 * Parse the login details (user name, password and options) from the URL and
 * strip them out of the host name
 *
 * Inputs: data->set.use_netrc (CURLOPT_NETRC)
 *         conn->host.name
 *
 * Outputs: (almost :- all currently undefined)
 *          conn->bits.user_passwd  - non-zero if non-default passwords exist
 *          user                    - non-zero length if defined
 *          passwd                  - non-zero length if defined
 *          options                 - non-zero length if defined
 *          conn->host.name         - remove user name and password
 */
static CURLcode parse_url_login(struct SessionHandle *data,
                                struct connectdata *conn,
                                char *user, char *passwd, char *options)
{
  CURLcode result = CURLE_OK;
  char *userp = NULL;
  char *passwdp = NULL;
  char *optionsp = NULL;

  /* At this point, we're hoping all the other special cases have
   * been taken care of, so conn->host.name is at most
   *    [user[:password][;options]]@]hostname
   *
   * We need somewhere to put the embedded details, so do that first.
   */

  char *ptr = strchr(conn->host.name, '@');
  char *login = conn->host.name;

  user[0] = 0;   /* to make everything well-defined */
  passwd[0] = 0;
  options[0] = 0;

  /* We will now try to extract the
   * possible login information in a string like:
   * ftp://user:password@ftp.my.site:8021/README */
  if(ptr) {
    /* There's login information to the left of the @ */

    conn->host.name = ++ptr;

    /* So the hostname is sane.  Only bother interpreting the
     * results if we could care.  It could still be wasted
     * work because it might be overtaken by the programmatically
     * set user/passwd, but doing that first adds more cases here :-(
     */

    if(data->set.use_netrc != CURL_NETRC_REQUIRED) {
      /* We could use the login information in the URL so extract it */
      result = parse_login_details(login, ptr - login - 1,
                                   &userp, &passwdp, &optionsp);
      if(!result) {
        if(userp) {
          char *newname;

          /* We have a user in the URL */
          conn->bits.userpwd_in_url = TRUE;
          conn->bits.user_passwd = TRUE; /* enable user+password */

          /* Decode the user */
          newname = curl_easy_unescape(data, userp, 0, NULL);
          if(!newname)
            return CURLE_OUT_OF_MEMORY;

          if(strlen(newname) < MAX_CURL_USER_LENGTH)
            strcpy(user, newname);

          free(newname);
        }

        if(passwdp) {
          /* We have a password in the URL so decode it */
          char *newpasswd = curl_easy_unescape(data, passwdp, 0, NULL);
          if(!newpasswd)
            return CURLE_OUT_OF_MEMORY;

          if(strlen(newpasswd) < MAX_CURL_PASSWORD_LENGTH)
            strcpy(passwd, newpasswd);

          free(newpasswd);
        }

        if(optionsp) {
          /* We have an options list in the URL so decode it */
          char *newoptions = curl_easy_unescape(data, optionsp, 0, NULL);
          if(!newoptions)
            return CURLE_OUT_OF_MEMORY;

          if(strlen(newoptions) < MAX_CURL_OPTIONS_LENGTH)
            strcpy(options, newoptions);

          free(newoptions);
        }
      }

      Curl_safefree(userp);
      Curl_safefree(passwdp);
      Curl_safefree(optionsp);
    }
  }

  return result;
}

/*
 * parse_login_details()
 *
 * This is used to parse a login string for user name, password and options in
 * the following formats:
 *
 *   user
 *   user:password
 *   user:password;options
 *   user;options
 *   user;options:password
 *   :password
 *   :password;options
 *   ;options
 *   ;options:password
 *
 * Parameters:
 *
 * login    [in]     - The login string.
 * len      [in]     - The length of the login string.
 * userp    [in/out] - The address where a pointer to newly allocated memory
 *                     holding the user will be stored upon completion.
 * passdwp  [in/out] - The address where a pointer to newly allocated memory
 *                     holding the password will be stored upon completion.
 * optionsp [in/out] - The address where a pointer to newly allocated memory
 *                     holding the options will be stored upon completion.
 *
 * Returns CURLE_OK on success.
 */
static CURLcode parse_login_details(const char *login, const size_t len,
                                    char **userp, char **passwdp,
                                    char **optionsp)
{
  CURLcode result = CURLE_OK;
  char *ubuf = NULL;
  char *pbuf = NULL;
  char *obuf = NULL;
  const char *psep = NULL;
  const char *osep = NULL;
  size_t ulen;
  size_t plen;
  size_t olen;

  /* Attempt to find the password separator */
  if(passwdp) {
    psep = strchr(login, ':');

    /* Within the constraint of the login string */
    if(psep >= login + len)
      psep = NULL;
  }

  /* Attempt to find the options separator */
  if(optionsp) {
    osep = strchr(login, ';');

    /* Within the constraint of the login string */
    if(osep >= login + len)
      osep = NULL;
  }

  /* Calculate the portion lengths */
  ulen = (psep ?
          (size_t)(osep && psep > osep ? osep - login : psep - login) :
          (osep ? (size_t)(osep - login) : len));
  plen = (psep ?
          (osep && osep > psep ? (size_t)(osep - psep) :
                                 (size_t)(login + len - psep)) - 1 : 0);
  olen = (osep ?
          (psep && psep > osep ? (size_t)(psep - osep) :
                                 (size_t)(login + len - osep)) - 1 : 0);

  /* Allocate the user portion buffer */
  if(userp && ulen) {
    ubuf = malloc(ulen + 1);
    if(!ubuf)
      result = CURLE_OUT_OF_MEMORY;
  }

  /* Allocate the password portion buffer */
  if(!result && passwdp && plen) {
    pbuf = malloc(plen + 1);
    if(!pbuf)
      result = CURLE_OUT_OF_MEMORY;
  }

  /* Allocate the options portion buffer */
  if(!result && optionsp && olen) {
    obuf = malloc(olen + 1);
    if(!obuf)
      result = CURLE_OUT_OF_MEMORY;
  }

  if(!result) {
    /* Store the user portion if necessary */
    if(ubuf) {
      memcpy(ubuf, login, ulen);
      ubuf[ulen] = '\0';
      Curl_safefree(*userp);
      *userp = ubuf;
    }

    /* Store the password portion if necessary */
    if(pbuf) {
      memcpy(pbuf, psep + 1, plen);
      pbuf[plen] = '\0';
      Curl_safefree(*passwdp);
      *passwdp = pbuf;
    }

    /* Store the options portion if necessary */
    if(obuf) {
      memcpy(obuf, osep + 1, olen);
      obuf[olen] = '\0';
      Curl_safefree(*optionsp);
      *optionsp = obuf;
    }
  }

  return result;
}

/*************************************************************
 * Figure out the remote port number and fix it in the URL
 *
 * No matter if we use a proxy or not, we have to figure out the remote
 * port number of various reasons.
 *
 * To be able to detect port number flawlessly, we must not confuse them
 * IPv6-specified addresses in the [0::1] style. (RFC2732)
 *
 * The conn->host.name is currently [user:passwd@]host[:port] where host
 * could be a hostname, IPv4 address or IPv6 address.
 *
 * The port number embedded in the URL is replaced, if necessary.
 *************************************************************/
static CURLcode parse_remote_port(struct SessionHandle *data,
                                  struct connectdata *conn)
{
  char *portptr;
  char endbracket;

  /* Note that at this point, the IPv6 address cannot contain any scope
     suffix as that has already been removed in the parseurlandfillconn()
     function */
  if((1 == sscanf(conn->host.name, "[%*45[0123456789abcdefABCDEF:.]%c",
                  &endbracket)) &&
     (']' == endbracket)) {
    /* this is a RFC2732-style specified IP-address */
    conn->bits.ipv6_ip = TRUE;

    conn->host.name++; /* skip over the starting bracket */
    portptr = strchr(conn->host.name, ']');
    if(portptr) {
      *portptr++ = '\0'; /* zero terminate, killing the bracket */
      if(':' != *portptr)
        portptr = NULL; /* no port number available */
    }
  }
  else {
#ifdef ENABLE_IPV6
    struct in6_addr in6;
    if(Curl_inet_pton(AF_INET6, conn->host.name, &in6) > 0) {
      /* This is a numerical IPv6 address, meaning this is a wrongly formatted
         URL */
      failf(data, "IPv6 numerical address used in URL without brackets");
      return CURLE_URL_MALFORMAT;
    }
#endif

    portptr = strrchr(conn->host.name, ':');
  }

  if(data->set.use_port && data->state.allow_port) {
    /* if set, we use this and ignore the port possibly given in the URL */
    conn->remote_port = (unsigned short)data->set.use_port;
    if(portptr)
      *portptr = '\0'; /* cut off the name there anyway - if there was a port
                      number - since the port number is to be ignored! */
    if(conn->bits.httpproxy) {
      /* we need to create new URL with the new port number */
      char *url;
      char type[12]="";

      if(conn->bits.type_set)
        snprintf(type, sizeof(type), ";type=%c",
                 data->set.prefer_ascii?'A':
                 (data->set.ftp_list_only?'D':'I'));

      /*
       * This synthesized URL isn't always right--suffixes like ;type=A are
       * stripped off. It would be better to work directly from the original
       * URL and simply replace the port part of it.
       */
      url = aprintf("%s://%s%s%s:%hu%s%s%s", conn->given->scheme,
                    conn->bits.ipv6_ip?"[":"", conn->host.name,
                    conn->bits.ipv6_ip?"]":"", conn->remote_port,
                    data->state.slash_removed?"/":"", data->state.path,
                    type);
      if(!url)
        return CURLE_OUT_OF_MEMORY;

      if(data->change.url_alloc) {
        Curl_safefree(data->change.url);
        data->change.url_alloc = FALSE;
      }

      data->change.url = url;
      data->change.url_alloc = TRUE;
    }
  }
  else if(portptr) {
    /* no CURLOPT_PORT given, extract the one from the URL */

    char *rest;
    unsigned long port;

    port=strtoul(portptr+1, &rest, 10);  /* Port number must be decimal */

    if(rest != (portptr+1) && *rest == '\0') {
      /* The colon really did have only digits after it,
       * so it is either a port number or a mistake */

      if(port > 0xffff) {   /* Single unix standard says port numbers are
                              * 16 bits long */
        failf(data, "Port number too large: %lu", port);
        return CURLE_URL_MALFORMAT;
      }

      *portptr = '\0'; /* cut off the name there */
      conn->remote_port = curlx_ultous(port);
    }
    else if(!port)
      /* Browser behavior adaptation. If there's a colon with no digits after,
         just cut off the name there which makes us ignore the colon and just
         use the default port. Firefox and Chrome both do that. */
      *portptr = '\0';
  }
  return CURLE_OK;
}

/*
 * Override the login details from the URL with that in the CURLOPT_USERPWD
 * option or a .netrc file, if applicable.
 */
static void override_login(struct SessionHandle *data,
                           struct connectdata *conn,
                           char *user, char *passwd, char *options)
{
  if(data->set.str[STRING_USERNAME]) {
    strncpy(user, data->set.str[STRING_USERNAME], MAX_CURL_USER_LENGTH);
    user[MAX_CURL_USER_LENGTH - 1] = '\0';   /* To be on safe side */
  }

  if(data->set.str[STRING_PASSWORD]) {
    strncpy(passwd, data->set.str[STRING_PASSWORD], MAX_CURL_PASSWORD_LENGTH);
    passwd[MAX_CURL_PASSWORD_LENGTH - 1] = '\0'; /* To be on safe side */
  }

  if(data->set.str[STRING_OPTIONS]) {
    strncpy(options, data->set.str[STRING_OPTIONS], MAX_CURL_OPTIONS_LENGTH);
    options[MAX_CURL_OPTIONS_LENGTH - 1] = '\0'; /* To be on safe side */
  }

  conn->bits.netrc = FALSE;
  if(data->set.use_netrc != CURL_NETRC_IGNORED) {
    if(Curl_parsenetrc(conn->host.name,
                       user, passwd,
                       data->set.str[STRING_NETRC_FILE])) {
      infof(data, "Couldn't find host %s in the "
            DOT_CHAR "netrc file; using defaults\n",
            conn->host.name);
    }
    else {
      /* set bits.netrc TRUE to remember that we got the name from a .netrc
         file, so that it is safe to use even if we followed a Location: to a
         different host or similar. */
      conn->bits.netrc = TRUE;

      conn->bits.user_passwd = TRUE; /* enable user+password */
    }
  }
}

/*
 * Set password so it's available in the connection.
 */
static CURLcode set_login(struct connectdata *conn,
                          const char *user, const char *passwd,
                          const char *options)
{
  CURLcode result = CURLE_OK;

  /* If our protocol needs a password and we have none, use the defaults */
  if((conn->handler->flags & PROTOPT_NEEDSPWD) && !conn->bits.user_passwd) {
    /* Store the default user */
    conn->user = strdup(CURL_DEFAULT_USER);

    /* Store the default password */
    if(conn->user)
      conn->passwd = strdup(CURL_DEFAULT_PASSWORD);
    else
      conn->passwd = NULL;

    /* This is the default password, so DON'T set conn->bits.user_passwd */
  }
  else {
    /* Store the user, zero-length if not set */
    conn->user = strdup(user);

    /* Store the password (only if user is present), zero-length if not set */
    if(conn->user)
      conn->passwd = strdup(passwd);
    else
      conn->passwd = NULL;
  }

  if(!conn->user || !conn->passwd)
    result = CURLE_OUT_OF_MEMORY;

  /* Store the options, null if not set */
  if(!result && options[0]) {
    conn->options = strdup(options);

    if(!conn->options)
      result = CURLE_OUT_OF_MEMORY;
  }

  return result;
}

/*************************************************************
 * Resolve the address of the server or proxy
 *************************************************************/
static CURLcode resolve_server(struct SessionHandle *data,
                               struct connectdata *conn,
                               bool *async)
{
  CURLcode result=CURLE_OK;
  long timeout_ms = Curl_timeleft(data, NULL, TRUE);

  /*************************************************************
   * Resolve the name of the server or proxy
   *************************************************************/
  if(conn->bits.reuse)
    /* We're reusing the connection - no need to resolve anything, and
       fix_hostname() was called already in create_conn() for the re-use
       case. */
    *async = FALSE;

  else {
    /* this is a fresh connect */
    int rc;
    struct Curl_dns_entry *hostaddr;

    /* set a pointer to the hostname we display */
    fix_hostname(data, conn, &conn->host);

    if(!conn->proxy.name || !*conn->proxy.name) {
      /* If not connecting via a proxy, extract the port from the URL, if it is
       * there, thus overriding any defaults that might have been set above. */
      conn->port =  conn->remote_port; /* it is the same port */

      /* Resolve target host right on */
      rc = Curl_resolv_timeout(conn, conn->host.name, (int)conn->port,
                               &hostaddr, timeout_ms);
      if(rc == CURLRESOLV_PENDING)
        *async = TRUE;

      else if(rc == CURLRESOLV_TIMEDOUT)
        result = CURLE_OPERATION_TIMEDOUT;

      else if(!hostaddr) {
        failf(data, "Couldn't resolve host '%s'", conn->host.dispname);
        result =  CURLE_COULDNT_RESOLVE_HOST;
        /* don't return yet, we need to clean up the timeout first */
      }
    }
    else {
      /* This is a proxy that hasn't been resolved yet. */

      /* IDN-fix the proxy name */
      fix_hostname(data, conn, &conn->proxy);

      /* resolve proxy */
      rc = Curl_resolv_timeout(conn, conn->proxy.name, (int)conn->port,
                               &hostaddr, timeout_ms);

      if(rc == CURLRESOLV_PENDING)
        *async = TRUE;

      else if(rc == CURLRESOLV_TIMEDOUT)
        result = CURLE_OPERATION_TIMEDOUT;

      else if(!hostaddr) {
        failf(data, "Couldn't resolve proxy '%s'", conn->proxy.dispname);
        result = CURLE_COULDNT_RESOLVE_PROXY;
        /* don't return yet, we need to clean up the timeout first */
      }
    }
    DEBUGASSERT(conn->dns_entry == NULL);
    conn->dns_entry = hostaddr;
  }

  return result;
}

/*
 * Cleanup the connection just allocated before we can move along and use the
 * previously existing one.  All relevant data is copied over and old_conn is
 * ready for freeing once this function returns.
 */
static void reuse_conn(struct connectdata *old_conn,
                       struct connectdata *conn)
{
  if(old_conn->proxy.rawalloc)
    free(old_conn->proxy.rawalloc);

  /* free the SSL config struct from this connection struct as this was
     allocated in vain and is targeted for destruction */
  Curl_free_ssl_config(&old_conn->ssl_config);

  conn->data = old_conn->data;

  /* get the user+password information from the old_conn struct since it may
   * be new for this request even when we re-use an existing connection */
  conn->bits.user_passwd = old_conn->bits.user_passwd;
  if(conn->bits.user_passwd) {
    /* use the new user name and password though */
    Curl_safefree(conn->user);
    Curl_safefree(conn->passwd);
    conn->user = old_conn->user;
    conn->passwd = old_conn->passwd;
    old_conn->user = NULL;
    old_conn->passwd = NULL;
  }

  conn->bits.proxy_user_passwd = old_conn->bits.proxy_user_passwd;
  if(conn->bits.proxy_user_passwd) {
    /* use the new proxy user name and proxy password though */
    Curl_safefree(conn->proxyuser);
    Curl_safefree(conn->proxypasswd);
    conn->proxyuser = old_conn->proxyuser;
    conn->proxypasswd = old_conn->proxypasswd;
    old_conn->proxyuser = NULL;
    old_conn->proxypasswd = NULL;
  }

  /* host can change, when doing keepalive with a proxy or if the case is
     different this time etc */
  Curl_safefree(conn->host.rawalloc);
  conn->host=old_conn->host;

  /* persist connection info in session handle */
  Curl_persistconninfo(conn);

  /* re-use init */
  conn->bits.reuse = TRUE; /* yes, we're re-using here */

  Curl_safefree(old_conn->user);
  Curl_safefree(old_conn->passwd);
  Curl_safefree(old_conn->proxyuser);
  Curl_safefree(old_conn->proxypasswd);
  Curl_safefree(old_conn->localdev);

  Curl_llist_destroy(old_conn->send_pipe, NULL);
  Curl_llist_destroy(old_conn->recv_pipe, NULL);

  old_conn->send_pipe = NULL;
  old_conn->recv_pipe = NULL;

  Curl_safefree(old_conn->master_buffer);
}

/**
 * create_conn() sets up a new connectdata struct, or re-uses an already
 * existing one, and resolves host name.
 *
 * if this function returns CURLE_OK and *async is set to TRUE, the resolve
 * response will be coming asynchronously. If *async is FALSE, the name is
 * already resolved.
 *
 * @param data The sessionhandle pointer
 * @param in_connect is set to the next connection data pointer
 * @param async is set TRUE when an async DNS resolution is pending
 * @see Curl_setup_conn()
 *
 * *NOTE* this function assigns the conn->data pointer!
 */

static CURLcode create_conn(struct SessionHandle *data,
                            struct connectdata **in_connect,
                            bool *async)
{
  CURLcode result = CURLE_OK;
  struct connectdata *conn;
  struct connectdata *conn_temp = NULL;
  size_t urllen;
  char user[MAX_CURL_USER_LENGTH];
  char passwd[MAX_CURL_PASSWORD_LENGTH];
  char options[MAX_CURL_OPTIONS_LENGTH];
  bool reuse;
  char *proxy = NULL;
  bool prot_missing = FALSE;
  bool no_connections_available = FALSE;
  bool force_reuse;
  size_t max_host_connections = Curl_multi_max_host_connections(data->multi);
  size_t max_total_connections = Curl_multi_max_total_connections(data->multi);

  *async = FALSE;

  /*************************************************************
   * Check input data
   *************************************************************/

  if(!data->change.url)
    return CURLE_URL_MALFORMAT;

  /* First, split up the current URL in parts so that we can use the
     parts for checking against the already present connections. In order
     to not have to modify everything at once, we allocate a temporary
     connection data struct and fill in for comparison purposes. */
  conn = allocate_conn(data);

  if(!conn)
    return CURLE_OUT_OF_MEMORY;

  /* We must set the return variable as soon as possible, so that our
     parent can cleanup any possible allocs we may have done before
     any failure */
  *in_connect = conn;

  /* This initing continues below, see the comment "Continue connectdata
   * initialization here" */

  /***********************************************************
   * We need to allocate memory to store the path in. We get the size of the
   * full URL to be sure, and we need to make it at least 256 bytes since
   * other parts of the code will rely on this fact
   ***********************************************************/
#define LEAST_PATH_ALLOC 256
  urllen=strlen(data->change.url);
  if(urllen < LEAST_PATH_ALLOC)
    urllen=LEAST_PATH_ALLOC;

  /*
   * We malloc() the buffers below urllen+2 to make room for 2 possibilities:
   * 1 - an extra terminating zero
   * 2 - an extra slash (in case a syntax like "www.host.com?moo" is used)
   */

  Curl_safefree(data->state.pathbuffer);
  data->state.path = NULL;

  data->state.pathbuffer = malloc(urllen+2);
  if(NULL == data->state.pathbuffer)
    return CURLE_OUT_OF_MEMORY; /* really bad error */
  data->state.path = data->state.pathbuffer;

  conn->host.rawalloc = malloc(urllen+2);
  if(NULL == conn->host.rawalloc) {
    Curl_safefree(data->state.pathbuffer);
    data->state.path = NULL;
    return CURLE_OUT_OF_MEMORY;
  }

  conn->host.name = conn->host.rawalloc;
  conn->host.name[0] = 0;

  result = parseurlandfillconn(data, conn, &prot_missing, user, passwd,
                               options);
  if(result != CURLE_OK)
    return result;

  /*************************************************************
   * No protocol part in URL was used, add it!
   *************************************************************/
  if(prot_missing) {
    /* We're guessing prefixes here and if we're told to use a proxy or if
       we're gonna follow a Location: later or... then we need the protocol
       part added so that we have a valid URL. */
    char *reurl;

    reurl = aprintf("%s://%s", conn->handler->scheme, data->change.url);

    if(!reurl) {
      Curl_safefree(proxy);
      return CURLE_OUT_OF_MEMORY;
    }

    if(data->change.url_alloc) {
      Curl_safefree(data->change.url);
      data->change.url_alloc = FALSE;
    }

    data->change.url = reurl;
    data->change.url_alloc = TRUE; /* free this later */
  }

  /*************************************************************
   * If the protocol can't handle url query strings, then cut
   * of the unhandable part
   *************************************************************/
  if((conn->given->flags&PROTOPT_NOURLQUERY)) {
    char *path_q_sep = strchr(conn->data->state.path, '?');
    if(path_q_sep) {
      /* according to rfc3986, allow the query (?foo=bar)
         also on protocols that can't handle it.

         cut the string-part after '?'
      */

      /* terminate the string */
      path_q_sep[0] = 0;
    }
  }

#ifndef CURL_DISABLE_PROXY
  /*************************************************************
   * Extract the user and password from the authentication string
   *************************************************************/
  if(conn->bits.proxy_user_passwd) {
    result = parse_proxy_auth(data, conn);
    if(result != CURLE_OK)
      return result;
  }

  /*************************************************************
   * Detect what (if any) proxy to use
   *************************************************************/
  if(data->set.str[STRING_PROXY]) {
    proxy = strdup(data->set.str[STRING_PROXY]);
    /* if global proxy is set, this is it */
    if(NULL == proxy) {
      failf(data, "memory shortage");
      return CURLE_OUT_OF_MEMORY;
    }
  }

  if(data->set.str[STRING_NOPROXY] &&
     check_noproxy(conn->host.name, data->set.str[STRING_NOPROXY])) {
    if(proxy) {
      free(proxy);  /* proxy is in exception list */
      proxy = NULL;
    }
  }
  else if(!proxy)
    proxy = detect_proxy(conn);

  if(proxy && (!*proxy || (conn->handler->flags & PROTOPT_NONETWORK))) {
    free(proxy);  /* Don't bother with an empty proxy string or if the
                     protocol doesn't work with network */
    proxy = NULL;
  }

  /***********************************************************************
   * If this is supposed to use a proxy, we need to figure out the proxy host
   * name, proxy type and port number, so that we can re-use an existing
   * connection that may exist registered to the same proxy host.
   ***********************************************************************/
  if(proxy) {
    result = parse_proxy(data, conn, proxy);

    free(proxy); /* parse_proxy copies the proxy string */

    if(result)
      return result;

    if((conn->proxytype == CURLPROXY_HTTP) ||
       (conn->proxytype == CURLPROXY_HTTP_1_0)) {
#ifdef CURL_DISABLE_HTTP
      /* asking for a HTTP proxy is a bit funny when HTTP is disabled... */
      return CURLE_UNSUPPORTED_PROTOCOL;
#else
      /* force this connection's protocol to become HTTP if not already
         compatible - if it isn't tunneling through */
      if(!(conn->handler->protocol & CURLPROTO_HTTP) &&
         !conn->bits.tunnel_proxy)
        conn->handler = &Curl_handler_http;

      conn->bits.httpproxy = TRUE;
#endif
    }
    else
      conn->bits.httpproxy = FALSE; /* not a HTTP proxy */
    conn->bits.proxy = TRUE;
  }
  else {
    /* we aren't using the proxy after all... */
    conn->bits.proxy = FALSE;
    conn->bits.httpproxy = FALSE;
    conn->bits.proxy_user_passwd = FALSE;
    conn->bits.tunnel_proxy = FALSE;
  }

#endif /* CURL_DISABLE_PROXY */

  /*************************************************************
   * Setup internals depending on protocol. Needs to be done after
   * we figured out what/if proxy to use.
   *************************************************************/
  result = setup_connection_internals(conn);
  if(result != CURLE_OK) {
    Curl_safefree(proxy);
    return result;
  }

  conn->recv[FIRSTSOCKET] = Curl_recv_plain;
  conn->send[FIRSTSOCKET] = Curl_send_plain;
  conn->recv[SECONDARYSOCKET] = Curl_recv_plain;
  conn->send[SECONDARYSOCKET] = Curl_send_plain;

  /***********************************************************************
   * file: is a special case in that it doesn't need a network connection
   ***********************************************************************/
#ifndef CURL_DISABLE_FILE
  if(conn->handler->flags & PROTOPT_NONETWORK) {
    bool done;
    /* this is supposed to be the connect function so we better at least check
       that the file is present here! */
    DEBUGASSERT(conn->handler->connect_it);
    result = conn->handler->connect_it(conn, &done);

    /* Setup a "faked" transfer that'll do nothing */
    if(CURLE_OK == result) {
      conn->data = data;
      conn->bits.tcpconnect[FIRSTSOCKET] = TRUE; /* we are "connected */

      ConnectionStore(data, conn);

      /*
       * Setup whatever necessary for a resumed transfer
       */
      result = setup_range(data);
      if(result) {
        DEBUGASSERT(conn->handler->done);
        /* we ignore the return code for the protocol-specific DONE */
        (void)conn->handler->done(conn, result, FALSE);
        return result;
      }

      Curl_setup_transfer(conn, -1, -1, FALSE, NULL, /* no download */
                          -1, NULL); /* no upload */
    }

    return result;
  }
#endif

  /*************************************************************
   * If the protocol is using SSL and HTTP proxy is used, we set
   * the tunnel_proxy bit.
   *************************************************************/
  if((conn->given->flags&PROTOPT_SSL) && conn->bits.httpproxy)
    conn->bits.tunnel_proxy = TRUE;

  /*************************************************************
   * Figure out the remote port number and fix it in the URL
   *************************************************************/
  result = parse_remote_port(data, conn);
  if(result != CURLE_OK)
    return result;

  /* Check for overridden login details and set them accordingly */
  override_login(data, conn, user, passwd, options);
  result = set_login(conn, user, passwd, options);
  if(result != CURLE_OK)
    return result;

  /* Get a cloned copy of the SSL config situation stored in the
     connection struct. But to get this going nicely, we must first make
     sure that the strings in the master copy are pointing to the correct
     strings in the session handle strings array!

     Keep in mind that the pointers in the master copy are pointing to strings
     that will be freed as part of the SessionHandle struct, but all cloned
     copies will be separately allocated.
  */
  data->set.ssl.CApath = data->set.str[STRING_SSL_CAPATH];
  data->set.ssl.CAfile = data->set.str[STRING_SSL_CAFILE];
  data->set.ssl.CRLfile = data->set.str[STRING_SSL_CRLFILE];
  data->set.ssl.issuercert = data->set.str[STRING_SSL_ISSUERCERT];
  data->set.ssl.random_file = data->set.str[STRING_SSL_RANDOM_FILE];
  data->set.ssl.egdsocket = data->set.str[STRING_SSL_EGDSOCKET];
  data->set.ssl.cipher_list = data->set.str[STRING_SSL_CIPHER_LIST];
#ifdef USE_TLS_SRP
  data->set.ssl.username = data->set.str[STRING_TLSAUTH_USERNAME];
  data->set.ssl.password = data->set.str[STRING_TLSAUTH_PASSWORD];
#endif

  if(!Curl_clone_ssl_config(&data->set.ssl, &conn->ssl_config))
    return CURLE_OUT_OF_MEMORY;

  /*************************************************************
   * Check the current list of connections to see if we can
   * re-use an already existing one or if we have to create a
   * new one.
   *************************************************************/

  /* reuse_fresh is TRUE if we are told to use a new connection by force, but
     we only acknowledge this option if this is not a re-used connection
     already (which happens due to follow-location or during a HTTP
     authentication phase). */
  if(data->set.reuse_fresh && !data->state.this_is_a_follow)
    reuse = FALSE;
  else
    reuse = ConnectionExists(data, conn, &conn_temp, &force_reuse);

  /* If we found a reusable connection, we may still want to
     open a new connection if we are pipelining. */
  if(reuse && !force_reuse && IsPipeliningPossible(data, conn_temp)) {
    size_t pipelen = conn_temp->send_pipe->size + conn_temp->recv_pipe->size;
    if(pipelen > 0) {
      infof(data, "Found connection %d, with requests in the pipe (%d)\n",
            conn_temp->connection_id, pipelen);

      if(conn_temp->bundle->num_connections < max_host_connections &&
         data->state.conn_cache->num_connections < max_total_connections) {
        /* We want a new connection anyway */
        reuse = FALSE;

        infof(data, "We can reuse, but we want a new connection anyway\n");
      }
    }
  }

  if(reuse) {
    /*
     * We already have a connection for this, we got the former connection
     * in the conn_temp variable and thus we need to cleanup the one we
     * just allocated before we can move along and use the previously
     * existing one.
     */
    conn_temp->inuse = TRUE; /* mark this as being in use so that no other
                                handle in a multi stack may nick it */
    reuse_conn(conn, conn_temp);
    free(conn);          /* we don't need this anymore */
    conn = conn_temp;
    *in_connect = conn;

    /* set a pointer to the hostname we display */
    fix_hostname(data, conn, &conn->host);

    infof(data, "Re-using existing connection! (#%ld) with host %s\n",
          conn->connection_id,
          conn->proxy.name?conn->proxy.dispname:conn->host.dispname);
  }
  else {
    /* We have decided that we want a new connection. However, we may not
       be able to do that if we have reached the limit of how many
       connections we are allowed to open. */
    struct connectbundle *bundle;

    bundle = Curl_conncache_find_bundle(data->state.conn_cache,
                                        conn->host.name);
    if(max_host_connections > 0 && bundle &&
       (bundle->num_connections >= max_host_connections)) {
      struct connectdata *conn_candidate;

      /* The bundle is full. Let's see if we can kill a connection. */
      conn_candidate = find_oldest_idle_connection_in_bundle(data, bundle);

      if(conn_candidate) {
        /* Set the connection's owner correctly, then kill it */
        conn_candidate->data = data;
        (void)Curl_disconnect(conn_candidate, /* dead_connection */ FALSE);
      }
      else
        no_connections_available = TRUE;
    }

    if(max_total_connections > 0 &&
       (data->state.conn_cache->num_connections >= max_total_connections)) {
      struct connectdata *conn_candidate;

      /* The cache is full. Let's see if we can kill a connection. */
      conn_candidate = find_oldest_idle_connection(data);

      if(conn_candidate) {
        /* Set the connection's owner correctly, then kill it */
        conn_candidate->data = data;
        (void)Curl_disconnect(conn_candidate, /* dead_connection */ FALSE);
      }
      else
        no_connections_available = TRUE;
    }


    if(no_connections_available) {
      infof(data, "No connections available.\n");

      conn_free(conn);
      *in_connect = NULL;

      return CURLE_NO_CONNECTION_AVAILABLE;
    }
    else {
      /*
       * This is a brand new connection, so let's store it in the connection
       * cache of ours!
       */
      ConnectionStore(data, conn);
    }
  }

  /* Mark the connection as used */
  conn->inuse = TRUE;

  /* Setup and init stuff before DO starts, in preparing for the transfer. */
  do_init(conn);

  /*
   * Setup whatever necessary for a resumed transfer
   */
  result = setup_range(data);
  if(result)
    return result;

  /* Continue connectdata initialization here. */

  /*
   * Inherit the proper values from the urldata struct AFTER we have arranged
   * the persistent connection stuff
   */
  conn->fread_func = data->set.fread_func;
  conn->fread_in = data->set.in;
  conn->seek_func = data->set.seek_func;
  conn->seek_client = data->set.seek_client;

  /*************************************************************
   * Resolve the address of the server or proxy
   *************************************************************/
  result = resolve_server(data, conn, async);

  return result;
}

/* Curl_setup_conn() is called after the name resolve initiated in
 * create_conn() is all done.
 *
 * Curl_setup_conn() also handles reused connections
 *
 * conn->data MUST already have been setup fine (in create_conn)
 */

CURLcode Curl_setup_conn(struct connectdata *conn,
                         bool *protocol_done)
{
  CURLcode result = CURLE_OK;
  struct SessionHandle *data = conn->data;

  Curl_pgrsTime(data, TIMER_NAMELOOKUP);

  if(conn->handler->flags & PROTOPT_NONETWORK) {
    /* nothing to setup when not using a network */
    *protocol_done = TRUE;
    return result;
  }
  *protocol_done = FALSE; /* default to not done */

  /* set proxy_connect_closed to false unconditionally already here since it
     is used strictly to provide extra information to a parent function in the
     case of proxy CONNECT failures and we must make sure we don't have it
     lingering set from a previous invoke */
  conn->bits.proxy_connect_closed = FALSE;

  /*
   * Set user-agent. Used for HTTP, but since we can attempt to tunnel
   * basically anything through a http proxy we can't limit this based on
   * protocol.
   */
  if(data->set.str[STRING_USERAGENT]) {
    Curl_safefree(conn->allocptr.uagent);
    conn->allocptr.uagent =
      aprintf("User-Agent: %s\r\n", data->set.str[STRING_USERAGENT]);
    if(!conn->allocptr.uagent)
      return CURLE_OUT_OF_MEMORY;
  }

  data->req.headerbytecount = 0;

#ifdef CURL_DO_LINEEND_CONV
  data->state.crlf_conversions = 0; /* reset CRLF conversion counter */
#endif /* CURL_DO_LINEEND_CONV */

  /* set start time here for timeout purposes in the connect procedure, it
     is later set again for the progress meter purpose */
  conn->now = Curl_tvnow();

  for(;;) {
    /* loop for CURL_SERVER_CLOSED_CONNECTION */

    if(CURL_SOCKET_BAD == conn->sock[FIRSTSOCKET]) {
      /* Try to connect only if not already connected */
      bool connected = FALSE;

      result = ConnectPlease(data, conn, &connected);

      if(result && !conn->ip_addr) {
        /* transport connection failure not related with authentication */
        conn->bits.tcpconnect[FIRSTSOCKET] = FALSE;
        return result;
      }

      if(connected) {
        result = Curl_protocol_connect(conn, protocol_done);
        if(CURLE_OK == result)
          conn->bits.tcpconnect[FIRSTSOCKET] = TRUE;
      }
      else
        conn->bits.tcpconnect[FIRSTSOCKET] = FALSE;

      /* if the connection was closed by the server while exchanging
         authentication informations, retry with the new set
         authentication information */
      if(conn->bits.proxy_connect_closed) {
        /* reset the error buffer */
        if(data->set.errorbuffer)
          data->set.errorbuffer[0] = '\0';
        data->state.errorbuf = FALSE;
        continue;
      }

      if(CURLE_OK != result)
        return result;
    }
    else {
      Curl_pgrsTime(data, TIMER_CONNECT); /* we're connected already */
      Curl_pgrsTime(data, TIMER_APPCONNECT); /* we're connected already */
      conn->bits.tcpconnect[FIRSTSOCKET] = TRUE;
      *protocol_done = TRUE;
      Curl_verboseconnect(conn);
      Curl_updateconninfo(conn, conn->sock[FIRSTSOCKET]);
    }
    /* Stop the loop now */
    break;
  }

  conn->now = Curl_tvnow(); /* time this *after* the connect is done, we
                               set this here perhaps a second time */

#ifdef __EMX__
  /*
   * This check is quite a hack. We're calling _fsetmode to fix the problem
   * with fwrite converting newline characters (you get mangled text files,
   * and corrupted binary files when you download to stdout and redirect it to
   * a file).
   */

  if((data->set.out)->_handle == NULL) {
    _fsetmode(stdout, "b");
  }
#endif

  return result;
}

CURLcode Curl_connect(struct SessionHandle *data,
                      struct connectdata **in_connect,
                      bool *asyncp,
                      bool *protocol_done)
{
  CURLcode code;

  *asyncp = FALSE; /* assume synchronous resolves by default */

  /* call the stuff that needs to be called */
  code = create_conn(data, in_connect, asyncp);

  if(CURLE_OK == code) {
    /* no error */
    if((*in_connect)->send_pipe->size || (*in_connect)->recv_pipe->size)
      /* pipelining */
      *protocol_done = TRUE;
    else if(!*asyncp) {
      /* DNS resolution is done: that's either because this is a reused
         connection, in which case DNS was unnecessary, or because DNS
         really did finish already (synch resolver/fast async resolve) */
      code = Curl_setup_conn(*in_connect, protocol_done);
    }
  }

  if(code == CURLE_NO_CONNECTION_AVAILABLE) {
    *in_connect = NULL;
    return code;
  }

  if(code && *in_connect) {
    /* We're not allowed to return failure with memory left allocated
       in the connectdata struct, free those here */
    Curl_disconnect(*in_connect, FALSE); /* close the connection */
    *in_connect = NULL;           /* return a NULL */
  }

  return code;
}

CURLcode Curl_done(struct connectdata **connp,
                   CURLcode status,  /* an error if this is called after an
                                        error was detected */
                   bool premature)
{
  CURLcode result;
  struct connectdata *conn;
  struct SessionHandle *data;

  DEBUGASSERT(*connp);

  conn = *connp;
  data = conn->data;

  if(conn->bits.done)
    /* Stop if Curl_done() has already been called */
    return CURLE_OK;

  Curl_getoff_all_pipelines(data, conn);

  if((conn->send_pipe->size + conn->recv_pipe->size != 0 &&
      !data->set.reuse_forbid &&
      !conn->bits.close))
    /* Stop if pipeline is not empty and we do not have to close
       connection. */
    return CURLE_OK;

  conn->bits.done = TRUE; /* called just now! */

  /* Cleanup possible redirect junk */
  if(data->req.newurl) {
    free(data->req.newurl);
    data->req.newurl = NULL;
  }
  if(data->req.location) {
    free(data->req.location);
    data->req.location = NULL;
  }

  Curl_resolver_cancel(conn);

  if(conn->dns_entry) {
    Curl_resolv_unlock(data, conn->dns_entry); /* done with this */
    conn->dns_entry = NULL;
  }

  if(status == CURLE_ABORTED_BY_CALLBACK)
    /* When we're aborted due to a callback return code it basically have to
       be counted as premature as there is trouble ahead if we don't. We have
       many callbacks and protocols work differently, we could potentially do
       this more fine-grained in the future. */
    premature = TRUE;

  /* this calls the protocol-specific function pointer previously set */
  if(conn->handler->done)
    result = conn->handler->done(conn, status, premature);
  else
    result = CURLE_OK;

  if(Curl_pgrsDone(conn) && !result)
    result = CURLE_ABORTED_BY_CALLBACK;

  /* if the transfer was completed in a paused state there can be buffered
     data left to write and then kill */
  if(data->state.tempwrite) {
    free(data->state.tempwrite);
    data->state.tempwrite = NULL;
  }

  /* if data->set.reuse_forbid is TRUE, it means the libcurl client has
     forced us to close this no matter what we think.

     if conn->bits.close is TRUE, it means that the connection should be
     closed in spite of all our efforts to be nice, due to protocol
     restrictions in our or the server's end

     if premature is TRUE, it means this connection was said to be DONE before
     the entire request operation is complete and thus we can't know in what
     state it is for re-using, so we're forced to close it. In a perfect world
     we can add code that keep track of if we really must close it here or not,
     but currently we have no such detail knowledge.
  */
  if(data->set.reuse_forbid || conn->bits.close || premature) {
    CURLcode res2 = Curl_disconnect(conn, premature); /* close connection */

    /* If we had an error already, make sure we return that one. But
       if we got a new error, return that. */
    if(!result && res2)
      result = res2;
  }
  else {
    /* the connection is no longer in use */
    if(ConnectionDone(data, conn)) {
      /* remember the most recently used connection */
      data->state.lastconnect = conn;

      infof(data, "Connection #%ld to host %s left intact\n",
            conn->connection_id,
            conn->bits.httpproxy?conn->proxy.dispname:conn->host.dispname);
    }
    else
      data->state.lastconnect = NULL;
  }

  *connp = NULL; /* to make the caller of this function better detect that
                    this was either closed or handed over to the connection
                    cache here, and therefore cannot be used from this point on
                 */

  return result;
}

/*
 * do_init() inits the readwrite session. This is inited each time (in the DO
 * function before the protocol-specific DO functions are invoked) for a
 * transfer, sometimes multiple times on the same SessionHandle. Make sure
 * nothing in here depends on stuff that are setup dynamically for the
 * transfer.
 */

static CURLcode do_init(struct connectdata *conn)
{
  struct SessionHandle *data = conn->data;
  struct SingleRequest *k = &data->req;

  conn->bits.done = FALSE; /* Curl_done() is not called yet */
  conn->bits.do_more = FALSE; /* by default there's no curl_do_more() to use */
  data->state.expect100header = FALSE;

  if(data->set.opt_no_body)
    /* in HTTP lingo, no body means using the HEAD request... */
    data->set.httpreq = HTTPREQ_HEAD;
  else if(HTTPREQ_HEAD == data->set.httpreq)
    /* ... but if unset there really is no perfect method that is the
       "opposite" of HEAD but in reality most people probably think GET
       then. The important thing is that we can't let it remain HEAD if the
       opt_no_body is set FALSE since then we'll behave wrong when getting
       HTTP. */
    data->set.httpreq = HTTPREQ_GET;

  /* NB: the content encoding software depends on this initialization */
  Curl_easy_initHandleData(data);

  k->start = Curl_tvnow(); /* start time */
  k->now = k->start;   /* current time is now */
  k->header = TRUE; /* assume header */

  k->bytecount = 0;

  k->buf = data->state.buffer;
  k->uploadbuf = data->state.uploadbuffer;
  k->hbufp = data->state.headerbuff;
  k->ignorebody=FALSE;

  Curl_speedinit(data);

  Curl_pgrsSetUploadCounter(data, 0);
  Curl_pgrsSetDownloadCounter(data, 0);

  return CURLE_OK;
}

/*
 * do_complete is called when the DO actions are complete.
 *
 * We init chunking and trailer bits to their default values here immediately
 * before receiving any header data for the current request in the pipeline.
 */
static void do_complete(struct connectdata *conn)
{
  conn->data->req.chunk=FALSE;
  conn->data->req.maxfd = (conn->sockfd>conn->writesockfd?
                           conn->sockfd:conn->writesockfd)+1;
  Curl_pgrsTime(conn->data, TIMER_PRETRANSFER);
}

CURLcode Curl_do(struct connectdata **connp, bool *done)
{
  CURLcode result=CURLE_OK;
  struct connectdata *conn = *connp;
  struct SessionHandle *data = conn->data;

  if(conn->handler->do_it) {
    /* generic protocol-specific function pointer set in curl_connect() */
    result = conn->handler->do_it(conn, done);

    /* This was formerly done in transfer.c, but we better do it here */
    if((CURLE_SEND_ERROR == result) && conn->bits.reuse) {
      /*
       * If the connection is using an easy handle, call reconnect
       * to re-establish the connection.  Otherwise, let the multi logic
       * figure out how to re-establish the connection.
       */
      if(!data->multi) {
        result = Curl_reconnect_request(connp);

        if(result == CURLE_OK) {
          /* ... finally back to actually retry the DO phase */
          conn = *connp; /* re-assign conn since Curl_reconnect_request
                            creates a new connection */
          result = conn->handler->do_it(conn, done);
        }
      }
      else
        return result;
    }

    if((result == CURLE_OK) && *done)
      /* do_complete must be called after the protocol-specific DO function */
      do_complete(conn);
  }
  return result;
}

/*
 * Curl_do_more() is called during the DO_MORE multi state. It is basically a
 * second stage DO state which (wrongly) was introduced to support FTP's
 * second connection.
 *
 * TODO: A future libcurl should be able to work away this state.
 *
 */

CURLcode Curl_do_more(struct connectdata *conn, bool *completed)
{
  CURLcode result=CURLE_OK;

  *completed = FALSE;

  if(conn->handler->do_more)
    result = conn->handler->do_more(conn, completed);

  if(!result && *completed)
    /* do_complete must be called after the protocol-specific DO function */
    do_complete(conn);

  return result;
}

/* Called on connect, and if there's already a protocol-specific struct
   allocated for a different connection, this frees it that it can be setup
   properly later on. */
void Curl_reset_reqproto(struct connectdata *conn)
{
  struct SessionHandle *data = conn->data;
  if(data->state.proto.generic && data->state.current_conn != conn) {
    free(data->state.proto.generic);
    data->state.proto.generic = NULL;
  }
  data->state.current_conn = conn;
}
