/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) 1998 - 2019, Daniel Stenberg, <daniel@haxx.se>, et al.
 *
 * This software is licensed as described in the file COPYING, which
 * you should have received as part of this distribution. The terms
 * are also available at https://curl.haxx.se/docs/copyright.html.
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
#ifdef HAVE_IPHLPAPI_H
#include <Iphlpapi.h>
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

#ifdef HAVE_SYS_UN_H
#include <sys/un.h>
#endif

#ifndef HAVE_SOCKET
#error "We can't compile without socket() support!"
#endif

#include <limits.h>

#ifdef USE_LIBIDN2
#include <idn2.h>

#elif defined(USE_WIN32_IDN)
/* prototype for curl_win32_idn_to_ascii() */
bool curl_win32_idn_to_ascii(const char *in, char **out);
#endif  /* USE_LIBIDN2 */

#include "urldata.h"
#include "netrc.h"

#include "formdata.h"
#include "mime.h"
#include "vtls/vtls.h"
#include "hostip.h"
#include "transfer.h"
#include "sendf.h"
#include "progress.h"
#include "cookie.h"
#include "strcase.h"
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
#include "warnless.h"
#include "non-ascii.h"
#include "inet_pton.h"
#include "getinfo.h"
#include "urlapi-int.h"
#include "system_win32.h"

/* And now for the protocols */
#include "ftp.h"
#include "dict.h"
#include "telnet.h"
#include "tftp.h"
#include "http.h"
#include "http2.h"
#include "file.h"
#include "curl_ldap.h"
#include "ssh.h"
#include "imap.h"
#include "url.h"
#include "connect.h"
#include "inet_ntop.h"
#include "http_ntlm.h"
#include "socks.h"
#include "curl_rtmp.h"
#include "gopher.h"
#include "http_proxy.h"
#include "conncache.h"
#include "multihandle.h"
#include "dotdot.h"
#include "strdup.h"
#include "setopt.h"
#include "altsvc.h"

/* The last 3 #include files should be in this order */
#include "curl_printf.h"
#include "curl_memory.h"
#include "memdebug.h"

static void conn_free(struct connectdata *conn);
static void free_idnconverted_hostname(struct hostname *host);
static unsigned int get_protocol_family(unsigned int protocol);

/* Some parts of the code (e.g. chunked encoding) assume this buffer has at
 * more than just a few bytes to play with. Don't let it become too small or
 * bad things will happen.
 */
#if READBUFFER_SIZE < READBUFFER_MIN
# error READBUFFER_SIZE is too small
#endif


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

#if defined(USE_SSH)
  &Curl_handler_scp,
#endif

#if defined(USE_SSH)
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

#if !defined(CURL_DISABLE_SMB) && defined(USE_NTLM) && \
   (CURL_SIZEOF_CURL_OFF_T > 4) && \
   (!defined(USE_WINDOWS_SSPI) || defined(USE_WIN32_CRYPTO))
  &Curl_handler_smb,
#ifdef USE_SSL
  &Curl_handler_smbs,
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
  ZERO_NULL,                            /* connection_check */
  0,                                    /* defport */
  0,                                    /* protocol */
  PROTOPT_NONE                          /* flags */
};

void Curl_freeset(struct Curl_easy *data)
{
  /* Free all dynamic strings stored in the data->set substructure. */
  enum dupstring i;
  for(i = (enum dupstring)0; i < STRING_LAST; i++) {
    Curl_safefree(data->set.str[i]);
  }

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

  Curl_mime_cleanpart(&data->set.mimepost);
}

/* free the URL pieces */
static void up_free(struct Curl_easy *data)
{
  struct urlpieces *up = &data->state.up;
  Curl_safefree(up->scheme);
  Curl_safefree(up->hostname);
  Curl_safefree(up->port);
  Curl_safefree(up->user);
  Curl_safefree(up->password);
  Curl_safefree(up->options);
  Curl_safefree(up->path);
  Curl_safefree(up->query);
  curl_url_cleanup(data->state.uh);
  data->state.uh = NULL;
}

/*
 * This is the internal function curl_easy_cleanup() calls. This should
 * cleanup and free all resources associated with this sessionhandle.
 *
 * NOTE: if we ever add something that attempts to write to a socket or
 * similar here, we must ignore SIGPIPE first. It is currently only done
 * when curl_easy_perform() is invoked.
 */

CURLcode Curl_close(struct Curl_easy *data)
{
  struct Curl_multi *m;

  if(!data)
    return CURLE_OK;

  Curl_expire_clear(data); /* shut off timers */

  m = data->multi;
  if(m)
    /* This handle is still part of a multi handle, take care of this first
       and detach this handle from there. */
    curl_multi_remove_handle(data->multi, data);

  if(data->multi_easy) {
    /* when curl_easy_perform() is used, it creates its own multi handle to
       use and this is the one */
    curl_multi_cleanup(data->multi_easy);
    data->multi_easy = NULL;
  }

  /* Destroy the timeout list that is held in the easy handle. It is
     /normally/ done by curl_multi_remove_handle() but this is "just in
     case" */
  Curl_llist_destroy(&data->state.timeoutlist, NULL);

  data->magic = 0; /* force a clear AFTER the possibly enforced removal from
                      the multi handle, since that function uses the magic
                      field! */

  if(data->state.rangestringalloc)
    free(data->state.range);

  /* freed here just in case DONE wasn't called */
  Curl_free_request_state(data);

  /* Close down all open SSL info and sessions */
  Curl_ssl_close_all(data);
  Curl_safefree(data->state.first_host);
  Curl_safefree(data->state.scratch);
  Curl_ssl_free_certinfo(data);

  /* Cleanup possible redirect junk */
  free(data->req.newurl);
  data->req.newurl = NULL;

  if(data->change.referer_alloc) {
    Curl_safefree(data->change.referer);
    data->change.referer_alloc = FALSE;
  }
  data->change.referer = NULL;

  up_free(data);
  Curl_safefree(data->state.buffer);
  Curl_safefree(data->state.headerbuff);
  Curl_safefree(data->state.ulbuf);
  Curl_flush_cookies(data, 1);
#ifdef USE_ALTSVC
  Curl_altsvc_save(data->asi, data->set.str[STRING_ALTSVC]);
  Curl_altsvc_cleanup(data->asi);
  data->asi = NULL;
#endif
#if !defined(CURL_DISABLE_HTTP) && !defined(CURL_DISABLE_CRYPTO_AUTH)
  Curl_http_auth_cleanup_digest(data);
#endif
  Curl_safefree(data->info.contenttype);
  Curl_safefree(data->info.wouldredirect);

  /* this destroys the channel and we cannot use it anymore after this */
  Curl_resolver_cleanup(data->state.resolver);

  Curl_http2_cleanup_dependencies(data);
  Curl_convert_close(data);

  /* No longer a dirty share, if it exists */
  if(data->share) {
    Curl_share_lock(data, CURL_LOCK_DATA_SHARE, CURL_LOCK_ACCESS_SINGLE);
    data->share->dirty--;
    Curl_share_unlock(data, CURL_LOCK_DATA_SHARE);
  }

  /* destruct wildcard structures if it is needed */
  Curl_wildcard_dtor(&data->wildcard);
  Curl_freeset(data);
  free(data);
  return CURLE_OK;
}

/*
 * Initialize the UserDefined fields within a Curl_easy.
 * This may be safely called on a new or existing Curl_easy.
 */
CURLcode Curl_init_userdefined(struct Curl_easy *data)
{
  struct UserDefined *set = &data->set;
  CURLcode result = CURLE_OK;

  set->out = stdout; /* default output to stdout */
  set->in_set = stdin;  /* default input from stdin */
  set->err  = stderr;  /* default stderr to stderr */

  /* use fwrite as default function to store output */
  set->fwrite_func = (curl_write_callback)fwrite;

  /* use fread as default function to read input */
  set->fread_func_set = (curl_read_callback)fread;
  set->is_fread_set = 0;
  set->is_fwrite_set = 0;

  set->seek_func = ZERO_NULL;
  set->seek_client = ZERO_NULL;

  /* conversion callbacks for non-ASCII hosts */
  set->convfromnetwork = ZERO_NULL;
  set->convtonetwork   = ZERO_NULL;
  set->convfromutf8    = ZERO_NULL;

  set->filesize = -1;        /* we don't know the size */
  set->postfieldsize = -1;   /* unknown size */
  set->maxredirs = -1;       /* allow any amount by default */

  set->httpreq = HTTPREQ_GET; /* Default HTTP request */
  set->rtspreq = RTSPREQ_OPTIONS; /* Default RTSP request */
#ifndef CURL_DISABLE_FTP
  set->ftp_use_epsv = TRUE;   /* FTP defaults to EPSV operations */
  set->ftp_use_eprt = TRUE;   /* FTP defaults to EPRT operations */
  set->ftp_use_pret = FALSE;  /* mainly useful for drftpd servers */
  set->ftp_filemethod = FTPFILE_MULTICWD;
#endif
  set->dns_cache_timeout = 60; /* Timeout every 60 seconds by default */

  /* Set the default size of the SSL session ID cache */
  set->general_ssl.max_ssl_sessions = 5;

  set->proxyport = 0;
  set->proxytype = CURLPROXY_HTTP; /* defaults to HTTP proxy */
  set->httpauth = CURLAUTH_BASIC;  /* defaults to basic */
  set->proxyauth = CURLAUTH_BASIC; /* defaults to basic */

  /* SOCKS5 proxy auth defaults to username/password + GSS-API */
  set->socks5auth = CURLAUTH_BASIC | CURLAUTH_GSSAPI;

  /* make libcurl quiet by default: */
  set->hide_progress = TRUE;  /* CURLOPT_NOPROGRESS changes these */

  Curl_mime_initpart(&set->mimepost, data);

  /*
   * libcurl 7.10 introduced SSL verification *by default*! This needs to be
   * switched off unless wanted.
   */
  set->ssl.primary.verifypeer = TRUE;
  set->ssl.primary.verifyhost = TRUE;
#ifdef USE_TLS_SRP
  set->ssl.authtype = CURL_TLSAUTH_NONE;
#endif
  set->ssh_auth_types = CURLSSH_AUTH_DEFAULT; /* defaults to any auth
                                                      type */
  set->ssl.primary.sessionid = TRUE; /* session ID caching enabled by
                                        default */
  set->proxy_ssl = set->ssl;

  set->new_file_perms = 0644;    /* Default permissions */
  set->new_directory_perms = 0755; /* Default permissions */

  /* for the *protocols fields we don't use the CURLPROTO_ALL convenience
     define since we internally only use the lower 16 bits for the passed
     in bitmask to not conflict with the private bits */
  set->allowed_protocols = CURLPROTO_ALL;
  set->redir_protocols = CURLPROTO_HTTP | CURLPROTO_HTTPS | CURLPROTO_FTP |
                         CURLPROTO_FTPS;

#if defined(HAVE_GSSAPI) || defined(USE_WINDOWS_SSPI)
  /*
   * disallow unprotected protection negotiation NEC reference implementation
   * seem not to follow rfc1961 section 4.3/4.4
   */
  set->socks5_gssapi_nec = FALSE;
#endif

  /* Set the default CA cert bundle/path detected/specified at build time.
   *
   * If Schannel is the selected SSL backend then these locations are
   * ignored. We allow setting CA location for schannel only when explicitly
   * specified by the user via CURLOPT_CAINFO / --cacert.
   */
  if(Curl_ssl_backend() != CURLSSLBACKEND_SCHANNEL) {
#if defined(CURL_CA_BUNDLE)
    result = Curl_setstropt(&set->str[STRING_SSL_CAFILE_ORIG], CURL_CA_BUNDLE);
    if(result)
      return result;

    result = Curl_setstropt(&set->str[STRING_SSL_CAFILE_PROXY],
                            CURL_CA_BUNDLE);
    if(result)
      return result;
#endif
#if defined(CURL_CA_PATH)
    result = Curl_setstropt(&set->str[STRING_SSL_CAPATH_ORIG], CURL_CA_PATH);
    if(result)
      return result;

    result = Curl_setstropt(&set->str[STRING_SSL_CAPATH_PROXY], CURL_CA_PATH);
    if(result)
      return result;
#endif
  }

  set->wildcard_enabled = FALSE;
  set->chunk_bgn      = ZERO_NULL;
  set->chunk_end      = ZERO_NULL;
  set->tcp_keepalive = FALSE;
  set->tcp_keepintvl = 60;
  set->tcp_keepidle = 60;
  set->tcp_fastopen = FALSE;
  set->tcp_nodelay = TRUE;
  set->ssl_enable_npn = TRUE;
  set->ssl_enable_alpn = TRUE;
  set->expect_100_timeout = 1000L; /* Wait for a second by default. */
  set->sep_headers = TRUE; /* separated header lists by default */
  set->buffer_size = READBUFFER_SIZE;
  set->upload_buffer_size = UPLOADBUFFER_DEFAULT;
  set->happy_eyeballs_timeout = CURL_HET_DEFAULT;
  set->fnmatch = ZERO_NULL;
  set->upkeep_interval_ms = CURL_UPKEEP_INTERVAL_DEFAULT;
  set->maxconnects = DEFAULT_CONNCACHE_SIZE; /* for easy handles */
  set->maxage_conn = 118;
  set->http09_allowed = FALSE;
  set->httpversion =
#ifdef USE_NGHTTP2
    CURL_HTTP_VERSION_2TLS
#else
    CURL_HTTP_VERSION_1_1
#endif
    ;
  Curl_http2_init_userset(set);
  return result;
}

/**
 * Curl_open()
 *
 * @param curl is a pointer to a sessionhandle pointer that gets set by this
 * function.
 * @return CURLcode
 */

CURLcode Curl_open(struct Curl_easy **curl)
{
  CURLcode result;
  struct Curl_easy *data;

  /* Very simple start-up: alloc the struct, init it with zeroes and return */
  data = calloc(1, sizeof(struct Curl_easy));
  if(!data) {
    /* this is a very serious error */
    DEBUGF(fprintf(stderr, "Error: calloc of Curl_easy failed\n"));
    return CURLE_OUT_OF_MEMORY;
  }

  data->magic = CURLEASY_MAGIC_NUMBER;

  result = Curl_resolver_init(data, &data->state.resolver);
  if(result) {
    DEBUGF(fprintf(stderr, "Error: resolver_init failed\n"));
    free(data);
    return result;
  }

  /* We do some initial setup here, all those fields that can't be just 0 */

  data->state.buffer = malloc(READBUFFER_SIZE + 1);
  if(!data->state.buffer) {
    DEBUGF(fprintf(stderr, "Error: malloc of buffer failed\n"));
    result = CURLE_OUT_OF_MEMORY;
  }
  else {
    data->state.headerbuff = malloc(HEADERSIZE);
    if(!data->state.headerbuff) {
      DEBUGF(fprintf(stderr, "Error: malloc of headerbuff failed\n"));
      result = CURLE_OUT_OF_MEMORY;
    }
    else {
      result = Curl_init_userdefined(data);

      data->state.headersize = HEADERSIZE;
      Curl_convert_init(data);
      Curl_initinfo(data);

      /* most recent connection is not yet defined */
      data->state.lastconnect = NULL;

      data->progress.flags |= PGRS_HIDE;
      data->state.current_speed = -1; /* init to negative == impossible */

      Curl_http2_init_state(&data->state);
    }
  }

  if(result) {
    Curl_resolver_cleanup(data->state.resolver);
    free(data->state.buffer);
    free(data->state.headerbuff);
    Curl_freeset(data);
    free(data);
    data = NULL;
  }
  else
    *curl = data;

  return result;
}

#ifdef USE_RECV_BEFORE_SEND_WORKAROUND
static void conn_reset_postponed_data(struct connectdata *conn, int num)
{
  struct postponed_data * const psnd = &(conn->postponed[num]);
  if(psnd->buffer) {
    DEBUGASSERT(psnd->allocated_size > 0);
    DEBUGASSERT(psnd->recv_size <= psnd->allocated_size);
    DEBUGASSERT(psnd->recv_size ?
                (psnd->recv_processed < psnd->recv_size) :
                (psnd->recv_processed == 0));
    DEBUGASSERT(psnd->bindsock != CURL_SOCKET_BAD);
    free(psnd->buffer);
    psnd->buffer = NULL;
    psnd->allocated_size = 0;
    psnd->recv_size = 0;
    psnd->recv_processed = 0;
#ifdef DEBUGBUILD
    psnd->bindsock = CURL_SOCKET_BAD; /* used only for DEBUGASSERT */
#endif /* DEBUGBUILD */
  }
  else {
    DEBUGASSERT(psnd->allocated_size == 0);
    DEBUGASSERT(psnd->recv_size == 0);
    DEBUGASSERT(psnd->recv_processed == 0);
    DEBUGASSERT(psnd->bindsock == CURL_SOCKET_BAD);
  }
}

static void conn_reset_all_postponed_data(struct connectdata *conn)
{
  conn_reset_postponed_data(conn, 0);
  conn_reset_postponed_data(conn, 1);
}
#else  /* ! USE_RECV_BEFORE_SEND_WORKAROUND */
/* Use "do-nothing" macro instead of function when workaround not used */
#define conn_reset_all_postponed_data(c) do {} WHILE_FALSE
#endif /* ! USE_RECV_BEFORE_SEND_WORKAROUND */


static void conn_shutdown(struct connectdata *conn)
{
  if(!conn)
    return;

  infof(conn->data, "Closing connection %ld\n", conn->connection_id);
  DEBUGASSERT(conn->data);

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
  if(CURL_SOCKET_BAD != conn->tempsock[0])
    Curl_closesocket(conn, conn->tempsock[0]);
  if(CURL_SOCKET_BAD != conn->tempsock[1])
    Curl_closesocket(conn, conn->tempsock[1]);

  /* unlink ourselves. this should be called last since other shutdown
     procedures need a valid conn->data and this may clear it. */
  Curl_conncache_remove_conn(conn->data, conn, TRUE);
}

static void conn_free(struct connectdata *conn)
{
  if(!conn)
    return;

  free_idnconverted_hostname(&conn->host);
  free_idnconverted_hostname(&conn->conn_to_host);
  free_idnconverted_hostname(&conn->http_proxy.host);
  free_idnconverted_hostname(&conn->socks_proxy.host);

  Curl_safefree(conn->user);
  Curl_safefree(conn->passwd);
  Curl_safefree(conn->oauth_bearer);
  Curl_safefree(conn->sasl_authzid);
  Curl_safefree(conn->options);
  Curl_safefree(conn->http_proxy.user);
  Curl_safefree(conn->socks_proxy.user);
  Curl_safefree(conn->http_proxy.passwd);
  Curl_safefree(conn->socks_proxy.passwd);
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
  Curl_safefree(conn->conn_to_host.rawalloc); /* host name buffer */
  Curl_safefree(conn->hostname_resolve);
  Curl_safefree(conn->secondaryhostname);
  Curl_safefree(conn->http_proxy.host.rawalloc); /* http proxy name buffer */
  Curl_safefree(conn->socks_proxy.host.rawalloc); /* socks proxy name buffer */
  Curl_safefree(conn->connect_state);

  conn_reset_all_postponed_data(conn);
  Curl_llist_destroy(&conn->easyq, NULL);
  Curl_safefree(conn->localdev);
  Curl_free_primary_ssl_config(&conn->ssl_config);
  Curl_free_primary_ssl_config(&conn->proxy_ssl_config);

#ifdef USE_UNIX_SOCKETS
  Curl_safefree(conn->unix_domain_socket);
#endif

#ifdef USE_SSL
  Curl_safefree(conn->ssl_extra);
#endif
  free(conn); /* free all the connection oriented data */
}

/*
 * Disconnects the given connection. Note the connection may not be the
 * primary connection, like when freeing room in the connection cache or
 * killing of a dead old connection.
 *
 * A connection needs an easy handle when closing down. We support this passed
 * in separately since the connection to get closed here is often already
 * disassociated from an easy handle.
 *
 * This function MUST NOT reset state in the Curl_easy struct if that
 * isn't strictly bound to the life-time of *this* particular connection.
 *
 */

CURLcode Curl_disconnect(struct Curl_easy *data,
                         struct connectdata *conn, bool dead_connection)
{
  if(!conn)
    return CURLE_OK; /* this is closed and fine already */

  if(!data) {
    DEBUGF(infof(data, "DISCONNECT without easy handle, ignoring\n"));
    return CURLE_OK;
  }

  /*
   * If this connection isn't marked to force-close, leave it open if there
   * are other users of it
   */
  if(CONN_INUSE(conn) && !dead_connection) {
    DEBUGF(infof(data, "Curl_disconnect when inuse: %zu\n", CONN_INUSE(conn)));
    return CURLE_OK;
  }

  if(conn->dns_entry != NULL) {
    Curl_resolv_unlock(data, conn->dns_entry);
    conn->dns_entry = NULL;
  }

  Curl_hostcache_prune(data); /* kill old DNS cache entries */

#if !defined(CURL_DISABLE_HTTP) && defined(USE_NTLM)
  /* Cleanup NTLM connection-related data */
  Curl_http_auth_cleanup_ntlm(conn);
#endif
#if !defined(CURL_DISABLE_HTTP) && defined(USE_SPNEGO)
  /* Cleanup NEGOTIATE connection-related data */
  Curl_http_auth_cleanup_negotiate(conn);
#endif

  /* the protocol specific disconnect handler and conn_shutdown need a transfer
     for the connection! */
  conn->data = data;

  if(conn->bits.connect_only)
    /* treat the connection as dead in CONNECT_ONLY situations */
    dead_connection = TRUE;

  if(conn->handler->disconnect)
    /* This is set if protocol-specific cleanups should be made */
    conn->handler->disconnect(conn, dead_connection);

  conn_shutdown(conn);
  conn_free(conn);
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

  sval = SOCKET_READABLE(sock, 0);
  if(sval == 0)
    /* timeout */
    ret_val = FALSE;

  return ret_val;
}

/*
 * IsMultiplexingPossible()
 *
 * Return a bitmask with the available multiplexing options for the given
 * requested connection.
 */
static int IsMultiplexingPossible(const struct Curl_easy *handle,
                                  const struct connectdata *conn)
{
  int avail = 0;

  /* If a HTTP protocol and multiplexing is enabled */
  if((conn->handler->protocol & PROTO_FAMILY_HTTP) &&
     (!conn->bits.protoconnstart || !conn->bits.close)) {

    if(Curl_multiplex_wanted(handle->multi) &&
       (handle->set.httpversion >= CURL_HTTP_VERSION_2))
      /* allows HTTP/2 */
      avail |= CURLPIPE_MULTIPLEX;
  }
  return avail;
}

#ifndef CURL_DISABLE_PROXY
static bool
proxy_info_matches(const struct proxy_info* data,
                   const struct proxy_info* needle)
{
  if((data->proxytype == needle->proxytype) &&
     (data->port == needle->port) &&
     Curl_safe_strcasecompare(data->host.name, needle->host.name))
    return TRUE;

  return FALSE;
}
#else
/* disabled, won't get called */
#define proxy_info_matches(x,y) FALSE
#endif

/* A connection has to have been idle for a shorter time than 'maxage_conn' to
   be subject for reuse. The success rate is just too low after this. */

static bool conn_maxage(struct Curl_easy *data,
                        struct connectdata *conn,
                        struct curltime now)
{
  if(!conn->data) {
    timediff_t idletime = Curl_timediff(now, conn->lastused);
    idletime /= 1000; /* integer seconds is fine */

    if(idletime > data->set.maxage_conn) {
      infof(data, "Too old connection (%ld seconds), disconnect it\n",
            idletime);
      return TRUE;
    }
  }
  return FALSE;
}

/*
 * This function checks if the given connection is dead and extracts it from
 * the connection cache if so.
 *
 * When this is called as a Curl_conncache_foreach() callback, the connection
 * cache lock is held!
 *
 * Returns TRUE if the connection was dead and extracted.
 */
static bool extract_if_dead(struct connectdata *conn,
                            struct Curl_easy *data)
{
  if(!CONN_INUSE(conn) && !conn->data) {
    /* The check for a dead socket makes sense only if the connection isn't in
       use */
    bool dead;
    struct curltime now = Curl_now();
    if(conn_maxage(data, conn, now)) {
      dead = TRUE;
    }
    else if(conn->handler->connection_check) {
      /* The protocol has a special method for checking the state of the
         connection. Use it to check if the connection is dead. */
      unsigned int state;
      struct Curl_easy *olddata = conn->data;
      conn->data = data; /* use this transfer for now */
      state = conn->handler->connection_check(conn, CONNCHECK_ISDEAD);
      conn->data = olddata;
      dead = (state & CONNRESULT_DEAD);
    }
    else {
      /* Use the general method for determining the death of a connection */
      dead = SocketIsDead(conn->sock[FIRSTSOCKET]);
    }

    if(dead) {
      infof(data, "Connection %ld seems to be dead!\n", conn->connection_id);
      Curl_conncache_remove_conn(data, conn, FALSE);
      return TRUE;
    }
  }
  return FALSE;
}

struct prunedead {
  struct Curl_easy *data;
  struct connectdata *extracted;
};

/*
 * Wrapper to use extract_if_dead() function in Curl_conncache_foreach()
 *
 */
static int call_extract_if_dead(struct connectdata *conn, void *param)
{
  struct prunedead *p = (struct prunedead *)param;
  if(extract_if_dead(conn, p->data)) {
    /* stop the iteration here, pass back the connection that was extracted */
    p->extracted = conn;
    return 1;
  }
  return 0; /* continue iteration */
}

/*
 * This function scans the connection cache for half-open/dead connections,
 * closes and removes them.
 * The cleanup is done at most once per second.
 */
static void prune_dead_connections(struct Curl_easy *data)
{
  struct curltime now = Curl_now();
  timediff_t elapsed =
    Curl_timediff(now, data->state.conn_cache->last_cleanup);

  if(elapsed >= 1000L) {
    struct prunedead prune;
    prune.data = data;
    prune.extracted = NULL;
    while(Curl_conncache_foreach(data, data->state.conn_cache, &prune,
                                 call_extract_if_dead)) {
      /* disconnect it */
      (void)Curl_disconnect(data, prune.extracted, /* dead_connection */TRUE);
    }
    data->state.conn_cache->last_cleanup = now;
  }
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
 * The force_reuse flag is set if the connection must be used.
 */
static bool
ConnectionExists(struct Curl_easy *data,
                 struct connectdata *needle,
                 struct connectdata **usethis,
                 bool *force_reuse,
                 bool *waitpipe)
{
  struct connectdata *check;
  struct connectdata *chosen = 0;
  bool foundPendingCandidate = FALSE;
  bool canmultiplex = IsMultiplexingPossible(data, needle);
  struct connectbundle *bundle;
  const char *hostbundle;

#ifdef USE_NTLM
  bool wantNTLMhttp = ((data->state.authhost.want &
                      (CURLAUTH_NTLM | CURLAUTH_NTLM_WB)) &&
                      (needle->handler->protocol & PROTO_FAMILY_HTTP));
  bool wantProxyNTLMhttp = (needle->bits.proxy_user_passwd &&
                           ((data->state.authproxy.want &
                           (CURLAUTH_NTLM | CURLAUTH_NTLM_WB)) &&
                           (needle->handler->protocol & PROTO_FAMILY_HTTP)));
#endif

  *force_reuse = FALSE;
  *waitpipe = FALSE;

  /* Look up the bundle with all the connections to this particular host.
     Locks the connection cache, beware of early returns! */
  bundle = Curl_conncache_find_bundle(needle, data->state.conn_cache,
                                      &hostbundle);
  if(bundle) {
    /* Max pipe length is zero (unlimited) for multiplexed connections */
    struct curl_llist_element *curr;

    infof(data, "Found bundle for host %s: %p [%s]\n",
          hostbundle, (void *)bundle, (bundle->multiuse == BUNDLE_MULTIPLEX ?
                                       "can multiplex" : "serially"));

    /* We can't multiplex if we don't know anything about the server */
    if(canmultiplex) {
      if(bundle->multiuse == BUNDLE_UNKNOWN) {
        if((bundle->multiuse == BUNDLE_UNKNOWN) && data->set.pipewait) {
          infof(data, "Server doesn't support multiplex yet, wait\n");
          *waitpipe = TRUE;
          Curl_conncache_unlock(data);
          return FALSE; /* no re-use */
        }

        infof(data, "Server doesn't support multiplex (yet)\n");
        canmultiplex = FALSE;
      }
      if((bundle->multiuse == BUNDLE_MULTIPLEX) &&
         !Curl_multiplex_wanted(data->multi)) {
        infof(data, "Could multiplex, but not asked to!\n");
        canmultiplex = FALSE;
      }
      if(bundle->multiuse == BUNDLE_NO_MULTIUSE) {
        infof(data, "Can not multiplex, even if we wanted to!\n");
        canmultiplex = FALSE;
      }
    }

    curr = bundle->conn_list.head;
    while(curr) {
      bool match = FALSE;
      size_t multiplexed;

      /*
       * Note that if we use a HTTP proxy in normal mode (no tunneling), we
       * check connections to that proxy and not to the actual remote server.
       */
      check = curr->ptr;
      curr = curr->next;

      if(check->bits.connect_only)
        /* connect-only connections will not be reused */
        continue;

      multiplexed = CONN_INUSE(check) &&
        (bundle->multiuse == BUNDLE_MULTIPLEX);

      if(canmultiplex) {
        if(check->bits.protoconnstart && check->bits.close)
          continue;
      }
      else {
        if(multiplexed) {
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
          if(!check->bits.close)
            foundPendingCandidate = TRUE;
          /* Don't pick a connection that hasn't connected yet or that is going
             to get closed. */
          infof(data, "Connection #%ld isn't open enough, can't reuse\n",
                check->connection_id);
          continue;
        }
      }

#ifdef USE_UNIX_SOCKETS
      if(needle->unix_domain_socket) {
        if(!check->unix_domain_socket)
          continue;
        if(strcmp(needle->unix_domain_socket, check->unix_domain_socket))
          continue;
        if(needle->abstract_unix_socket != check->abstract_unix_socket)
          continue;
      }
      else if(check->unix_domain_socket)
        continue;
#endif

      if((needle->handler->flags&PROTOPT_SSL) !=
         (check->handler->flags&PROTOPT_SSL))
        /* don't do mixed SSL and non-SSL connections */
        if(get_protocol_family(check->handler->protocol) !=
           needle->handler->protocol || !check->tls_upgraded)
          /* except protocols that have been upgraded via TLS */
          continue;

      if(needle->bits.httpproxy != check->bits.httpproxy ||
         needle->bits.socksproxy != check->bits.socksproxy)
        continue;

      if(needle->bits.socksproxy && !proxy_info_matches(&needle->socks_proxy,
                                                        &check->socks_proxy))
        continue;

      if(needle->bits.conn_to_host != check->bits.conn_to_host)
        /* don't mix connections that use the "connect to host" feature and
         * connections that don't use this feature */
        continue;

      if(needle->bits.conn_to_port != check->bits.conn_to_port)
        /* don't mix connections that use the "connect to port" feature and
         * connections that don't use this feature */
        continue;

      if(needle->bits.httpproxy) {
        if(!proxy_info_matches(&needle->http_proxy, &check->http_proxy))
          continue;

        if(needle->bits.tunnel_proxy != check->bits.tunnel_proxy)
          continue;

        if(needle->http_proxy.proxytype == CURLPROXY_HTTPS) {
          /* use https proxy */
          if(needle->handler->flags&PROTOPT_SSL) {
            /* use double layer ssl */
            if(!Curl_ssl_config_matches(&needle->proxy_ssl_config,
                                        &check->proxy_ssl_config))
              continue;
            if(check->proxy_ssl[FIRSTSOCKET].state != ssl_connection_complete)
              continue;
          }
          else {
            if(!Curl_ssl_config_matches(&needle->ssl_config,
                                        &check->ssl_config))
              continue;
            if(check->ssl[FIRSTSOCKET].state != ssl_connection_complete)
              continue;
          }
        }
      }

      if(!canmultiplex && check->data)
        /* this request can't be multiplexed but the checked connection is
           already in use so we skip it */
        continue;

      if(CONN_INUSE(check) && check->data &&
         (check->data->multi != needle->data->multi))
        /* this could be subject for multiplex use, but only if they belong to
         * the same multi handle */
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
           (needle->localdev &&
            (!check->localdev || strcmp(check->localdev, needle->localdev))))
          continue;
      }

      if(!(needle->handler->flags & PROTOPT_CREDSPERREQUEST)) {
        /* This protocol requires credentials per connection,
           so verify that we're using the same name and password as well */
        if(strcmp(needle->user, check->user) ||
           strcmp(needle->passwd, check->passwd)) {
          /* one of them was different */
          continue;
        }
      }

      if(!needle->bits.httpproxy || (needle->handler->flags&PROTOPT_SSL) ||
         needle->bits.tunnel_proxy) {
        /* The requested connection does not use a HTTP proxy or it uses SSL or
           it is a non-SSL protocol tunneled or it is a non-SSL protocol which
           is allowed to be upgraded via TLS */

        if((strcasecompare(needle->handler->scheme, check->handler->scheme) ||
            (get_protocol_family(check->handler->protocol) ==
             needle->handler->protocol && check->tls_upgraded)) &&
           (!needle->bits.conn_to_host || strcasecompare(
            needle->conn_to_host.name, check->conn_to_host.name)) &&
           (!needle->bits.conn_to_port ||
             needle->conn_to_port == check->conn_to_port) &&
           strcasecompare(needle->host.name, check->host.name) &&
           needle->remote_port == check->remote_port) {
          /* The schemes match or the the protocol family is the same and the
             previous connection was TLS upgraded, and the hostname and host
             port match */
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
            if(check->ssl[FIRSTSOCKET].state != ssl_connection_complete) {
              foundPendingCandidate = TRUE;
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
      else {
        /* The requested connection is using the same HTTP proxy in normal
           mode (no tunneling) */
        match = TRUE;
      }

      if(match) {
#if defined(USE_NTLM)
        /* If we are looking for an HTTP+NTLM connection, check if this is
           already authenticating with the right credentials. If not, keep
           looking so that we can reuse NTLM connections if
           possible. (Especially we must not reuse the same connection if
           partway through a handshake!) */
        if(wantNTLMhttp) {
          if(strcmp(needle->user, check->user) ||
             strcmp(needle->passwd, check->passwd))
            continue;
        }
        else if(check->http_ntlm_state != NTLMSTATE_NONE) {
          /* Connection is using NTLM auth but we don't want NTLM */
          continue;
        }

        /* Same for Proxy NTLM authentication */
        if(wantProxyNTLMhttp) {
          /* Both check->http_proxy.user and check->http_proxy.passwd can be
           * NULL */
          if(!check->http_proxy.user || !check->http_proxy.passwd)
            continue;

          if(strcmp(needle->http_proxy.user, check->http_proxy.user) ||
             strcmp(needle->http_proxy.passwd, check->http_proxy.passwd))
            continue;
        }
        else if(check->proxy_ntlm_state != NTLMSTATE_NONE) {
          /* Proxy connection is using NTLM auth but we don't want NTLM */
          continue;
        }

        if(wantNTLMhttp || wantProxyNTLMhttp) {
          /* Credentials are already checked, we can use this connection */
          chosen = check;

          if((wantNTLMhttp &&
             (check->http_ntlm_state != NTLMSTATE_NONE)) ||
              (wantProxyNTLMhttp &&
               (check->proxy_ntlm_state != NTLMSTATE_NONE))) {
            /* We must use this connection, no other */
            *force_reuse = TRUE;
            break;
          }

          /* Continue look up for a better connection */
          continue;
        }
#endif
        if(canmultiplex) {
          /* We can multiplex if we want to. Let's continue looking for
             the optimal connection to use. */

          if(!multiplexed) {
            /* We have the optimal connection. Let's stop looking. */
            chosen = check;
            break;
          }

#ifdef USE_NGHTTP2
          /* If multiplexed, make sure we don't go over concurrency limit */
          if(check->bits.multiplex) {
            /* Multiplexed connections can only be HTTP/2 for now */
            struct http_conn *httpc = &check->proto.httpc;
            if(multiplexed >= httpc->settings.max_concurrent_streams) {
              infof(data, "MAX_CONCURRENT_STREAMS reached, skip (%zu)\n",
                    multiplexed);
              continue;
            }
          }
#endif
          /* When not multiplexed, we have a match here! */
          chosen = check;
          infof(data, "Multiplexed connection found!\n");
          break;
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
    /* mark it as used before releasing the lock */
    chosen->data = data; /* own it! */
    Curl_conncache_unlock(data);
    *usethis = chosen;
    return TRUE; /* yes, we found one to use! */
  }
  Curl_conncache_unlock(data);

  if(foundPendingCandidate && data->set.pipewait) {
    infof(data,
          "Found pending candidate for reuse and CURLOPT_PIPEWAIT is set\n");
    *waitpipe = TRUE;
  }

  return FALSE; /* no matching connecting exists */
}

/* after a TCP connection to the proxy has been verified, this function does
   the next magic step.

   Note: this function's sub-functions call failf()

*/
CURLcode Curl_connected_proxy(struct connectdata *conn, int sockindex)
{
  CURLcode result = CURLE_OK;

  if(conn->bits.socksproxy) {
#ifndef CURL_DISABLE_PROXY
    /* for the secondary socket (FTP), use the "connect to host"
     * but ignore the "connect to port" (use the secondary port)
     */
    const char * const host = conn->bits.httpproxy ?
                              conn->http_proxy.host.name :
                              conn->bits.conn_to_host ?
                              conn->conn_to_host.name :
                              sockindex == SECONDARYSOCKET ?
                              conn->secondaryhostname : conn->host.name;
    const int port = conn->bits.httpproxy ? (int)conn->http_proxy.port :
                     sockindex == SECONDARYSOCKET ? conn->secondary_port :
                     conn->bits.conn_to_port ? conn->conn_to_port :
                     conn->remote_port;
    conn->bits.socksproxy_connecting = TRUE;
    switch(conn->socks_proxy.proxytype) {
    case CURLPROXY_SOCKS5:
    case CURLPROXY_SOCKS5_HOSTNAME:
      result = Curl_SOCKS5(conn->socks_proxy.user, conn->socks_proxy.passwd,
                         host, port, sockindex, conn);
      break;

    case CURLPROXY_SOCKS4:
    case CURLPROXY_SOCKS4A:
      result = Curl_SOCKS4(conn->socks_proxy.user, host, port, sockindex,
                           conn);
      break;

    default:
      failf(conn->data, "unknown proxytype option given");
      result = CURLE_COULDNT_CONNECT;
    } /* switch proxytype */
    conn->bits.socksproxy_connecting = FALSE;
#else
  (void)sockindex;
#endif /* CURL_DISABLE_PROXY */
  }

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
          conn->bits.socksproxy ? conn->socks_proxy.host.dispname :
          conn->bits.httpproxy ? conn->http_proxy.host.dispname :
          conn->bits.conn_to_host ? conn->conn_to_host.dispname :
          conn->host.dispname,
          conn->ip_addr_str, conn->port, conn->connection_id);
}
#endif

int Curl_protocol_getsock(struct connectdata *conn,
                          curl_socket_t *socks)
{
  if(conn->handler->proto_getsock)
    return conn->handler->proto_getsock(conn, socks);
  /* Backup getsock logic. Since there is a live socket in use, we must wait
     for it or it will be removed from watching when the multi_socket API is
     used. */
  socks[0] = conn->sock[FIRSTSOCKET];
  return GETSOCK_READSOCK(0) | GETSOCK_WRITESOCK(0);
}

int Curl_doing_getsock(struct connectdata *conn,
                       curl_socket_t *socks)
{
  if(conn && conn->handler->doing_getsock)
    return conn->handler->doing_getsock(conn, socks);
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
  CURLcode result = CURLE_OK;

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
  CURLcode result = CURLE_OK;

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
  CURLcode result = CURLE_OK;

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

    result = Curl_proxy_connect(conn, FIRSTSOCKET);
    if(result)
      return result;

    if(CONNECT_FIRSTSOCKET_PROXY_SSL())
      /* wait for HTTPS proxy SSL initialization to complete */
      return CURLE_OK;

    if(conn->bits.tunnel_proxy && conn->bits.httpproxy &&
       Curl_connect_ongoing(conn))
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
 * Helpers for IDNA conversions.
 */
static bool is_ASCII_name(const char *hostname)
{
  const unsigned char *ch = (const unsigned char *)hostname;

  while(*ch) {
    if(*ch++ & 0x80)
      return FALSE;
  }
  return TRUE;
}

/*
 * Strip single trailing dot in the hostname,
 * primarily for SNI and http host header.
 */
static void strip_trailing_dot(struct hostname *host)
{
  size_t len;
  if(!host || !host->name)
    return;
  len = strlen(host->name);
  if(len && (host->name[len-1] == '.'))
    host->name[len-1] = 0;
}

/*
 * Perform any necessary IDN conversion of hostname
 */
static CURLcode idnconvert_hostname(struct connectdata *conn,
                                    struct hostname *host)
{
  struct Curl_easy *data = conn->data;

#ifndef USE_LIBIDN2
  (void)data;
  (void)conn;
#elif defined(CURL_DISABLE_VERBOSE_STRINGS)
  (void)conn;
#endif

  /* set the name we use to display the host name */
  host->dispname = host->name;

  /* Check name for non-ASCII and convert hostname to ACE form if we can */
  if(!is_ASCII_name(host->name)) {
#ifdef USE_LIBIDN2
    if(idn2_check_version(IDN2_VERSION)) {
      char *ace_hostname = NULL;
#if IDN2_VERSION_NUMBER >= 0x00140000
      /* IDN2_NFC_INPUT: Normalize input string using normalization form C.
         IDN2_NONTRANSITIONAL: Perform Unicode TR46 non-transitional
         processing. */
      int flags = IDN2_NFC_INPUT | IDN2_NONTRANSITIONAL;
#else
      int flags = IDN2_NFC_INPUT;
#endif
      int rc = idn2_lookup_ul((const char *)host->name, &ace_hostname, flags);
      if(rc == IDN2_OK) {
        host->encalloc = (char *)ace_hostname;
        /* change the name pointer to point to the encoded hostname */
        host->name = host->encalloc;
      }
      else {
        failf(data, "Failed to convert %s to ACE; %s\n", host->name,
              idn2_strerror(rc));
        return CURLE_URL_MALFORMAT;
      }
    }
#elif defined(USE_WIN32_IDN)
    char *ace_hostname = NULL;

    if(curl_win32_idn_to_ascii(host->name, &ace_hostname)) {
      host->encalloc = ace_hostname;
      /* change the name pointer to point to the encoded hostname */
      host->name = host->encalloc;
    }
    else {
      failf(data, "Failed to convert %s to ACE;\n", host->name);
      return CURLE_URL_MALFORMAT;
    }
#else
    infof(data, "IDN support not present, can't parse Unicode domains\n");
#endif
  }
  return CURLE_OK;
}

/*
 * Frees data allocated by idnconvert_hostname()
 */
static void free_idnconverted_hostname(struct hostname *host)
{
#if defined(USE_LIBIDN2)
  if(host->encalloc) {
    idn2_free(host->encalloc); /* must be freed with idn2_free() since this was
                                 allocated by libidn */
    host->encalloc = NULL;
  }
#elif defined(USE_WIN32_IDN)
  free(host->encalloc); /* must be freed with free() since this was
                           allocated by curl_win32_idn_to_ascii */
  host->encalloc = NULL;
#else
  (void)host;
#endif
}

/*
 * Allocate and initialize a new connectdata object.
 */
static struct connectdata *allocate_conn(struct Curl_easy *data)
{
  struct connectdata *conn = calloc(1, sizeof(struct connectdata));
  if(!conn)
    return NULL;

#ifdef USE_SSL
  /* The SSL backend-specific data (ssl_backend_data) objects are allocated as
     a separate array to ensure suitable alignment.
     Note that these backend pointers can be swapped by vtls (eg ssl backend
     data becomes proxy backend data). */
  {
    size_t sslsize = Curl_ssl->sizeof_ssl_backend_data;
    char *ssl = calloc(4, sslsize);
    if(!ssl) {
      free(conn);
      return NULL;
    }
    conn->ssl_extra = ssl;
    conn->ssl[0].backend = (void *)ssl;
    conn->ssl[1].backend = (void *)(ssl + sslsize);
    conn->proxy_ssl[0].backend = (void *)(ssl + 2 * sslsize);
    conn->proxy_ssl[1].backend = (void *)(ssl + 3 * sslsize);
  }
#endif

  conn->handler = &Curl_handler_dummy;  /* Be sure we have a handler defined
                                           already from start to avoid NULL
                                           situations and checks */

  /* and we setup a few fields in case we end up actually using this struct */

  conn->sock[FIRSTSOCKET] = CURL_SOCKET_BAD;     /* no file descriptor */
  conn->sock[SECONDARYSOCKET] = CURL_SOCKET_BAD; /* no file descriptor */
  conn->tempsock[0] = CURL_SOCKET_BAD; /* no file descriptor */
  conn->tempsock[1] = CURL_SOCKET_BAD; /* no file descriptor */
  conn->connection_id = -1;    /* no ID */
  conn->port = -1; /* unknown at this point */
  conn->remote_port = -1; /* unknown at this point */
#if defined(USE_RECV_BEFORE_SEND_WORKAROUND) && defined(DEBUGBUILD)
  conn->postponed[0].bindsock = CURL_SOCKET_BAD; /* no file descriptor */
  conn->postponed[1].bindsock = CURL_SOCKET_BAD; /* no file descriptor */
#endif /* USE_RECV_BEFORE_SEND_WORKAROUND && DEBUGBUILD */

  /* Default protocol-independent behavior doesn't support persistent
     connections, so we set this to force-close. Protocols that support
     this need to set this to FALSE in their "curl_do" functions. */
  connclose(conn, "Default to force-close");

  /* Store creation time to help future close decision making */
  conn->created = Curl_now();

  /* Store current time to give a baseline to keepalive connection times. */
  conn->keepalive = Curl_now();

  /* Store off the configured connection upkeep time. */
  conn->upkeep_interval_ms = data->set.upkeep_interval_ms;

  conn->data = data; /* Setup the association between this connection
                        and the Curl_easy */

  conn->http_proxy.proxytype = data->set.proxytype;
  conn->socks_proxy.proxytype = CURLPROXY_SOCKS4;

#if !defined(CURL_DISABLE_PROXY)
  /* note that these two proxy bits are now just on what looks to be
     requested, they may be altered down the road */
  conn->bits.proxy = (data->set.str[STRING_PROXY] &&
                      *data->set.str[STRING_PROXY]) ? TRUE : FALSE;
  conn->bits.httpproxy = (conn->bits.proxy &&
                          (conn->http_proxy.proxytype == CURLPROXY_HTTP ||
                           conn->http_proxy.proxytype == CURLPROXY_HTTP_1_0 ||
                           conn->http_proxy.proxytype == CURLPROXY_HTTPS)) ?
                           TRUE : FALSE;
  conn->bits.socksproxy = (conn->bits.proxy &&
                           !conn->bits.httpproxy) ? TRUE : FALSE;

  if(data->set.str[STRING_PRE_PROXY] && *data->set.str[STRING_PRE_PROXY]) {
    conn->bits.proxy = TRUE;
    conn->bits.socksproxy = TRUE;
  }

  conn->bits.proxy_user_passwd =
    (data->set.str[STRING_PROXYUSERNAME]) ? TRUE : FALSE;
  conn->bits.tunnel_proxy = data->set.tunnel_thru_httpproxy;
#endif /* CURL_DISABLE_PROXY */

  conn->bits.user_passwd = (data->set.str[STRING_USERNAME]) ? TRUE : FALSE;
#ifndef CURL_DISABLE_FTP
  conn->bits.ftp_use_epsv = data->set.ftp_use_epsv;
  conn->bits.ftp_use_eprt = data->set.ftp_use_eprt;
#endif
  conn->ssl_config.verifystatus = data->set.ssl.primary.verifystatus;
  conn->ssl_config.verifypeer = data->set.ssl.primary.verifypeer;
  conn->ssl_config.verifyhost = data->set.ssl.primary.verifyhost;
  conn->proxy_ssl_config.verifystatus =
    data->set.proxy_ssl.primary.verifystatus;
  conn->proxy_ssl_config.verifypeer = data->set.proxy_ssl.primary.verifypeer;
  conn->proxy_ssl_config.verifyhost = data->set.proxy_ssl.primary.verifyhost;
  conn->ip_version = data->set.ipver;
  conn->bits.connect_only = data->set.connect_only;
  conn->transport = TRNSPRT_TCP; /* most of them are TCP streams */

#if !defined(CURL_DISABLE_HTTP) && defined(USE_NTLM) && \
    defined(NTLM_WB_ENABLED)
  conn->ntlm_auth_hlpr_socket = CURL_SOCKET_BAD;
#endif

  /* Initialize the easy handle list */
  Curl_llist_init(&conn->easyq, NULL);

#ifdef HAVE_GSSAPI
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
     it may live on without (this specific) Curl_easy */
  conn->fclosesocket = data->set.fclosesocket;
  conn->closesocket_client = data->set.closesocket_client;

  return conn;
  error:

  Curl_llist_destroy(&conn->easyq, NULL);
  free(conn->localdev);
#ifdef USE_SSL
  free(conn->ssl_extra);
#endif
  free(conn);
  return NULL;
}

/* returns the handler if the given scheme is built-in */
const struct Curl_handler *Curl_builtin_scheme(const char *scheme)
{
  const struct Curl_handler * const *pp;
  const struct Curl_handler *p;
  /* Scan protocol handler table and match against 'scheme'. The handler may
     be changed later when the protocol specific setup function is called. */
  for(pp = protocols; (p = *pp) != NULL; pp++)
    if(strcasecompare(p->scheme, scheme))
      /* Protocol found in table. Check if allowed */
      return p;
  return NULL; /* not found */
}


static CURLcode findprotocol(struct Curl_easy *data,
                             struct connectdata *conn,
                             const char *protostr)
{
  const struct Curl_handler *p = Curl_builtin_scheme(protostr);

  if(p && /* Protocol found in table. Check if allowed */
     (data->set.allowed_protocols & p->protocol)) {

    /* it is allowed for "normal" request, now do an extra check if this is
       the result of a redirect */
    if(data->state.this_is_a_follow &&
       !(data->set.redir_protocols & p->protocol))
      /* nope, get out */
      ;
    else {
      /* Perform setup complement if some. */
      conn->handler = conn->given = p;

      /* 'port' and 'remote_port' are set in setup_connection_internals() */
      return CURLE_OK;
    }
  }

  /* The protocol was not found in the table, but we don't have to assign it
     to anything since it is already assigned to a dummy-struct in the
     create_conn() function when the connectdata struct is allocated. */
  failf(data, "Protocol \"%s\" not supported or disabled in " LIBCURL_NAME,
        protostr);

  return CURLE_UNSUPPORTED_PROTOCOL;
}


CURLcode Curl_uc_to_curlcode(CURLUcode uc)
{
  switch(uc) {
  default:
    return CURLE_URL_MALFORMAT;
  case CURLUE_UNSUPPORTED_SCHEME:
    return CURLE_UNSUPPORTED_PROTOCOL;
  case CURLUE_OUT_OF_MEMORY:
    return CURLE_OUT_OF_MEMORY;
  case CURLUE_USER_NOT_ALLOWED:
    return CURLE_LOGIN_DENIED;
  }
}

/*
 * If the URL was set with an IPv6 numerical address with a zone id part, set
 * the scope_id based on that!
 */

static void zonefrom_url(CURLU *uh, struct connectdata *conn)
{
  char *zoneid;
  CURLUcode uc;

  uc = curl_url_get(uh, CURLUPART_ZONEID, &zoneid, 0);

  if(!uc && zoneid) {
    char *endp;
    unsigned long scope = strtoul(zoneid, &endp, 10);
    if(!*endp && (scope < UINT_MAX))
      /* A plain number, use it directly as a scope id. */
      conn->scope_id = (unsigned int)scope;
#if defined(HAVE_IF_NAMETOINDEX)
    else {
#elif defined(WIN32)
    else if(Curl_if_nametoindex) {
#endif

#if defined(HAVE_IF_NAMETOINDEX) || defined(WIN32)
      /* Zone identifier is not numeric */
      unsigned int scopeidx = 0;
#if defined(WIN32)
      scopeidx = Curl_if_nametoindex(zoneid);
#else
      scopeidx = if_nametoindex(zoneid);
#endif
      if(!scopeidx)
        infof(conn->data, "Invalid zoneid: %s; %s\n", zoneid,
              strerror(errno));
      else
        conn->scope_id = scopeidx;
    }
#endif /* HAVE_IF_NAMETOINDEX || WIN32 */

    free(zoneid);
  }
}

/*
 * Parse URL and fill in the relevant members of the connection struct.
 */
static CURLcode parseurlandfillconn(struct Curl_easy *data,
                                    struct connectdata *conn)
{
  CURLcode result;
  CURLU *uh;
  CURLUcode uc;
  char *hostname;

  up_free(data); /* cleanup previous leftovers first */

  /* parse the URL */
  if(data->set.uh) {
    uh = data->state.uh = curl_url_dup(data->set.uh);
  }
  else {
    uh = data->state.uh = curl_url();
  }

  if(!uh)
    return CURLE_OUT_OF_MEMORY;

  if(data->set.str[STRING_DEFAULT_PROTOCOL] &&
     !Curl_is_absolute_url(data->change.url, NULL, MAX_SCHEME_LEN)) {
    char *url;
    if(data->change.url_alloc)
      free(data->change.url);
    url = aprintf("%s://%s", data->set.str[STRING_DEFAULT_PROTOCOL],
                  data->change.url);
    if(!url)
      return CURLE_OUT_OF_MEMORY;
    data->change.url = url;
    data->change.url_alloc = TRUE;
  }

  if(!data->set.uh) {
    uc = curl_url_set(uh, CURLUPART_URL, data->change.url,
                    CURLU_GUESS_SCHEME |
                    CURLU_NON_SUPPORT_SCHEME |
                    (data->set.disallow_username_in_url ?
                     CURLU_DISALLOW_USER : 0) |
                    (data->set.path_as_is ? CURLU_PATH_AS_IS : 0));
    if(uc) {
      DEBUGF(infof(data, "curl_url_set rejected %s\n", data->change.url));
      return Curl_uc_to_curlcode(uc);
    }
  }

  uc = curl_url_get(uh, CURLUPART_SCHEME, &data->state.up.scheme, 0);
  if(uc)
    return Curl_uc_to_curlcode(uc);

  result = findprotocol(data, conn, data->state.up.scheme);
  if(result)
    return result;

  uc = curl_url_get(uh, CURLUPART_USER, &data->state.up.user,
                    CURLU_URLDECODE);
  if(!uc) {
    conn->user = strdup(data->state.up.user);
    if(!conn->user)
      return CURLE_OUT_OF_MEMORY;
    conn->bits.user_passwd = TRUE;
  }
  else if(uc != CURLUE_NO_USER)
    return Curl_uc_to_curlcode(uc);

  uc = curl_url_get(uh, CURLUPART_PASSWORD, &data->state.up.password,
                    CURLU_URLDECODE);
  if(!uc) {
    conn->passwd = strdup(data->state.up.password);
    if(!conn->passwd)
      return CURLE_OUT_OF_MEMORY;
    conn->bits.user_passwd = TRUE;
  }
  else if(uc != CURLUE_NO_PASSWORD)
    return Curl_uc_to_curlcode(uc);

  uc = curl_url_get(uh, CURLUPART_OPTIONS, &data->state.up.options,
                    CURLU_URLDECODE);
  if(!uc) {
    conn->options = strdup(data->state.up.options);
    if(!conn->options)
      return CURLE_OUT_OF_MEMORY;
  }
  else if(uc != CURLUE_NO_OPTIONS)
    return Curl_uc_to_curlcode(uc);

  uc = curl_url_get(uh, CURLUPART_HOST, &data->state.up.hostname, 0);
  if(uc) {
    if(!strcasecompare("file", data->state.up.scheme))
      return CURLE_OUT_OF_MEMORY;
  }

  uc = curl_url_get(uh, CURLUPART_PATH, &data->state.up.path, 0);
  if(uc)
    return Curl_uc_to_curlcode(uc);

  uc = curl_url_get(uh, CURLUPART_PORT, &data->state.up.port,
                    CURLU_DEFAULT_PORT);
  if(uc) {
    if(!strcasecompare("file", data->state.up.scheme))
      return CURLE_OUT_OF_MEMORY;
  }
  else {
    unsigned long port = strtoul(data->state.up.port, NULL, 10);
    conn->port = conn->remote_port = curlx_ultous(port);
  }

  (void)curl_url_get(uh, CURLUPART_QUERY, &data->state.up.query, 0);

  hostname = data->state.up.hostname;
  if(!hostname)
    /* this is for file:// transfers, get a dummy made */
    hostname = (char *)"";

  if(hostname[0] == '[') {
    /* This looks like an IPv6 address literal. See if there is an address
       scope. */
    size_t hlen;
    conn->bits.ipv6_ip = TRUE;
    /* cut off the brackets! */
    hostname++;
    hlen = strlen(hostname);
    hostname[hlen - 1] = 0;

    zonefrom_url(uh, conn);
  }

  /* make sure the connect struct gets its own copy of the host name */
  conn->host.rawalloc = strdup(hostname);
  if(!conn->host.rawalloc)
    return CURLE_OUT_OF_MEMORY;
  conn->host.name = conn->host.rawalloc;

  if(data->set.scope_id)
    /* Override any scope that was set above.  */
    conn->scope_id = data->set.scope_id;

  return CURLE_OK;
}


/*
 * If we're doing a resumed transfer, we need to setup our stuff
 * properly.
 */
static CURLcode setup_range(struct Curl_easy *data)
{
  struct UrlState *s = &data->state;
  s->resume_from = data->set.set_resume_from;
  if(s->resume_from || data->set.str[STRING_SET_RANGE]) {
    if(s->rangestringalloc)
      free(s->range);

    if(s->resume_from)
      s->range = aprintf("%" CURL_FORMAT_CURL_OFF_T "-", s->resume_from);
    else
      s->range = strdup(data->set.str[STRING_SET_RANGE]);

    s->rangestringalloc = (s->range) ? TRUE : FALSE;

    if(!s->range)
      return CURLE_OUT_OF_MEMORY;

    /* tell ourselves to fetch this range */
    s->use_range = TRUE;        /* enable range download */
  }
  else
    s->use_range = FALSE; /* disable range download */

  return CURLE_OK;
}


/*
 * setup_connection_internals() -
 *
 * Setup connection internals specific to the requested protocol in the
 * Curl_easy. This is inited and setup before the connection is made but
 * is about the particular protocol that is to be used.
 *
 * This MUST get called after proxy magic has been figured out.
 */
static CURLcode setup_connection_internals(struct connectdata *conn)
{
  const struct Curl_handler * p;
  CURLcode result;

  /* Perform setup complement if some. */
  p = conn->handler;

  if(p->setup_connection) {
    result = (*p->setup_connection)(conn);

    if(result)
      return result;

    p = conn->handler;              /* May have changed. */
  }

  if(conn->port < 0)
    /* we check for -1 here since if proxy was detected already, this
       was very likely already set to the proxy port */
    conn->port = p->defport;

  return CURLE_OK;
}

/*
 * Curl_free_request_state() should free temp data that was allocated in the
 * Curl_easy for this single request.
 */

void Curl_free_request_state(struct Curl_easy *data)
{
  Curl_safefree(data->req.protop);
  Curl_safefree(data->req.newurl);
}


#ifndef CURL_DISABLE_PROXY
/****************************************************************
* Checks if the host is in the noproxy list. returns true if it matches
* and therefore the proxy should NOT be used.
****************************************************************/
static bool check_noproxy(const char *name, const char *no_proxy)
{
  /* no_proxy=domain1.dom,host.domain2.dom
   *   (a comma-separated list of hosts which should
   *   not be proxied, or an asterisk to override
   *   all proxy variables)
   */
  if(no_proxy && no_proxy[0]) {
    size_t tok_start;
    size_t tok_end;
    const char *separator = ", ";
    size_t no_proxy_len;
    size_t namelen;
    char *endptr;
    if(strcasecompare("*", no_proxy)) {
      return TRUE;
    }

    /* NO_PROXY was specified and it wasn't just an asterisk */

    no_proxy_len = strlen(no_proxy);
    if(name[0] == '[') {
      /* IPv6 numerical address */
      endptr = strchr(name, ']');
      if(!endptr)
        return FALSE;
      name++;
      namelen = endptr - name;
    }
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
        if(strncasecompare(no_proxy + tok_start, checkn,
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

#ifndef CURL_DISABLE_HTTP
/****************************************************************
* Detect what (if any) proxy to use. Remember that this selects a host
* name and is not limited to HTTP proxies only.
* The returned pointer must be freed by the caller (unless NULL)
****************************************************************/
static char *detect_proxy(struct connectdata *conn)
{
  char *proxy = NULL;

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
  char proxy_env[128];
  const char *protop = conn->handler->scheme;
  char *envp = proxy_env;
  char *prox;

  /* Now, build <protocol>_proxy and check for such a one to use */
  while(*protop)
    *envp++ = (char)tolower((int)*protop++);

  /* append _proxy */
  strcpy(envp, "_proxy");

  /* read the protocol proxy: */
  prox = curl_getenv(proxy_env);

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
  if(!prox && !strcasecompare("http_proxy", proxy_env)) {
    /* There was no lowercase variable, try the uppercase version: */
    Curl_strntoupper(proxy_env, proxy_env, sizeof(proxy_env));
    prox = curl_getenv(proxy_env);
  }

  envp = proxy_env;
  if(prox) {
    proxy = prox; /* use this */
  }
  else {
    envp = (char *)"all_proxy";
    proxy = curl_getenv(envp); /* default proxy to use */
    if(!proxy) {
      envp = (char *)"ALL_PROXY";
      proxy = curl_getenv(envp);
    }
  }
  if(proxy)
    infof(conn->data, "Uses proxy env variable %s == '%s'\n", envp, proxy);

  return proxy;
}
#endif /* CURL_DISABLE_HTTP */

/*
 * If this is supposed to use a proxy, we need to figure out the proxy
 * host name, so that we can re-use an existing connection
 * that may exist registered to the same proxy host.
 */
static CURLcode parse_proxy(struct Curl_easy *data,
                            struct connectdata *conn, char *proxy,
                            curl_proxytype proxytype)
{
  char *portptr = NULL;
  long port = -1;
  char *proxyuser = NULL;
  char *proxypasswd = NULL;
  char *host;
  bool sockstype;
  CURLUcode uc;
  struct proxy_info *proxyinfo;
  CURLU *uhp = curl_url();
  CURLcode result = CURLE_OK;
  char *scheme = NULL;

  /* When parsing the proxy, allowing non-supported schemes since we have
     these made up ones for proxies. Guess scheme for URLs without it. */
  uc = curl_url_set(uhp, CURLUPART_URL, proxy,
                    CURLU_NON_SUPPORT_SCHEME|CURLU_GUESS_SCHEME);
  if(!uc) {
    /* parsed okay as a URL */
    uc = curl_url_get(uhp, CURLUPART_SCHEME, &scheme, 0);
    if(uc) {
      result = CURLE_OUT_OF_MEMORY;
      goto error;
    }

    if(strcasecompare("https", scheme))
      proxytype = CURLPROXY_HTTPS;
    else if(strcasecompare("socks5h", scheme))
      proxytype = CURLPROXY_SOCKS5_HOSTNAME;
    else if(strcasecompare("socks5", scheme))
      proxytype = CURLPROXY_SOCKS5;
    else if(strcasecompare("socks4a", scheme))
      proxytype = CURLPROXY_SOCKS4A;
    else if(strcasecompare("socks4", scheme) ||
            strcasecompare("socks", scheme))
      proxytype = CURLPROXY_SOCKS4;
    else if(strcasecompare("http", scheme))
      ; /* leave it as HTTP or HTTP/1.0 */
    else {
      /* Any other xxx:// reject! */
      failf(data, "Unsupported proxy scheme for \'%s\'", proxy);
      result = CURLE_COULDNT_CONNECT;
      goto error;
    }
  }
  else {
    failf(data, "Unsupported proxy syntax in \'%s\'", proxy);
    result = CURLE_COULDNT_RESOLVE_PROXY;
    goto error;
  }

#ifdef USE_SSL
  if(!(Curl_ssl->supports & SSLSUPP_HTTPS_PROXY))
#endif
    if(proxytype == CURLPROXY_HTTPS) {
      failf(data, "Unsupported proxy \'%s\', libcurl is built without the "
                  "HTTPS-proxy support.", proxy);
      result = CURLE_NOT_BUILT_IN;
      goto error;
    }

  sockstype =
    proxytype == CURLPROXY_SOCKS5_HOSTNAME ||
    proxytype == CURLPROXY_SOCKS5 ||
    proxytype == CURLPROXY_SOCKS4A ||
    proxytype == CURLPROXY_SOCKS4;

  proxyinfo = sockstype ? &conn->socks_proxy : &conn->http_proxy;
  proxyinfo->proxytype = proxytype;

  /* Is there a username and password given in this proxy url? */
  curl_url_get(uhp, CURLUPART_USER, &proxyuser, CURLU_URLDECODE);
  curl_url_get(uhp, CURLUPART_PASSWORD, &proxypasswd, CURLU_URLDECODE);
  if(proxyuser || proxypasswd) {
    Curl_safefree(proxyinfo->user);
    proxyinfo->user = proxyuser;
    Curl_safefree(proxyinfo->passwd);
    if(!proxypasswd) {
      proxypasswd = strdup("");
      if(!proxypasswd) {
        result = CURLE_OUT_OF_MEMORY;
        goto error;
      }
    }
    proxyinfo->passwd = proxypasswd;
    conn->bits.proxy_user_passwd = TRUE; /* enable it */
  }

  curl_url_get(uhp, CURLUPART_PORT, &portptr, 0);

  if(portptr) {
    port = strtol(portptr, NULL, 10);
    free(portptr);
  }
  else {
    if(data->set.proxyport)
      /* None given in the proxy string, then get the default one if it is
         given */
      port = data->set.proxyport;
    else {
      if(proxytype == CURLPROXY_HTTPS)
        port = CURL_DEFAULT_HTTPS_PROXY_PORT;
      else
        port = CURL_DEFAULT_PROXY_PORT;
    }
  }
  if(port >= 0) {
    proxyinfo->port = port;
    if(conn->port < 0 || sockstype || !conn->socks_proxy.host.rawalloc)
      conn->port = port;
  }

  /* now, clone the proxy host name */
  uc = curl_url_get(uhp, CURLUPART_HOST, &host, CURLU_URLDECODE);
  if(uc) {
    result = CURLE_OUT_OF_MEMORY;
    goto error;
  }
  Curl_safefree(proxyinfo->host.rawalloc);
  proxyinfo->host.rawalloc = host;
  if(host[0] == '[') {
    /* this is a numerical IPv6, strip off the brackets */
    size_t len = strlen(host);
    host[len-1] = 0; /* clear the trailing bracket */
    host++;
    zonefrom_url(uhp, conn);
  }
  proxyinfo->host.name = host;

  error:
  free(scheme);
  curl_url_cleanup(uhp);
  return result;
}

/*
 * Extract the user and password from the authentication string
 */
static CURLcode parse_proxy_auth(struct Curl_easy *data,
                                 struct connectdata *conn)
{
  char proxyuser[MAX_CURL_USER_LENGTH]="";
  char proxypasswd[MAX_CURL_PASSWORD_LENGTH]="";
  CURLcode result;

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

  result = Curl_urldecode(data, proxyuser, 0, &conn->http_proxy.user, NULL,
                          FALSE);
  if(!result)
    result = Curl_urldecode(data, proxypasswd, 0, &conn->http_proxy.passwd,
                            NULL, FALSE);
  return result;
}

/* create_conn helper to parse and init proxy values. to be called after unix
   socket init but before any proxy vars are evaluated. */
static CURLcode create_conn_helper_init_proxy(struct connectdata *conn)
{
  char *proxy = NULL;
  char *socksproxy = NULL;
  char *no_proxy = NULL;
  CURLcode result = CURLE_OK;
  struct Curl_easy *data = conn->data;

  /*************************************************************
   * Extract the user and password from the authentication string
   *************************************************************/
  if(conn->bits.proxy_user_passwd) {
    result = parse_proxy_auth(data, conn);
    if(result)
      goto out;
  }

  /*************************************************************
   * Detect what (if any) proxy to use
   *************************************************************/
  if(data->set.str[STRING_PROXY]) {
    proxy = strdup(data->set.str[STRING_PROXY]);
    /* if global proxy is set, this is it */
    if(NULL == proxy) {
      failf(data, "memory shortage");
      result = CURLE_OUT_OF_MEMORY;
      goto out;
    }
  }

  if(data->set.str[STRING_PRE_PROXY]) {
    socksproxy = strdup(data->set.str[STRING_PRE_PROXY]);
    /* if global socks proxy is set, this is it */
    if(NULL == socksproxy) {
      failf(data, "memory shortage");
      result = CURLE_OUT_OF_MEMORY;
      goto out;
    }
  }

  if(!data->set.str[STRING_NOPROXY]) {
    const char *p = "no_proxy";
    no_proxy = curl_getenv(p);
    if(!no_proxy) {
      p = "NO_PROXY";
      no_proxy = curl_getenv(p);
    }
    if(no_proxy) {
      infof(conn->data, "Uses proxy env variable %s == '%s'\n", p, no_proxy);
    }
  }

  if(check_noproxy(conn->host.name, data->set.str[STRING_NOPROXY] ?
      data->set.str[STRING_NOPROXY] : no_proxy)) {
    Curl_safefree(proxy);
    Curl_safefree(socksproxy);
  }
#ifndef CURL_DISABLE_HTTP
  else if(!proxy && !socksproxy)
    /* if the host is not in the noproxy list, detect proxy. */
    proxy = detect_proxy(conn);
#endif /* CURL_DISABLE_HTTP */

  Curl_safefree(no_proxy);

#ifdef USE_UNIX_SOCKETS
  /* For the time being do not mix proxy and unix domain sockets. See #1274 */
  if(proxy && conn->unix_domain_socket) {
    free(proxy);
    proxy = NULL;
  }
#endif

  if(proxy && (!*proxy || (conn->handler->flags & PROTOPT_NONETWORK))) {
    free(proxy);  /* Don't bother with an empty proxy string or if the
                     protocol doesn't work with network */
    proxy = NULL;
  }
  if(socksproxy && (!*socksproxy ||
                    (conn->handler->flags & PROTOPT_NONETWORK))) {
    free(socksproxy);  /* Don't bother with an empty socks proxy string or if
                          the protocol doesn't work with network */
    socksproxy = NULL;
  }

  /***********************************************************************
   * If this is supposed to use a proxy, we need to figure out the proxy host
   * name, proxy type and port number, so that we can re-use an existing
   * connection that may exist registered to the same proxy host.
   ***********************************************************************/
  if(proxy || socksproxy) {
    if(proxy) {
      result = parse_proxy(data, conn, proxy, conn->http_proxy.proxytype);
      Curl_safefree(proxy); /* parse_proxy copies the proxy string */
      if(result)
        goto out;
    }

    if(socksproxy) {
      result = parse_proxy(data, conn, socksproxy,
                           conn->socks_proxy.proxytype);
      /* parse_proxy copies the socks proxy string */
      Curl_safefree(socksproxy);
      if(result)
        goto out;
    }

    if(conn->http_proxy.host.rawalloc) {
#ifdef CURL_DISABLE_HTTP
      /* asking for a HTTP proxy is a bit funny when HTTP is disabled... */
      result = CURLE_UNSUPPORTED_PROTOCOL;
      goto out;
#else
      /* force this connection's protocol to become HTTP if compatible */
      if(!(conn->handler->protocol & PROTO_FAMILY_HTTP)) {
        if((conn->handler->flags & PROTOPT_PROXY_AS_HTTP) &&
           !conn->bits.tunnel_proxy)
          conn->handler = &Curl_handler_http;
        else
          /* if not converting to HTTP over the proxy, enforce tunneling */
          conn->bits.tunnel_proxy = TRUE;
      }
      conn->bits.httpproxy = TRUE;
#endif
    }
    else {
      conn->bits.httpproxy = FALSE; /* not a HTTP proxy */
      conn->bits.tunnel_proxy = FALSE; /* no tunneling if not HTTP */
    }

    if(conn->socks_proxy.host.rawalloc) {
      if(!conn->http_proxy.host.rawalloc) {
        /* once a socks proxy */
        if(!conn->socks_proxy.user) {
          conn->socks_proxy.user = conn->http_proxy.user;
          conn->http_proxy.user = NULL;
          Curl_safefree(conn->socks_proxy.passwd);
          conn->socks_proxy.passwd = conn->http_proxy.passwd;
          conn->http_proxy.passwd = NULL;
        }
      }
      conn->bits.socksproxy = TRUE;
    }
    else
      conn->bits.socksproxy = FALSE; /* not a socks proxy */
  }
  else {
    conn->bits.socksproxy = FALSE;
    conn->bits.httpproxy = FALSE;
  }
  conn->bits.proxy = conn->bits.httpproxy || conn->bits.socksproxy;

  if(!conn->bits.proxy) {
    /* we aren't using the proxy after all... */
    conn->bits.proxy = FALSE;
    conn->bits.httpproxy = FALSE;
    conn->bits.socksproxy = FALSE;
    conn->bits.proxy_user_passwd = FALSE;
    conn->bits.tunnel_proxy = FALSE;
  }

out:

  free(socksproxy);
  free(proxy);
  return result;
}
#endif /* CURL_DISABLE_PROXY */

/*
 * Curl_parse_login_details()
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
 * passwdp  [in/out] - The address where a pointer to newly allocated memory
 *                     holding the password will be stored upon completion.
 * optionsp [in/out] - The address where a pointer to newly allocated memory
 *                     holding the options will be stored upon completion.
 *
 * Returns CURLE_OK on success.
 */
CURLcode Curl_parse_login_details(const char *login, const size_t len,
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
    if(!pbuf) {
      free(ubuf);
      result = CURLE_OUT_OF_MEMORY;
    }
  }

  /* Allocate the options portion buffer */
  if(!result && optionsp && olen) {
    obuf = malloc(olen + 1);
    if(!obuf) {
      free(pbuf);
      free(ubuf);
      result = CURLE_OUT_OF_MEMORY;
    }
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
 * The port number embedded in the URL is replaced, if necessary.
 *************************************************************/
static CURLcode parse_remote_port(struct Curl_easy *data,
                                  struct connectdata *conn)
{

  if(data->set.use_port && data->state.allow_port) {
    /* if set, we use this instead of the port possibly given in the URL */
    char portbuf[16];
    CURLUcode uc;
    conn->remote_port = (unsigned short)data->set.use_port;
    msnprintf(portbuf, sizeof(portbuf), "%d", conn->remote_port);
    uc = curl_url_set(data->state.uh, CURLUPART_PORT, portbuf, 0);
    if(uc)
      return CURLE_OUT_OF_MEMORY;
  }

  return CURLE_OK;
}

/*
 * Override the login details from the URL with that in the CURLOPT_USERPWD
 * option or a .netrc file, if applicable.
 */
static CURLcode override_login(struct Curl_easy *data,
                               struct connectdata *conn,
                               char **userp, char **passwdp, char **optionsp)
{
  bool user_changed = FALSE;
  bool passwd_changed = FALSE;
  CURLUcode uc;

  if(data->set.use_netrc == CURL_NETRC_REQUIRED && conn->bits.user_passwd) {
    /* ignore user+password in the URL */
    if(*userp) {
      Curl_safefree(*userp);
      user_changed = TRUE;
    }
    if(*passwdp) {
      Curl_safefree(*passwdp);
      passwd_changed = TRUE;
    }
    conn->bits.user_passwd = FALSE; /* disable user+password */
  }

  if(data->set.str[STRING_USERNAME]) {
    free(*userp);
    *userp = strdup(data->set.str[STRING_USERNAME]);
    if(!*userp)
      return CURLE_OUT_OF_MEMORY;
    conn->bits.user_passwd = TRUE; /* enable user+password */
    user_changed = TRUE;
  }

  if(data->set.str[STRING_PASSWORD]) {
    free(*passwdp);
    *passwdp = strdup(data->set.str[STRING_PASSWORD]);
    if(!*passwdp)
      return CURLE_OUT_OF_MEMORY;
    conn->bits.user_passwd = TRUE; /* enable user+password */
    passwd_changed = TRUE;
  }

  if(data->set.str[STRING_OPTIONS]) {
    free(*optionsp);
    *optionsp = strdup(data->set.str[STRING_OPTIONS]);
    if(!*optionsp)
      return CURLE_OUT_OF_MEMORY;
  }

  conn->bits.netrc = FALSE;
  if(data->set.use_netrc != CURL_NETRC_IGNORED &&
      (!*userp || !**userp || !*passwdp || !**passwdp)) {
    bool netrc_user_changed = FALSE;
    bool netrc_passwd_changed = FALSE;
    int ret;

    ret = Curl_parsenetrc(conn->host.name,
                          userp, passwdp,
                          &netrc_user_changed, &netrc_passwd_changed,
                          data->set.str[STRING_NETRC_FILE]);
    if(ret > 0) {
      infof(data, "Couldn't find host %s in the "
            DOT_CHAR "netrc file; using defaults\n",
            conn->host.name);
    }
    else if(ret < 0) {
      return CURLE_OUT_OF_MEMORY;
    }
    else {
      /* set bits.netrc TRUE to remember that we got the name from a .netrc
         file, so that it is safe to use even if we followed a Location: to a
         different host or similar. */
      conn->bits.netrc = TRUE;
      conn->bits.user_passwd = TRUE; /* enable user+password */

      if(netrc_user_changed) {
        user_changed = TRUE;
      }
      if(netrc_passwd_changed) {
        passwd_changed = TRUE;
      }
    }
  }

  /* for updated strings, we update them in the URL */
  if(user_changed) {
    uc = curl_url_set(data->state.uh, CURLUPART_USER, *userp, 0);
    if(uc)
      return Curl_uc_to_curlcode(uc);
  }
  if(passwd_changed) {
    uc = curl_url_set(data->state.uh, CURLUPART_PASSWORD, *passwdp, 0);
    if(uc)
      return Curl_uc_to_curlcode(uc);
  }
  return CURLE_OK;
}

/*
 * Set the login details so they're available in the connection
 */
static CURLcode set_login(struct connectdata *conn)
{
  CURLcode result = CURLE_OK;
  const char *setuser = CURL_DEFAULT_USER;
  const char *setpasswd = CURL_DEFAULT_PASSWORD;

  /* If our protocol needs a password and we have none, use the defaults */
  if((conn->handler->flags & PROTOPT_NEEDSPWD) && !conn->bits.user_passwd)
    ;
  else {
    setuser = "";
    setpasswd = "";
  }
  /* Store the default user */
  if(!conn->user) {
    conn->user = strdup(setuser);
    if(!conn->user)
      return CURLE_OUT_OF_MEMORY;
  }

  /* Store the default password */
  if(!conn->passwd) {
    conn->passwd = strdup(setpasswd);
    if(!conn->passwd)
      result = CURLE_OUT_OF_MEMORY;
  }

  /* if there's a user without password, consider password blank */
  if(conn->user && !conn->passwd) {
    conn->passwd = strdup("");
    if(!conn->passwd)
      result = CURLE_OUT_OF_MEMORY;
  }

  return result;
}

/*
 * Parses a "host:port" string to connect to.
 * The hostname and the port may be empty; in this case, NULL is returned for
 * the hostname and -1 for the port.
 */
static CURLcode parse_connect_to_host_port(struct Curl_easy *data,
                                           const char *host,
                                           char **hostname_result,
                                           int *port_result)
{
  char *host_dup;
  char *hostptr;
  char *host_portno;
  char *portptr;
  int port = -1;

#if defined(CURL_DISABLE_VERBOSE_STRINGS)
  (void) data;
#endif

  *hostname_result = NULL;
  *port_result = -1;

  if(!host || !*host)
    return CURLE_OK;

  host_dup = strdup(host);
  if(!host_dup)
    return CURLE_OUT_OF_MEMORY;

  hostptr = host_dup;

  /* start scanning for port number at this point */
  portptr = hostptr;

  /* detect and extract RFC6874-style IPv6-addresses */
  if(*hostptr == '[') {
#ifdef ENABLE_IPV6
    char *ptr = ++hostptr; /* advance beyond the initial bracket */
    while(*ptr && (ISXDIGIT(*ptr) || (*ptr == ':') || (*ptr == '.')))
      ptr++;
    if(*ptr == '%') {
      /* There might be a zone identifier */
      if(strncmp("%25", ptr, 3))
        infof(data, "Please URL encode %% as %%25, see RFC 6874.\n");
      ptr++;
      /* Allow unreserved characters as defined in RFC 3986 */
      while(*ptr && (ISALPHA(*ptr) || ISXDIGIT(*ptr) || (*ptr == '-') ||
                     (*ptr == '.') || (*ptr == '_') || (*ptr == '~')))
        ptr++;
    }
    if(*ptr == ']')
      /* yeps, it ended nicely with a bracket as well */
      *ptr++ = '\0';
    else
      infof(data, "Invalid IPv6 address format\n");
    portptr = ptr;
    /* Note that if this didn't end with a bracket, we still advanced the
     * hostptr first, but I can't see anything wrong with that as no host
     * name nor a numeric can legally start with a bracket.
     */
#else
    failf(data, "Use of IPv6 in *_CONNECT_TO without IPv6 support built-in!");
    free(host_dup);
    return CURLE_NOT_BUILT_IN;
#endif
  }

  /* Get port number off server.com:1080 */
  host_portno = strchr(portptr, ':');
  if(host_portno) {
    char *endp = NULL;
    *host_portno = '\0'; /* cut off number from host name */
    host_portno++;
    if(*host_portno) {
      long portparse = strtol(host_portno, &endp, 10);
      if((endp && *endp) || (portparse < 0) || (portparse > 65535)) {
        infof(data, "No valid port number in connect to host string (%s)\n",
              host_portno);
        hostptr = NULL;
        port = -1;
      }
      else
        port = (int)portparse; /* we know it will fit */
    }
  }

  /* now, clone the cleaned host name */
  if(hostptr) {
    *hostname_result = strdup(hostptr);
    if(!*hostname_result) {
      free(host_dup);
      return CURLE_OUT_OF_MEMORY;
    }
  }

  *port_result = port;

  free(host_dup);
  return CURLE_OK;
}

/*
 * Parses one "connect to" string in the form:
 * "HOST:PORT:CONNECT-TO-HOST:CONNECT-TO-PORT".
 */
static CURLcode parse_connect_to_string(struct Curl_easy *data,
                                        struct connectdata *conn,
                                        const char *conn_to_host,
                                        char **host_result,
                                        int *port_result)
{
  CURLcode result = CURLE_OK;
  const char *ptr = conn_to_host;
  int host_match = FALSE;
  int port_match = FALSE;

  *host_result = NULL;
  *port_result = -1;

  if(*ptr == ':') {
    /* an empty hostname always matches */
    host_match = TRUE;
    ptr++;
  }
  else {
    /* check whether the URL's hostname matches */
    size_t hostname_to_match_len;
    char *hostname_to_match = aprintf("%s%s%s",
                                      conn->bits.ipv6_ip ? "[" : "",
                                      conn->host.name,
                                      conn->bits.ipv6_ip ? "]" : "");
    if(!hostname_to_match)
      return CURLE_OUT_OF_MEMORY;
    hostname_to_match_len = strlen(hostname_to_match);
    host_match = strncasecompare(ptr, hostname_to_match,
                                 hostname_to_match_len);
    free(hostname_to_match);
    ptr += hostname_to_match_len;

    host_match = host_match && *ptr == ':';
    ptr++;
  }

  if(host_match) {
    if(*ptr == ':') {
      /* an empty port always matches */
      port_match = TRUE;
      ptr++;
    }
    else {
      /* check whether the URL's port matches */
      char *ptr_next = strchr(ptr, ':');
      if(ptr_next) {
        char *endp = NULL;
        long port_to_match = strtol(ptr, &endp, 10);
        if((endp == ptr_next) && (port_to_match == conn->remote_port)) {
          port_match = TRUE;
          ptr = ptr_next + 1;
        }
      }
    }
  }

  if(host_match && port_match) {
    /* parse the hostname and port to connect to */
    result = parse_connect_to_host_port(data, ptr, host_result, port_result);
  }

  return result;
}

/*
 * Processes all strings in the "connect to" slist, and uses the "connect
 * to host" and "connect to port" of the first string that matches.
 */
static CURLcode parse_connect_to_slist(struct Curl_easy *data,
                                       struct connectdata *conn,
                                       struct curl_slist *conn_to_host)
{
  CURLcode result = CURLE_OK;
  char *host = NULL;
  int port = -1;

  while(conn_to_host && !host && port == -1) {
    result = parse_connect_to_string(data, conn, conn_to_host->data,
                                     &host, &port);
    if(result)
      return result;

    if(host && *host) {
      conn->conn_to_host.rawalloc = host;
      conn->conn_to_host.name = host;
      conn->bits.conn_to_host = TRUE;

      infof(data, "Connecting to hostname: %s\n", host);
    }
    else {
      /* no "connect to host" */
      conn->bits.conn_to_host = FALSE;
      Curl_safefree(host);
    }

    if(port >= 0) {
      conn->conn_to_port = port;
      conn->bits.conn_to_port = TRUE;
      infof(data, "Connecting to port: %d\n", port);
    }
    else {
      /* no "connect to port" */
      conn->bits.conn_to_port = FALSE;
      port = -1;
    }

    conn_to_host = conn_to_host->next;
  }

#ifdef USE_ALTSVC
  if(data->asi && !host && (port == -1) &&
     (conn->handler->protocol == CURLPROTO_HTTPS)) {
    /* no connect_to match, try alt-svc! */
    enum alpnid srcalpnid;
    bool hit;
    struct altsvc *as;
    const int allowed_versions = ( ALPN_h1
#ifdef USE_NGHTTP2
      | ALPN_h2
#endif
#ifdef ENABLE_QUIC
      | ALPN_h3
#endif
      ) & data->asi->flags;

    host = conn->host.rawalloc;
#ifdef USE_NGHTTP2
    /* with h2 support, check that first */
    srcalpnid = ALPN_h2;
    hit = Curl_altsvc_lookup(data->asi,
                             srcalpnid, host, conn->remote_port, /* from */
                             &as /* to */,
                             allowed_versions);
    if(!hit)
#endif
    {
      srcalpnid = ALPN_h1;
      hit = Curl_altsvc_lookup(data->asi,
                               srcalpnid, host, conn->remote_port, /* from */
                               &as /* to */,
                               allowed_versions);
    }
    if(hit) {
      char *hostd = strdup((char *)as->dst.host);
      if(!hostd)
        return CURLE_OUT_OF_MEMORY;
      conn->conn_to_host.rawalloc = hostd;
      conn->conn_to_host.name = hostd;
      conn->bits.conn_to_host = TRUE;
      conn->conn_to_port = as->dst.port;
      conn->bits.conn_to_port = TRUE;
      conn->bits.altused = TRUE;
      infof(data, "Alt-svc connecting from [%s]%s:%d to [%s]%s:%d\n",
            Curl_alpnid2str(srcalpnid), host, conn->remote_port,
            Curl_alpnid2str(as->dst.alpnid), hostd, as->dst.port);
      if(srcalpnid != as->dst.alpnid) {
        /* protocol version switch */
        switch(as->dst.alpnid) {
        case ALPN_h1:
          conn->httpversion = 11;
          break;
        case ALPN_h2:
          conn->httpversion = 20;
          break;
        case ALPN_h3:
          conn->transport = TRNSPRT_QUIC;
          conn->httpversion = 30;
          break;
        default: /* shouldn't be possible */
          break;
        }
      }
    }
  }
#endif

  return result;
}

/*************************************************************
 * Resolve the address of the server or proxy
 *************************************************************/
static CURLcode resolve_server(struct Curl_easy *data,
                               struct connectdata *conn,
                               bool *async)
{
  CURLcode result = CURLE_OK;
  timediff_t timeout_ms = Curl_timeleft(data, NULL, TRUE);

  DEBUGASSERT(conn);
  DEBUGASSERT(data);
  /*************************************************************
   * Resolve the name of the server or proxy
   *************************************************************/
  if(conn->bits.reuse)
    /* We're reusing the connection - no need to resolve anything, and
       idnconvert_hostname() was called already in create_conn() for the re-use
       case. */
    *async = FALSE;

  else {
    /* this is a fresh connect */
    int rc;
    struct Curl_dns_entry *hostaddr;

#ifdef USE_UNIX_SOCKETS
    if(conn->unix_domain_socket) {
      /* Unix domain sockets are local. The host gets ignored, just use the
       * specified domain socket address. Do not cache "DNS entries". There is
       * no DNS involved and we already have the filesystem path available */
      const char *path = conn->unix_domain_socket;

      hostaddr = calloc(1, sizeof(struct Curl_dns_entry));
      if(!hostaddr)
        result = CURLE_OUT_OF_MEMORY;
      else {
        bool longpath = FALSE;
        hostaddr->addr = Curl_unix2addr(path, &longpath,
                                        conn->abstract_unix_socket);
        if(hostaddr->addr)
          hostaddr->inuse++;
        else {
          /* Long paths are not supported for now */
          if(longpath) {
            failf(data, "Unix socket path too long: '%s'", path);
            result = CURLE_COULDNT_RESOLVE_HOST;
          }
          else
            result = CURLE_OUT_OF_MEMORY;
          free(hostaddr);
          hostaddr = NULL;
        }
      }
    }
    else
#endif
    if(!conn->bits.proxy) {
      struct hostname *connhost;
      if(conn->bits.conn_to_host)
        connhost = &conn->conn_to_host;
      else
        connhost = &conn->host;

      /* If not connecting via a proxy, extract the port from the URL, if it is
       * there, thus overriding any defaults that might have been set above. */
      if(conn->bits.conn_to_port)
        conn->port = conn->conn_to_port;
      else
        conn->port = conn->remote_port;

      /* Resolve target host right on */
      conn->hostname_resolve = strdup(connhost->name);
      if(!conn->hostname_resolve)
        return CURLE_OUT_OF_MEMORY;
      rc = Curl_resolv_timeout(conn, conn->hostname_resolve, (int)conn->port,
                               &hostaddr, timeout_ms);
      if(rc == CURLRESOLV_PENDING)
        *async = TRUE;

      else if(rc == CURLRESOLV_TIMEDOUT)
        result = CURLE_OPERATION_TIMEDOUT;

      else if(!hostaddr) {
        failf(data, "Couldn't resolve host '%s'", connhost->dispname);
        result =  CURLE_COULDNT_RESOLVE_HOST;
        /* don't return yet, we need to clean up the timeout first */
      }
    }
    else {
      /* This is a proxy that hasn't been resolved yet. */

      struct hostname * const host = conn->bits.socksproxy ?
        &conn->socks_proxy.host : &conn->http_proxy.host;

      /* resolve proxy */
      conn->hostname_resolve = strdup(host->name);
      if(!conn->hostname_resolve)
        return CURLE_OUT_OF_MEMORY;
      rc = Curl_resolv_timeout(conn, conn->hostname_resolve, (int)conn->port,
                               &hostaddr, timeout_ms);

      if(rc == CURLRESOLV_PENDING)
        *async = TRUE;

      else if(rc == CURLRESOLV_TIMEDOUT)
        result = CURLE_OPERATION_TIMEDOUT;

      else if(!hostaddr) {
        failf(data, "Couldn't resolve proxy '%s'", host->dispname);
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
  free_idnconverted_hostname(&old_conn->http_proxy.host);
  free_idnconverted_hostname(&old_conn->socks_proxy.host);

  free(old_conn->http_proxy.host.rawalloc);
  free(old_conn->socks_proxy.host.rawalloc);

  /* free the SSL config struct from this connection struct as this was
     allocated in vain and is targeted for destruction */
  Curl_free_primary_ssl_config(&old_conn->ssl_config);
  Curl_free_primary_ssl_config(&old_conn->proxy_ssl_config);

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
    Curl_safefree(conn->http_proxy.user);
    Curl_safefree(conn->socks_proxy.user);
    Curl_safefree(conn->http_proxy.passwd);
    Curl_safefree(conn->socks_proxy.passwd);
    conn->http_proxy.user = old_conn->http_proxy.user;
    conn->socks_proxy.user = old_conn->socks_proxy.user;
    conn->http_proxy.passwd = old_conn->http_proxy.passwd;
    conn->socks_proxy.passwd = old_conn->socks_proxy.passwd;
    old_conn->http_proxy.user = NULL;
    old_conn->socks_proxy.user = NULL;
    old_conn->http_proxy.passwd = NULL;
    old_conn->socks_proxy.passwd = NULL;
  }

  /* host can change, when doing keepalive with a proxy or if the case is
     different this time etc */
  free_idnconverted_hostname(&conn->host);
  free_idnconverted_hostname(&conn->conn_to_host);
  Curl_safefree(conn->host.rawalloc);
  Curl_safefree(conn->conn_to_host.rawalloc);
  conn->host = old_conn->host;
  conn->conn_to_host = old_conn->conn_to_host;
  conn->conn_to_port = old_conn->conn_to_port;
  conn->remote_port = old_conn->remote_port;
  Curl_safefree(conn->hostname_resolve);

  conn->hostname_resolve = old_conn->hostname_resolve;
  old_conn->hostname_resolve = NULL;

  /* persist connection info in session handle */
  Curl_persistconninfo(conn);

  conn_reset_all_postponed_data(old_conn); /* free buffers */

  /* re-use init */
  conn->bits.reuse = TRUE; /* yes, we're re-using here */

  Curl_safefree(old_conn->user);
  Curl_safefree(old_conn->passwd);
  Curl_safefree(old_conn->options);
  Curl_safefree(old_conn->http_proxy.user);
  Curl_safefree(old_conn->socks_proxy.user);
  Curl_safefree(old_conn->http_proxy.passwd);
  Curl_safefree(old_conn->socks_proxy.passwd);
  Curl_safefree(old_conn->localdev);
  Curl_llist_destroy(&old_conn->easyq, NULL);

#ifdef USE_UNIX_SOCKETS
  Curl_safefree(old_conn->unix_domain_socket);
#endif
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

static CURLcode create_conn(struct Curl_easy *data,
                            struct connectdata **in_connect,
                            bool *async)
{
  CURLcode result = CURLE_OK;
  struct connectdata *conn;
  struct connectdata *conn_temp = NULL;
  bool reuse;
  bool connections_available = TRUE;
  bool force_reuse = FALSE;
  bool waitpipe = FALSE;
  size_t max_host_connections = Curl_multi_max_host_connections(data->multi);
  size_t max_total_connections = Curl_multi_max_total_connections(data->multi);

  *async = FALSE;
  *in_connect = NULL;

  /*************************************************************
   * Check input data
   *************************************************************/
  if(!data->change.url) {
    result = CURLE_URL_MALFORMAT;
    goto out;
  }

  /* First, split up the current URL in parts so that we can use the
     parts for checking against the already present connections. In order
     to not have to modify everything at once, we allocate a temporary
     connection data struct and fill in for comparison purposes. */
  conn = allocate_conn(data);

  if(!conn) {
    result = CURLE_OUT_OF_MEMORY;
    goto out;
  }

  /* We must set the return variable as soon as possible, so that our
     parent can cleanup any possible allocs we may have done before
     any failure */
  *in_connect = conn;

  result = parseurlandfillconn(data, conn);
  if(result)
    goto out;

  if(data->set.str[STRING_BEARER]) {
    conn->oauth_bearer = strdup(data->set.str[STRING_BEARER]);
    if(!conn->oauth_bearer) {
      result = CURLE_OUT_OF_MEMORY;
      goto out;
    }
  }

  if(data->set.str[STRING_SASL_AUTHZID]) {
    conn->sasl_authzid = strdup(data->set.str[STRING_SASL_AUTHZID]);
    if(!conn->sasl_authzid) {
      result = CURLE_OUT_OF_MEMORY;
      goto out;
    }
  }

#ifdef USE_UNIX_SOCKETS
  if(data->set.str[STRING_UNIX_SOCKET_PATH]) {
    conn->unix_domain_socket = strdup(data->set.str[STRING_UNIX_SOCKET_PATH]);
    if(conn->unix_domain_socket == NULL) {
      result = CURLE_OUT_OF_MEMORY;
      goto out;
    }
    conn->abstract_unix_socket = data->set.abstract_unix_socket;
  }
#endif

  /* After the unix socket init but before the proxy vars are used, parse and
     initialize the proxy vars */
#ifndef CURL_DISABLE_PROXY
  result = create_conn_helper_init_proxy(conn);
  if(result)
    goto out;
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
  if(result)
    goto out;

  /* Check for overridden login details and set them accordingly so they
     they are known when protocol->setup_connection is called! */
  result = override_login(data, conn, &conn->user, &conn->passwd,
                          &conn->options);
  if(result)
    goto out;

  result = set_login(conn); /* default credentials */
  if(result)
    goto out;

  /*************************************************************
   * Process the "connect to" linked list of hostname/port mappings.
   * Do this after the remote port number has been fixed in the URL.
   *************************************************************/
  result = parse_connect_to_slist(data, conn, data->set.connect_to);
  if(result)
    goto out;

  /*************************************************************
   * IDN-convert the hostnames
   *************************************************************/
  result = idnconvert_hostname(conn, &conn->host);
  if(result)
    goto out;
  if(conn->bits.conn_to_host) {
    result = idnconvert_hostname(conn, &conn->conn_to_host);
    if(result)
      goto out;
  }
  if(conn->bits.httpproxy) {
    result = idnconvert_hostname(conn, &conn->http_proxy.host);
    if(result)
      goto out;
  }
  if(conn->bits.socksproxy) {
    result = idnconvert_hostname(conn, &conn->socks_proxy.host);
    if(result)
      goto out;
  }

  /*************************************************************
   * Check whether the host and the "connect to host" are equal.
   * Do this after the hostnames have been IDN-converted.
   *************************************************************/
  if(conn->bits.conn_to_host &&
     strcasecompare(conn->conn_to_host.name, conn->host.name)) {
    conn->bits.conn_to_host = FALSE;
  }

  /*************************************************************
   * Check whether the port and the "connect to port" are equal.
   * Do this after the remote port number has been fixed in the URL.
   *************************************************************/
  if(conn->bits.conn_to_port && conn->conn_to_port == conn->remote_port) {
    conn->bits.conn_to_port = FALSE;
  }

  /*************************************************************
   * If the "connect to" feature is used with an HTTP proxy,
   * we set the tunnel_proxy bit.
   *************************************************************/
  if((conn->bits.conn_to_host || conn->bits.conn_to_port) &&
      conn->bits.httpproxy)
    conn->bits.tunnel_proxy = TRUE;

  /*************************************************************
   * Setup internals depending on protocol. Needs to be done after
   * we figured out what/if proxy to use.
   *************************************************************/
  result = setup_connection_internals(conn);
  if(result)
    goto out;

  conn->recv[FIRSTSOCKET] = Curl_recv_plain;
  conn->send[FIRSTSOCKET] = Curl_send_plain;
  conn->recv[SECONDARYSOCKET] = Curl_recv_plain;
  conn->send[SECONDARYSOCKET] = Curl_send_plain;

  conn->bits.tcp_fastopen = data->set.tcp_fastopen;

  /***********************************************************************
   * file: is a special case in that it doesn't need a network connection
   ***********************************************************************/
#ifndef CURL_DISABLE_FILE
  if(conn->handler->flags & PROTOPT_NONETWORK) {
    bool done;
    /* this is supposed to be the connect function so we better at least check
       that the file is present here! */
    DEBUGASSERT(conn->handler->connect_it);
    Curl_persistconninfo(conn);
    result = conn->handler->connect_it(conn, &done);

    /* Setup a "faked" transfer that'll do nothing */
    if(!result) {
      conn->bits.tcpconnect[FIRSTSOCKET] = TRUE; /* we are "connected */

      result = Curl_conncache_add_conn(data->state.conn_cache, conn);
      if(result)
        goto out;

      /*
       * Setup whatever necessary for a resumed transfer
       */
      result = setup_range(data);
      if(result) {
        DEBUGASSERT(conn->handler->done);
        /* we ignore the return code for the protocol-specific DONE */
        (void)conn->handler->done(conn, result, FALSE);
        goto out;
      }
      Curl_attach_connnection(data, conn);
      Curl_setup_transfer(data, -1, -1, FALSE, -1);
    }

    /* since we skip do_init() */
    Curl_init_do(data, conn);

    goto out;
  }
#endif

  /* Get a cloned copy of the SSL config situation stored in the
     connection struct. But to get this going nicely, we must first make
     sure that the strings in the master copy are pointing to the correct
     strings in the session handle strings array!

     Keep in mind that the pointers in the master copy are pointing to strings
     that will be freed as part of the Curl_easy struct, but all cloned
     copies will be separately allocated.
  */
  data->set.ssl.primary.CApath = data->set.str[STRING_SSL_CAPATH_ORIG];
  data->set.proxy_ssl.primary.CApath = data->set.str[STRING_SSL_CAPATH_PROXY];
  data->set.ssl.primary.CAfile = data->set.str[STRING_SSL_CAFILE_ORIG];
  data->set.proxy_ssl.primary.CAfile = data->set.str[STRING_SSL_CAFILE_PROXY];
  data->set.ssl.primary.random_file = data->set.str[STRING_SSL_RANDOM_FILE];
  data->set.proxy_ssl.primary.random_file =
    data->set.str[STRING_SSL_RANDOM_FILE];
  data->set.ssl.primary.egdsocket = data->set.str[STRING_SSL_EGDSOCKET];
  data->set.proxy_ssl.primary.egdsocket = data->set.str[STRING_SSL_EGDSOCKET];
  data->set.ssl.primary.cipher_list =
    data->set.str[STRING_SSL_CIPHER_LIST_ORIG];
  data->set.proxy_ssl.primary.cipher_list =
    data->set.str[STRING_SSL_CIPHER_LIST_PROXY];
  data->set.ssl.primary.cipher_list13 =
    data->set.str[STRING_SSL_CIPHER13_LIST_ORIG];
  data->set.proxy_ssl.primary.cipher_list13 =
    data->set.str[STRING_SSL_CIPHER13_LIST_PROXY];

  data->set.ssl.CRLfile = data->set.str[STRING_SSL_CRLFILE_ORIG];
  data->set.proxy_ssl.CRLfile = data->set.str[STRING_SSL_CRLFILE_PROXY];
  data->set.ssl.issuercert = data->set.str[STRING_SSL_ISSUERCERT_ORIG];
  data->set.proxy_ssl.issuercert = data->set.str[STRING_SSL_ISSUERCERT_PROXY];
  data->set.ssl.cert = data->set.str[STRING_CERT_ORIG];
  data->set.proxy_ssl.cert = data->set.str[STRING_CERT_PROXY];
  data->set.ssl.cert_type = data->set.str[STRING_CERT_TYPE_ORIG];
  data->set.proxy_ssl.cert_type = data->set.str[STRING_CERT_TYPE_PROXY];
  data->set.ssl.key = data->set.str[STRING_KEY_ORIG];
  data->set.proxy_ssl.key = data->set.str[STRING_KEY_PROXY];
  data->set.ssl.key_type = data->set.str[STRING_KEY_TYPE_ORIG];
  data->set.proxy_ssl.key_type = data->set.str[STRING_KEY_TYPE_PROXY];
  data->set.ssl.key_passwd = data->set.str[STRING_KEY_PASSWD_ORIG];
  data->set.proxy_ssl.key_passwd = data->set.str[STRING_KEY_PASSWD_PROXY];
  data->set.ssl.primary.clientcert = data->set.str[STRING_CERT_ORIG];
  data->set.proxy_ssl.primary.clientcert = data->set.str[STRING_CERT_PROXY];
#ifdef USE_TLS_SRP
  data->set.ssl.username = data->set.str[STRING_TLSAUTH_USERNAME_ORIG];
  data->set.proxy_ssl.username = data->set.str[STRING_TLSAUTH_USERNAME_PROXY];
  data->set.ssl.password = data->set.str[STRING_TLSAUTH_PASSWORD_ORIG];
  data->set.proxy_ssl.password = data->set.str[STRING_TLSAUTH_PASSWORD_PROXY];
#endif

  if(!Curl_clone_primary_ssl_config(&data->set.ssl.primary,
     &conn->ssl_config)) {
    result = CURLE_OUT_OF_MEMORY;
    goto out;
  }

  if(!Curl_clone_primary_ssl_config(&data->set.proxy_ssl.primary,
                                    &conn->proxy_ssl_config)) {
    result = CURLE_OUT_OF_MEMORY;
    goto out;
  }

  prune_dead_connections(data);

  /*************************************************************
   * Check the current list of connections to see if we can
   * re-use an already existing one or if we have to create a
   * new one.
   *************************************************************/

  DEBUGASSERT(conn->user);
  DEBUGASSERT(conn->passwd);

  /* reuse_fresh is TRUE if we are told to use a new connection by force, but
     we only acknowledge this option if this is not a re-used connection
     already (which happens due to follow-location or during a HTTP
     authentication phase). CONNECT_ONLY transfers also refuse reuse. */
  if((data->set.reuse_fresh && !data->state.this_is_a_follow) ||
     data->set.connect_only)
    reuse = FALSE;
  else
    reuse = ConnectionExists(data, conn, &conn_temp, &force_reuse, &waitpipe);

  /* If we found a reusable connection that is now marked as in use, we may
     still want to open a new connection if we are multiplexing. */
  if(reuse && !force_reuse && IsMultiplexingPossible(data, conn_temp)) {
    size_t multiplexed = CONN_INUSE(conn_temp);
    if(multiplexed > 0) {
      infof(data, "Found connection %ld, with %zu requests on it\n",
            conn_temp->connection_id, multiplexed);

      if(Curl_conncache_bundle_size(conn_temp) < max_host_connections &&
         Curl_conncache_size(data) < max_total_connections) {
        /* We want a new connection anyway */
        reuse = FALSE;

        infof(data, "We can reuse, but we want a new connection anyway\n");
        Curl_conncache_return_conn(conn_temp);
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
    reuse_conn(conn, conn_temp);
#ifdef USE_SSL
    free(conn->ssl_extra);
#endif
    free(conn);          /* we don't need this anymore */
    conn = conn_temp;
    *in_connect = conn;

    infof(data, "Re-using existing connection! (#%ld) with %s %s\n",
          conn->connection_id,
          conn->bits.proxy?"proxy":"host",
          conn->socks_proxy.host.name ? conn->socks_proxy.host.dispname :
          conn->http_proxy.host.name ? conn->http_proxy.host.dispname :
                                       conn->host.dispname);
  }
  else {
    /* We have decided that we want a new connection. However, we may not
       be able to do that if we have reached the limit of how many
       connections we are allowed to open. */

    if(conn->handler->flags & PROTOPT_ALPN_NPN) {
      /* The protocol wants it, so set the bits if enabled in the easy handle
         (default) */
      if(data->set.ssl_enable_alpn)
        conn->bits.tls_enable_alpn = TRUE;
      if(data->set.ssl_enable_npn)
        conn->bits.tls_enable_npn = TRUE;
    }

    if(waitpipe)
      /* There is a connection that *might* become usable for multiplexing
         "soon", and we wait for that */
      connections_available = FALSE;
    else {
      /* this gets a lock on the conncache */
      const char *bundlehost;
      struct connectbundle *bundle =
        Curl_conncache_find_bundle(conn, data->state.conn_cache, &bundlehost);

      if(max_host_connections > 0 && bundle &&
         (bundle->num_connections >= max_host_connections)) {
        struct connectdata *conn_candidate;

        /* The bundle is full. Extract the oldest connection. */
        conn_candidate = Curl_conncache_extract_bundle(data, bundle);
        Curl_conncache_unlock(data);

        if(conn_candidate)
          (void)Curl_disconnect(data, conn_candidate,
                                /* dead_connection */ FALSE);
        else {
          infof(data, "No more connections allowed to host %s: %zu\n",
                bundlehost, max_host_connections);
          connections_available = FALSE;
        }
      }
      else
        Curl_conncache_unlock(data);

    }

    if(connections_available &&
       (max_total_connections > 0) &&
       (Curl_conncache_size(data) >= max_total_connections)) {
      struct connectdata *conn_candidate;

      /* The cache is full. Let's see if we can kill a connection. */
      conn_candidate = Curl_conncache_extract_oldest(data);
      if(conn_candidate)
        (void)Curl_disconnect(data, conn_candidate,
                              /* dead_connection */ FALSE);
      else {
        infof(data, "No connections available in cache\n");
        connections_available = FALSE;
      }
    }

    if(!connections_available) {
      infof(data, "No connections available.\n");

      conn_free(conn);
      *in_connect = NULL;

      result = CURLE_NO_CONNECTION_AVAILABLE;
      goto out;
    }
    else {
      /*
       * This is a brand new connection, so let's store it in the connection
       * cache of ours!
       */
      result = Curl_conncache_add_conn(data->state.conn_cache, conn);
      if(result)
        goto out;
    }

#if defined(USE_NTLM)
    /* If NTLM is requested in a part of this connection, make sure we don't
       assume the state is fine as this is a fresh connection and NTLM is
       connection based. */
    if((data->state.authhost.picked & (CURLAUTH_NTLM | CURLAUTH_NTLM_WB)) &&
       data->state.authhost.done) {
      infof(data, "NTLM picked AND auth done set, clear picked!\n");
      data->state.authhost.picked = CURLAUTH_NONE;
      data->state.authhost.done = FALSE;
    }

    if((data->state.authproxy.picked & (CURLAUTH_NTLM | CURLAUTH_NTLM_WB)) &&
       data->state.authproxy.done) {
      infof(data, "NTLM-proxy picked AND auth done set, clear picked!\n");
      data->state.authproxy.picked = CURLAUTH_NONE;
      data->state.authproxy.done = FALSE;
    }
#endif
  }

  /* Setup and init stuff before DO starts, in preparing for the transfer. */
  Curl_init_do(data, conn);

  /*
   * Setup whatever necessary for a resumed transfer
   */
  result = setup_range(data);
  if(result)
    goto out;

  /* Continue connectdata initialization here. */

  /*
   * Inherit the proper values from the urldata struct AFTER we have arranged
   * the persistent connection stuff
   */
  conn->seek_func = data->set.seek_func;
  conn->seek_client = data->set.seek_client;

  /*************************************************************
   * Resolve the address of the server or proxy
   *************************************************************/
  result = resolve_server(data, conn, async);

  /* Strip trailing dots. resolve_server copied the name. */
  strip_trailing_dot(&conn->host);
  if(conn->bits.httpproxy)
    strip_trailing_dot(&conn->http_proxy.host);
  if(conn->bits.socksproxy)
    strip_trailing_dot(&conn->socks_proxy.host);
  if(conn->bits.conn_to_host)
    strip_trailing_dot(&conn->conn_to_host);

out:
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
  struct Curl_easy *data = conn->data;

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
  conn->now = Curl_now();

  if(CURL_SOCKET_BAD == conn->sock[FIRSTSOCKET]) {
    conn->bits.tcpconnect[FIRSTSOCKET] = FALSE;
    result = Curl_connecthost(conn, conn->dns_entry);
    if(result)
      return result;
  }
  else {
    Curl_pgrsTime(data, TIMER_CONNECT);    /* we're connected already */
    Curl_pgrsTime(data, TIMER_APPCONNECT); /* we're connected already */
    conn->bits.tcpconnect[FIRSTSOCKET] = TRUE;
    *protocol_done = TRUE;
    Curl_updateconninfo(conn, conn->sock[FIRSTSOCKET]);
    Curl_verboseconnect(conn);
  }

  conn->now = Curl_now(); /* time this *after* the connect is done, we set
                             this here perhaps a second time */
  return result;
}

CURLcode Curl_connect(struct Curl_easy *data,
                      bool *asyncp,
                      bool *protocol_done)
{
  CURLcode result;
  struct connectdata *conn;

  *asyncp = FALSE; /* assume synchronous resolves by default */

  /* init the single-transfer specific data */
  Curl_free_request_state(data);
  memset(&data->req, 0, sizeof(struct SingleRequest));
  data->req.maxdownload = -1;

  /* call the stuff that needs to be called */
  result = create_conn(data, &conn, asyncp);

  if(!result) {
    if(CONN_INUSE(conn))
      /* multiplexed */
      *protocol_done = TRUE;
    else if(!*asyncp) {
      /* DNS resolution is done: that's either because this is a reused
         connection, in which case DNS was unnecessary, or because DNS
         really did finish already (synch resolver/fast async resolve) */
      result = Curl_setup_conn(conn, protocol_done);
    }
  }

  if(result == CURLE_NO_CONNECTION_AVAILABLE) {
    return result;
  }
  else if(result && conn) {
    /* We're not allowed to return failure with memory left allocated in the
       connectdata struct, free those here */
    Curl_disconnect(data, conn, TRUE);
  }
  else if(!result && !data->conn)
    /* FILE: transfers already have the connection attached */
    Curl_attach_connnection(data, conn);

  return result;
}

/*
 * Curl_init_do() inits the readwrite session. This is inited each time (in
 * the DO function before the protocol-specific DO functions are invoked) for
 * a transfer, sometimes multiple times on the same Curl_easy. Make sure
 * nothing in here depends on stuff that are setup dynamically for the
 * transfer.
 *
 * Allow this function to get called with 'conn' set to NULL.
 */

CURLcode Curl_init_do(struct Curl_easy *data, struct connectdata *conn)
{
  struct SingleRequest *k = &data->req;

  if(conn) {
    conn->bits.do_more = FALSE; /* by default there's no curl_do_more() to
                                   use */
    /* if the protocol used doesn't support wildcards, switch it off */
    if(data->state.wildcardmatch &&
       !(conn->handler->flags & PROTOPT_WILDCARD))
      data->state.wildcardmatch = FALSE;
  }

  data->state.done = FALSE; /* *_done() is not called yet */
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

  k->start = Curl_now(); /* start time */
  k->now = k->start;   /* current time is now */
  k->header = TRUE; /* assume header */

  k->bytecount = 0;

  k->buf = data->state.buffer;
  k->hbufp = data->state.headerbuff;
  k->ignorebody = FALSE;

  Curl_speedinit(data);

  Curl_pgrsSetUploadCounter(data, 0);
  Curl_pgrsSetDownloadCounter(data, 0);

  return CURLE_OK;
}

/*
* get_protocol_family()
*
* This is used to return the protocol family for a given protocol.
*
* Parameters:
*
* protocol  [in]  - A single bit protocol identifier such as HTTP or HTTPS.
*
* Returns the family as a single bit protocol identifier.
*/

static unsigned int get_protocol_family(unsigned int protocol)
{
  unsigned int family;

  switch(protocol) {
  case CURLPROTO_HTTP:
  case CURLPROTO_HTTPS:
    family = CURLPROTO_HTTP;
    break;

  case CURLPROTO_FTP:
  case CURLPROTO_FTPS:
    family = CURLPROTO_FTP;
    break;

  case CURLPROTO_SCP:
    family = CURLPROTO_SCP;
    break;

  case CURLPROTO_SFTP:
    family = CURLPROTO_SFTP;
    break;

  case CURLPROTO_TELNET:
    family = CURLPROTO_TELNET;
    break;

  case CURLPROTO_LDAP:
  case CURLPROTO_LDAPS:
    family = CURLPROTO_LDAP;
    break;

  case CURLPROTO_DICT:
    family = CURLPROTO_DICT;
    break;

  case CURLPROTO_FILE:
    family = CURLPROTO_FILE;
    break;

  case CURLPROTO_TFTP:
    family = CURLPROTO_TFTP;
    break;

  case CURLPROTO_IMAP:
  case CURLPROTO_IMAPS:
    family = CURLPROTO_IMAP;
    break;

  case CURLPROTO_POP3:
  case CURLPROTO_POP3S:
    family = CURLPROTO_POP3;
    break;

  case CURLPROTO_SMTP:
  case CURLPROTO_SMTPS:
      family = CURLPROTO_SMTP;
      break;

  case CURLPROTO_RTSP:
    family = CURLPROTO_RTSP;
    break;

  case CURLPROTO_RTMP:
  case CURLPROTO_RTMPS:
    family = CURLPROTO_RTMP;
    break;

  case CURLPROTO_RTMPT:
  case CURLPROTO_RTMPTS:
    family = CURLPROTO_RTMPT;
    break;

  case CURLPROTO_RTMPE:
    family = CURLPROTO_RTMPE;
    break;

  case CURLPROTO_RTMPTE:
    family = CURLPROTO_RTMPTE;
    break;

  case CURLPROTO_GOPHER:
    family = CURLPROTO_GOPHER;
    break;

  case CURLPROTO_SMB:
  case CURLPROTO_SMBS:
    family = CURLPROTO_SMB;
    break;

  default:
      family = 0;
      break;
  }

  return family;
}


/*
 * Wrapper to call functions in Curl_conncache_foreach()
 *
 * Returns always 0.
 */
static int conn_upkeep(struct connectdata *conn,
                       void *param)
{
  /* Param is unused. */
  (void)param;

  if(conn->handler->connection_check) {
    /* Do a protocol-specific keepalive check on the connection. */
    conn->handler->connection_check(conn, CONNCHECK_KEEPALIVE);
  }

  return 0; /* continue iteration */
}

CURLcode Curl_upkeep(struct conncache *conn_cache,
                          void *data)
{
  /* Loop over every connection and make connection alive. */
  Curl_conncache_foreach(data,
                         conn_cache,
                         data,
                         conn_upkeep);
  return CURLE_OK;
}
