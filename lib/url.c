/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
 *
 * This software is licensed as described in the file COPYING, which
 * you should have received as part of this distribution. The terms
 * are also available at https://curl.se/docs/copyright.html.
 *
 * You may opt to use, copy, modify, merge, publish, distribute and/or sell
 * copies of the Software, and permit persons to whom the Software is
 * furnished to do so, under the terms of the COPYING file.
 *
 * This software is distributed on an "AS IS" basis, WITHOUT WARRANTY OF ANY
 * KIND, either express or implied.
 *
 * SPDX-License-Identifier: curl
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
#error "We cannot compile without socket() support!"
#endif

#if defined(HAVE_IF_NAMETOINDEX) && defined(USE_WINSOCK)
#if defined(__MINGW32__) && (__MINGW64_VERSION_MAJOR <= 5)
#include <wincrypt.h>  /* workaround for old mingw-w64 missing to include it */
#endif
#include <iphlpapi.h>
#endif

#include "urldata.h"
#include "mime.h"
#include "bufref.h"
#include "vtls/vtls.h"
#include "vssh/vssh.h"
#include "hostip.h"
#include "transfer.h"
#include "curl_addrinfo.h"
#include "curl_trc.h"
#include "progress.h"
#include "cookie.h"
#include "strcase.h"
#include "escape.h"
#include "curl_share.h"
#include "http_digest.h"
#include "multiif.h"
#include "getinfo.h"
#include "pop3.h"
#include "urlapi-int.h"
#include "system_win32.h"
#include "hsts.h"
#include "noproxy.h"
#include "cfilters.h"
#include "idn.h"
#include "http_proxy.h"
#include "conncache.h"
#include "multihandle.h"
#include "curlx/strdup.h"
#include "setopt.h"
#include "altsvc.h"
#include "curlx/dynbuf.h"
#include "headers.h"
#include "curlx/strerr.h"
#include "curlx/strparse.h"

/* Now for the protocols */
#include "ftp.h"
#include "dict.h"
#include "telnet.h"
#include "tftp.h"
#include "http.h"
#include "file.h"
#include "curl_ldap.h"
#include "vssh/ssh.h"
#include "imap.h"
#include "url.h"
#include "connect.h"
#include "gopher.h"
#include "mqtt.h"
#include "rtsp.h"
#include "smtp.h"
#include "ws.h"

#ifdef USE_NGHTTP2
static void data_priority_cleanup(struct Curl_easy *data);
#else
#define data_priority_cleanup(x)
#endif

/* Some parts of the code (e.g. chunked encoding) assume this buffer has more
 * than a few bytes to play with. Do not let it become too small or bad things
 * will happen.
 */
#if READBUFFER_SIZE < READBUFFER_MIN
# error READBUFFER_SIZE is too small
#endif

/*
 * get_protocol_family()
 *
 * This is used to return the protocol family for a given protocol.
 *
 * Parameters:
 *
 * 's'  [in]  - struct Curl_scheme pointer.
 *
 * Returns the family as a single bit protocol identifier.
 */
static curl_prot_t get_protocol_family(const struct Curl_scheme *s)
{
  DEBUGASSERT(s);
  DEBUGASSERT(s->family);
  return s->family;
}

void Curl_freeset(struct Curl_easy *data)
{
  /* Free all dynamic strings stored in the data->set substructure. */
  enum dupstring i;
  enum dupblob j;

  for(i = (enum dupstring)0; i < STRING_LAST; i++) {
    curlx_safefree(data->set.str[i]);
  }

  for(j = (enum dupblob)0; j < BLOB_LAST; j++) {
    curlx_safefree(data->set.blobs[j]);
  }

  Curl_bufref_free(&data->state.referer);
  Curl_bufref_free(&data->state.url);

#if !defined(CURL_DISABLE_MIME) || !defined(CURL_DISABLE_FORM_API)
  Curl_mime_cleanpart(data->set.mimepostp);
  curlx_safefree(data->set.mimepostp);
#endif

#ifndef CURL_DISABLE_COOKIES
  curl_slist_free_all(data->state.cookielist);
  data->state.cookielist = NULL;
#endif
}

/* free the URL pieces */
static void up_free(struct Curl_easy *data)
{
  struct urlpieces *up = &data->state.up;
  curlx_safefree(up->scheme);
  curlx_safefree(up->hostname);
  curlx_safefree(up->port);
  curlx_safefree(up->user);
  curlx_safefree(up->password);
  curlx_safefree(up->options);
  curlx_safefree(up->path);
  curlx_safefree(up->query);
  curl_url_cleanup(data->state.uh);
  data->state.uh = NULL;
}

/*
 * This is the internal function curl_easy_cleanup() calls. This should
 * cleanup and free all resources associated with this sessionhandle.
 *
 * We ignore SIGPIPE when this is called from curl_easy_cleanup.
 */

CURLcode Curl_close(struct Curl_easy **datap)
{
  struct Curl_easy *data;

  if(!datap || !*datap)
    return CURLE_OK;

  data = *datap;
  *datap = NULL;

  if(!data->state.internal && data->multi) {
    /* This handle is still part of a multi handle, take care of this first
       and detach this handle from there.
       This detaches the connection. */
    curl_multi_remove_handle(data->multi, data);
  }
  else {
    /* Detach connection if any is left. This should not be normal, but can be
       the case for example with CONNECT_ONLY + recv/send (test 556) */
    Curl_detach_connection(data);
    if(!data->state.internal && data->multi_easy) {
      /* when curl_easy_perform() is used, it creates its own multi handle to
         use and this is the one */
      curl_multi_cleanup(data->multi_easy);
      data->multi_easy = NULL;
    }
  }
  DEBUGASSERT(!data->conn || data->state.internal);

  Curl_expire_clear(data); /* shut off any timers left */

  if(data->state.rangestringalloc)
    curlx_free(data->state.range);

  /* release any resolve information this transfer kept */
  Curl_resolv_destroy_all(data);

  data->set.verbose = FALSE; /* no more calls to DEBUGFUNCTION */
  data->magic = 0; /* force a clear AFTER the possibly enforced removal from
                    * the multi handle and async dns shutdown. The multi
                    * handle might check the magic and so might any
                    * DEBUGFUNCTION invoked for tracing */

  /* freed here in case DONE was not called */
  Curl_req_free(&data->req, data);

  /* Close down all open SSL info and sessions */
  Curl_ssl_close_all(data);
  Curl_peer_unlink(&data->state.first_origin);
  Curl_ssl_free_certinfo(data);

  Curl_bufref_free(&data->state.referer);

  up_free(data);
  curlx_dyn_free(&data->state.headerb);
  Curl_flush_cookies(data, TRUE);
#ifndef CURL_DISABLE_ALTSVC
  Curl_altsvc_save(data, data->asi, data->set.str[STRING_ALTSVC]);
  Curl_altsvc_cleanup(&data->asi);
#endif
#ifndef CURL_DISABLE_HSTS
  Curl_hsts_save(data, data->hsts, data->set.str[STRING_HSTS]);
  if(!data->share || !data->share->hsts)
    Curl_hsts_cleanup(&data->hsts);
  curl_slist_free_all(data->state.hstslist); /* clean up list */
#endif
#if !defined(CURL_DISABLE_HTTP) && !defined(CURL_DISABLE_DIGEST_AUTH)
  Curl_http_auth_cleanup_digest(data);
#endif
  curlx_safefree(data->state.most_recent_ftp_entrypath);
  curlx_safefree(data->info.contenttype);
  curlx_safefree(data->info.wouldredirect);

  data_priority_cleanup(data);

  /* No longer a dirty share, if it exists */
  if(Curl_share_easy_unlink(data))
    DEBUGASSERT(0);

  Curl_hash_destroy(&data->meta_hash);
  curlx_safefree(data->state.aptr.uagent);
  curlx_safefree(data->state.aptr.accept_encoding);
  curlx_safefree(data->state.aptr.rangeline);
  curlx_safefree(data->state.aptr.ref);
  curlx_safefree(data->state.aptr.host);
#ifndef CURL_DISABLE_COOKIES
  curlx_safefree(data->req.cookiehost);
#endif
#ifndef CURL_DISABLE_RTSP
  curlx_safefree(data->state.aptr.rtsp_transport);
#endif
  curlx_safefree(data->state.aptr.user);
  curlx_safefree(data->state.aptr.passwd);
#ifndef CURL_DISABLE_PROXY
  curlx_safefree(data->state.aptr.proxyuser);
  curlx_safefree(data->state.aptr.proxypasswd);
#endif

#if !defined(CURL_DISABLE_HTTP) && !defined(CURL_DISABLE_FORM_API)
  Curl_mime_cleanpart(data->state.formp);
  curlx_safefree(data->state.formp);
#endif

  /* destruct wildcard structures if it is needed */
  Curl_wildcard_dtor(&data->wildcard);
  Curl_freeset(data);
  Curl_headers_cleanup(data);
  Curl_netrc_cleanup(&data->state.netrc);
  curlx_free(data);
  return CURLE_OK;
}

/*
 * Initialize the UserDefined fields within a Curl_easy.
 * This may be safely called on a new or existing Curl_easy.
 */
void Curl_init_userdefined(struct Curl_easy *data)
{
  struct UserDefined *set = &data->set;

  set->out = stdout;  /* default output to stdout */
  set->in_set = stdin;  /* default input from stdin */
  set->err = stderr;  /* default stderr to stderr */

#if defined(__clang__) && __clang_major__ >= 16
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wcast-function-type-strict"
#endif
  /* use fwrite as default function to store output */
  set->fwrite_func = (curl_write_callback)fwrite;

  /* use fread as default function to read input */
  set->fread_func_set = (curl_read_callback)fread;
#if defined(__clang__) && __clang_major__ >= 16
#pragma clang diagnostic pop
#endif
  set->is_fread_set = 0;

  set->seek_client = ZERO_NULL;

  set->filesize = -1;        /* we do not know the size */
  set->postfieldsize = -1;   /* unknown size */
  set->maxredirs = 30;       /* sensible default */

  set->method = HTTPREQ_GET; /* Default HTTP request */
#ifndef CURL_DISABLE_RTSP
  set->rtspreq = RTSPREQ_OPTIONS; /* Default RTSP request */
#endif
#ifndef CURL_DISABLE_FTP
  set->ftp_use_epsv = TRUE;   /* FTP defaults to EPSV operations */
  set->ftp_use_eprt = TRUE;   /* FTP defaults to EPRT operations */
  set->ftp_use_pret = FALSE;  /* mainly useful for drftpd servers */
  set->ftp_filemethod = FTPFILE_MULTICWD;
  set->ftp_skip_ip = TRUE;    /* skip PASV IP by default */
#endif
  set->dns_cache_timeout_ms = 60000; /* Timeout every 60 seconds by default */

  /* Timeout every 24 hours by default */
  set->general_ssl.ca_cache_timeout = 24 * 60 * 60;

  set->httpauth = CURLAUTH_BASIC;  /* defaults to basic */

#ifndef CURL_DISABLE_PROXY
  set->proxyport = 0;
  set->proxytype = CURLPROXY_HTTP; /* defaults to HTTP proxy */
  set->proxyauth = CURLAUTH_BASIC; /* defaults to basic */
  /* SOCKS5 proxy auth defaults to username/password + GSS-API */
  set->socks5auth = CURLAUTH_BASIC | CURLAUTH_GSSAPI;
#endif

  Curl_ssl_easy_config_init(data);
#ifndef CURL_DISABLE_DOH
  set->doh_verifyhost = TRUE;
  set->doh_verifypeer = TRUE;
#endif
#ifdef USE_SSH
  /* defaults to any auth type */
  set->ssh_auth_types = CURLSSH_AUTH_DEFAULT;
  set->new_directory_perms = 0755; /* Default permissions */
#endif

  set->new_file_perms = 0644;    /* Default permissions */
  set->allowed_protocols = (curl_prot_t)CURLPROTO_64ALL;
  set->redir_protocols = CURLPROTO_REDIR;

#if defined(HAVE_GSSAPI) || defined(USE_WINDOWS_SSPI)
  /*
   * disallow unprotected protection negotiation NEC reference implementation
   * seem not to follow rfc1961 section 4.3/4.4
   */
  set->socks5_gssapi_nec = FALSE;
#endif

  /* set default minimum TLS version */
#ifdef USE_SSL
  Curl_setopt_SSLVERSION(data, CURLOPT_SSLVERSION, CURL_SSLVERSION_DEFAULT);
#ifndef CURL_DISABLE_PROXY
  Curl_setopt_SSLVERSION(data, CURLOPT_PROXY_SSLVERSION,
                         CURL_SSLVERSION_DEFAULT);
#endif
#endif
#ifndef CURL_DISABLE_FTP
  set->wildcard_enabled = FALSE;
  set->chunk_bgn = ZERO_NULL;
  set->chunk_end = ZERO_NULL;
  set->fnmatch = ZERO_NULL;
#endif
  set->tcp_keepalive = FALSE;
  set->tcp_keepintvl = 60;
  set->tcp_keepidle = 60;
  set->tcp_keepcnt = 9;
  set->tcp_fastopen = FALSE;
  set->tcp_nodelay = TRUE;
  set->ssl_enable_alpn = TRUE;
  set->expect_100_timeout = 1000L; /* Wait for a second by default. */
  set->sep_headers = TRUE; /* separated header lists by default */
  set->buffer_size = READBUFFER_SIZE;
  set->upload_buffer_size = UPLOADBUFFER_DEFAULT;
  set->upload_flags = CURLULFLAG_SEEN;
  set->happy_eyeballs_timeout = CURL_HET_DEFAULT;
  set->upkeep_interval_ms = CURL_UPKEEP_INTERVAL_DEFAULT;
  set->maxconnects = DEFAULT_CONNCACHE_SIZE; /* for easy handles */
  set->conn_max_idle_ms = 118 * 1000;
  set->conn_max_age_ms = 24 * 3600 * 1000;
  set->http09_allowed = FALSE;
  set->httpwant = CURL_HTTP_VERSION_NONE;
#if defined(USE_HTTP2) || defined(USE_HTTP3)
  memset(&set->priority, 0, sizeof(set->priority));
#endif
  set->quick_exit = 0L;
#ifndef CURL_DISABLE_WEBSOCKETS
  set->ws_raw_mode = FALSE;
  set->ws_no_auto_pong = FALSE;
#endif
}

/* easy->meta_hash destructor. Should never be called as elements
 * MUST be added with their own destructor */
static void easy_meta_freeentry(void *p)
{
  (void)p;
  /* Always FALSE. Cannot use a 0 assert here since compilers
   * are not in agreement if they then want a NORETURN attribute or
   * not. *sigh* */
  DEBUGASSERT(p == NULL);
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
  struct Curl_easy *data;

  /* simple start-up: alloc the struct, init it with zeroes and return */
  data = curlx_calloc(1, sizeof(struct Curl_easy));
  if(!data) {
    /* this is a serious error */
    DEBUGF(curl_mfprintf(stderr, "Error: calloc of Curl_easy failed\n"));
    return CURLE_OUT_OF_MEMORY;
  }

  data->magic = CURLEASY_MAGIC_NUMBER;
  /* most recent connection is not yet defined */
  data->state.lastconnect_id = -1;
  data->state.recent_conn_id = -1;
  /* and not assigned an id yet */
  data->id = -1;
  data->mid = UINT32_MAX;
  data->master_mid = UINT32_MAX;
  data->progress.hide = TRUE;
  data->state.current_speed = -1; /* init to negative == impossible */

  Curl_hash_init(&data->meta_hash, 23,
                 Curl_hash_str, curlx_str_key_compare, easy_meta_freeentry);
  curlx_dyn_init(&data->state.headerb, CURL_MAX_HTTP_HEADER);
  Curl_bufref_init(&data->state.url);
  Curl_bufref_init(&data->state.referer);
  Curl_req_init(&data->req);
  Curl_initinfo(data);
#ifndef CURL_DISABLE_HTTP
  Curl_llist_init(&data->state.httphdrs, NULL);
#endif
  Curl_netrc_init(&data->state.netrc);
  Curl_init_userdefined(data);

  *curl = data;
  return CURLE_OK;
}

void Curl_conn_free(struct Curl_easy *data, struct connectdata *conn)
{
  size_t i;

  DEBUGASSERT(conn);

  if(conn->scheme && conn->scheme->run->disconnect &&
     !conn->bits.shutdown_handler)
    conn->scheme->run->disconnect(data, conn, TRUE);

  for(i = 0; i < CURL_ARRAYSIZE(conn->cfilter); ++i) {
    Curl_conn_cf_discard_all(data, conn, (int)i);
  }

#ifndef CURL_DISABLE_PROXY
  curlx_safefree(conn->http_proxy.user);
  curlx_safefree(conn->socks_proxy.user);
  curlx_safefree(conn->http_proxy.passwd);
  curlx_safefree(conn->socks_proxy.passwd);
  Curl_peer_unlink(&conn->http_proxy.peer);
  Curl_peer_unlink(&conn->socks_proxy.peer);
#endif
  curlx_safefree(conn->user);
  curlx_safefree(conn->passwd);
  curlx_safefree(conn->sasl_authzid);
  curlx_safefree(conn->options);
  curlx_safefree(conn->oauth_bearer);
  curlx_safefree(conn->localdev);
  Curl_ssl_conn_config_cleanup(conn);

  curlx_safefree(conn->destination);
  Curl_hash_destroy(&conn->meta_hash);
  Curl_peer_unlink(&conn->origin);
  Curl_peer_unlink(&conn->via_peer);
  Curl_peer_unlink(&conn->origin2);
  Curl_peer_unlink(&conn->via_peer2);

  curlx_free(conn); /* free all the connection oriented data */
}

/*
 * xfer_may_multiplex()
 *
 * Return a TRUE, iff the transfer can be done over an (appropriate)
 * multiplexed connection.
 */
static bool xfer_may_multiplex(const struct Curl_easy *data,
                               const struct connectdata *conn)
{
#ifndef CURL_DISABLE_HTTP
  /* If an HTTP protocol and multiplexing is enabled */
  if((conn->scheme->protocol & PROTO_FAMILY_HTTP) &&
     (!conn->bits.protoconnstart || !conn->bits.close)) {

    if(Curl_multiplex_wanted(data->multi) &&
       (data->state.http_neg.allowed & (CURL_HTTP_V2x | CURL_HTTP_V3x)))
      /* allows HTTP/2 or newer */
      return TRUE;
  }
#else
  (void)data;
  (void)conn;
#endif
  return FALSE;
}

#ifndef CURL_DISABLE_PROXY
static bool proxy_info_matches(const struct proxy_info *data,
                               const struct proxy_info *needle)
{
  if((data->proxytype == needle->proxytype) &&
     Curl_peer_same_destination(data->peer, needle->peer)) {

    if(Curl_timestrcmp(data->user, needle->user) ||
       Curl_timestrcmp(data->passwd, needle->passwd))
      return FALSE;
    return TRUE;
  }
  return FALSE;
}
#endif

/* A connection has to have been idle for less than 'conn_max_idle_ms'
   (the success rate is too low after this), or created less than
   'conn_max_age_ms' ago, to be subject for reuse. */
static bool conn_maxage(struct Curl_easy *data,
                        struct connectdata *conn,
                        struct curltime now)
{
  timediff_t age_ms;

  if(data->set.conn_max_idle_ms) {
    age_ms = curlx_ptimediff_ms(&now, &conn->lastused);
    if(age_ms > data->set.conn_max_idle_ms) {
      infof(data, "Too old connection (%" FMT_TIMEDIFF_T
            " ms idle, max idle is %" FMT_TIMEDIFF_T " ms), disconnect it",
            age_ms, data->set.conn_max_idle_ms);
      return TRUE;
    }
  }

  if(data->set.conn_max_age_ms) {
    age_ms = curlx_ptimediff_ms(&now, &conn->created);
    if(age_ms > data->set.conn_max_age_ms) {
      infof(data,
            "Too old connection (created %" FMT_TIMEDIFF_T
            " ms ago, max lifetime is %" FMT_TIMEDIFF_T " ms), disconnect it",
            age_ms, data->set.conn_max_age_ms);
      return TRUE;
    }
  }

  return FALSE;
}

/*
 * Return TRUE iff the given connection is considered dead.
 */
bool Curl_conn_seems_dead(struct connectdata *conn,
                          struct Curl_easy *data)
{
  DEBUGASSERT(!data->conn);
  if(!CONN_INUSE(conn)) {
    /* The check for a dead socket makes sense only if the connection is not in
       use */
    bool dead;

    if(conn_maxage(data, conn, *Curl_pgrs_now(data))) {
      /* avoid check if already too old */
      dead = TRUE;
    }
    else if(conn->scheme->run->connection_is_dead) {
      /* The protocol has a special method for checking the state of the
         connection. Use it to check if the connection is dead. */
      /* briefly attach the connection for the check */
      Curl_attach_connection(data, conn);
      dead = conn->scheme->run->connection_is_dead(data, conn);
      Curl_detach_connection(data);
    }
    else {
      bool input_pending = FALSE;

      Curl_attach_connection(data, conn);
      dead = !Curl_conn_is_alive(data, conn, &input_pending);
      if(input_pending) {
        /* For reuse, we want a "clean" connection state. The includes
         * that we expect - in general - no waiting input data. Input
         * waiting might be a TLS Notify Close, for example. We reject
         * that.
         * For protocols where data from other end may arrive at
         * any time (HTTP/2 PING for example), the protocol handler needs
         * to install its own `connection_check` callback.
         */
        DEBUGF(infof(data, "connection has input pending, not reusable"));
        dead = TRUE;
      }
      Curl_detach_connection(data);
    }

    if(dead) {
      /* remove connection from cpool */
      infof(data, "Connection %" FMT_OFF_T " seems to be dead",
            conn->connection_id);
      return TRUE;
    }
  }
  return FALSE;
}

CURLcode Curl_conn_upkeep(struct Curl_easy *data,
                          struct connectdata *conn)
{
  CURLcode result = CURLE_OK;
  if(curlx_ptimediff_ms(Curl_pgrs_now(data), &conn->keepalive) <=
     data->set.upkeep_interval_ms)
    return result;

  /* briefly attach for action */
  Curl_attach_connection(data, conn);
  result = Curl_conn_keep_alive(data, conn, FIRSTSOCKET);
  Curl_detach_connection(data);

  conn->keepalive = *Curl_pgrs_now(data);
  return result;
}

#ifdef USE_SSH
static bool ssh_config_matches(struct connectdata *one,
                               struct connectdata *two)
{
  struct ssh_conn *sshc1, *sshc2;

  sshc1 = Curl_conn_meta_get(one, CURL_META_SSH_CONN);
  sshc2 = Curl_conn_meta_get(two, CURL_META_SSH_CONN);
  return sshc1 && sshc2 && Curl_safecmp(sshc1->rsa, sshc2->rsa) &&
         Curl_safecmp(sshc1->rsa_pub, sshc2->rsa_pub);
}
#endif

struct url_conn_match {
  struct connectdata *found;
  struct Curl_easy *data;
  struct connectdata *needle;
  BIT(may_multiplex);
  BIT(want_ntlm_http);
  BIT(want_proxy_ntlm_http);
  BIT(want_nego_http);
  BIT(want_proxy_nego_http);
  BIT(req_tls); /* require TLS use from a clear-text start */
  BIT(wait_pipe);
  BIT(force_reuse);
  BIT(seen_pending_conn);
  BIT(seen_single_use_conn);
  BIT(seen_multiplex_conn);
};

static bool url_match_connect_config(struct connectdata *conn,
                                     struct url_conn_match *m)
{
  /* connect-only or to-be-closed connections will not be reused */
  if(conn->bits.connect_only || conn->bits.close || conn->bits.no_reuse)
    return FALSE;

  /* ip_version must match */
  if(m->data->set.ipver != CURL_IPRESOLVE_WHATEVER &&
     m->data->set.ipver != conn->ip_version)
    return FALSE;

  if(m->needle->localdev || m->needle->localport) {
    /* If we are bound to a specific local end (IP+port), we must not reuse a
       random other one, although if we did not ask for a particular one we
       can reuse one that was bound.

       This comparison is a bit rough and too strict. Since the input
       parameters can be specified in numerous ways and still end up the same
       it would take a lot of processing to make it really accurate. Instead,
       this matching will assume that reuses of bound connections will most
       likely also reuse the exact same binding parameters and missing out a
       few edge cases should not hurt anyone much.
    */
    if((conn->localport != m->needle->localport) ||
       (conn->localportrange != m->needle->localportrange) ||
       (m->needle->localdev &&
        (!conn->localdev || strcmp(conn->localdev, m->needle->localdev))))
      return FALSE;
  }

  if(!m->needle->via_peer != !conn->via_peer)
    /* do not mix connections that use the "connect to host" feature and
     * connections that do not use this feature */
    return FALSE;

  return TRUE;
}

static bool url_match_fully_connected(struct connectdata *conn,
                                      struct url_conn_match *m)
{
  if(!Curl_conn_is_connected(conn, FIRSTSOCKET) ||
     conn->bits.upgrade_in_progress) {
    /* Not yet connected, or a protocol upgrade is in progress. The later
     * happens for HTTP/2 Upgrade: requests that need a response. */
    if(m->may_multiplex) {
      m->seen_pending_conn = TRUE;
      /* Do not pick a connection that has not connected yet */
      infof(m->data, "Connection #%" FMT_OFF_T
            " is not open enough, cannot reuse", conn->connection_id);
    }
    /* Do not pick a connection that has not connected yet */
    return FALSE;
  }
  return TRUE;
}

static bool url_match_multi(struct connectdata *conn,
                            struct url_conn_match *m)
{
  if(CONN_INUSE(conn)) {
    DEBUGASSERT(conn->attached_multi);
    if(conn->attached_multi != m->data->multi)
      return FALSE;
  }
  return TRUE;
}

static bool url_match_multiplex_needs(struct connectdata *conn,
                                      struct url_conn_match *m)
{
  if(CONN_INUSE(conn)) {
    if(!conn->bits.multiplex) {
      /* conn busy and conn cannot take more transfers */
      m->seen_single_use_conn = TRUE;
      return FALSE;
    }
    m->seen_multiplex_conn = TRUE;
    if(!m->may_multiplex || !url_match_multi(conn, m))
      /* conn busy and transfer cannot be multiplexed */
      return FALSE;
  }
  return TRUE;
}

static bool url_match_multiplex_limits(struct connectdata *conn,
                                       struct url_conn_match *m)
{
  if(CONN_INUSE(conn) && m->may_multiplex) {
    DEBUGASSERT(conn->bits.multiplex);
    /* If multiplexed, make sure we do not go over concurrency limit */
    if(conn->attached_xfers >=
            Curl_multi_max_concurrent_streams(m->data->multi)) {
      infof(m->data, "client side MAX_CONCURRENT_STREAMS reached"
            ", skip (%u)", conn->attached_xfers);
      return FALSE;
    }
    if(conn->attached_xfers >=
       Curl_conn_get_max_concurrent(m->data, conn, FIRSTSOCKET)) {
      infof(m->data, "MAX_CONCURRENT_STREAMS reached, skip (%u)",
            conn->attached_xfers);
      return FALSE;
    }
    /* When not multiplexed, we have a match here! */
    infof(m->data, "Multiplexed connection found");
  }
  return TRUE;
}

static bool url_match_ssl_use(struct connectdata *conn,
                              struct url_conn_match *m)
{
  if(m->needle->scheme->flags & PROTOPT_SSL) {
    /* We are looking for SSL, if `conn` does not do it, not a match. */
    if(!Curl_conn_is_ssl(conn, FIRSTSOCKET))
      return FALSE;
  }
  else if(Curl_conn_is_ssl(conn, FIRSTSOCKET)) {
    /* If the protocol does not allow reuse of SSL connections OR
       is of another protocol family, not a match. */
    if(!(m->needle->scheme->flags & PROTOPT_SSL_REUSE) ||
       (get_protocol_family(conn->scheme) != m->needle->scheme->protocol))
      return FALSE;
  }
  else if(m->req_tls)
    /* a clear-text STARTTLS protocol with required TLS */
    return FALSE;
  return TRUE;
}

#ifndef CURL_DISABLE_PROXY
static bool url_match_proxy_use(struct connectdata *conn,
                                struct url_conn_match *m)
{
  if(m->needle->bits.httpproxy != conn->bits.httpproxy ||
     m->needle->bits.socksproxy != conn->bits.socksproxy)
    return FALSE;

  if(m->needle->bits.socksproxy &&
     !proxy_info_matches(&m->needle->socks_proxy, &conn->socks_proxy))
    return FALSE;

  if(m->needle->bits.httpproxy) {
    if(m->needle->bits.tunnel_proxy != conn->bits.tunnel_proxy)
      return FALSE;

    if(!proxy_info_matches(&m->needle->http_proxy, &conn->http_proxy))
      return FALSE;

    if(IS_HTTPS_PROXY(m->needle->http_proxy.proxytype)) {
      /* https proxies come in different types, http/1.1, h2, ... */
      if(m->needle->http_proxy.proxytype != conn->http_proxy.proxytype)
        return FALSE;
      /* match SSL config to proxy */
      if(!Curl_ssl_conn_config_match(m->data, conn, TRUE)) {
        DEBUGF(infof(m->data,
                     "Connection #%" FMT_OFF_T
                     " has different SSL proxy parameters, cannot reuse",
                     conn->connection_id));
        return FALSE;
      }
      /* the SSL config to the server, which may apply here is checked
       * further below */
    }
  }
  return TRUE;
}
#else
#define url_match_proxy_use(c, m) ((void)(c), (void)(m), TRUE)
#endif

#ifndef CURL_DISABLE_HTTP
static bool url_match_http_multiplex(struct connectdata *conn,
                                     struct url_conn_match *m)
{
  if(m->may_multiplex &&
     (m->data->state.http_neg.allowed & (CURL_HTTP_V2x | CURL_HTTP_V3x)) &&
     (m->needle->scheme->protocol & CURLPROTO_HTTP) &&
     !conn->httpversion_seen) {
    if(m->data->set.pipewait) {
      infof(m->data, "Server upgrade does not support multiplex yet, wait");
      m->found = NULL;
      m->wait_pipe = TRUE;
      return TRUE; /* stop searching, we want to wait */
    }
    infof(m->data, "Server upgrade cannot be used");
    return FALSE;
  }
  return TRUE;
}

static bool url_match_http_version(struct connectdata *conn,
                                   struct url_conn_match *m)
{
  /* If looking for HTTP and the HTTP versions allowed do not include
   * the HTTP version of conn, continue looking. */
  if((m->needle->scheme->protocol & PROTO_FAMILY_HTTP)) {
    switch(Curl_conn_http_version(m->data, conn)) {
    case 30:
      if(!(m->data->state.http_neg.allowed & CURL_HTTP_V3x)) {
        DEBUGF(infof(m->data, "not reusing conn #%" CURL_FORMAT_CURL_OFF_T
                     ", we do not want h3", conn->connection_id));
        return FALSE;
      }
      break;
    case 20:
      if(!(m->data->state.http_neg.allowed & CURL_HTTP_V2x)) {
        DEBUGF(infof(m->data, "not reusing conn #%" CURL_FORMAT_CURL_OFF_T
                     ", we do not want h2", conn->connection_id));
        return FALSE;
      }
      break;
    default:
      if(!(m->data->state.http_neg.allowed & CURL_HTTP_V1x)) {
        DEBUGF(infof(m->data, "not reusing conn #%" CURL_FORMAT_CURL_OFF_T
                     ", we do not want h1", conn->connection_id));
        return FALSE;
      }
      break;
    }
  }
  return TRUE;
}
#else
#define url_match_http_multiplex(c, m) ((void)(c), (void)(m), TRUE)
#define url_match_http_version(c, m)   ((void)(c), (void)(m), TRUE)
#endif

static bool url_match_proto_config(struct connectdata *conn,
                                   struct url_conn_match *m)
{
  if(!url_match_http_version(conn, m))
    return FALSE;

#ifdef USE_SSH
  if(get_protocol_family(m->needle->scheme) & PROTO_FAMILY_SSH) {
    if(!ssh_config_matches(m->needle, conn))
      return FALSE;
  }
#endif
#ifndef CURL_DISABLE_FTP
  else if(get_protocol_family(m->needle->scheme) & PROTO_FAMILY_FTP) {
    if(!ftp_conns_match(m->needle, conn))
      return FALSE;
  }
#endif
  return TRUE;
}

static bool url_match_auth(struct connectdata *conn,
                           struct url_conn_match *m)
{
  if(!(m->needle->scheme->flags & PROTOPT_CREDSPERREQUEST)) {
    /* This protocol requires credentials per connection,
       so verify that we are using the same name and password as well */
    if(Curl_timestrcmp(m->needle->user, conn->user) ||
       Curl_timestrcmp(m->needle->passwd, conn->passwd) ||
       Curl_timestrcmp(m->needle->sasl_authzid, conn->sasl_authzid) ||
       Curl_timestrcmp(m->needle->oauth_bearer, conn->oauth_bearer)) {
      /* one of them was different */
      return FALSE;
    }
  }
#ifdef HAVE_GSSAPI
  /* GSS delegation differences do not actually affect every connection
     and auth method, but this check takes precaution before efficiency */
  if(m->needle->gssapi_delegation != conn->gssapi_delegation)
    return FALSE;
#endif

  return TRUE;
}

static bool url_match_destination(struct connectdata *conn,
                                  struct url_conn_match *m)
{
  /* Additional match requirements if talking TLS OR
   * not talking to an HTTP proxy OR using a tunnel through a proxy */
  if((m->needle->scheme->flags & PROTOPT_SSL)
#ifndef CURL_DISABLE_PROXY
     || !m->needle->bits.httpproxy || m->needle->bits.tunnel_proxy
#endif
    ) {
    if(m->needle->scheme != conn->scheme) {
      /* `needle` and `conn` do not have the same scheme... */
      if(get_protocol_family(conn->scheme) != m->needle->scheme->protocol) {
        /* and `conn`s protocol family is not the protocol `needle` wants.
         * IMAPS would work for IMAP, but no vice versa. */
        return FALSE;
      }
      /* We are in an IMAPS vs IMAP like case. We expect `conn` to have SSL */
      if(!Curl_conn_is_ssl(conn, FIRSTSOCKET)) {
        DEBUGF(infof(m->data, "Connection #%" FMT_OFF_T
                     " has compatible protocol family, but no SSL, no match",
                     conn->connection_id));
        return FALSE;
      }
    }

    /* `needle` must have the same hostname and port in origin and
     * via_peer (if present, NULL peers are equal) */
    if(!Curl_peer_same_destination(m->needle->origin, conn->origin) ||
       !Curl_peer_same_destination(m->needle->via_peer, conn->via_peer))
      return FALSE;
  }
  return TRUE;
}

static bool url_match_ssl_config(struct connectdata *conn,
                                 struct url_conn_match *m)
{
  /* If talking TLS, conn needs to use the same SSL options. */
  if((m->needle->scheme->flags & PROTOPT_SSL) &&
     !Curl_ssl_conn_config_match(m->data, conn, FALSE)) {
    DEBUGF(infof(m->data, "Connection #%" FMT_OFF_T
                 " has different SSL parameters, cannot reuse",
                 conn->connection_id));
    return FALSE;
  }
  return TRUE;
}

#ifdef USE_NTLM
static bool url_match_auth_ntlm(struct connectdata *conn,
                                struct url_conn_match *m)
{
  /* If we are looking for an HTTP+NTLM connection, check if this is
     already authenticating with the right credentials. If not, keep
     looking so that we can reuse NTLM connections if
     possible. (Especially we must not reuse the same connection if
     partway through a handshake!) */
  if(m->want_ntlm_http) {
    if(Curl_timestrcmp(m->needle->user, conn->user) ||
       Curl_timestrcmp(m->needle->passwd, conn->passwd)) {
      /* we prefer a credential match, but this is at least a connection
         that can be reused and "upgraded" to NTLM if it does
         not have any auth ongoing. */
#ifdef USE_SPNEGO
      if((conn->http_ntlm_state == NTLMSTATE_NONE)
         && (conn->http_negotiate_state == GSS_AUTHNONE)) {
#else
      if(conn->http_ntlm_state == NTLMSTATE_NONE) {
#endif
        m->found = conn;
      }
      return FALSE;
    }
  }
  else if(conn->http_ntlm_state != NTLMSTATE_NONE) {
    /* Connection is using NTLM auth but we do not want NTLM */
    return FALSE;
  }

#ifndef CURL_DISABLE_PROXY
  /* Same for Proxy NTLM authentication */
  if(m->want_proxy_ntlm_http) {
    /* Both conn->http_proxy.user and conn->http_proxy.passwd can be
     * NULL */
    if(!conn->http_proxy.user || !conn->http_proxy.passwd)
      return FALSE;

    if(Curl_timestrcmp(m->needle->http_proxy.user,
                       conn->http_proxy.user) ||
       Curl_timestrcmp(m->needle->http_proxy.passwd,
                       conn->http_proxy.passwd))
      return FALSE;
  }
  else if(conn->proxy_ntlm_state != NTLMSTATE_NONE) {
    /* Proxy connection is using NTLM auth but we do not want NTLM */
    return FALSE;
  }
#endif
  if(m->want_ntlm_http || m->want_proxy_ntlm_http) {
    /* Credentials are already checked, we may use this connection.
     * With NTLM being weird as it is, we MUST use a
     * connection where it has already been fully negotiated.
     * If it has not, we keep on looking for a better one. */
    m->found = conn;

    if((m->want_ntlm_http &&
       (conn->http_ntlm_state != NTLMSTATE_NONE)) ||
        (m->want_proxy_ntlm_http &&
         (conn->proxy_ntlm_state != NTLMSTATE_NONE))) {
      /* We must use this connection, no other */
      m->force_reuse = TRUE;
      return TRUE;
    }
    /* Continue look up for a better connection */
    return FALSE;
  }
  return TRUE;
}
#else
#define url_match_auth_ntlm(c, m) ((void)(c), (void)(m), TRUE)
#endif

#ifdef USE_SPNEGO
static bool url_match_auth_nego(struct connectdata *conn,
                                struct url_conn_match *m)
{
  /* If we are looking for an HTTP+Negotiate connection, check if this is
     already authenticating with the right credentials. If not, keep looking
     so that we can reuse Negotiate connections if possible. */
  if(m->want_nego_http) {
    if(Curl_timestrcmp(m->needle->user, conn->user) ||
       Curl_timestrcmp(m->needle->passwd, conn->passwd))
      return FALSE;
  }
  else if(conn->http_negotiate_state != GSS_AUTHNONE) {
    /* Connection is using Negotiate auth but we do not want Negotiate */
    return FALSE;
  }

#ifndef CURL_DISABLE_PROXY
  /* Same for Proxy Negotiate authentication */
  if(m->want_proxy_nego_http) {
    /* Both conn->http_proxy.user and conn->http_proxy.passwd can be
     * NULL */
    if(!conn->http_proxy.user || !conn->http_proxy.passwd)
      return FALSE;

    if(Curl_timestrcmp(m->needle->http_proxy.user,
                       conn->http_proxy.user) ||
       Curl_timestrcmp(m->needle->http_proxy.passwd,
                       conn->http_proxy.passwd))
      return FALSE;
  }
  else if(conn->proxy_negotiate_state != GSS_AUTHNONE) {
    /* Proxy connection is using Negotiate auth but we do not want Negotiate */
    return FALSE;
  }
#endif
  if(m->want_nego_http || m->want_proxy_nego_http) {
    /* Credentials are already checked, we may use this connection. We MUST
     * use a connection where it has already been fully negotiated. If it has
     * not, we keep on looking for a better one. */
    m->found = conn;
    if((m->want_nego_http &&
        (conn->http_negotiate_state != GSS_AUTHNONE)) ||
       (m->want_proxy_nego_http &&
        (conn->proxy_negotiate_state != GSS_AUTHNONE))) {
      /* We must use this connection, no other */
      m->force_reuse = TRUE;
      return TRUE;
    }
    return FALSE; /* get another */
  }
  return TRUE;
}
#else
#define url_match_auth_nego(c, m) ((void)(c), (void)(m), TRUE)
#endif

static bool url_match_conn(struct connectdata *conn, void *userdata)
{
  struct url_conn_match *m = userdata;
  /* Check if `conn` can be used for transfer `m->data` */

  /* general connect config setting match? */
  if(!url_match_connect_config(conn, m))
    return FALSE;

  /* match for destination and protocol? */
  if(!url_match_destination(conn, m))
    return FALSE;

  if(!url_match_fully_connected(conn, m))
    return FALSE;

  if(!url_match_multiplex_needs(conn, m))
    return FALSE;

  if(!url_match_ssl_use(conn, m))
    return FALSE;
  if(!url_match_proxy_use(conn, m))
    return FALSE;
  if(!url_match_ssl_config(conn, m))
    return FALSE;

  if(!url_match_http_multiplex(conn, m))
    return FALSE;
  else if(m->wait_pipe)
    /* we decided to wait on PIPELINING */
    return TRUE;

  if(!url_match_auth(conn, m))
    return FALSE;

  if(!url_match_proto_config(conn, m))
    return FALSE;

  if(!url_match_auth_ntlm(conn, m))
    return FALSE;
  else if(m->force_reuse)
    return TRUE;

  if(!url_match_auth_nego(conn, m))
    return FALSE;
  else if(m->force_reuse)
    return TRUE;

  if(!url_match_multiplex_limits(conn, m))
    return FALSE;

  if(!CONN_INUSE(conn) && Curl_conn_seems_dead(conn, m->data)) {
    /* remove and disconnect. */
    Curl_conn_terminate(m->data, conn, FALSE);
    return FALSE;
  }

  /* conn matches our needs. */
  m->found = conn;
  return TRUE;
}

static bool url_match_result(void *userdata)
{
  struct url_conn_match *match = userdata;
  if(match->found) {
    /* Attach it now while still under lock, so the connection does
     * no longer appear idle and can be reaped. */
    Curl_attach_connection(match->data, match->found);
    return TRUE;
  }
  else if(match->seen_single_use_conn && !match->seen_multiplex_conn) {
    /* We have seen a single-use, existing connection to the destination and
     * no multiplexed one. It seems safe to assume that the server does
     * not support multiplexing. */
    match->wait_pipe = FALSE;
  }
  else if(match->seen_pending_conn && match->data->set.pipewait) {
    infof(match->data,
          "Found pending candidate for reuse and CURLOPT_PIPEWAIT is set");
    match->wait_pipe = TRUE;
  }
  match->force_reuse = FALSE;
  return FALSE;
}

/*
 * Given a transfer and a prototype connection (needle),
 * find and attach an existing connection that matches.
 *
 * Return TRUE if an existing connection was attached.
 * `waitpipe` is TRUE if no existing connection matched, but there
 * might be suitable one in the near future (common cause: multiplexing
 * capability has not been determined yet, e.g. ALPN handshake).
 */
static bool url_attach_existing(struct Curl_easy *data,
                                struct connectdata *needle,
                                bool *waitpipe)
{
  struct url_conn_match match;
  bool success;

  DEBUGASSERT(!data->conn);
  memset(&match, 0, sizeof(match));
  match.data = data;
  match.needle = needle;
  match.may_multiplex = xfer_may_multiplex(data, needle);

#ifdef USE_NTLM
  match.want_ntlm_http =
    (data->state.authhost.want & CURLAUTH_NTLM) &&
    (needle->scheme->protocol & PROTO_FAMILY_HTTP);
#ifndef CURL_DISABLE_PROXY
  match.want_proxy_ntlm_http =
    needle->bits.proxy_user_passwd &&
    (data->state.authproxy.want & CURLAUTH_NTLM) &&
    (needle->scheme->protocol & PROTO_FAMILY_HTTP);
#endif
#endif

#if !defined(CURL_DISABLE_HTTP) && defined(USE_SPNEGO)
  match.want_nego_http =
    (data->state.authhost.want & CURLAUTH_NEGOTIATE) &&
    (needle->scheme->protocol & PROTO_FAMILY_HTTP);
#ifndef CURL_DISABLE_PROXY
  match.want_proxy_nego_http =
    needle->bits.proxy_user_passwd &&
    (data->state.authproxy.want & CURLAUTH_NEGOTIATE) &&
    (needle->scheme->protocol & PROTO_FAMILY_HTTP);
#endif
#endif
  match.req_tls = data->set.use_ssl >= CURLUSESSL_CONTROL;

  /* Find a connection in the pool that matches what "data + needle"
   * requires. If a suitable candidate is found, it is attached to "data". */
  success = Curl_cpool_find(data, needle->destination,
                            url_match_conn, url_match_result, &match);

  /* wait_pipe is TRUE if we encounter a bundle that is undecided. There
   * is no matching connection then, yet. */
  *waitpipe = (bool)match.wait_pipe;
  return success;
}

/*
 * Allocate and initialize a new connectdata object.
 */
static struct connectdata *allocate_conn(struct Curl_easy *data)
{
  struct connectdata *conn = curlx_calloc(1, sizeof(struct connectdata));
  if(!conn)
    return NULL;

  /* and we setup a few fields in case we end up actually using this struct */

  conn->sock[FIRSTSOCKET] = CURL_SOCKET_BAD;     /* no file descriptor */
  conn->sock[SECONDARYSOCKET] = CURL_SOCKET_BAD; /* no file descriptor */
  conn->recv_idx = 0; /* default for receiving transfer data */
  conn->send_idx = 0; /* default for sending transfer data */
  conn->connection_id = -1;    /* no ID */
  conn->attached_xfers = 0;

  /* Store creation time to help future close decision making */
  conn->created = *Curl_pgrs_now(data);

  /* Store current time to give a baseline to keepalive connection times. */
  conn->keepalive = conn->created;

#ifndef CURL_DISABLE_PROXY
  conn->http_proxy.proxytype = data->set.proxytype;
  conn->socks_proxy.proxytype = CURLPROXY_SOCKS4;

  /* note that these two proxy bits are set on what looks to be
     requested, they may be altered down the road */
  conn->bits.proxy = (data->set.str[STRING_PROXY] &&
                      *data->set.str[STRING_PROXY]);
  conn->bits.httpproxy = (conn->bits.proxy &&
                          (conn->http_proxy.proxytype == CURLPROXY_HTTP ||
                           conn->http_proxy.proxytype == CURLPROXY_HTTP_1_0 ||
                           IS_HTTPS_PROXY(conn->http_proxy.proxytype)));
  conn->bits.socksproxy = (conn->bits.proxy && !conn->bits.httpproxy);

  if(data->set.str[STRING_PRE_PROXY] && *data->set.str[STRING_PRE_PROXY]) {
    conn->bits.proxy = TRUE;
    conn->bits.socksproxy = TRUE;
  }

  conn->bits.proxy_user_passwd = !!data->state.aptr.proxyuser;
  conn->bits.tunnel_proxy = data->set.tunnel_thru_httpproxy;
#endif /* CURL_DISABLE_PROXY */

#ifndef CURL_DISABLE_FTP
  conn->bits.ftp_use_epsv = data->set.ftp_use_epsv;
  conn->bits.ftp_use_eprt = data->set.ftp_use_eprt;
#endif
  conn->ip_version = data->set.ipver;
  conn->bits.connect_only = (bool)data->set.connect_only;
  conn->transport_wanted = TRNSPRT_TCP; /* most of them are TCP streams */

  /* Store the local bind parameters that will be used for this connection */
  if(data->set.str[STRING_DEVICE]) {
    conn->localdev = curlx_strdup(data->set.str[STRING_DEVICE]);
    if(!conn->localdev)
      goto error;
  }
#ifndef CURL_DISABLE_BINDLOCAL
  conn->localportrange = data->set.localportrange;
  conn->localport = data->set.localport;
#endif

  /* the close socket stuff needs to be copied to the connection struct as
     it may live on without (this specific) Curl_easy */
  conn->fclosesocket = data->set.fclosesocket;
  conn->closesocket_client = data->set.closesocket_client;
  conn->lastused = conn->created;
#ifdef HAVE_GSSAPI
  conn->gssapi_delegation = data->set.gssapi_delegation;
#endif
  DEBUGF(infof(data, "alloc connection, bits.close=%d", conn->bits.close));
  return conn;
error:

  curlx_free(conn->localdev);
  curlx_free(conn);
  return NULL;
}

static CURLcode url_set_conn_scheme(struct Curl_easy *data,
                                    struct connectdata *conn,
                                    const struct Curl_scheme *scheme)
{
  /* URL scheme is usable for connection when it is
   * - allowed
   * - not from a redirect or an allowed redirect protocol */
  if(scheme->run &&
     (data->set.allowed_protocols & scheme->protocol) &&
     (!data->state.this_is_a_follow ||
       (data->set.redir_protocols & scheme->protocol))) {
    conn->scheme = conn->given = scheme;
    return CURLE_OK;
  }
  if(scheme->flags & PROTOPT_NO_TRANSFER)
    failf(data, "Protocol \"%s\" is not for transfers", scheme->name);
  else
    failf(data, "Protocol \"%s\" is disabled%s", scheme->name,
          data->state.this_is_a_follow ? " (in redirect)" : "");
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

#ifndef CURL_DISABLE_HSTS
static CURLcode hsts_upgrade(struct Curl_easy *data,
                             struct connectdata *conn,
                             CURLU *uh,
                             uint16_t port_override,
                             uint32_t scope_id)
{
  /* HSTS upgrade */
  if(data->hsts && (conn->origin->scheme == &Curl_scheme_http) &&
     Curl_hsts_applies(data->hsts, conn->origin)) {
    char *url;
    CURLUcode uc;
    CURLcode result;

    curlx_safefree(data->state.up.scheme);
    uc = curl_url_set(uh, CURLUPART_SCHEME, "https", 0);
    if(uc)
      return Curl_uc_to_curlcode(uc);
    Curl_bufref_free(&data->state.url);
    /* after update, get the updated version */
    uc = curl_url_get(uh, CURLUPART_URL, &url, 0);
    if(uc)
      return Curl_uc_to_curlcode(uc);
    Curl_bufref_set(&data->state.url, url, 0, curl_free);

    result = Curl_peer_from_url(uh, data, port_override, scope_id,
                                &data->state.up, &conn->origin);
    if(result)
      return result;
    infof(data, "Switched from HTTP to HTTPS due to HSTS => %s", url);
  }
  return CURLE_OK;
}
#else
#define hsts_upgrade(x, y, z) CURLE_OK
#endif

/*
 * Parse URL and fill in the relevant members of the connection struct.
 */
static CURLcode parseurlandfillconn(struct Curl_easy *data,
                                    struct connectdata *conn)
{
  CURLcode result;
  CURLU *uh;
  CURLUcode uc;
  bool use_set_uh = (data->set.uh && !data->state.this_is_a_follow);
  uint16_t port_override = data->state.allow_port ? data->set.use_port : 0;
  uint32_t scope_id = 0;

  up_free(data); /* cleanup previous leftovers first */

  /* parse the URL */
  if(use_set_uh)
    uh = data->state.uh = curl_url_dup(data->set.uh);
  else
    uh = data->state.uh = curl_url();
  if(!uh)
    return CURLE_OUT_OF_MEMORY;

  /* Calculate the *real* URL this transfer uses, applying defaults
   * where information is missing. */
  if(data->set.str[STRING_DEFAULT_PROTOCOL] &&
     !Curl_is_absolute_url(Curl_bufref_ptr(&data->state.url), NULL, 0, TRUE)) {
    char *url = curl_maprintf("%s://%s",
                              data->set.str[STRING_DEFAULT_PROTOCOL],
                              Curl_bufref_ptr(&data->state.url));
    if(!url)
      return CURLE_OUT_OF_MEMORY;
    Curl_bufref_set(&data->state.url, url, 0, curl_free);
  }

  if(!use_set_uh) {
    char *newurl;
    uc = curl_url_set(uh, CURLUPART_URL, Curl_bufref_ptr(&data->state.url),
                      (unsigned int)(CURLU_GUESS_SCHEME |
                       CURLU_NON_SUPPORT_SCHEME |
                       (data->set.disallow_username_in_url ?
                        CURLU_DISALLOW_USER : 0) |
                       (data->set.path_as_is ? CURLU_PATH_AS_IS : 0)));
    if(uc) {
      failf(data, "URL rejected: %s", curl_url_strerror(uc));
      return Curl_uc_to_curlcode(uc);
    }

    /* after it was parsed, get the generated normalized version */
    uc = curl_url_get(uh, CURLUPART_URL, &newurl, 0);
    if(uc)
      return Curl_uc_to_curlcode(uc);
    Curl_bufref_set(&data->state.url, newurl, 0, curl_free);
  }

#ifdef USE_IPV6
  scope_id = data->set.scope_id;
#endif

  /* `uh` is now as the connection should use it, probably. */
  result = Curl_peer_from_url(uh, data, port_override, scope_id,
                              &data->state.up, &conn->origin);
  if(result)
    return result;

  result = hsts_upgrade(data, conn, uh, port_override, scope_id);
  if(result)
    return result;

  /* now that the origin is fixed, check and set the connection scheme */
  result = url_set_conn_scheme(data, conn, conn->origin->scheme);
  if(result)
    return result;

  /*
   * username and password set with their own options override the credentials
   * possibly set in the URL, but netrc does not.
   */
  if(!data->state.aptr.passwd || (data->state.creds_from != CREDS_OPTION)) {
    uc = curl_url_get(uh, CURLUPART_PASSWORD, &data->state.up.password, 0);
    if(!uc) {
      char *decoded;
      result = Curl_urldecode(data->state.up.password, 0, &decoded, NULL,
                              conn->scheme->flags&PROTOPT_USERPWDCTRL ?
                              REJECT_ZERO : REJECT_CTRL);
      if(result)
        return result;
      conn->passwd = decoded;
      result = Curl_setstropt(&data->state.aptr.passwd, decoded);
      if(result)
        return result;
      data->state.creds_from = CREDS_URL;
    }
    else if(uc != CURLUE_NO_PASSWORD)
      return Curl_uc_to_curlcode(uc);
  }

  if(!data->state.aptr.user || (data->state.creds_from != CREDS_OPTION)) {
    /* we do not use the URL API's URL decoder option here since it rejects
       control codes and we want to allow them for some schemes in the user
       and password fields */
    uc = curl_url_get(uh, CURLUPART_USER, &data->state.up.user, 0);
    if(!uc) {
      char *decoded;
      result = Curl_urldecode(data->state.up.user, 0, &decoded, NULL,
                              conn->scheme->flags&PROTOPT_USERPWDCTRL ?
                              REJECT_ZERO : REJECT_CTRL);
      if(result)
        return result;
      conn->user = decoded;
      result = Curl_setstropt(&data->state.aptr.user, decoded);
      data->state.creds_from = CREDS_URL;
    }
    else if(uc != CURLUE_NO_USER)
      return Curl_uc_to_curlcode(uc);
    if(result)
      return result;
  }

  uc = curl_url_get(uh, CURLUPART_OPTIONS, &data->state.up.options,
                    CURLU_URLDECODE);
  if(!uc) {
    conn->options = curlx_strdup(data->state.up.options);
    if(!conn->options)
      return CURLE_OUT_OF_MEMORY;
  }
  else if(uc != CURLUE_NO_OPTIONS)
    return Curl_uc_to_curlcode(uc);

  uc = curl_url_get(uh, CURLUPART_PATH, &data->state.up.path, CURLU_URLENCODE);
  if(uc)
    return Curl_uc_to_curlcode(uc);

  uc = curl_url_get(uh, CURLUPART_QUERY, &data->state.up.query, 0);
  if(uc && (uc != CURLUE_NO_QUERY))
    return CURLE_OUT_OF_MEMORY;

#ifdef USE_IPV6
  /* Fill in the conn parts that do not use authority, yet. */
  conn->scope_id = conn->origin->ipv6scope_id;
#endif

  return CURLE_OK;
}

/*
 * If we are doing a resumed transfer, we need to setup our stuff
 * properly.
 */
static CURLcode setup_range(struct Curl_easy *data)
{
  struct UrlState *s = &data->state;
  s->resume_from = data->set.set_resume_from;
  if(s->resume_from || data->set.str[STRING_SET_RANGE]) {
    if(s->rangestringalloc)
      curlx_free(s->range);

    if(s->resume_from)
      s->range = curl_maprintf("%" FMT_OFF_T "-", s->resume_from);
    else
      s->range = curlx_strdup(data->set.str[STRING_SET_RANGE]);

    if(!s->range)
      return CURLE_OUT_OF_MEMORY;

    s->rangestringalloc = TRUE;

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
static CURLcode setup_connection_internals(struct Curl_easy *data,
                                           struct connectdata *conn)
{
  struct Curl_peer *peer = NULL;
  CURLcode result;

  DEBUGF(infof(data, "setup connection, bits.close=%d", conn->bits.close));
  if(conn->scheme->run->setup_connection) {
    result = conn->scheme->run->setup_connection(data, conn);
    if(result)
      return result;
  }
  DEBUGF(infof(data, "setup connection, bits.close=%d", conn->bits.close));

  /* Now create the destination name */
#ifndef CURL_DISABLE_PROXY
  if(conn->bits.httpproxy && !conn->bits.tunnel_proxy)
    peer = conn->http_proxy.peer;
  else
#endif
    peer = Curl_conn_get_destination(conn, FIRSTSOCKET);

  if(!peer)
    return CURLE_FAILED_INIT;

  /* IPv6 addresses with a scope_id (0 is default == global) have a
   * printable representation with a '%<scope_id>' suffix. */
  if(peer->ipv6)
    if(peer->ipv6scope_id)
      conn->destination = curl_maprintf("[%s%%%u]:%u",
        peer->hostname, peer->ipv6scope_id, peer->port);
    else
      conn->destination = curl_maprintf("[%s]:%u",
        peer->hostname, peer->port);
  else
    conn->destination = curl_maprintf("%s:%u", peer->hostname, peer->port);
  if(!conn->destination)
    return CURLE_OUT_OF_MEMORY;

  Curl_strntolower(conn->destination, conn->destination,
                   strlen(conn->destination));

  return CURLE_OK;
}

#ifndef CURL_DISABLE_PROXY

#ifndef CURL_DISABLE_HTTP
/****************************************************************
 * Detect what (if any) proxy to use. Remember that this selects a host
 * name and is not limited to HTTP proxies only.
 * The returned pointer must be freed by the caller (unless NULL)
 ****************************************************************/
static char *url_detect_proxy(struct Curl_easy *data,
                              struct connectdata *conn)
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
   * checked if the lowercase versions do not exist.
   */
  char proxy_env[20];
  const char *envp;
  VERBOSE(envp = proxy_env);

  curl_msnprintf(proxy_env, sizeof(proxy_env), "%s_proxy",
                 conn->scheme->name);

  /* read the protocol proxy: */
  proxy = curl_getenv(proxy_env);

  /*
   * We do not try the uppercase version of HTTP_PROXY because of
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
  if(!proxy && !curl_strequal("http_proxy", proxy_env)) {
    /* There was no lowercase variable, try the uppercase version: */
    Curl_strntoupper(proxy_env, proxy_env, sizeof(proxy_env));
    proxy = curl_getenv(proxy_env);
  }

  if(!proxy) {
#ifndef CURL_DISABLE_WEBSOCKETS
    /* websocket proxy fallbacks */
    if(curl_strequal("ws_proxy", proxy_env)) {
      proxy = curl_getenv("http_proxy");
    }
    else if(curl_strequal("wss_proxy", proxy_env)) {
      proxy = curl_getenv("https_proxy");
      if(!proxy)
        proxy = curl_getenv("HTTPS_PROXY");
    }
    if(!proxy) {
#endif
      envp = "all_proxy";
      proxy = curl_getenv(envp); /* default proxy to use */
      if(!proxy) {
        envp = "ALL_PROXY";
        proxy = curl_getenv(envp);
      }
#ifndef CURL_DISABLE_WEBSOCKETS
    }
#endif
  }
  if(proxy)
    infof(data, "Uses proxy env variable %s == '%s'", envp, proxy);

  return proxy;
}
#endif /* CURL_DISABLE_HTTP */

/*
 * If this is supposed to use a proxy, we need to figure out the proxy
 * hostname, so that we can reuse an existing connection
 * that may exist registered to the same proxy host.
 */
static CURLcode parse_proxy(struct Curl_easy *data,
                            struct connectdata *conn, const char *proxy,
                            uint8_t proxytype)
{
  char *proxyuser = NULL;
  char *proxypasswd = NULL;
  struct proxy_info *proxyinfo = NULL;
  CURLcode result = CURLE_OK;
  struct Curl_peer *peer = NULL;
  CURLU *uhp = curl_url();
  CURLUcode uc;

  if(!uhp) {
    result = CURLE_OUT_OF_MEMORY;
    goto error;
  }
  /* When parsing the proxy, allowing non-supported schemes since we have
     these made up ones for proxies. Guess scheme for URLs without it. */
  uc = curl_url_set(uhp, CURLUPART_URL, proxy,
                    CURLU_NON_SUPPORT_SCHEME | CURLU_GUESS_SCHEME);
  if(uc) {
    failf(data, "Unsupported proxy syntax in \'%s\': %s", proxy,
          curl_url_strerror(uc));
    result = CURLE_COULDNT_RESOLVE_PROXY;
    goto error;
  }

  result = Curl_peer_from_proxy_url(uhp, data, proxy, proxytype,
                                    &peer, &proxytype);
  if(result)
    goto error;

  switch(proxytype) {
    case CURLPROXY_HTTP:
    case CURLPROXY_HTTP_1_0:
    case CURLPROXY_HTTPS:
    case CURLPROXY_HTTPS2:
      proxyinfo = &conn->http_proxy;
      break;
    case CURLPROXY_SOCKS4:
    case CURLPROXY_SOCKS4A:
    case CURLPROXY_SOCKS5:
    case CURLPROXY_SOCKS5_HOSTNAME:
      proxyinfo = &conn->socks_proxy;
      break;
    default:
      break;
  }

  if(!proxyinfo) {
    failf(data, "Unsupported proxy type %u for \'%s\'", proxytype, proxy);
    result = CURLE_COULDNT_RESOLVE_PROXY;
    goto error;
  }

  /* Is there a username and password given in this proxy URL? */
  uc = curl_url_get(uhp, CURLUPART_USER, &proxyuser, CURLU_URLDECODE);
  if(uc && (uc != CURLUE_NO_USER)) {
    result = Curl_uc_to_curlcode(uc);
    goto error;
  }
  uc = curl_url_get(uhp, CURLUPART_PASSWORD, &proxypasswd, CURLU_URLDECODE);
  if(uc && (uc != CURLUE_NO_PASSWORD)) {
    result = Curl_uc_to_curlcode(uc);
    goto error;
  }

  if(proxyuser || proxypasswd) {
    curlx_free(proxyinfo->user);
    proxyinfo->user = proxyuser;
    result = Curl_setstropt(&data->state.aptr.proxyuser, proxyuser);
    proxyuser = NULL;
    if(result)
      goto error;
    curlx_safefree(proxyinfo->passwd);
    if(!proxypasswd) {
      proxypasswd = curlx_strdup("");
      if(!proxypasswd) {
        result = CURLE_OUT_OF_MEMORY;
        goto error;
      }
    }
    proxyinfo->passwd = proxypasswd;
    result = Curl_setstropt(&data->state.aptr.proxypasswd, proxypasswd);
    proxypasswd = NULL;
    if(result)
      goto error;
    conn->bits.proxy_user_passwd = TRUE; /* enable it */
  }

  Curl_peer_link(&proxyinfo->peer, peer);
  proxyinfo->proxytype = proxytype;

error:
  curlx_free(proxyuser);
  curlx_free(proxypasswd);
  Curl_peer_unlink(&peer);
  curl_url_cleanup(uhp);
#ifdef DEBUGBUILD
  if(!result) {
    DEBUGASSERT(proxyinfo);
    DEBUGASSERT(proxyinfo->peer);
  }
#endif
  return result;
}

/*
 * Extract the user and password from the authentication string
 */
static CURLcode parse_proxy_auth(struct Curl_easy *data,
                                 struct connectdata *conn)
{
  const char *proxyuser = data->state.aptr.proxyuser ?
    data->state.aptr.proxyuser : "";
  const char *proxypasswd = data->state.aptr.proxypasswd ?
    data->state.aptr.proxypasswd : "";
  CURLcode result = CURLE_OUT_OF_MEMORY;

  conn->http_proxy.user = curlx_strdup(proxyuser);
  if(conn->http_proxy.user) {
    conn->http_proxy.passwd = curlx_strdup(proxypasswd);
    if(conn->http_proxy.passwd)
      result = CURLE_OK;
    else
      curlx_safefree(conn->http_proxy.user);
  }
  return result;
}

static CURLcode url_set_conn_proxies(struct Curl_easy *data,
                                     struct connectdata *conn)
{
  char *proxy = NULL;
  char *socksproxy = NULL;
  char *no_proxy = NULL;
  CURLcode result = CURLE_OK;

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
    proxy = curlx_strdup(data->set.str[STRING_PROXY]);
    /* if global proxy is set, this is it */
    if(!proxy) {
      failf(data, "memory shortage");
      result = CURLE_OUT_OF_MEMORY;
      goto out;
    }
  }

  if(data->set.str[STRING_PRE_PROXY]) {
    socksproxy = curlx_strdup(data->set.str[STRING_PRE_PROXY]);
    /* if global socks proxy is set, this is it */
    if(!socksproxy) {
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
      infof(data, "Uses proxy env variable %s == '%s'", p, no_proxy);
    }
  }

  if(Curl_check_noproxy(conn->origin->hostname, data->set.str[STRING_NOPROXY] ?
                        data->set.str[STRING_NOPROXY] : no_proxy)) {
    curlx_safefree(proxy);
    curlx_safefree(socksproxy);
  }
#ifndef CURL_DISABLE_HTTP
  else if(!proxy && !socksproxy)
    /* if the host is not in the noproxy list, detect proxy. */
    proxy = url_detect_proxy(data, conn);
#endif /* CURL_DISABLE_HTTP */
  curlx_safefree(no_proxy);

  if(proxy && (!*proxy || (conn->scheme->flags & PROTOPT_NONETWORK))) {
    curlx_free(proxy);  /* Do not bother with an empty proxy string
                           or if the protocol does not work with network */
    proxy = NULL;
  }
  if(socksproxy && (!*socksproxy ||
                    (conn->scheme->flags & PROTOPT_NONETWORK))) {
    curlx_free(socksproxy);  /* Do not bother with an empty socks proxy string
                                or if the protocol does not work with
                                network */
    socksproxy = NULL;
  }

  /***********************************************************************
   * If this is supposed to use a proxy, we need to figure out the proxy host
   * name, proxy type and port number, so that we can reuse an existing
   * connection that may exist registered to the same proxy host.
   ***********************************************************************/
  if(proxy || socksproxy) {
    if(proxy) {
      result = parse_proxy(data, conn, proxy, conn->http_proxy.proxytype);
      curlx_safefree(proxy); /* parse_proxy copies the proxy string */
      if(result)
        goto out;
    }

    if(socksproxy) {
      result = parse_proxy(data, conn, socksproxy,
                           conn->socks_proxy.proxytype);
      /* parse_proxy copies the socks proxy string */
      curlx_safefree(socksproxy);
      if(result)
        goto out;
    }

    if(conn->http_proxy.peer) {
#ifdef CURL_DISABLE_HTTP
      /* asking for an HTTP proxy is a bit funny when HTTP is disabled... */
      result = CURLE_UNSUPPORTED_PROTOCOL;
      goto out;
#else
      /* force this connection's protocol to become HTTP if compatible */
      if(!(conn->scheme->protocol & PROTO_FAMILY_HTTP)) {
        if((conn->scheme->flags & PROTOPT_PROXY_AS_HTTP) &&
           !conn->bits.tunnel_proxy)
          conn->scheme = &Curl_scheme_http;
        else
          /* if not converting to HTTP over the proxy, enforce tunneling */
          conn->bits.tunnel_proxy = TRUE;
      }
      conn->bits.httpproxy = TRUE;
#endif
    }
    else {
      conn->bits.httpproxy = FALSE; /* not an HTTP proxy */
      conn->bits.tunnel_proxy = FALSE; /* no tunneling if not HTTP */
    }

    if(conn->socks_proxy.peer) {
      if(!conn->http_proxy.peer) {
        /* once a socks proxy */
        if(!conn->socks_proxy.user) {
          conn->socks_proxy.user = conn->http_proxy.user;
          conn->http_proxy.user = NULL;
          curlx_free(conn->socks_proxy.passwd);
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
    /* we are not using the proxy after all... */
    conn->bits.proxy = FALSE;
    conn->bits.httpproxy = FALSE;
    conn->bits.socksproxy = FALSE;
    conn->bits.proxy_user_passwd = FALSE;
    conn->bits.tunnel_proxy = FALSE;
    /* CURLPROXY_HTTPS does not have its own flag in conn->bits, yet we need
       to signal that CURLPROXY_HTTPS is not used for this connection */
    conn->http_proxy.proxytype = CURLPROXY_HTTP;
  }

out:

  curlx_free(socksproxy);
  curlx_free(proxy);
  return result;
}
#endif /* CURL_DISABLE_PROXY */

/*
 * Curl_parse_login_details()
 *
 * This is used to parse a login string for username, password and options in
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
 * login    [in]     - login string.
 * len      [in]     - length of the login string.
 * userp    [in/out] - address where a pointer to newly allocated memory
 *                     holding the user will be stored upon completion.
 * passwdp  [in/out] - address where a pointer to newly allocated memory
 *                     holding the password will be stored upon completion.
 * optionsp [in/out] - OPTIONAL address where a pointer to newly allocated
 *                     memory holding the options will be stored upon
 *                     completion.
 *
 * Returns CURLE_OK on success.
 */
CURLcode Curl_parse_login_details(const char *login, const size_t len,
                                  char **userp, char **passwdp,
                                  char **optionsp)
{
  char *ubuf = NULL;
  char *pbuf = NULL;
  const char *psep = NULL;
  const char *osep = NULL;
  size_t ulen;
  size_t plen;
  size_t olen;

  DEBUGASSERT(userp);
  DEBUGASSERT(passwdp);

  /* Attempt to find the password separator */
  psep = memchr(login, ':', len);

  /* Attempt to find the options separator */
  if(optionsp)
    osep = memchr(login, ';', len);

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

  /* Clone the user portion buffer, which can be zero length */
  ubuf = curlx_memdup0(login, ulen);
  if(!ubuf)
    goto error;

  /* Clone the password portion buffer */
  if(psep) {
    pbuf = curlx_memdup0(&psep[1], plen);
    if(!pbuf)
      goto error;
  }

  /* Allocate the options portion buffer */
  if(optionsp) {
    char *obuf = NULL;
    if(olen) {
      obuf = curlx_memdup0(&osep[1], olen);
      if(!obuf)
        goto error;
    }
    *optionsp = obuf;
  }
  *userp = ubuf;
  *passwdp = pbuf;
  return CURLE_OK;
error:
  curlx_free(ubuf);
  curlx_free(pbuf);
  return CURLE_OUT_OF_MEMORY;
}

#ifndef CURL_DISABLE_NETRC
static bool str_has_ctrl(const char *input)
{
  if(input) {
    const unsigned char *str = (const unsigned char *)input;
    while(*str) {
      if(*str < 0x20)
        return TRUE;
      str++;
    }
  }
  return FALSE;
}
#endif

/*
 * Override the login details from the URL with that in the CURLOPT_USERPWD
 * option or a .netrc file, if applicable.
 */
static CURLcode override_login(struct Curl_easy *data,
                               struct connectdata *conn)
{
  CURLUcode uc;
  char **userp = &conn->user;
  char **passwdp = &conn->passwd;
  char **optionsp = &conn->options;

  if(data->set.str[STRING_OPTIONS]) {
    curlx_free(*optionsp);
    *optionsp = curlx_strdup(data->set.str[STRING_OPTIONS]);
    if(!*optionsp)
      return CURLE_OUT_OF_MEMORY;
  }

#ifndef CURL_DISABLE_NETRC
  if(data->set.use_netrc == CURL_NETRC_REQUIRED) {
    curlx_safefree(*userp);
    curlx_safefree(*passwdp);
  }
  conn->bits.netrc = FALSE;
  if(data->set.use_netrc && !data->set.str[STRING_USERNAME]) {
    bool url_provided = FALSE;

    if(data->state.aptr.user &&
       (data->state.creds_from != CREDS_NETRC)) {
      /* there was a username with a length in the URL. Use the URL decoded
         version */
      userp = &data->state.aptr.user;
      url_provided = TRUE;
    }

    if(!*passwdp) {
      NETRCcode ret = Curl_parsenetrc(&data->state.netrc,
                                      conn->origin->hostname,
                                      userp, passwdp,
                                      data->set.str[STRING_NETRC_FILE]);
      if(ret == NETRC_OUT_OF_MEMORY)
        return CURLE_OUT_OF_MEMORY;
      else if(ret && ((ret == NETRC_NO_MATCH) ||
                      (data->set.use_netrc == CURL_NETRC_OPTIONAL))) {
        infof(data, "Could not find host %s in the %s file; using defaults",
              conn->origin->hostname,
              (data->set.str[STRING_NETRC_FILE] ?
               data->set.str[STRING_NETRC_FILE] : ".netrc"));
      }
      else if(ret) {
        const char *m = Curl_netrc_strerror(ret);
        failf(data, ".netrc error: %s", m);
        return CURLE_READ_ERROR;
      }
      else {
        if(!(conn->scheme->flags & PROTOPT_USERPWDCTRL)) {
          /* if the protocol cannot handle control codes in credentials, make
             sure there are none */
          if(str_has_ctrl(*userp) || str_has_ctrl(*passwdp)) {
            failf(data, "control code detected in .netrc credentials");
            return CURLE_READ_ERROR;
          }
        }
        /* set bits.netrc TRUE to remember that we got the name from a .netrc
           file, so that it is safe to use even if we followed a Location: to a
           different host or similar. */
        conn->bits.netrc = TRUE;
      }
    }
    if(url_provided) {
      curlx_free(conn->user);
      conn->user = curlx_strdup(*userp);
      if(!conn->user)
        return CURLE_OUT_OF_MEMORY;
    }
    /* no user was set but a password, set a blank user */
    if(!*userp && *passwdp) {
      *userp = curlx_strdup("");
      if(!*userp)
        return CURLE_OUT_OF_MEMORY;
    }
  }
#endif

  /* for updated strings, we update them in the URL */
  if(*userp) {
    CURLcode result;
    if(data->state.aptr.user != *userp) {
      /* nothing to do then */
      result = Curl_setstropt(&data->state.aptr.user, *userp);
      if(result)
        return result;
      data->state.creds_from = CREDS_NETRC;
    }
  }
  if(data->state.aptr.user) {
    uc = curl_url_set(data->state.uh, CURLUPART_USER, data->state.aptr.user,
                      CURLU_URLENCODE);
    if(uc)
      return Curl_uc_to_curlcode(uc);
    if(!*userp) {
      *userp = curlx_strdup(data->state.aptr.user);
      if(!*userp)
        return CURLE_OUT_OF_MEMORY;
    }
  }
  if(*passwdp) {
    CURLcode result = Curl_setstropt(&data->state.aptr.passwd, *passwdp);
    if(result)
      return result;
    data->state.creds_from = CREDS_NETRC;
  }
  if(data->state.aptr.passwd) {
    uc = curl_url_set(data->state.uh, CURLUPART_PASSWORD,
                      data->state.aptr.passwd, CURLU_URLENCODE);
    if(uc)
      return Curl_uc_to_curlcode(uc);
    if(!*passwdp) {
      *passwdp = curlx_strdup(data->state.aptr.passwd);
      if(!*passwdp)
        return CURLE_OUT_OF_MEMORY;
    }
  }

  return CURLE_OK;
}

/*
 * Set the login details so they are available in the connection
 */
static CURLcode set_login(struct Curl_easy *data,
                          struct connectdata *conn)
{
  CURLcode result = CURLE_OK;
  const char *setuser = CURL_DEFAULT_USER;
  const char *setpasswd = CURL_DEFAULT_PASSWORD;

  /* If our protocol needs a password and we have none, use the defaults */
  if((conn->scheme->flags & PROTOPT_NEEDSPWD) && !data->state.aptr.user)
    ;
  else {
    setuser = "";
    setpasswd = "";
  }
  /* Store the default user */
  if(!conn->user) {
    conn->user = curlx_strdup(setuser);
    if(!conn->user)
      return CURLE_OUT_OF_MEMORY;
  }

  /* Store the default password */
  if(!conn->passwd) {
    conn->passwd = curlx_strdup(setpasswd);
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
static CURLcode url_make_connect_to_dest(struct Curl_easy *data,
                                         const struct Curl_peer *dest,
                                         const char *host,
                                         struct Curl_peer **pvia_dest)
{
  char *host_portno;
  const char *portptr;
  const char *via_host;
  size_t via_hostlen;
  uint16_t via_port = dest->port;
  CURLcode result = CURLE_OK;

  *pvia_dest = NULL;
  if(!host || !*host)
    return CURLE_OK;

  via_host = host;
  via_hostlen = 0;

  /* start scanning for port number at this point */
  portptr = via_host;

  /* detect and extract RFC6874-style IPv6-addresses */
  if(*via_host == '[') {
#ifdef USE_IPV6
    const char *ptr = ++via_host; /* advance beyond the initial bracket */
    while(*ptr && (ISXDIGIT(*ptr) || (*ptr == ':') || (*ptr == '.')))
      ptr++;
    if(*ptr == '%') {
      /* There might be a zone identifier */
      if(strncmp("%25", ptr, 3))
        infof(data, "Please URL encode %% as %%25, see RFC 6874.");
      ptr++;
      /* Allow unreserved characters as defined in RFC 3986 */
      while(*ptr && (ISALPHA(*ptr) || ISXDIGIT(*ptr) || (*ptr == '-') ||
                     (*ptr == '.') || (*ptr == '_') || (*ptr == '~')))
        ptr++;
      /* The zone id is not really used here, but should. */
    }

    if(*ptr == ']')
      /* yeps, it ended nicely with a bracket as well */
      via_hostlen = ptr - via_host;
    else
      infof(data, "Invalid IPv6 address format");
    portptr = ptr;
    /* Note that if this did not end with a bracket, we still advanced the
     * portptr first, but I cannot see anything wrong with that as no host
     * name nor a numeric can legally start with a bracket.
     */
#else
    failf(data, "Use of IPv6 in *_CONNECT_TO without IPv6 support built-in");
    result = CURLE_NOT_BUILT_IN;
    goto error;
#endif
  }

  /* Get port number off server.com:1080 */
  host_portno = strchr(portptr, ':');
  if(host_portno) {
    if(!via_hostlen)
      via_hostlen = host_portno - via_host;
    host_portno++;
    if(*host_portno) {
      curl_off_t portparse;
      const char *p = host_portno;
      if(curlx_str_number(&p, &portparse, 0xffff)) {
        failf(data, "No valid port number in connect to host string (%s)",
              host_portno);
        result = CURLE_SETOPT_OPTION_SYNTAX;
        goto error;
      }
      via_port = (uint16_t)portparse; /* we know it will fit */
    }
  }

  if(!via_hostlen) { /* no via_host found, only port switch */
    via_host = dest->hostname;
    via_hostlen = strlen(via_host);
  }

  result = Curl_peer_create(dest->scheme, via_host, via_hostlen,
                            via_port, NULL, 0, pvia_dest);
error:
  return result;
}

/*
 * Parses one "connect to" string in the form:
 * "HOST:PORT:CONNECT-TO-HOST:CONNECT-TO-PORT".
 */
static CURLcode parse_connect_to_string(struct Curl_easy *data,
                                        const struct Curl_peer *dest,
                                        const char *conn_to_line,
                                        struct Curl_peer **pvia_dest)
{
  CURLcode result = CURLE_OK;
  const char *ptr = conn_to_line;
  bool host_match = FALSE;
  bool port_match = FALSE;

  *pvia_dest = NULL;

  if(*ptr == ':') {
    /* an empty hostname always matches */
    host_match = TRUE;
    ptr++;
  }
  else {
    /* check whether the URL's hostname matches. Use the URL hostname
     * when it was an IPv6 address. Otherwise use the connection's hostname
     * that has IDN conversion. */
    const char *hostname_to_match = (dest->user_hostname[0] == '[') ?
      dest->user_hostname : dest->hostname;
    size_t hlen = strlen(hostname_to_match);
    host_match = curl_strnequal(ptr, hostname_to_match, hlen);
    ptr += hlen;

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
      const char *ptr_next = strchr(ptr, ':');
      if(ptr_next) {
        curl_off_t port_to_match;
        if(!curlx_str_number(&ptr, &port_to_match, 0xffff) &&
           ((uint16_t)port_to_match == dest->port)) {
          port_match = TRUE;
        }
        ptr = ptr_next + 1;
      }
    }
  }

  if(host_match && port_match) {
    /* parse the hostname and port to connect to */
    result = url_make_connect_to_dest(data, dest, ptr, pvia_dest);
  }

  return result;
}

/* With `conn->origin` known, determine if we should talk to that
 * directly or via another peer. This is the result of inspecting
 * the "connect to" slist and "alt-svc" settings. */
static CURLcode url_set_conn_peer(struct Curl_easy *data,
                                  struct connectdata *conn)
{
  CURLcode result = CURLE_OK;
  const struct Curl_peer *origin = conn->origin;
  struct Curl_peer *via_peer = NULL;
  struct curl_slist *conn_to_entry = data->set.connect_to;

  DEBUGASSERT(!conn->via_peer);
  Curl_peer_unlink(&conn->via_peer);

  while(conn_to_entry && !via_peer) {
    result = parse_connect_to_string(data, origin, conn_to_entry->data,
                                     &via_peer);
    if(result)
      return result;
    conn_to_entry = conn_to_entry->next;
  }

#ifndef CURL_DISABLE_ALTSVC
  if(data->asi && !via_peer &&
     ((conn->scheme->protocol == CURLPROTO_HTTPS) ||
#ifdef DEBUGBUILD
      /* allow debug builds to circumvent the HTTPS restriction */
      getenv("CURL_ALTSVC_HTTP")
#else
      0
#endif
       )) {
    /* no connect_to match, try alt-svc! */
    enum alpnid srcalpnid = ALPN_none;
    bool hit = FALSE;
    struct altsvc *as = NULL;
    int allowed_alpns = ALPN_none;
    struct http_negotiation *neg = &data->state.http_neg;
    bool same_dest = FALSE;

    DEBUGF(infof(data, "Alt-svc check wanted=%x, allowed=%x",
                 neg->wanted, neg->allowed));
#ifdef USE_HTTP3
    if(neg->allowed & CURL_HTTP_V3x)
      allowed_alpns |= ALPN_h3;
#endif
#ifdef USE_HTTP2
    if(neg->allowed & CURL_HTTP_V2x)
      allowed_alpns |= ALPN_h2;
#endif
    if(neg->allowed & CURL_HTTP_V1x)
      allowed_alpns |= ALPN_h1;
    allowed_alpns &= (int)data->asi->flags;

    DEBUGF(infof(data, "check Alt-Svc for host '%s'", origin->hostname));
#ifdef USE_HTTP3
    if(!hit && (neg->wanted & CURL_HTTP_V3x)) {
      srcalpnid = ALPN_h3;
      hit = Curl_altsvc_lookup(data->asi,
                               ALPN_h3, origin->hostname,
                               origin->port, /* from */
                               &as /* to */,
                               allowed_alpns, &same_dest);
    }
#endif
#ifdef USE_HTTP2
    if(!hit && (neg->wanted & CURL_HTTP_V2x) &&
       !neg->h2_prior_knowledge) {
      srcalpnid = ALPN_h2;
      hit = Curl_altsvc_lookup(data->asi,
                               ALPN_h2, origin->hostname,
                               origin->port, /* from */
                               &as /* to */,
                               allowed_alpns, &same_dest);
    }
#endif
    if(!hit && (neg->wanted & CURL_HTTP_V1x) &&
       !neg->only_10) {
      srcalpnid = ALPN_h1;
      hit = Curl_altsvc_lookup(data->asi,
                               ALPN_h1, origin->hostname,
                               origin->port, /* from */
                               &as /* to */,
                               allowed_alpns, &same_dest);
    }

    if(hit && same_dest) {
      /* same destination, but more HTTPS version options */
      switch(as->dst.alpnid) {
      case ALPN_h1:
        neg->wanted |= CURL_HTTP_V1x;
        neg->preferred = CURL_HTTP_V1x;
        break;
      case ALPN_h2:
        neg->wanted |= CURL_HTTP_V2x;
        neg->preferred = CURL_HTTP_V2x;
        break;
      case ALPN_h3:
        neg->wanted |= CURL_HTTP_V3x;
        neg->preferred = CURL_HTTP_V3x;
        break;
      default: /* should not be possible */
        break;
      }
    }
    else if(hit) {
      result = Curl_peer_create(conn->origin->scheme,
                                as->dst.host, strlen(as->dst.host),
                                as->dst.port, NULL, 0, &via_peer);
      if(result)
        return result;
      infof(data, "Alt-svc connecting from [%s]%s:%u to [%s]%s:%u",
            Curl_alpnid2str(srcalpnid), origin->hostname, origin->port,
            Curl_alpnid2str(as->dst.alpnid),
            via_peer->hostname, via_peer->port);
      conn->bits.altused = TRUE;
      if(srcalpnid != as->dst.alpnid) {
        /* protocol version switch */
        switch(as->dst.alpnid) {
        case ALPN_h1:
          neg->wanted = neg->allowed = CURL_HTTP_V1x;
          neg->only_10 = FALSE;
          break;
        case ALPN_h2:
          neg->wanted = neg->allowed = CURL_HTTP_V2x;
          break;
        case ALPN_h3:
          conn->transport_wanted = TRNSPRT_QUIC;
          neg->wanted = neg->allowed = CURL_HTTP_V3x;
          break;
        default: /* should not be possible */
          break;
        }
      }
    }
  }
#endif

  if(via_peer)
    conn->via_peer = via_peer;

  return result;
}

/*
 * Adjust reused connection settings to the transfer/needle.
 */
static void url_conn_reuse_adjust(struct Curl_easy *data,
                                  struct connectdata *needle)
{
  struct connectdata *conn = data->conn;

  /* get the user+password information from the needle since it may
   * be new for this request even when we reuse conn */
  if(needle->user) {
    /* use the new username and password though */
    curlx_free(conn->user);
    curlx_free(conn->passwd);
    conn->user = needle->user;
    conn->passwd = needle->passwd;
    needle->user = NULL;
    needle->passwd = NULL;
  }

#ifndef CURL_DISABLE_PROXY
  conn->bits.proxy_user_passwd = needle->bits.proxy_user_passwd;
  if(conn->bits.proxy_user_passwd) {
    /* use the new proxy username and proxy password though */
    curlx_free(conn->http_proxy.user);
    curlx_free(conn->socks_proxy.user);
    curlx_free(conn->http_proxy.passwd);
    curlx_free(conn->socks_proxy.passwd);
    conn->http_proxy.user = needle->http_proxy.user;
    conn->socks_proxy.user = needle->socks_proxy.user;
    conn->http_proxy.passwd = needle->http_proxy.passwd;
    conn->socks_proxy.passwd = needle->socks_proxy.passwd;
    needle->http_proxy.user = NULL;
    needle->socks_proxy.user = NULL;
    needle->http_proxy.passwd = NULL;
    needle->socks_proxy.passwd = NULL;
  }
#endif

  /* Finding a connection for reuse in the cpool matches, among other
   * things on the "remote-relevant" hostname. This is not necessarily
   * the authority of the URL, e.g. conn->origin. For example:
   * - we use a proxy (not tunneling). we want to send all requests
   *   that use the same proxy on this connection.
   * - we have a "connect-to" setting that may redirect the hostname of
   *   a new request to the same remote endpoint of an existing conn.
   *   We want to reuse an existing conn to the remote endpoint.
   * Since connection reuse does not match on conn->origin necessarily, we
   * switch conn to needle's host settings.
   */
  Curl_peer_link(&conn->origin, needle->origin);
  Curl_peer_link(&conn->via_peer, needle->via_peer);
  Curl_peer_link(&conn->origin2, needle->origin2);
  Curl_peer_link(&conn->via_peer2, needle->via_peer2);
}

static void conn_meta_freeentry(void *p)
{
  (void)p;
  /* Always FALSE. Cannot use a 0 assert here since compilers
   * are not in agreement if they then want a NORETURN attribute or
   * not. *sigh* */
  DEBUGASSERT(p == NULL);
}

static CURLcode url_create_needle(struct Curl_easy *data,
                                  struct connectdata **pneedle)
{
  struct connectdata *needle = NULL;
  CURLcode result = CURLE_OK;
  bool network_scheme = TRUE; /* almost all are */

  /*************************************************************
   * Check input data
   *************************************************************/
  if(!Curl_bufref_ptr(&data->state.url)) {
    result = CURLE_URL_MALFORMAT;
    goto out;
  }

  /* First, split up the current URL in parts so that we can use the
     parts for checking against the already present connections. In order
     to not have to modify everything at once, we allocate a temporary
     connection data struct and fill in for comparison purposes. */
  needle = allocate_conn(data);
  if(!needle) {
    result = CURLE_OUT_OF_MEMORY;
    goto out;
  }

  /* Do the unfailable inits first, before checks that may early return */
  Curl_hash_init(&needle->meta_hash, 23,
                 Curl_hash_str, curlx_str_key_compare, conn_meta_freeentry);

  /*************************************************************
   * Determine `conn->origin` and propulate `data->state.up` and
   * other URL related properties.
   *************************************************************/
  result = parseurlandfillconn(data, needle);
  if(result)
    goto out;
  DEBUGASSERT(needle->origin);
  network_scheme = !(needle->origin->scheme->flags & PROTOPT_NONETWORK);

#ifdef USE_UNIX_SOCKETS
  /*************************************************************
   * Set UDS first. It overrides "via_peer" and proxy settings.
   *************************************************************/
  if(network_scheme && data->set.str[STRING_UNIX_SOCKET_PATH]) {
    result = Curl_peer_uds_create(needle->origin->scheme,
                                  data->set.str[STRING_UNIX_SOCKET_PATH],
                                  (bool)data->set.abstract_unix_socket,
                                  &needle->via_peer);
    if(result)
      goto out;
  }
#endif /* USE_UNIX_SOCKETS */

  if(network_scheme && !needle->via_peer) {
    /*************************************************************
     * If the `via_peer` is not already set (via UDS above),
     * determine if we talk to `conn->origin` directly or use
     * `conn->via_peer` using "connect to" and "alt-svc" properties.
     *************************************************************/
    result = url_set_conn_peer(data, needle);
    if(result)
      goto out;
  }

#ifndef CURL_DISABLE_PROXY
  /* After the Unix socket init but before the proxy vars are used, parse and
   * initialize the proxy settings.
   * Any UDS `via_peer` disables proxies. */
  if(network_scheme && !(needle->via_peer && needle->via_peer->unix_socket)) {
    result = url_set_conn_proxies(data, needle);
    if(result)
      goto out;

    /*************************************************************
     * If the protocol is using SSL and HTTP proxy is used, we set
     * the tunnel_proxy bit.
     *************************************************************/
    if((needle->given->flags & PROTOPT_SSL) && needle->bits.httpproxy)
      needle->bits.tunnel_proxy = TRUE;
  }
#endif /* CURL_DISABLE_PROXY */

  if(data->set.str[STRING_SASL_AUTHZID]) {
    needle->sasl_authzid = curlx_strdup(data->set.str[STRING_SASL_AUTHZID]);
    if(!needle->sasl_authzid) {
      result = CURLE_OUT_OF_MEMORY;
      goto out;
    }
  }

  if(data->set.str[STRING_BEARER]) {
    needle->oauth_bearer = curlx_strdup(data->set.str[STRING_BEARER]);
    if(!needle->oauth_bearer) {
      result = CURLE_OUT_OF_MEMORY;
      goto out;
    }
  }

  /* Check for overridden login details and set them accordingly so that
     they are known when protocol->setup_connection is called! */
  result = override_login(data, needle);
  if(result)
    goto out;

  result = set_login(data, needle); /* default credentials */
  if(result)
    goto out;

  /*************************************************************
   * Check whether the host and the "connect to host" are equal.
   * Do this after the hostnames have been IDN-converted.
   *************************************************************/
  if(Curl_peer_equal(needle->origin, needle->via_peer)) {
    Curl_peer_unlink(&needle->via_peer);
  }

#ifndef CURL_DISABLE_PROXY
  /*************************************************************
   * If the "connect to" feature is used with an HTTP proxy,
   * we set the tunnel_proxy bit.
   *************************************************************/
  if(needle->via_peer && needle->bits.httpproxy)
    needle->bits.tunnel_proxy = TRUE;
#endif

  /*************************************************************
   * Setup internals depending on protocol. Needs to be done after
   * we figured out what/if proxy to use.
   *************************************************************/
  result = setup_connection_internals(data, needle);
  if(result)
    goto out;

  if(needle->scheme->flags & PROTOPT_ALPN) {
    /* The protocol wants it, so set the bits if enabled in the easy handle
       (default) */
    if(data->set.ssl_enable_alpn)
      needle->bits.tls_enable_alpn = TRUE;
  }

  if(network_scheme) {
    /* Setup callbacks for network connections */
    needle->recv[FIRSTSOCKET] = Curl_cf_recv;
    needle->send[FIRSTSOCKET] = Curl_cf_send;
    needle->recv[SECONDARYSOCKET] = Curl_cf_recv;
    needle->send[SECONDARYSOCKET] = Curl_cf_send;
    needle->bits.tcp_fastopen = data->set.tcp_fastopen;
#ifdef USE_UNIX_SOCKETS
    if(Curl_conn_get_connect_peer(needle, FIRSTSOCKET)->unix_socket)
      needle->transport_wanted = TRNSPRT_UNIX;
#endif
  }

out:
  if(!result) {
    DEBUGASSERT(needle);
    DEBUGASSERT(needle->origin);
    *pneedle = needle;
  }
  else {
    *pneedle = NULL;
    if(needle)
      Curl_conn_free(data, needle);
  }
  return result;
}

/**
 * Find an existing connection for the transfer or create a new one.
 * Returns
 * - CURLE_OK on success with a connection attached to data
 * - CURLE_NO_CONNECTION_AVAILABLE when connection limits apply or when
 *   a suitable connection has not determined its multiplex capability.
 * - a fatal error
 */
static CURLcode url_find_or_create_conn(struct Curl_easy *data)
{
  struct connectdata *needle = NULL;
  bool waitpipe = FALSE;
  CURLcode result;

  /* create the template connection for transfer data. Use this needle to
   * find an existing connection or, if none exists, convert needle
   * to a full connection and attach it to data. */
  result = url_create_needle(data, &needle);
  if(result)
    goto out;
  DEBUGASSERT(needle);

  /***********************************************************************
   * file: is a special case in that it does not need a network connection
   ***********************************************************************/
#ifndef CURL_DISABLE_FILE
  if(needle->scheme->flags & PROTOPT_NONETWORK) {
    bool done;
    /* this is supposed to be the connect function so we better at least check
       that the file is present here! */
    DEBUGASSERT(needle->scheme->run->connect_it);
    data->info.conn_scheme = needle->scheme->name;
    /* conn_protocol can only provide "old" protocols */
    data->info.conn_protocol = (needle->scheme->protocol) & CURLPROTO_MASK;
    result = needle->scheme->run->connect_it(data, &done);
    if(result)
      goto out;

    /* Setup a "faked" transfer that will do nothing */
    Curl_attach_connection(data, needle);
    needle = NULL;
    result = Curl_cpool_add(data, data->conn);
    if(!result) {
      /* Setup whatever necessary for a resumed transfer */
      result = setup_range(data);
      if(!result) {
        Curl_xfer_setup_nop(data);
        result = Curl_init_do(data, data->conn);
      }
    }

    if(result) {
      DEBUGASSERT(data->conn->scheme->run->done);
      /* we ignore the return code for the protocol-specific DONE */
      (void)data->conn->scheme->run->done(data, result, FALSE);
    }
    goto out;
  }
#endif

  /* Complete the easy's SSL configuration for connection cache matching */
  result = Curl_ssl_easy_config_complete(data);
  if(result)
    goto out;

  /* Get rid of any dead connections so limit are easier kept. */
  Curl_cpool_prune_dead(data);

  /*************************************************************
   * Reuse of existing connection is not allowed when
   * - connect_only is set or
   * - reuse_fresh is set and this is not a follow-up request
   *   (like with HTTP followlocation)
   *************************************************************/
  if((!data->set.reuse_fresh || data->state.followlocation) &&
     !data->set.connect_only) {
    /* Ok, try to find and attach an existing one */
    url_attach_existing(data, needle, &waitpipe);
  }

  if(data->conn) {
    /* We attached an existing connection for this transfer. Copy
     * over transfer specific properties over from needle. */
    struct connectdata *conn = data->conn;
    VERBOSE(bool tls_upgraded = (!(needle->given->flags & PROTOPT_SSL) &&
                                 Curl_conn_is_ssl(conn, FIRSTSOCKET)));

    conn->bits.reuse = TRUE;
    url_conn_reuse_adjust(data, needle);

#ifndef CURL_DISABLE_PROXY
    infof(data, "Reusing existing %s: connection%s with %s %s",
          conn->given->name,
          tls_upgraded ? " (upgraded to SSL)" : "",
          conn->bits.proxy ? "proxy" : "host",
          conn->socks_proxy.peer ? conn->socks_proxy.peer->user_hostname :
          conn->http_proxy.peer ? conn->http_proxy.peer->user_hostname :
          conn->origin->hostname);
#else
    infof(data, "Reusing existing %s: connection%s with host %s",
          conn->given->name,
          tls_upgraded ? " (upgraded to SSL)" : "",
          conn->origin->hostname);
#endif
  }
  else {
    /* We have decided that we want a new connection. We may not be able to do
       that if we have reached the limit of how many connections we are
       allowed to open. */
    DEBUGF(infof(data, "new connection, bits.close=%d", needle->bits.close));

    if(waitpipe) {
      /* There is a connection that *might* become usable for multiplexing
         "soon", and we wait for that */
      infof(data, "Waiting on connection to negotiate possible multiplexing.");
      result = CURLE_NO_CONNECTION_AVAILABLE;
      goto out;
    }
    else {
      switch(Curl_cpool_check_limits(data, needle)) {
      case CPOOL_LIMIT_DEST:
        infof(data, "No more connections allowed to host");
        result = CURLE_NO_CONNECTION_AVAILABLE;
        goto out;
      case CPOOL_LIMIT_TOTAL:
        if(data->master_mid != UINT32_MAX)
          CURL_TRC_M(data, "Allowing sub-requests (like DoH) to override "
                     "max connection limit");
        else {
          infof(data, "No connections available, total of %zu reached.",
                data->multi->max_total_connections);
          result = CURLE_NO_CONNECTION_AVAILABLE;
          goto out;
        }
        break;
      default:
        break;
      }
    }

    /* Convert needle into a full connection by filling in all the
     * remaining parts like the cloned SSL configuration. */
    result = Curl_ssl_conn_config_init(data, needle);
    if(result) {
      DEBUGF(curl_mfprintf(stderr, "Error: init connection ssl config\n"));
      goto out;
    }
    /* attach it and no longer own it */
    Curl_attach_connection(data, needle);
    needle = NULL;

    result = Curl_cpool_add(data, data->conn);
    if(result)
      goto out;

#ifdef USE_NTLM
    /* If NTLM is requested in a part of this connection, make sure we do not
       assume the state is fine as this is a fresh connection and NTLM is
       connection based. */
    if((data->state.authhost.picked & CURLAUTH_NTLM) &&
       data->state.authhost.done) {
      infof(data, "NTLM picked AND auth done set, clear picked");
      data->state.authhost.picked = CURLAUTH_NONE;
      data->state.authhost.done = FALSE;
    }

    if((data->state.authproxy.picked & CURLAUTH_NTLM) &&
       data->state.authproxy.done) {
      infof(data, "NTLM-proxy picked AND auth done set, clear picked");
      data->state.authproxy.picked = CURLAUTH_NONE;
      data->state.authproxy.done = FALSE;
    }
#endif
  }

  /* Setup and init stuff before DO starts, in preparing for the transfer. */
  result = Curl_init_do(data, data->conn);
  if(result)
    goto out;

  /* Setup whatever necessary for a resumed transfer */
  result = setup_range(data);
  if(result)
    goto out;

  /* persist the scheme and handler the transfer is using */
  data->info.conn_scheme = data->conn->scheme->name;
  /* conn_protocol can only provide "old" protocols */
  data->info.conn_protocol = (data->conn->scheme->protocol) & CURLPROTO_MASK;
  data->info.used_proxy =
#ifdef CURL_DISABLE_PROXY
    0
#else
    data->conn->bits.proxy
#endif
    ;

  /* Lastly, inform connection filters that a new transfer is attached */
  result = Curl_conn_ev_data_setup(data);

out:
  if(needle)
    Curl_conn_free(data, needle);
  DEBUGASSERT(result || data->conn);
  return result;
}

CURLcode Curl_connect(struct Curl_easy *data, bool *pconnected)
{
  CURLcode result;
  struct connectdata *conn;

  *pconnected = FALSE;

  /* Set the request to virgin state based on transfer settings */
  Curl_req_hard_reset(&data->req, data);

  /* Get or create a connection for the transfer. */
  result = url_find_or_create_conn(data);
  conn = data->conn;

  if(result)
    goto out;

  DEBUGASSERT(conn);
  Curl_pgrsTime(data, TIMER_POSTQUEUE);
  if(conn->bits.reuse) {
    if(conn->attached_xfers > 1)
      /* multiplexed */
      *pconnected = TRUE;
  }
  else if(conn->scheme->flags & PROTOPT_NONETWORK) {
    Curl_pgrsTime(data, TIMER_NAMELOOKUP);
    *pconnected = TRUE;
  }
  else {
    result = Curl_conn_setup(data, conn, FIRSTSOCKET, NULL,
                             CURL_CF_SSL_DEFAULT);
    if(!result)
      result = Curl_headers_init(data);
    CURL_TRC_M(data, "Curl_conn_setup() -> %d", result);
  }

out:
  if(result == CURLE_NO_CONNECTION_AVAILABLE)
    DEBUGASSERT(!conn);

  if(result && conn) {
    /* We are not allowed to return failure with memory left allocated in the
       connectdata struct, free those here */
    Curl_detach_connection(data);
    Curl_conn_terminate(data, conn, TRUE);
  }

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
  CURLcode result;

  if(conn) {
    conn->bits.do_more = FALSE; /* by default there is no curl_do_more() to
                                   use */
    /* if the protocol used does not support wildcards, switch it off */
    if(data->state.wildcardmatch &&
       !(conn->scheme->flags & PROTOPT_WILDCARD))
      data->state.wildcardmatch = FALSE;
  }

  data->state.done = FALSE; /* *_done() is not called yet */

  data->req.no_body = data->set.opt_no_body;
  if(data->req.no_body)
    /* in HTTP lingo, no body means using the HEAD request... */
    data->state.httpreq = HTTPREQ_HEAD;

  result = Curl_req_start(&data->req, data);
  if(!result) {
    Curl_pgrsReset(data);
  }
  return result;
}

#if defined(USE_HTTP2) || defined(USE_HTTP3)

#ifdef USE_NGHTTP2

static void priority_remove_child(struct Curl_easy *parent,
                                  struct Curl_easy *child)
{
  struct Curl_data_prio_node **pnext = &parent->set.priority.children;
  struct Curl_data_prio_node *pnode = parent->set.priority.children;

  DEBUGASSERT(child->set.priority.parent == parent);
  while(pnode && pnode->data != child) {
    pnext = &pnode->next;
    pnode = pnode->next;
  }

  DEBUGASSERT(pnode);
  if(pnode) {
    *pnext = pnode->next;
    curlx_free(pnode);
  }

  child->set.priority.parent = 0;
  child->set.priority.exclusive = FALSE;
}

CURLcode Curl_data_priority_add_child(struct Curl_easy *parent,
                                      struct Curl_easy *child,
                                      bool exclusive)
{
  if(child->set.priority.parent) {
    priority_remove_child(child->set.priority.parent, child);
  }

  if(parent) {
    struct Curl_data_prio_node **tail;
    struct Curl_data_prio_node *pnode;

    pnode = curlx_calloc(1, sizeof(*pnode));
    if(!pnode)
      return CURLE_OUT_OF_MEMORY;
    pnode->data = child;

    if(parent->set.priority.children && exclusive) {
      /* exclusive: move all existing children underneath the new child */
      struct Curl_data_prio_node *node = parent->set.priority.children;
      while(node) {
        node->data->set.priority.parent = child;
        node = node->next;
      }

      tail = &child->set.priority.children;
      while(*tail)
        tail = &(*tail)->next;

      DEBUGASSERT(!*tail);
      *tail = parent->set.priority.children;
      parent->set.priority.children = 0;
    }

    tail = &parent->set.priority.children;
    while(*tail) {
      (*tail)->data->set.priority.exclusive = FALSE;
      tail = &(*tail)->next;
    }

    DEBUGASSERT(!*tail);
    *tail = pnode;
  }

  child->set.priority.parent = parent;
  child->set.priority.exclusive = exclusive;
  return CURLE_OK;
}

#endif /* USE_NGHTTP2 */

#ifdef USE_NGHTTP2
static void data_priority_cleanup(struct Curl_easy *data)
{
  while(data->set.priority.children) {
    struct Curl_easy *tmp = data->set.priority.children->data;
    priority_remove_child(data, tmp);
    if(data->set.priority.parent)
      Curl_data_priority_add_child(data->set.priority.parent, tmp, FALSE);
  }

  if(data->set.priority.parent)
    priority_remove_child(data->set.priority.parent, data);
}
#endif

void Curl_data_priority_clear_state(struct Curl_easy *data)
{
  memset(&data->state.priority, 0, sizeof(data->state.priority));
}

#endif /* USE_HTTP2 || USE_HTTP3 */

CURLcode Curl_conn_meta_set(struct connectdata *conn, const char *key,
                            void *meta_data, Curl_meta_dtor *meta_dtor)
{
  if(!Curl_hash_add2(&conn->meta_hash, CURL_UNCONST(key), strlen(key) + 1,
                     meta_data, meta_dtor)) {
    meta_dtor(CURL_UNCONST(key), strlen(key) + 1, meta_data);
    return CURLE_OUT_OF_MEMORY;
  }
  return CURLE_OK;
}

void Curl_conn_meta_remove(struct connectdata *conn, const char *key)
{
  Curl_hash_delete(&conn->meta_hash, CURL_UNCONST(key), strlen(key) + 1);
}

void *Curl_conn_meta_get(struct connectdata *conn, const char *key)
{
  return Curl_hash_pick(&conn->meta_hash, CURL_UNCONST(key), strlen(key) + 1);
}

CURLcode Curl_1st_fatal(CURLcode r1, CURLcode r2)
{
  if(r1 && (r1 != CURLE_AGAIN))
    return r1;
  if(r2 && (r2 != CURLE_AGAIN))
    return r2;
  return r1;
}
