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
#include <netinet/in.h> /* <netinet/tcp.h> may need it */
#endif
#ifdef HAVE_SYS_UN_H
#include <sys/un.h> /* for sockaddr_un */
#endif
#ifdef HAVE_LINUX_TCP_H
#include <linux/tcp.h>
#elif defined(HAVE_NETINET_TCP_H)
#include <netinet/tcp.h>
#endif
#ifdef HAVE_SYS_IOCTL_H
#include <sys/ioctl.h>
#endif
#ifdef HAVE_NETDB_H
#include <netdb.h>
#endif
#ifdef HAVE_FCNTL_H
#include <fcntl.h>
#endif
#ifdef HAVE_ARPA_INET_H
#include <arpa/inet.h>
#endif

#ifdef __VMS
#include <in.h>
#include <inet.h>
#endif

#include "urldata.h"
#include "sendf.h"
#include "if2ip.h"
#include "strerror.h"
#include "cfilters.h"
#include "connect.h"
#include "cf-haproxy.h"
#include "cf-https-connect.h"
#include "cf-socket.h"
#include "select.h"
#include "url.h" /* for Curl_safefree() */
#include "multiif.h"
#include "sockaddr.h" /* required for Curl_sockaddr_storage */
#include "inet_ntop.h"
#include "inet_pton.h"
#include "vtls/vtls.h" /* for vtsl cfilters */
#include "progress.h"
#include "warnless.h"
#include "conncache.h"
#include "multihandle.h"
#include "share.h"
#include "version_win32.h"
#include "vquic/vquic.h" /* for quic cfilters */
#include "http_proxy.h"
#include "socks.h"
#include "strcase.h"

/* The last 3 #include files should be in this order */
#include "curl_printf.h"
#include "curl_memory.h"
#include "memdebug.h"

#ifndef ARRAYSIZE
#define ARRAYSIZE(A) (sizeof(A)/sizeof((A)[0]))
#endif

#if !defined(CURL_DISABLE_ALTSVC) || defined(USE_HTTPSRR)

enum alpnid Curl_alpn2alpnid(char *name, size_t len)
{
  if(len == 2) {
    if(strncasecompare(name, "h1", 2))
      return ALPN_h1;
    if(strncasecompare(name, "h2", 2))
      return ALPN_h2;
    if(strncasecompare(name, "h3", 2))
      return ALPN_h3;
  }
  else if(len == 8) {
    if(strncasecompare(name, "http/1.1", 8))
      return ALPN_h1;
  }
  return ALPN_none; /* unknown, probably rubbish input */
}

#endif

/*
 * Curl_timeleft() returns the amount of milliseconds left allowed for the
 * transfer/connection. If the value is 0, there is no timeout (ie there is
 * infinite time left). If the value is negative, the timeout time has already
 * elapsed.
 * @param data the transfer to check on
 * @param nowp timestamp to use for calculation, NULL to use Curl_now()
 * @param duringconnect TRUE iff connect timeout is also taken into account.
 * @unittest: 1303
 */
timediff_t Curl_timeleft(struct Curl_easy *data,
                         struct curltime *nowp,
                         bool duringconnect)
{
  timediff_t timeleft_ms = 0;
  timediff_t ctimeleft_ms = 0;
  struct curltime now;

  /* The duration of a connect and the total transfer are calculated from two
     different time-stamps. It can end up with the total timeout being reached
     before the connect timeout expires and we must acknowledge whichever
     timeout that is reached first. The total timeout is set per entire
     operation, while the connect timeout is set per connect. */
  if(data->set.timeout <= 0 && !duringconnect)
    return 0; /* no timeout in place or checked, return "no limit" */

  if(!nowp) {
    now = Curl_now();
    nowp = &now;
  }

  if(data->set.timeout > 0) {
    timeleft_ms = data->set.timeout -
                  Curl_timediff(*nowp, data->progress.t_startop);
    if(!timeleft_ms)
      timeleft_ms = -1; /* 0 is "no limit", fake 1 ms expiry */
    if(!duringconnect)
      return timeleft_ms; /* no connect check, this is it */
  }

  if(duringconnect) {
    timediff_t ctimeout_ms = (data->set.connecttimeout > 0) ?
      data->set.connecttimeout : DEFAULT_CONNECT_TIMEOUT;
    ctimeleft_ms = ctimeout_ms -
                   Curl_timediff(*nowp, data->progress.t_startsingle);
    if(!ctimeleft_ms)
      ctimeleft_ms = -1; /* 0 is "no limit", fake 1 ms expiry */
    if(!timeleft_ms)
      return ctimeleft_ms; /* no general timeout, this is it */
  }
  /* return minimal time left or max amount already expired */
  return (ctimeleft_ms < timeleft_ms) ? ctimeleft_ms : timeleft_ms;
}

void Curl_shutdown_start(struct Curl_easy *data, int sockindex,
                         struct curltime *nowp)
{
  struct curltime now;

  DEBUGASSERT(data->conn);
  if(!nowp) {
    now = Curl_now();
    nowp = &now;
  }
  data->conn->shutdown.start[sockindex] = *nowp;
  data->conn->shutdown.timeout_ms = (data->set.shutdowntimeout > 0) ?
    data->set.shutdowntimeout : DEFAULT_SHUTDOWN_TIMEOUT_MS;
}

timediff_t Curl_shutdown_timeleft(struct connectdata *conn, int sockindex,
                                  struct curltime *nowp)
{
  struct curltime now;
  timediff_t left_ms;

  if(!conn->shutdown.start[sockindex].tv_sec || !conn->shutdown.timeout_ms)
    return 0; /* not started or no limits */

  if(!nowp) {
    now = Curl_now();
    nowp = &now;
  }
  left_ms = conn->shutdown.timeout_ms -
            Curl_timediff(*nowp, conn->shutdown.start[sockindex]);
  return left_ms ? left_ms : -1;
}

timediff_t Curl_conn_shutdown_timeleft(struct connectdata *conn,
                                       struct curltime *nowp)
{
  timediff_t left_ms = 0, ms;
  struct curltime now;
  int i;

  for(i = 0; conn->shutdown.timeout_ms && (i < 2); ++i) {
    if(!conn->shutdown.start[i].tv_sec)
      continue;
    if(!nowp) {
      now = Curl_now();
      nowp = &now;
    }
    ms = Curl_shutdown_timeleft(conn, i, nowp);
    if(ms && (!left_ms || ms < left_ms))
      left_ms = ms;
  }
  return left_ms;
}

void Curl_shutdown_clear(struct Curl_easy *data, int sockindex)
{
  struct curltime *pt = &data->conn->shutdown.start[sockindex];
  memset(pt, 0, sizeof(*pt));
}

bool Curl_shutdown_started(struct Curl_easy *data, int sockindex)
{
  struct curltime *pt = &data->conn->shutdown.start[sockindex];
  return (pt->tv_sec > 0) || (pt->tv_usec > 0);
}

static const struct Curl_addrinfo *
addr_first_match(const struct Curl_addrinfo *addr, int family)
{
  while(addr) {
    if(addr->ai_family == family)
      return addr;
    addr = addr->ai_next;
  }
  return NULL;
}

static const struct Curl_addrinfo *
addr_next_match(const struct Curl_addrinfo *addr, int family)
{
  while(addr && addr->ai_next) {
    addr = addr->ai_next;
    if(addr->ai_family == family)
      return addr;
  }
  return NULL;
}

/* retrieves ip address and port from a sockaddr structure.
   note it calls Curl_inet_ntop which sets errno on fail, not SOCKERRNO. */
bool Curl_addr2string(struct sockaddr *sa, curl_socklen_t salen,
                      char *addr, int *port)
{
  struct sockaddr_in *si = NULL;
#ifdef USE_IPV6
  struct sockaddr_in6 *si6 = NULL;
#endif
#if (defined(HAVE_SYS_UN_H) || defined(WIN32_SOCKADDR_UN)) && defined(AF_UNIX)
  struct sockaddr_un *su = NULL;
#else
  (void)salen;
#endif

  switch(sa->sa_family) {
    case AF_INET:
      si = (struct sockaddr_in *)(void *) sa;
      if(Curl_inet_ntop(sa->sa_family, &si->sin_addr,
                        addr, MAX_IPADR_LEN)) {
        unsigned short us_port = ntohs(si->sin_port);
        *port = us_port;
        return TRUE;
      }
      break;
#ifdef USE_IPV6
    case AF_INET6:
      si6 = (struct sockaddr_in6 *)(void *) sa;
      if(Curl_inet_ntop(sa->sa_family, &si6->sin6_addr,
                        addr, MAX_IPADR_LEN)) {
        unsigned short us_port = ntohs(si6->sin6_port);
        *port = us_port;
        return TRUE;
      }
      break;
#endif
#if (defined(HAVE_SYS_UN_H) || defined(WIN32_SOCKADDR_UN)) && defined(AF_UNIX)
    case AF_UNIX:
      if(salen > (curl_socklen_t)sizeof(CURL_SA_FAMILY_T)) {
        su = (struct sockaddr_un*)sa;
        msnprintf(addr, MAX_IPADR_LEN, "%s", su->sun_path);
      }
      else
        addr[0] = 0; /* socket with no name */
      *port = 0;
      return TRUE;
#endif
    default:
      break;
  }

  addr[0] = '\0';
  *port = 0;
  errno = EAFNOSUPPORT;
  return FALSE;
}

/*
 * Used to extract socket and connectdata struct for the most recent
 * transfer on the given Curl_easy.
 *
 * The returned socket will be CURL_SOCKET_BAD in case of failure!
 */
curl_socket_t Curl_getconnectinfo(struct Curl_easy *data,
                                  struct connectdata **connp)
{
  DEBUGASSERT(data);

  /* this works for an easy handle:
   * - that has been used for curl_easy_perform()
   * - that is associated with a multi handle, and whose connection
   *   was detached with CURLOPT_CONNECT_ONLY
   */
  if(data->state.lastconnect_id != -1) {
    struct connectdata *conn;

    conn = Curl_cpool_get_conn(data, data->state.lastconnect_id);
    if(!conn) {
      data->state.lastconnect_id = -1;
      return CURL_SOCKET_BAD;
    }

    if(connp)
      /* only store this if the caller cares for it */
      *connp = conn;
    return conn->sock[FIRSTSOCKET];
  }
  return CURL_SOCKET_BAD;
}

/*
 * Curl_conncontrol() marks streams or connection for closure.
 */
void Curl_conncontrol(struct connectdata *conn,
                      int ctrl /* see defines in header */
#if defined(DEBUGBUILD) && !defined(CURL_DISABLE_VERBOSE_STRINGS)
                      , const char *reason
#endif
  )
{
  /* close if a connection, or a stream that is not multiplexed. */
  /* This function will be called both before and after this connection is
     associated with a transfer. */
  bool closeit, is_multiplex;
  DEBUGASSERT(conn);
#if defined(DEBUGBUILD) && !defined(CURL_DISABLE_VERBOSE_STRINGS)
  (void)reason; /* useful for debugging */
#endif
  is_multiplex = Curl_conn_is_multiplex(conn, FIRSTSOCKET);
  closeit = (ctrl == CONNCTRL_CONNECTION) ||
    ((ctrl == CONNCTRL_STREAM) && !is_multiplex);
  if((ctrl == CONNCTRL_STREAM) && is_multiplex)
    ;  /* stream signal on multiplex conn never affects close state */
  else if((bit)closeit != conn->bits.close) {
    conn->bits.close = closeit; /* the only place in the source code that
                                   should assign this bit */
  }
}

/**
 * job walking the matching addr infos, creating a sub-cfilter with the
 * provided method `cf_create` and running setup/connect on it.
 */
struct eyeballer {
  const char *name;
  const struct Curl_addrinfo *first; /* complete address list, not owned */
  const struct Curl_addrinfo *addr;  /* List of addresses to try, not owned */
  int ai_family;                     /* matching address family only */
  cf_ip_connect_create *cf_create;   /* for creating cf */
  struct Curl_cfilter *cf;           /* current sub-cfilter connecting */
  struct eyeballer *primary;         /* eyeballer this one is backup for */
  timediff_t delay_ms;               /* delay until start */
  struct curltime started;           /* start of current attempt */
  timediff_t timeoutms;              /* timeout for current attempt */
  expire_id timeout_id;              /* ID for Curl_expire() */
  CURLcode result;
  int error;
  BIT(rewinded);                     /* if we rewinded the addr list */
  BIT(has_started);                  /* attempts have started */
  BIT(is_done);                      /* out of addresses/time */
  BIT(connected);                    /* cf has connected */
  BIT(shutdown);                     /* cf has shutdown */
  BIT(inconclusive);                 /* connect was not a hard failure, we
                                      * might talk to a restarting server */
};


typedef enum {
  SCFST_INIT,
  SCFST_WAITING,
  SCFST_DONE
} cf_connect_state;

struct cf_he_ctx {
  int transport;
  cf_ip_connect_create *cf_create;
  const struct Curl_dns_entry *remotehost;
  cf_connect_state state;
  struct eyeballer *baller[2];
  struct eyeballer *winner;
  struct curltime started;
};

/* when there are more than one IP address left to use, this macro returns how
   much of the given timeout to spend on *this* attempt */
#define TIMEOUT_LARGE 600
#define USETIME(ms) ((ms > TIMEOUT_LARGE) ? (ms / 2) : ms)

static CURLcode eyeballer_new(struct eyeballer **pballer,
                              cf_ip_connect_create *cf_create,
                              const struct Curl_addrinfo *addr,
                              int ai_family,
                              struct eyeballer *primary,
                              timediff_t delay_ms,
                              timediff_t timeout_ms,
                              expire_id timeout_id)
{
  struct eyeballer *baller;

  *pballer = NULL;
  baller = calloc(1, sizeof(*baller));
  if(!baller)
    return CURLE_OUT_OF_MEMORY;

  baller->name = ((ai_family == AF_INET) ? "ipv4" : (
#ifdef USE_IPV6
                  (ai_family == AF_INET6) ? "ipv6" :
#endif
                  "ip"));
  baller->cf_create = cf_create;
  baller->first = baller->addr = addr;
  baller->ai_family = ai_family;
  baller->primary = primary;
  baller->delay_ms = delay_ms;
  baller->timeoutms = addr_next_match(baller->addr, baller->ai_family) ?
    USETIME(timeout_ms) : timeout_ms;
  baller->timeout_id = timeout_id;
  baller->result = CURLE_COULDNT_CONNECT;

  *pballer = baller;
  return CURLE_OK;
}

static void baller_close(struct eyeballer *baller,
                          struct Curl_easy *data)
{
  if(baller && baller->cf) {
    Curl_conn_cf_discard_chain(&baller->cf, data);
  }
}

static void baller_free(struct eyeballer *baller,
                         struct Curl_easy *data)
{
  if(baller) {
    baller_close(baller, data);
    free(baller);
  }
}

static void baller_rewind(struct eyeballer *baller)
{
  baller->rewinded = TRUE;
  baller->addr = baller->first;
  baller->inconclusive = FALSE;
}

static void baller_next_addr(struct eyeballer *baller)
{
  baller->addr = addr_next_match(baller->addr, baller->ai_family);
}

/*
 * Initiate a connect attempt walk.
 *
 * Note that even on connect fail it returns CURLE_OK, but with 'sock' set to
 * CURL_SOCKET_BAD. Other errors will however return proper errors.
 */
static void baller_initiate(struct Curl_cfilter *cf,
                            struct Curl_easy *data,
                            struct eyeballer *baller)
{
  struct cf_he_ctx *ctx = cf->ctx;
  struct Curl_cfilter *cf_prev = baller->cf;
  struct Curl_cfilter *wcf;
  CURLcode result;


  /* Do not close a previous cfilter yet to ensure that the next IP's
     socket gets a different file descriptor, which can prevent bugs when
     the curl_multi_socket_action interface is used with certain select()
     replacements such as kqueue. */
  result = baller->cf_create(&baller->cf, data, cf->conn, baller->addr,
                             ctx->transport);
  if(result)
    goto out;

  /* the new filter might have sub-filters */
  for(wcf = baller->cf; wcf; wcf = wcf->next) {
    wcf->conn = cf->conn;
    wcf->sockindex = cf->sockindex;
  }

  if(addr_next_match(baller->addr, baller->ai_family)) {
    Curl_expire(data, baller->timeoutms, baller->timeout_id);
  }

out:
  if(result) {
    CURL_TRC_CF(data, cf, "%s failed", baller->name);
    baller_close(baller, data);
  }
  if(cf_prev)
    Curl_conn_cf_discard_chain(&cf_prev, data);
  baller->result = result;
}

/**
 * Start a connection attempt on the current baller address.
 * Will return CURLE_OK on the first address where a socket
 * could be created and the non-blocking connect started.
 * Returns error when all remaining addresses have been tried.
 */
static CURLcode baller_start(struct Curl_cfilter *cf,
                             struct Curl_easy *data,
                             struct eyeballer *baller,
                             timediff_t timeoutms)
{
  baller->error = 0;
  baller->connected = FALSE;
  baller->has_started = TRUE;

  while(baller->addr) {
    baller->started = Curl_now();
    baller->timeoutms = addr_next_match(baller->addr, baller->ai_family) ?
      USETIME(timeoutms) : timeoutms;
    baller_initiate(cf, data, baller);
    if(!baller->result)
      break;
    baller_next_addr(baller);
  }
  if(!baller->addr) {
    baller->is_done = TRUE;
  }
  return baller->result;
}


/* Used within the multi interface. Try next IP address, returns error if no
   more address exists or error */
static CURLcode baller_start_next(struct Curl_cfilter *cf,
                                  struct Curl_easy *data,
                                  struct eyeballer *baller,
                                  timediff_t timeoutms)
{
  if(cf->sockindex == FIRSTSOCKET) {
    baller_next_addr(baller);
    /* If we get inconclusive answers from the server(s), we start
     * again until this whole thing times out. This allows us to
     * connect to servers that are gracefully restarting and the
     * packet routing to the new instance has not happened yet (e.g. QUIC). */
    if(!baller->addr && baller->inconclusive)
      baller_rewind(baller);
    baller_start(cf, data, baller, timeoutms);
  }
  else {
    baller->error = 0;
    baller->connected = FALSE;
    baller->has_started = TRUE;
    baller->is_done = TRUE;
    baller->result = CURLE_COULDNT_CONNECT;
  }
  return baller->result;
}

static CURLcode baller_connect(struct Curl_cfilter *cf,
                               struct Curl_easy *data,
                               struct eyeballer *baller,
                               struct curltime *now,
                               bool *connected)
{
  (void)cf;
  *connected = baller->connected;
  if(!baller->result &&  !*connected) {
    /* evaluate again */
    baller->result = Curl_conn_cf_connect(baller->cf, data, 0, connected);

    if(!baller->result) {
      if(*connected) {
        baller->connected = TRUE;
        baller->is_done = TRUE;
      }
      else if(Curl_timediff(*now, baller->started) >= baller->timeoutms) {
        infof(data, "%s connect timeout after %" FMT_TIMEDIFF_T
              "ms, move on!", baller->name, baller->timeoutms);
#if defined(ETIMEDOUT)
        baller->error = ETIMEDOUT;
#endif
        baller->result = CURLE_OPERATION_TIMEDOUT;
      }
    }
    else if(baller->result == CURLE_WEIRD_SERVER_REPLY)
      baller->inconclusive = TRUE;
  }
  return baller->result;
}

/*
 * is_connected() checks if the socket has connected.
 */
static CURLcode is_connected(struct Curl_cfilter *cf,
                             struct Curl_easy *data,
                             bool *connected)
{
  struct cf_he_ctx *ctx = cf->ctx;
  struct connectdata *conn = cf->conn;
  CURLcode result;
  struct curltime now;
  size_t i;
  int ongoing, not_started;
  const char *hostname;

  /* Check if any of the conn->tempsock we use for establishing connections
   * succeeded and, if so, close any ongoing other ones.
   * Transfer the successful conn->tempsock to conn->sock[sockindex]
   * and set conn->tempsock to CURL_SOCKET_BAD.
   * If transport is QUIC, we need to shutdown the ongoing 'other'
   * cot ballers in a QUIC appropriate way. */
evaluate:
  *connected = FALSE; /* a negative world view is best */
  now = Curl_now();
  ongoing = not_started = 0;
  for(i = 0; i < ARRAYSIZE(ctx->baller); i++) {
    struct eyeballer *baller = ctx->baller[i];

    if(!baller || baller->is_done)
      continue;

    if(!baller->has_started) {
      ++not_started;
      continue;
    }
    baller->result = baller_connect(cf, data, baller, &now, connected);
    CURL_TRC_CF(data, cf, "%s connect -> %d, connected=%d",
                baller->name, baller->result, *connected);

    if(!baller->result) {
      if(*connected) {
        /* connected, declare the winner */
        ctx->winner = baller;
        ctx->baller[i] = NULL;
        break;
      }
      else { /* still waiting */
        ++ongoing;
      }
    }
    else if(!baller->is_done) {
      /* The baller failed to connect, start its next attempt */
      if(baller->error) {
        data->state.os_errno = baller->error;
        SET_SOCKERRNO(baller->error);
      }
      baller_start_next(cf, data, baller, Curl_timeleft(data, &now, TRUE));
      if(baller->is_done) {
        CURL_TRC_CF(data, cf, "%s done", baller->name);
      }
      else {
        /* next attempt was started */
        CURL_TRC_CF(data, cf, "%s trying next", baller->name);
        ++ongoing;
        Curl_expire(data, 0, EXPIRE_RUN_NOW);
      }
    }
  }

  if(ctx->winner) {
    *connected = TRUE;
    return CURLE_OK;
  }

  /* Nothing connected, check the time before we might
   * start new ballers or return ok. */
  if((ongoing || not_started) && Curl_timeleft(data, &now, TRUE) < 0) {
    failf(data, "Connection timeout after %" FMT_OFF_T " ms",
          Curl_timediff(now, data->progress.t_startsingle));
    return CURLE_OPERATION_TIMEDOUT;
  }

  /* Check if we have any waiting ballers to start now. */
  if(not_started > 0) {
    int added = 0;

    for(i = 0; i < ARRAYSIZE(ctx->baller); i++) {
      struct eyeballer *baller = ctx->baller[i];

      if(!baller || baller->has_started)
        continue;
      /* We start its primary baller has failed to connect or if
       * its start delay_ms have expired */
      if((baller->primary && baller->primary->is_done) ||
          Curl_timediff(now, ctx->started) >= baller->delay_ms) {
        baller_start(cf, data, baller, Curl_timeleft(data, &now, TRUE));
        if(baller->is_done) {
          CURL_TRC_CF(data, cf, "%s done", baller->name);
        }
        else {
          CURL_TRC_CF(data, cf, "%s starting (timeout=%" FMT_TIMEDIFF_T "ms)",
                      baller->name, baller->timeoutms);
          ++ongoing;
          ++added;
        }
      }
    }
    if(added > 0)
      goto evaluate;
  }

  if(ongoing > 0) {
    /* We are still trying, return for more waiting */
    *connected = FALSE;
    return CURLE_OK;
  }

  /* all ballers have failed to connect. */
  CURL_TRC_CF(data, cf, "all eyeballers failed");
  result = CURLE_COULDNT_CONNECT;
  for(i = 0; i < ARRAYSIZE(ctx->baller); i++) {
    struct eyeballer *baller = ctx->baller[i];
    if(!baller)
      continue;
    CURL_TRC_CF(data, cf, "%s assess started=%d, result=%d",
                baller->name, baller->has_started, baller->result);
    if(baller->has_started && baller->result) {
      result = baller->result;
      break;
    }
  }

#ifndef CURL_DISABLE_PROXY
  if(conn->bits.socksproxy)
    hostname = conn->socks_proxy.host.name;
  else if(conn->bits.httpproxy)
    hostname = conn->http_proxy.host.name;
  else
#endif
    if(conn->bits.conn_to_host)
      hostname = conn->conn_to_host.name;
  else
    hostname = conn->host.name;

  failf(data, "Failed to connect to %s port %u after "
        "%" FMT_TIMEDIFF_T " ms: %s",
        hostname, conn->primary.remote_port,
        Curl_timediff(now, data->progress.t_startsingle),
        curl_easy_strerror(result));

#ifdef WSAETIMEDOUT
  if(WSAETIMEDOUT == data->state.os_errno)
    result = CURLE_OPERATION_TIMEDOUT;
#elif defined(ETIMEDOUT)
  if(ETIMEDOUT == data->state.os_errno)
    result = CURLE_OPERATION_TIMEDOUT;
#endif

  return result;
}

/*
 * Connect to the given host with timeout, proxy or remote does not matter.
 * There might be more than one IP address to try out.
 */
static CURLcode start_connect(struct Curl_cfilter *cf,
                              struct Curl_easy *data,
                              const struct Curl_dns_entry *remotehost)
{
  struct cf_he_ctx *ctx = cf->ctx;
  struct connectdata *conn = cf->conn;
  CURLcode result = CURLE_COULDNT_CONNECT;
  int ai_family0 = 0, ai_family1 = 0;
  timediff_t timeout_ms = Curl_timeleft(data, NULL, TRUE);
  const struct Curl_addrinfo *addr0 = NULL, *addr1 = NULL;

  if(timeout_ms < 0) {
    /* a precaution, no need to continue if time already is up */
    failf(data, "Connection time-out");
    return CURLE_OPERATION_TIMEDOUT;
  }

  ctx->started = Curl_now();

  /* remotehost->addr is the list of addresses from the resolver, each
   * with an address family. The list has at least one entry, possibly
   * many more.
   * We try at most 2 at a time, until we either get a connection or
   * run out of addresses to try. Since likelihood of success is tied
   * to the address family (e.g. IPV6 might not work at all ), we want
   * the 2 connect attempt ballers to try different families, if possible.
   *
   */
  if(conn->ip_version == CURL_IPRESOLVE_V6) {
#ifdef USE_IPV6
    ai_family0 = AF_INET6;
    addr0 = addr_first_match(remotehost->addr, ai_family0);
#endif
  }
  else if(conn->ip_version == CURL_IPRESOLVE_V4) {
    ai_family0 = AF_INET;
    addr0 = addr_first_match(remotehost->addr, ai_family0);
  }
  else {
    /* no user preference, we try ipv6 always first when available */
#ifdef USE_IPV6
    ai_family0 = AF_INET6;
    addr0 = addr_first_match(remotehost->addr, ai_family0);
#endif
    /* next candidate is ipv4 */
    ai_family1 = AF_INET;
    addr1 = addr_first_match(remotehost->addr, ai_family1);
    /* no ip address families, probably AF_UNIX or something, use the
     * address family given to us */
    if(!addr1  && !addr0 && remotehost->addr) {
      ai_family0 = remotehost->addr->ai_family;
      addr0 = addr_first_match(remotehost->addr, ai_family0);
    }
  }

  if(!addr0 && addr1) {
    /* switch around, so a single baller always uses addr0 */
    addr0 = addr1;
    ai_family0 = ai_family1;
    addr1 = NULL;
  }

  /* We found no address that matches our criteria, we cannot connect */
  if(!addr0) {
    return CURLE_COULDNT_CONNECT;
  }

  memset(ctx->baller, 0, sizeof(ctx->baller));
  result = eyeballer_new(&ctx->baller[0], ctx->cf_create, addr0, ai_family0,
                          NULL, 0, /* no primary/delay, start now */
                          timeout_ms,  EXPIRE_DNS_PER_NAME);
  if(result)
    return result;
  CURL_TRC_CF(data, cf, "created %s (timeout %" FMT_TIMEDIFF_T "ms)",
              ctx->baller[0]->name, ctx->baller[0]->timeoutms);
  if(addr1) {
    /* second one gets a delayed start */
    result = eyeballer_new(&ctx->baller[1], ctx->cf_create, addr1, ai_family1,
                            ctx->baller[0], /* wait on that to fail */
                            /* or start this delayed */
                            data->set.happy_eyeballs_timeout,
                            timeout_ms,  EXPIRE_DNS_PER_NAME2);
    if(result)
      return result;
    CURL_TRC_CF(data, cf, "created %s (timeout %" FMT_TIMEDIFF_T "ms)",
                ctx->baller[1]->name, ctx->baller[1]->timeoutms);
    Curl_expire(data, data->set.happy_eyeballs_timeout,
                EXPIRE_HAPPY_EYEBALLS);
  }

  return CURLE_OK;
}

static void cf_he_ctx_clear(struct Curl_cfilter *cf, struct Curl_easy *data)
{
  struct cf_he_ctx *ctx = cf->ctx;
  size_t i;

  DEBUGASSERT(ctx);
  DEBUGASSERT(data);
  for(i = 0; i < ARRAYSIZE(ctx->baller); i++) {
    baller_free(ctx->baller[i], data);
    ctx->baller[i] = NULL;
  }
  baller_free(ctx->winner, data);
  ctx->winner = NULL;
}

static CURLcode cf_he_shutdown(struct Curl_cfilter *cf,
                               struct Curl_easy *data, bool *done)
{
  struct cf_he_ctx *ctx = cf->ctx;
  size_t i;
  CURLcode result = CURLE_OK;

  DEBUGASSERT(data);
  if(cf->connected) {
    *done = TRUE;
    return CURLE_OK;
  }

  /* shutdown all ballers that have not done so already. If one fails,
   * continue shutting down others until all are shutdown. */
  for(i = 0; i < ARRAYSIZE(ctx->baller); i++) {
    struct eyeballer *baller = ctx->baller[i];
    bool bdone = FALSE;
    if(!baller || !baller->cf || baller->shutdown)
      continue;
    baller->result = baller->cf->cft->do_shutdown(baller->cf, data, &bdone);
    if(baller->result || bdone)
      baller->shutdown = TRUE; /* treat a failed shutdown as done */
  }

  *done = TRUE;
  for(i = 0; i < ARRAYSIZE(ctx->baller); i++) {
    if(ctx->baller[i] && !ctx->baller[i]->shutdown)
      *done = FALSE;
  }
  if(*done) {
    for(i = 0; i < ARRAYSIZE(ctx->baller); i++) {
      if(ctx->baller[i] && ctx->baller[i]->result)
        result = ctx->baller[i]->result;
    }
  }
  CURL_TRC_CF(data, cf, "shutdown -> %d, done=%d", result, *done);
  return result;
}

static void cf_he_adjust_pollset(struct Curl_cfilter *cf,
                                  struct Curl_easy *data,
                                  struct easy_pollset *ps)
{
  struct cf_he_ctx *ctx = cf->ctx;
  size_t i;

  if(!cf->connected) {
    for(i = 0; i < ARRAYSIZE(ctx->baller); i++) {
      struct eyeballer *baller = ctx->baller[i];
      if(!baller || !baller->cf)
        continue;
      Curl_conn_cf_adjust_pollset(baller->cf, data, ps);
    }
    CURL_TRC_CF(data, cf, "adjust_pollset -> %d socks", ps->num);
  }
}

static CURLcode cf_he_connect(struct Curl_cfilter *cf,
                              struct Curl_easy *data,
                              bool blocking, bool *done)
{
  struct cf_he_ctx *ctx = cf->ctx;
  CURLcode result = CURLE_OK;

  if(cf->connected) {
    *done = TRUE;
    return CURLE_OK;
  }

  (void)blocking; /* TODO: do we want to support this? */
  DEBUGASSERT(ctx);
  *done = FALSE;

  switch(ctx->state) {
    case SCFST_INIT:
      DEBUGASSERT(CURL_SOCKET_BAD == Curl_conn_cf_get_socket(cf, data));
      DEBUGASSERT(!cf->connected);
      result = start_connect(cf, data, ctx->remotehost);
      if(result)
        return result;
      ctx->state = SCFST_WAITING;
      FALLTHROUGH();
    case SCFST_WAITING:
      result = is_connected(cf, data, done);
      if(!result && *done) {
        DEBUGASSERT(ctx->winner);
        DEBUGASSERT(ctx->winner->cf);
        DEBUGASSERT(ctx->winner->cf->connected);
        /* we have a winner. Install and activate it.
         * close/free all others. */
        ctx->state = SCFST_DONE;
        cf->connected = TRUE;
        cf->next = ctx->winner->cf;
        ctx->winner->cf = NULL;
        cf_he_ctx_clear(cf, data);

        if(cf->conn->handler->protocol & PROTO_FAMILY_SSH)
          Curl_pgrsTime(data, TIMER_APPCONNECT); /* we are connected already */
        if(Curl_trc_cf_is_verbose(cf, data)) {
          struct ip_quadruple ipquad;
          int is_ipv6;
          if(!Curl_conn_cf_get_ip_info(cf->next, data, &is_ipv6, &ipquad)) {
            const char *host, *disphost;
            int port;
            cf->next->cft->get_host(cf->next, data, &host, &disphost, &port);
            CURL_TRC_CF(data, cf, "Connected to %s (%s) port %u",
                        disphost, ipquad.remote_ip, ipquad.remote_port);
          }
        }
        data->info.numconnects++; /* to track the # of connections made */
      }
      break;
    case SCFST_DONE:
      *done = TRUE;
      break;
  }
  return result;
}

static void cf_he_close(struct Curl_cfilter *cf,
                        struct Curl_easy *data)
{
  struct cf_he_ctx *ctx = cf->ctx;

  CURL_TRC_CF(data, cf, "close");
  cf_he_ctx_clear(cf, data);
  cf->connected = FALSE;
  ctx->state = SCFST_INIT;

  if(cf->next) {
    cf->next->cft->do_close(cf->next, data);
    Curl_conn_cf_discard_chain(&cf->next, data);
  }
}

static bool cf_he_data_pending(struct Curl_cfilter *cf,
                               const struct Curl_easy *data)
{
  struct cf_he_ctx *ctx = cf->ctx;
  size_t i;

  if(cf->connected)
    return cf->next->cft->has_data_pending(cf->next, data);

  for(i = 0; i < ARRAYSIZE(ctx->baller); i++) {
    struct eyeballer *baller = ctx->baller[i];
    if(!baller || !baller->cf)
      continue;
    if(baller->cf->cft->has_data_pending(baller->cf, data))
      return TRUE;
  }
  return FALSE;
}

static struct curltime get_max_baller_time(struct Curl_cfilter *cf,
                                          struct Curl_easy *data,
                                          int query)
{
  struct cf_he_ctx *ctx = cf->ctx;
  struct curltime t, tmax;
  size_t i;

  memset(&tmax, 0, sizeof(tmax));
  for(i = 0; i < ARRAYSIZE(ctx->baller); i++) {
    struct eyeballer *baller = ctx->baller[i];

    memset(&t, 0, sizeof(t));
    if(baller && baller->cf &&
       !baller->cf->cft->query(baller->cf, data, query, NULL, &t)) {
      if((t.tv_sec || t.tv_usec) && Curl_timediff_us(t, tmax) > 0)
        tmax = t;
    }
  }
  return tmax;
}

static CURLcode cf_he_query(struct Curl_cfilter *cf,
                            struct Curl_easy *data,
                            int query, int *pres1, void *pres2)
{
  struct cf_he_ctx *ctx = cf->ctx;

  if(!cf->connected) {
    switch(query) {
    case CF_QUERY_CONNECT_REPLY_MS: {
      int reply_ms = -1;
      size_t i;

      for(i = 0; i < ARRAYSIZE(ctx->baller); i++) {
        struct eyeballer *baller = ctx->baller[i];
        int breply_ms;

        if(baller && baller->cf &&
           !baller->cf->cft->query(baller->cf, data, query,
                                   &breply_ms, NULL)) {
          if(breply_ms >= 0 && (reply_ms < 0 || breply_ms < reply_ms))
            reply_ms = breply_ms;
        }
      }
      *pres1 = reply_ms;
      CURL_TRC_CF(data, cf, "query connect reply: %dms", *pres1);
      return CURLE_OK;
    }
    case CF_QUERY_TIMER_CONNECT: {
      struct curltime *when = pres2;
      *when = get_max_baller_time(cf, data, CF_QUERY_TIMER_CONNECT);
      return CURLE_OK;
    }
    case CF_QUERY_TIMER_APPCONNECT: {
      struct curltime *when = pres2;
      *when = get_max_baller_time(cf, data, CF_QUERY_TIMER_APPCONNECT);
      return CURLE_OK;
    }
    default:
      break;
    }
  }

  return cf->next ?
    cf->next->cft->query(cf->next, data, query, pres1, pres2) :
    CURLE_UNKNOWN_OPTION;
}

static void cf_he_destroy(struct Curl_cfilter *cf, struct Curl_easy *data)
{
  struct cf_he_ctx *ctx = cf->ctx;

  CURL_TRC_CF(data, cf, "destroy");
  if(ctx) {
    cf_he_ctx_clear(cf, data);
  }
  /* release any resources held in state */
  Curl_safefree(ctx);
}

struct Curl_cftype Curl_cft_happy_eyeballs = {
  "HAPPY-EYEBALLS",
  0,
  CURL_LOG_LVL_NONE,
  cf_he_destroy,
  cf_he_connect,
  cf_he_close,
  cf_he_shutdown,
  Curl_cf_def_get_host,
  cf_he_adjust_pollset,
  cf_he_data_pending,
  Curl_cf_def_send,
  Curl_cf_def_recv,
  Curl_cf_def_cntrl,
  Curl_cf_def_conn_is_alive,
  Curl_cf_def_conn_keep_alive,
  cf_he_query,
};

/**
 * Create a happy eyeball connection filter that uses the, once resolved,
 * address information to connect on ip families based on connection
 * configuration.
 * @param pcf        output, the created cfilter
 * @param data       easy handle used in creation
 * @param conn       connection the filter is created for
 * @param cf_create  method to create the sub-filters performing the
 *                   actual connects.
 */
static CURLcode
cf_happy_eyeballs_create(struct Curl_cfilter **pcf,
                         struct Curl_easy *data,
                         struct connectdata *conn,
                         cf_ip_connect_create *cf_create,
                         const struct Curl_dns_entry *remotehost,
                         int transport)
{
  struct cf_he_ctx *ctx = NULL;
  CURLcode result;

  (void)data;
  (void)conn;
  *pcf = NULL;
  ctx = calloc(1, sizeof(*ctx));
  if(!ctx) {
    result = CURLE_OUT_OF_MEMORY;
    goto out;
  }
  ctx->transport = transport;
  ctx->cf_create = cf_create;
  ctx->remotehost = remotehost;

  result = Curl_cf_create(pcf, &Curl_cft_happy_eyeballs, ctx);

out:
  if(result) {
    Curl_safefree(*pcf);
    Curl_safefree(ctx);
  }
  return result;
}

struct transport_provider {
  int transport;
  cf_ip_connect_create *cf_create;
};

static
#ifndef UNITTESTS
const
#endif
struct transport_provider transport_providers[] = {
  { TRNSPRT_TCP, Curl_cf_tcp_create },
#ifdef USE_HTTP3
  { TRNSPRT_QUIC, Curl_cf_quic_create },
#endif
#ifndef CURL_DISABLE_TFTP
  { TRNSPRT_UDP, Curl_cf_udp_create },
#endif
#ifdef USE_UNIX_SOCKETS
  { TRNSPRT_UNIX, Curl_cf_unix_create },
#endif
};

static cf_ip_connect_create *get_cf_create(int transport)
{
  size_t i;
  for(i = 0; i < ARRAYSIZE(transport_providers); ++i) {
    if(transport == transport_providers[i].transport)
      return transport_providers[i].cf_create;
  }
  return NULL;
}

static CURLcode cf_he_insert_after(struct Curl_cfilter *cf_at,
                                   struct Curl_easy *data,
                                   const struct Curl_dns_entry *remotehost,
                                   int transport)
{
  cf_ip_connect_create *cf_create;
  struct Curl_cfilter *cf;
  CURLcode result;

  /* Need to be first */
  DEBUGASSERT(cf_at);
  cf_create = get_cf_create(transport);
  if(!cf_create) {
    CURL_TRC_CF(data, cf_at, "unsupported transport type %d", transport);
    return CURLE_UNSUPPORTED_PROTOCOL;
  }
  result = cf_happy_eyeballs_create(&cf, data, cf_at->conn,
                                    cf_create, remotehost,
                                    transport);
  if(result)
    return result;

  Curl_conn_cf_insert_after(cf_at, cf);
  return CURLE_OK;
}

typedef enum {
  CF_SETUP_INIT,
  CF_SETUP_CNNCT_EYEBALLS,
  CF_SETUP_CNNCT_SOCKS,
  CF_SETUP_CNNCT_HTTP_PROXY,
  CF_SETUP_CNNCT_HAPROXY,
  CF_SETUP_CNNCT_SSL,
  CF_SETUP_DONE
} cf_setup_state;

struct cf_setup_ctx {
  cf_setup_state state;
  const struct Curl_dns_entry *remotehost;
  int ssl_mode;
  int transport;
};

static CURLcode cf_setup_connect(struct Curl_cfilter *cf,
                                 struct Curl_easy *data,
                                 bool blocking, bool *done)
{
  struct cf_setup_ctx *ctx = cf->ctx;
  CURLcode result = CURLE_OK;

  if(cf->connected) {
    *done = TRUE;
    return CURLE_OK;
  }

  /* connect current sub-chain */
connect_sub_chain:
  if(cf->next && !cf->next->connected) {
    result = Curl_conn_cf_connect(cf->next, data, blocking, done);
    if(result || !*done)
      return result;
  }

  if(ctx->state < CF_SETUP_CNNCT_EYEBALLS) {
    result = cf_he_insert_after(cf, data, ctx->remotehost, ctx->transport);
    if(result)
      return result;
    ctx->state = CF_SETUP_CNNCT_EYEBALLS;
    if(!cf->next || !cf->next->connected)
      goto connect_sub_chain;
  }

  /* sub-chain connected, do we need to add more? */
#ifndef CURL_DISABLE_PROXY
  if(ctx->state < CF_SETUP_CNNCT_SOCKS && cf->conn->bits.socksproxy) {
    result = Curl_cf_socks_proxy_insert_after(cf, data);
    if(result)
      return result;
    ctx->state = CF_SETUP_CNNCT_SOCKS;
    if(!cf->next || !cf->next->connected)
      goto connect_sub_chain;
  }

  if(ctx->state < CF_SETUP_CNNCT_HTTP_PROXY && cf->conn->bits.httpproxy) {
#ifdef USE_SSL
    if(IS_HTTPS_PROXY(cf->conn->http_proxy.proxytype)
       && !Curl_conn_is_ssl(cf->conn, cf->sockindex)) {
      result = Curl_cf_ssl_proxy_insert_after(cf, data);
      if(result)
        return result;
    }
#endif /* USE_SSL */

#if !defined(CURL_DISABLE_HTTP)
    if(cf->conn->bits.tunnel_proxy) {
      result = Curl_cf_http_proxy_insert_after(cf, data);
      if(result)
        return result;
    }
#endif /* !CURL_DISABLE_HTTP */
    ctx->state = CF_SETUP_CNNCT_HTTP_PROXY;
    if(!cf->next || !cf->next->connected)
      goto connect_sub_chain;
  }
#endif /* !CURL_DISABLE_PROXY */

  if(ctx->state < CF_SETUP_CNNCT_HAPROXY) {
#if !defined(CURL_DISABLE_PROXY)
    if(data->set.haproxyprotocol) {
      if(Curl_conn_is_ssl(cf->conn, cf->sockindex)) {
        failf(data, "haproxy protocol not support with SSL "
              "encryption in place (QUIC?)");
        return CURLE_UNSUPPORTED_PROTOCOL;
      }
      result = Curl_cf_haproxy_insert_after(cf, data);
      if(result)
        return result;
    }
#endif /* !CURL_DISABLE_PROXY */
    ctx->state = CF_SETUP_CNNCT_HAPROXY;
    if(!cf->next || !cf->next->connected)
      goto connect_sub_chain;
  }

  if(ctx->state < CF_SETUP_CNNCT_SSL) {
#ifdef USE_SSL
    if((ctx->ssl_mode == CURL_CF_SSL_ENABLE
        || (ctx->ssl_mode != CURL_CF_SSL_DISABLE
           && cf->conn->handler->flags & PROTOPT_SSL)) /* we want SSL */
       && !Curl_conn_is_ssl(cf->conn, cf->sockindex)) { /* it is missing */
      result = Curl_cf_ssl_insert_after(cf, data);
      if(result)
        return result;
    }
#endif /* USE_SSL */
    ctx->state = CF_SETUP_CNNCT_SSL;
    if(!cf->next || !cf->next->connected)
      goto connect_sub_chain;
  }

  ctx->state = CF_SETUP_DONE;
  cf->connected = TRUE;
  *done = TRUE;
  return CURLE_OK;
}

static void cf_setup_close(struct Curl_cfilter *cf,
                           struct Curl_easy *data)
{
  struct cf_setup_ctx *ctx = cf->ctx;

  CURL_TRC_CF(data, cf, "close");
  cf->connected = FALSE;
  ctx->state = CF_SETUP_INIT;

  if(cf->next) {
    cf->next->cft->do_close(cf->next, data);
    Curl_conn_cf_discard_chain(&cf->next, data);
  }
}

static void cf_setup_destroy(struct Curl_cfilter *cf, struct Curl_easy *data)
{
  struct cf_setup_ctx *ctx = cf->ctx;

  (void)data;
  CURL_TRC_CF(data, cf, "destroy");
  Curl_safefree(ctx);
}


struct Curl_cftype Curl_cft_setup = {
  "SETUP",
  0,
  CURL_LOG_LVL_NONE,
  cf_setup_destroy,
  cf_setup_connect,
  cf_setup_close,
  Curl_cf_def_shutdown,
  Curl_cf_def_get_host,
  Curl_cf_def_adjust_pollset,
  Curl_cf_def_data_pending,
  Curl_cf_def_send,
  Curl_cf_def_recv,
  Curl_cf_def_cntrl,
  Curl_cf_def_conn_is_alive,
  Curl_cf_def_conn_keep_alive,
  Curl_cf_def_query,
};

static CURLcode cf_setup_create(struct Curl_cfilter **pcf,
                                struct Curl_easy *data,
                                const struct Curl_dns_entry *remotehost,
                                int transport,
                                int ssl_mode)
{
  struct Curl_cfilter *cf = NULL;
  struct cf_setup_ctx *ctx;
  CURLcode result = CURLE_OK;

  (void)data;
  ctx = calloc(1, sizeof(*ctx));
  if(!ctx) {
    result = CURLE_OUT_OF_MEMORY;
    goto out;
  }
  ctx->state = CF_SETUP_INIT;
  ctx->remotehost = remotehost;
  ctx->ssl_mode = ssl_mode;
  ctx->transport = transport;

  result = Curl_cf_create(&cf, &Curl_cft_setup, ctx);
  if(result)
    goto out;
  ctx = NULL;

out:
  *pcf = result ? NULL : cf;
  free(ctx);
  return result;
}

static CURLcode cf_setup_add(struct Curl_easy *data,
                             struct connectdata *conn,
                             int sockindex,
                             const struct Curl_dns_entry *remotehost,
                             int transport,
                             int ssl_mode)
{
  struct Curl_cfilter *cf;
  CURLcode result = CURLE_OK;

  DEBUGASSERT(data);
  result = cf_setup_create(&cf, data, remotehost, transport, ssl_mode);
  if(result)
    goto out;
  Curl_conn_cf_add(data, conn, sockindex, cf);
out:
  return result;
}

#ifdef UNITTESTS
/* used by unit2600.c */
void Curl_debug_set_transport_provider(int transport,
                                       cf_ip_connect_create *cf_create)
{
  size_t i;
  for(i = 0; i < ARRAYSIZE(transport_providers); ++i) {
    if(transport == transport_providers[i].transport) {
      transport_providers[i].cf_create = cf_create;
      return;
    }
  }
}
#endif /* UNITTESTS */

CURLcode Curl_cf_setup_insert_after(struct Curl_cfilter *cf_at,
                                    struct Curl_easy *data,
                                    const struct Curl_dns_entry *remotehost,
                                    int transport,
                                    int ssl_mode)
{
  struct Curl_cfilter *cf;
  CURLcode result;

  DEBUGASSERT(data);
  result = cf_setup_create(&cf, data, remotehost, transport, ssl_mode);
  if(result)
    goto out;
  Curl_conn_cf_insert_after(cf_at, cf);
out:
  return result;
}

CURLcode Curl_conn_setup(struct Curl_easy *data,
                         struct connectdata *conn,
                         int sockindex,
                         const struct Curl_dns_entry *remotehost,
                         int ssl_mode)
{
  CURLcode result = CURLE_OK;

  DEBUGASSERT(data);
  DEBUGASSERT(conn->handler);

#if !defined(CURL_DISABLE_HTTP)
  if(!conn->cfilter[sockindex] &&
     conn->handler->protocol == CURLPROTO_HTTPS) {
    DEBUGASSERT(ssl_mode != CURL_CF_SSL_DISABLE);
    result = Curl_cf_https_setup(data, conn, sockindex, remotehost);
    if(result)
      goto out;
  }
#endif /* !defined(CURL_DISABLE_HTTP) */

  /* Still no cfilter set, apply default. */
  if(!conn->cfilter[sockindex]) {
    result = cf_setup_add(data, conn, sockindex, remotehost,
                          conn->transport, ssl_mode);
    if(result)
      goto out;
  }

  DEBUGASSERT(conn->cfilter[sockindex]);
out:
  return result;
}
