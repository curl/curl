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
 * are also available at https://fetch.se/docs/copyright.html.
 *
 * You may opt to use, copy, modify, merge, publish, distribute and/or sell
 * copies of the Software, and permit persons to whom the Software is
 * furnished to do so, under the terms of the COPYING file.
 *
 * This software is distributed on an "AS IS" basis, WITHOUT WARRANTY OF ANY
 * KIND, either express or implied.
 *
 * SPDX-License-Identifier: fetch
 *
 ***************************************************************************/

#include "fetch_setup.h"

#ifdef HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif
#ifdef HAVE_NETINET_IN6_H
#include <netinet/in6.h>
#endif
#ifdef HAVE_NETDB_H
#include <netdb.h>
#endif
#ifdef HAVE_ARPA_INET_H
#include <arpa/inet.h>
#endif
#ifdef __VMS
#include <in.h>
#include <inet.h>
#endif

#include <setjmp.h>
#include <signal.h>

#include "urldata.h"
#include "sendf.h"
#include "hostip.h"
#include "hash.h"
#include "rand.h"
#include "share.h"
#include "url.h"
#include "inet_ntop.h"
#include "inet_pton.h"
#include "multiif.h"
#include "doh.h"
#include "warnless.h"
#include "strcase.h"
#include "easy_lock.h"
/* The last 3 #include files should be in this order */
#include "fetch_printf.h"
#include "fetch_memory.h"
#include "memdebug.h"

#if defined(FETCHRES_SYNCH) && \
    defined(HAVE_ALARM) &&     \
    defined(SIGALRM) &&        \
    defined(HAVE_SIGSETJMP) && \
    defined(GLOBAL_INIT_IS_THREADSAFE)
/* alarm-based timeouts can only be used with all the dependencies satisfied */
#define USE_ALARM_TIMEOUT
#endif

#define MAX_HOSTCACHE_LEN (255 + 7) /* max FQDN + colon + port number + zero */

#define MAX_DNS_CACHE_SIZE 29999

/*
 * hostip.c explained
 * ==================
 *
 * The main COMPILE-TIME DEFINES to keep in mind when reading the host*.c
 * source file are these:
 *
 * FETCHRES_IPV6 - this host has getaddrinfo() and family, and thus we use
 * that. The host may not be able to resolve IPv6, but we do not really have to
 * take that into account. Hosts that are not IPv6-enabled have FETCHRES_IPV4
 * defined.
 *
 * FETCHRES_ARES - is defined if libfetch is built to use c-ares for
 * asynchronous name resolves. This can be Windows or *nix.
 *
 * FETCHRES_THREADED - is defined if libfetch is built to run under (native)
 * Windows, and then the name resolve will be done in a new thread, and the
 * supported API will be the same as for ares-builds.
 *
 * If any of the two previous are defined, FETCHRES_ASYNCH is defined too. If
 * libfetch is not built to use an asynchronous resolver, FETCHRES_SYNCH is
 * defined.
 *
 * The host*.c sources files are split up like this:
 *
 * hostip.c   - method-independent resolver functions and utility functions
 * hostasyn.c - functions for asynchronous name resolves
 * hostsyn.c  - functions for synchronous name resolves
 * hostip4.c  - IPv4 specific functions
 * hostip6.c  - IPv6 specific functions
 *
 * The two asynchronous name resolver backends are implemented in:
 * asyn-ares.c   - functions for ares-using name resolves
 * asyn-thread.c - functions for threaded name resolves

 * The hostip.h is the united header file for all this. It defines the
 * FETCHRES_* defines based on the config*.h and fetch_setup.h defines.
 */

static void hostcache_unlink_entry(void *entry);

#ifndef FETCH_DISABLE_VERBOSE_STRINGS
static void show_resolve_info(struct Fetch_easy *data,
                              struct Fetch_dns_entry *dns);
#else
#define show_resolve_info(x, y) Fetch_nop_stmt
#endif

/*
 * Fetch_printable_address() stores a printable version of the 1st address
 * given in the 'ai' argument. The result will be stored in the buf that is
 * bufsize bytes big.
 *
 * If the conversion fails, the target buffer is empty.
 */
void Fetch_printable_address(const struct Fetch_addrinfo *ai, char *buf,
                            size_t bufsize)
{
  DEBUGASSERT(bufsize);
  buf[0] = 0;

  switch (ai->ai_family)
  {
  case AF_INET:
  {
    const struct sockaddr_in *sa4 = (const void *)ai->ai_addr;
    const struct in_addr *ipaddr4 = &sa4->sin_addr;
    (void)Fetch_inet_ntop(ai->ai_family, (const void *)ipaddr4, buf, bufsize);
    break;
  }
#ifdef USE_IPV6
  case AF_INET6:
  {
    const struct sockaddr_in6 *sa6 = (const void *)ai->ai_addr;
    const struct in6_addr *ipaddr6 = &sa6->sin6_addr;
    (void)Fetch_inet_ntop(ai->ai_family, (const void *)ipaddr6, buf, bufsize);
    break;
  }
#endif
  default:
    break;
  }
}

/*
 * Create a hostcache id string for the provided host + port, to be used by
 * the DNS caching. Without alloc. Return length of the id string.
 */
static size_t
create_hostcache_id(const char *name,
                    size_t nlen, /* 0 or actual name length */
                    int port, char *ptr, size_t buflen)
{
  size_t len = nlen ? nlen : strlen(name);
  DEBUGASSERT(buflen >= MAX_HOSTCACHE_LEN);
  if (len > (buflen - 7))
    len = buflen - 7;
  /* store and lower case the name */
  Fetch_strntolower(ptr, name, len);
  return msnprintf(&ptr[len], 7, ":%u", port) + len;
}

struct hostcache_prune_data
{
  time_t now;
  time_t oldest; /* oldest time in cache not pruned. */
  int max_age_sec;
};

/*
 * This function is set as a callback to be called for every entry in the DNS
 * cache when we want to prune old unused entries.
 *
 * Returning non-zero means remove the entry, return 0 to keep it in the
 * cache.
 */
static int
hostcache_entry_is_stale(void *datap, void *hc)
{
  struct hostcache_prune_data *prune =
      (struct hostcache_prune_data *)datap;
  struct Fetch_dns_entry *dns = (struct Fetch_dns_entry *)hc;

  if (dns->timestamp)
  {
    /* age in seconds */
    time_t age = prune->now - dns->timestamp;
    if (age >= (time_t)prune->max_age_sec)
      return TRUE;
    if (age > prune->oldest)
      prune->oldest = age;
  }
  return FALSE;
}

/*
 * Prune the DNS cache. This assumes that a lock has already been taken.
 * Returns the 'age' of the oldest still kept entry.
 */
static time_t
hostcache_prune(struct Fetch_hash *hostcache, int cache_timeout,
                time_t now)
{
  struct hostcache_prune_data user;

  user.max_age_sec = cache_timeout;
  user.now = now;
  user.oldest = 0;

  Fetch_hash_clean_with_criterium(hostcache,
                                 (void *)&user,
                                 hostcache_entry_is_stale);

  return user.oldest;
}

/*
 * Library-wide function for pruning the DNS cache. This function takes and
 * returns the appropriate locks.
 */
void Fetch_hostcache_prune(struct Fetch_easy *data)
{
  time_t now;
  /* the timeout may be set -1 (forever) */
  int timeout = data->set.dns_cache_timeout;

  if (!data->dns.hostcache)
    /* NULL hostcache means we cannot do it */
    return;

  if (data->share)
    Fetch_share_lock(data, FETCH_LOCK_DATA_DNS, FETCH_LOCK_ACCESS_SINGLE);

  now = time(NULL);

  do
  {
    /* Remove outdated and unused entries from the hostcache */
    time_t oldest = hostcache_prune(data->dns.hostcache, timeout, now);

    if (oldest < INT_MAX)
      timeout = (int)oldest; /* we know it fits */
    else
      timeout = INT_MAX - 1;

    /* if the cache size is still too big, use the oldest age as new
       prune limit */
  } while (timeout &&
           (Fetch_hash_count(data->dns.hostcache) > MAX_DNS_CACHE_SIZE));

  if (data->share)
    Fetch_share_unlock(data, FETCH_LOCK_DATA_DNS);
}

#ifdef USE_ALARM_TIMEOUT
/* Beware this is a global and unique instance. This is used to store the
   return address that we can jump back to from inside a signal handler. This
   is not thread-safe stuff. */
static sigjmp_buf fetch_jmpenv;
static fetch_simple_lock fetch_jmpenv_lock;
#endif

/* lookup address, returns entry if found and not stale */
static struct Fetch_dns_entry *fetch_addr(struct Fetch_easy *data,
                                         const char *hostname,
                                         int port)
{
  struct Fetch_dns_entry *dns = NULL;
  char entry_id[MAX_HOSTCACHE_LEN];

  /* Create an entry id, based upon the hostname and port */
  size_t entry_len = create_hostcache_id(hostname, 0, port,
                                         entry_id, sizeof(entry_id));

  /* See if it is already in our dns cache */
  dns = Fetch_hash_pick(data->dns.hostcache, entry_id, entry_len + 1);

  /* No entry found in cache, check if we might have a wildcard entry */
  if (!dns && data->state.wildcard_resolve)
  {
    entry_len = create_hostcache_id("*", 1, port, entry_id, sizeof(entry_id));

    /* See if it is already in our dns cache */
    dns = Fetch_hash_pick(data->dns.hostcache, entry_id, entry_len + 1);
  }

  if (dns && (data->set.dns_cache_timeout != -1))
  {
    /* See whether the returned entry is stale. Done before we release lock */
    struct hostcache_prune_data user;

    user.now = time(NULL);
    user.max_age_sec = data->set.dns_cache_timeout;
    user.oldest = 0;

    if (hostcache_entry_is_stale(&user, dns))
    {
      infof(data, "Hostname in DNS cache was stale, zapped");
      dns = NULL; /* the memory deallocation is being handled by the hash */
      Fetch_hash_delete(data->dns.hostcache, entry_id, entry_len + 1);
    }
  }

  /* See if the returned entry matches the required resolve mode */
  if (dns && data->conn->ip_version != FETCH_IPRESOLVE_WHATEVER)
  {
    int pf = PF_INET;
    bool found = FALSE;
    struct Fetch_addrinfo *addr = dns->addr;

#ifdef PF_INET6
    if (data->conn->ip_version == FETCH_IPRESOLVE_V6)
      pf = PF_INET6;
#endif

    while (addr)
    {
      if (addr->ai_family == pf)
      {
        found = TRUE;
        break;
      }
      addr = addr->ai_next;
    }

    if (!found)
    {
      infof(data, "Hostname in DNS cache does not have needed family, zapped");
      dns = NULL; /* the memory deallocation is being handled by the hash */
      Fetch_hash_delete(data->dns.hostcache, entry_id, entry_len + 1);
    }
  }
  return dns;
}

/*
 * Fetch_fetch_addr() fetches a 'Fetch_dns_entry' already in the DNS cache.
 *
 * Fetch_resolv() checks initially and multi_runsingle() checks each time
 * it discovers the handle in the state WAITRESOLVE whether the hostname
 * has already been resolved and the address has already been stored in
 * the DNS cache. This short circuits waiting for a lot of pending
 * lookups for the same hostname requested by different handles.
 *
 * Returns the Fetch_dns_entry entry pointer or NULL if not in the cache.
 *
 * The returned data *MUST* be "released" with Fetch_resolv_unlink() after
 * use, or we will leak memory!
 */
struct Fetch_dns_entry *
Fetch_fetch_addr(struct Fetch_easy *data,
                const char *hostname,
                int port)
{
  struct Fetch_dns_entry *dns = NULL;

  if (data->share)
    Fetch_share_lock(data, FETCH_LOCK_DATA_DNS, FETCH_LOCK_ACCESS_SINGLE);

  dns = fetch_addr(data, hostname, port);

  if (dns)
    dns->refcount++; /* we use it! */

  if (data->share)
    Fetch_share_unlock(data, FETCH_LOCK_DATA_DNS);

  return dns;
}

#ifndef FETCH_DISABLE_SHUFFLE_DNS
/*
 * Return # of addresses in a Fetch_addrinfo struct
 */
static int num_addresses(const struct Fetch_addrinfo *addr)
{
  int i = 0;
  while (addr)
  {
    addr = addr->ai_next;
    i++;
  }
  return i;
}

UNITTEST FETCHcode Fetch_shuffle_addr(struct Fetch_easy *data,
                                     struct Fetch_addrinfo **addr);
/*
 * Fetch_shuffle_addr() shuffles the order of addresses in a 'Fetch_addrinfo'
 * struct by re-linking its linked list.
 *
 * The addr argument should be the address of a pointer to the head node of a
 * `Fetch_addrinfo` list and it will be modified to point to the new head after
 * shuffling.
 *
 * Not declared static only to make it easy to use in a unit test!
 *
 * @unittest: 1608
 */
UNITTEST FETCHcode Fetch_shuffle_addr(struct Fetch_easy *data,
                                     struct Fetch_addrinfo **addr)
{
  FETCHcode result = FETCHE_OK;
  const int num_addrs = num_addresses(*addr);

  if (num_addrs > 1)
  {
    struct Fetch_addrinfo **nodes;
    infof(data, "Shuffling %i addresses", num_addrs);

    nodes = malloc(num_addrs * sizeof(*nodes));
    if (nodes)
    {
      int i;
      unsigned int *rnd;
      const size_t rnd_size = num_addrs * sizeof(*rnd);

      /* build a plain array of Fetch_addrinfo pointers */
      nodes[0] = *addr;
      for (i = 1; i < num_addrs; i++)
      {
        nodes[i] = nodes[i - 1]->ai_next;
      }

      rnd = malloc(rnd_size);
      if (rnd)
      {
        /* Fisher-Yates shuffle */
        if (Fetch_rand(data, (unsigned char *)rnd, rnd_size) == FETCHE_OK)
        {
          struct Fetch_addrinfo *swap_tmp;
          for (i = num_addrs - 1; i > 0; i--)
          {
            swap_tmp = nodes[rnd[i] % (unsigned int)(i + 1)];
            nodes[rnd[i] % (unsigned int)(i + 1)] = nodes[i];
            nodes[i] = swap_tmp;
          }

          /* relink list in the new order */
          for (i = 1; i < num_addrs; i++)
          {
            nodes[i - 1]->ai_next = nodes[i];
          }

          nodes[num_addrs - 1]->ai_next = NULL;
          *addr = nodes[0];
        }
        free(rnd);
      }
      else
        result = FETCHE_OUT_OF_MEMORY;
      free(nodes);
    }
    else
      result = FETCHE_OUT_OF_MEMORY;
  }
  return result;
}
#endif

/*
 * Fetch_cache_addr() stores a 'Fetch_addrinfo' struct in the DNS cache.
 *
 * When calling Fetch_resolv() has resulted in a response with a returned
 * address, we call this function to store the information in the dns
 * cache etc
 *
 * Returns the Fetch_dns_entry entry pointer or NULL if the storage failed.
 */
struct Fetch_dns_entry *
Fetch_cache_addr(struct Fetch_easy *data,
                struct Fetch_addrinfo *addr,
                const char *hostname,
                size_t hostlen, /* length or zero */
                int port,
                bool permanent)
{
  char entry_id[MAX_HOSTCACHE_LEN];
  size_t entry_len;
  struct Fetch_dns_entry *dns;
  struct Fetch_dns_entry *dns2;

#ifndef FETCH_DISABLE_SHUFFLE_DNS
  /* shuffle addresses if requested */
  if (data->set.dns_shuffle_addresses)
  {
    FETCHcode result = Fetch_shuffle_addr(data, &addr);
    if (result)
      return NULL;
  }
#endif
  if (!hostlen)
    hostlen = strlen(hostname);

  /* Create a new cache entry */
  dns = calloc(1, sizeof(struct Fetch_dns_entry) + hostlen);
  if (!dns)
  {
    return NULL;
  }

  /* Create an entry id, based upon the hostname and port */
  entry_len = create_hostcache_id(hostname, hostlen, port,
                                  entry_id, sizeof(entry_id));

  dns->refcount = 1; /* the cache has the first reference */
  dns->addr = addr;  /* this is the address(es) */
  if (permanent)
    dns->timestamp = 0; /* an entry that never goes stale */
  else
  {
    dns->timestamp = time(NULL);
    if (dns->timestamp == 0)
      dns->timestamp = 1;
  }
  dns->hostport = port;
  if (hostlen)
    memcpy(dns->hostname, hostname, hostlen);

  /* Store the resolved data in our DNS cache. */
  dns2 = Fetch_hash_add(data->dns.hostcache, entry_id, entry_len + 1,
                       (void *)dns);
  if (!dns2)
  {
    free(dns);
    return NULL;
  }

  dns = dns2;
  dns->refcount++; /* mark entry as in-use */
  return dns;
}

#ifdef USE_IPV6
/* return a static IPv6 ::1 for the name */
static struct Fetch_addrinfo *get_localhost6(int port, const char *name)
{
  struct Fetch_addrinfo *ca;
  const size_t ss_size = sizeof(struct sockaddr_in6);
  const size_t hostlen = strlen(name);
  struct sockaddr_in6 sa6;
  unsigned char ipv6[16];
  unsigned short port16 = (unsigned short)(port & 0xffff);
  ca = calloc(1, sizeof(struct Fetch_addrinfo) + ss_size + hostlen + 1);
  if (!ca)
    return NULL;

  sa6.sin6_family = AF_INET6;
  sa6.sin6_port = htons(port16);
  sa6.sin6_flowinfo = 0;
#ifdef HAVE_SOCKADDR_IN6_SIN6_SCOPE_ID
  sa6.sin6_scope_id = 0;
#endif

  (void)Fetch_inet_pton(AF_INET6, "::1", ipv6);
  memcpy(&sa6.sin6_addr, ipv6, sizeof(ipv6));

  ca->ai_flags = 0;
  ca->ai_family = AF_INET6;
  ca->ai_socktype = SOCK_STREAM;
  ca->ai_protocol = IPPROTO_TCP;
  ca->ai_addrlen = (fetch_socklen_t)ss_size;
  ca->ai_next = NULL;
  ca->ai_addr = (void *)((char *)ca + sizeof(struct Fetch_addrinfo));
  memcpy(ca->ai_addr, &sa6, ss_size);
  ca->ai_canonname = (char *)ca->ai_addr + ss_size;
  strcpy(ca->ai_canonname, name);
  return ca;
}
#else
#define get_localhost6(x, y) NULL
#endif

/* return a static IPv4 127.0.0.1 for the given name */
static struct Fetch_addrinfo *get_localhost(int port, const char *name)
{
  struct Fetch_addrinfo *ca;
  struct Fetch_addrinfo *ca6;
  const size_t ss_size = sizeof(struct sockaddr_in);
  const size_t hostlen = strlen(name);
  struct sockaddr_in sa;
  unsigned int ipv4;
  unsigned short port16 = (unsigned short)(port & 0xffff);

  /* memset to clear the sa.sin_zero field */
  memset(&sa, 0, sizeof(sa));
  sa.sin_family = AF_INET;
  sa.sin_port = htons(port16);
  if (Fetch_inet_pton(AF_INET, "127.0.0.1", (char *)&ipv4) < 1)
    return NULL;
  memcpy(&sa.sin_addr, &ipv4, sizeof(ipv4));

  ca = calloc(1, sizeof(struct Fetch_addrinfo) + ss_size + hostlen + 1);
  if (!ca)
    return NULL;
  ca->ai_flags = 0;
  ca->ai_family = AF_INET;
  ca->ai_socktype = SOCK_STREAM;
  ca->ai_protocol = IPPROTO_TCP;
  ca->ai_addrlen = (fetch_socklen_t)ss_size;
  ca->ai_addr = (void *)((char *)ca + sizeof(struct Fetch_addrinfo));
  memcpy(ca->ai_addr, &sa, ss_size);
  ca->ai_canonname = (char *)ca->ai_addr + ss_size;
  strcpy(ca->ai_canonname, name);

  ca6 = get_localhost6(port, name);
  if (!ca6)
    return ca;
  ca6->ai_next = ca;
  return ca6;
}

#ifdef USE_IPV6
/*
 * Fetch_ipv6works() returns TRUE if IPv6 seems to work.
 */
bool Fetch_ipv6works(struct Fetch_easy *data)
{
  if (data)
  {
    /* the nature of most system is that IPv6 status does not come and go
       during a program's lifetime so we only probe the first time and then we
       have the info kept for fast reuse */
    DEBUGASSERT(data);
    DEBUGASSERT(data->multi);
    if (data->multi->ipv6_up == IPV6_UNKNOWN)
    {
      bool works = Fetch_ipv6works(NULL);
      data->multi->ipv6_up = works ? IPV6_WORKS : IPV6_DEAD;
    }
    return data->multi->ipv6_up == IPV6_WORKS;
  }
  else
  {
    int ipv6_works = -1;
    /* probe to see if we have a working IPv6 stack */
    fetch_socket_t s = socket(PF_INET6, SOCK_DGRAM, 0);
    if (s == FETCH_SOCKET_BAD)
      /* an IPv6 address was requested but we cannot get/use one */
      ipv6_works = 0;
    else
    {
      ipv6_works = 1;
      sclose(s);
    }
    return ipv6_works > 0;
  }
}
#endif /* USE_IPV6 */

/*
 * Fetch_host_is_ipnum() returns TRUE if the given string is a numerical IPv4
 * (or IPv6 if supported) address.
 */
bool Fetch_host_is_ipnum(const char *hostname)
{
  struct in_addr in;
#ifdef USE_IPV6
  struct in6_addr in6;
#endif
  if (Fetch_inet_pton(AF_INET, hostname, &in) > 0
#ifdef USE_IPV6
      || Fetch_inet_pton(AF_INET6, hostname, &in6) > 0
#endif
  )
    return TRUE;
  return FALSE;
}

/* return TRUE if 'part' is a case insensitive tail of 'full' */
static bool tailmatch(const char *full, const char *part)
{
  size_t plen = strlen(part);
  size_t flen = strlen(full);
  if (plen > flen)
    return FALSE;
  return strncasecompare(part, &full[flen - plen], plen);
}

/*
 * Fetch_resolv() is the main name resolve function within libfetch. It resolves
 * a name and returns a pointer to the entry in the 'entry' argument (if one
 * is provided). This function might return immediately if we are using asynch
 * resolves. See the return codes.
 *
 * The cache entry we return will get its 'inuse' counter increased when this
 * function is used. You MUST call Fetch_resolv_unlink() later (when you are
 * done using this struct) to decrease the reference counter again.
 *
 * Return codes:
 *
 * FETCHRESOLV_ERROR   (-1) = error, no pointer
 * FETCHRESOLV_RESOLVED (0) = OK, pointer provided
 * FETCHRESOLV_PENDING  (1) = waiting for response, no pointer
 */

enum resolve_t Fetch_resolv(struct Fetch_easy *data,
                           const char *hostname,
                           int port,
                           bool allowDOH,
                           struct Fetch_dns_entry **entry)
{
  struct Fetch_dns_entry *dns = NULL;
  FETCHcode result;
  enum resolve_t rc = FETCHRESOLV_ERROR; /* default to failure */
  struct connectdata *conn = data->conn;
  /* We should intentionally error and not resolve .onion TLDs */
  size_t hostname_len = strlen(hostname);
  if (hostname_len >= 7 &&
      (fetch_strequal(&hostname[hostname_len - 6], ".onion") ||
       fetch_strequal(&hostname[hostname_len - 7], ".onion.")))
  {
    failf(data, "Not resolving .onion address (RFC 7686)");
    return FETCHRESOLV_ERROR;
  }
  *entry = NULL;
#ifndef FETCH_DISABLE_DOH
  conn->bits.doh = FALSE; /* default is not */
#else
  (void)allowDOH;
#endif

  if (data->share)
    Fetch_share_lock(data, FETCH_LOCK_DATA_DNS, FETCH_LOCK_ACCESS_SINGLE);

  dns = fetch_addr(data, hostname, port);

  if (dns)
  {
    infof(data, "Hostname %s was found in DNS cache", hostname);
    dns->refcount++; /* we use it! */
    rc = FETCHRESOLV_RESOLVED;
  }

  if (data->share)
    Fetch_share_unlock(data, FETCH_LOCK_DATA_DNS);

  if (!dns)
  {
    /* The entry was not in the cache. Resolve it to IP address */

    struct Fetch_addrinfo *addr = NULL;
    int respwait = 0;
#if !defined(FETCH_DISABLE_DOH) || !defined(USE_RESOLVE_ON_IPS)
    struct in_addr in;
#endif
#ifndef FETCH_DISABLE_DOH
#ifndef USE_RESOLVE_ON_IPS
    const
#endif
        bool ipnum = FALSE;
#endif

    /* notify the resolver start callback */
    if (data->set.resolver_start)
    {
      int st;
      Fetch_set_in_callback(data, TRUE);
      st = data->set.resolver_start(
#ifdef USE_FETCH_ASYNC
          data->state.async.resolver,
#else
          NULL,
#endif
          NULL,
          data->set.resolver_start_client);
      Fetch_set_in_callback(data, FALSE);
      if (st)
        return FETCHRESOLV_ERROR;
    }

#ifndef USE_RESOLVE_ON_IPS
    /* First check if this is an IPv4 address string */
    if (Fetch_inet_pton(AF_INET, hostname, &in) > 0)
    {
      /* This is a dotted IP address 123.123.123.123-style */
      addr = Fetch_ip2addr(AF_INET, &in, hostname, port);
      if (!addr)
        return FETCHRESOLV_ERROR;
    }
#ifdef USE_IPV6
    else
    {
      struct in6_addr in6;
      /* check if this is an IPv6 address string */
      if (Fetch_inet_pton(AF_INET6, hostname, &in6) > 0)
      {
        /* This is an IPv6 address literal */
        addr = Fetch_ip2addr(AF_INET6, &in6, hostname, port);
        if (!addr)
          return FETCHRESOLV_ERROR;
      }
    }
#endif /* USE_IPV6 */

#else /* if USE_RESOLVE_ON_IPS */
#ifndef FETCH_DISABLE_DOH
    /* First check if this is an IPv4 address string */
    if (Fetch_inet_pton(AF_INET, hostname, &in) > 0)
      /* This is a dotted IP address 123.123.123.123-style */
      ipnum = TRUE;
#ifdef USE_IPV6
    else
    {
      struct in6_addr in6;
      /* check if this is an IPv6 address string */
      if (Fetch_inet_pton(AF_INET6, hostname, &in6) > 0)
        /* This is an IPv6 address literal */
        ipnum = TRUE;
    }
#endif /* USE_IPV6 */
#endif /* FETCH_DISABLE_DOH */

#endif /* !USE_RESOLVE_ON_IPS */

    if (!addr)
    {
      if (conn->ip_version == FETCH_IPRESOLVE_V6 && !Fetch_ipv6works(data))
        return FETCHRESOLV_ERROR;

      if (strcasecompare(hostname, "localhost") ||
          strcasecompare(hostname, "localhost.") ||
          tailmatch(hostname, ".localhost") ||
          tailmatch(hostname, ".localhost."))
        addr = get_localhost(port, hostname);
#ifndef FETCH_DISABLE_DOH
      else if (allowDOH && data->set.doh && !ipnum)
        addr = Fetch_doh(data, hostname, port, &respwait);
#endif
      else
      {
        /* Check what IP specifics the app has requested and if we can provide
         * it. If not, bail out. */
        if (!Fetch_ipvalid(data, conn))
          return FETCHRESOLV_ERROR;
        /* If Fetch_getaddrinfo() returns NULL, 'respwait' might be set to a
           non-zero value indicating that we need to wait for the response to
           the resolve call */
        addr = Fetch_getaddrinfo(data, hostname, port, &respwait);
      }
    }
    if (!addr)
    {
      if (respwait)
      {
        /* the response to our resolve call will come asynchronously at
           a later time, good or bad */
        /* First, check that we have not received the info by now */
        result = Fetch_resolv_check(data, &dns);
        if (result) /* error detected */
          return FETCHRESOLV_ERROR;
        if (dns)
          rc = FETCHRESOLV_RESOLVED; /* pointer provided */
        else
          rc = FETCHRESOLV_PENDING; /* no info yet */
      }
    }
    else
    {
      if (data->share)
        Fetch_share_lock(data, FETCH_LOCK_DATA_DNS, FETCH_LOCK_ACCESS_SINGLE);

      /* we got a response, store it in the cache */
      dns = Fetch_cache_addr(data, addr, hostname, 0, port, FALSE);

      if (data->share)
        Fetch_share_unlock(data, FETCH_LOCK_DATA_DNS);

      if (!dns)
        /* returned failure, bail out nicely */
        Fetch_freeaddrinfo(addr);
      else
      {
        rc = FETCHRESOLV_RESOLVED;
        show_resolve_info(data, dns);
      }
    }
  }

  *entry = dns;

  return rc;
}

#ifdef USE_ALARM_TIMEOUT
/*
 * This signal handler jumps back into the main libfetch code and continues
 * execution. This effectively causes the remainder of the application to run
 * within a signal handler which is nonportable and could lead to problems.
 */
FETCH_NORETURN static void alarmfunc(int sig)
{
  (void)sig;
  siglongjmp(fetch_jmpenv, 1);
}
#endif /* USE_ALARM_TIMEOUT */

/*
 * Fetch_resolv_timeout() is the same as Fetch_resolv() but specifies a
 * timeout. This function might return immediately if we are using asynch
 * resolves. See the return codes.
 *
 * The cache entry we return will get its 'inuse' counter increased when this
 * function is used. You MUST call Fetch_resolv_unlink() later (when you are
 * done using this struct) to decrease the reference counter again.
 *
 * If built with a synchronous resolver and use of signals is not
 * disabled by the application, then a nonzero timeout will cause a
 * timeout after the specified number of milliseconds. Otherwise, timeout
 * is ignored.
 *
 * Return codes:
 *
 * FETCHRESOLV_TIMEDOUT(-2) = warning, time too short or previous alarm expired
 * FETCHRESOLV_ERROR   (-1) = error, no pointer
 * FETCHRESOLV_RESOLVED (0) = OK, pointer provided
 * FETCHRESOLV_PENDING  (1) = waiting for response, no pointer
 */

enum resolve_t Fetch_resolv_timeout(struct Fetch_easy *data,
                                   const char *hostname,
                                   int port,
                                   struct Fetch_dns_entry **entry,
                                   timediff_t timeoutms)
{
#ifdef USE_ALARM_TIMEOUT
#ifdef HAVE_SIGACTION
  struct sigaction keep_sigact;       /* store the old struct here */
  volatile bool keep_copysig = FALSE; /* whether old sigact has been saved */
  struct sigaction sigact;
#else
#ifdef HAVE_SIGNAL
  void (*keep_sigact)(int); /* store the old handler here */
#endif /* HAVE_SIGNAL */
#endif /* HAVE_SIGACTION */
  volatile long timeout;
  volatile unsigned int prev_alarm = 0;
#endif /* USE_ALARM_TIMEOUT */
  enum resolve_t rc;

  *entry = NULL;

  if (timeoutms < 0)
    /* got an already expired timeout */
    return FETCHRESOLV_TIMEDOUT;

#ifdef USE_ALARM_TIMEOUT
  if (data->set.no_signal)
    /* Ignore the timeout when signals are disabled */
    timeout = 0;
  else
    timeout = (timeoutms > LONG_MAX) ? LONG_MAX : (long)timeoutms;

  if (!timeout)
    /* USE_ALARM_TIMEOUT defined, but no timeout actually requested */
    return Fetch_resolv(data, hostname, port, TRUE, entry);

  if (timeout < 1000)
  {
    /* The alarm() function only provides integer second resolution, so if
       we want to wait less than one second we must bail out already now. */
    failf(data,
          "remaining timeout of %ld too small to resolve via SIGALRM method",
          timeout);
    return FETCHRESOLV_TIMEDOUT;
  }
  /* This allows us to time-out from the name resolver, as the timeout
     will generate a signal and we will siglongjmp() from that here.
     This technique has problems (see alarmfunc).
     This should be the last thing we do before calling Fetch_resolv(),
     as otherwise we would have to worry about variables that get modified
     before we invoke Fetch_resolv() (and thus use "volatile"). */
  fetch_simple_lock_lock(&fetch_jmpenv_lock);

  if (sigsetjmp(fetch_jmpenv, 1))
  {
    /* this is coming from a siglongjmp() after an alarm signal */
    failf(data, "name lookup timed out");
    rc = FETCHRESOLV_ERROR;
    goto clean_up;
  }
  else
  {
    /*************************************************************
     * Set signal handler to catch SIGALRM
     * Store the old value to be able to set it back later!
     *************************************************************/
#ifdef HAVE_SIGACTION
    sigaction(SIGALRM, NULL, &sigact);
    keep_sigact = sigact;
    keep_copysig = TRUE; /* yes, we have a copy */
    sigact.sa_handler = alarmfunc;
#ifdef SA_RESTART
    /* HP-UX does not have SA_RESTART but defaults to that behavior! */
    sigact.sa_flags &= ~SA_RESTART;
#endif
    /* now set the new struct */
    sigaction(SIGALRM, &sigact, NULL);
#else /* HAVE_SIGACTION */
    /* no sigaction(), revert to the much lamer signal() */
#ifdef HAVE_SIGNAL
    keep_sigact = signal(SIGALRM, alarmfunc);
#endif
#endif /* HAVE_SIGACTION */

    /* alarm() makes a signal get sent when the timeout fires off, and that
       will abort system calls */
    prev_alarm = alarm(fetchx_sltoui(timeout / 1000L));
  }

#else
#ifndef FETCHRES_ASYNCH
  if (timeoutms)
    infof(data, "timeout on name lookup is not supported");
#else
  (void)timeoutms; /* timeoutms not used with an async resolver */
#endif
#endif /* USE_ALARM_TIMEOUT */

  /* Perform the actual name resolution. This might be interrupted by an
   * alarm if it takes too long.
   */
  rc = Fetch_resolv(data, hostname, port, TRUE, entry);

#ifdef USE_ALARM_TIMEOUT
clean_up:

  if (!prev_alarm)
    /* deactivate a possibly active alarm before uninstalling the handler */
    alarm(0);

#ifdef HAVE_SIGACTION
  if (keep_copysig)
  {
    /* we got a struct as it looked before, now put that one back nice
       and clean */
    sigaction(SIGALRM, &keep_sigact, NULL); /* put it back */
  }
#else
#ifdef HAVE_SIGNAL
  /* restore the previous SIGALRM handler */
  signal(SIGALRM, keep_sigact);
#endif
#endif /* HAVE_SIGACTION */

  fetch_simple_lock_unlock(&fetch_jmpenv_lock);

  /* switch back the alarm() to either zero or to what it was before minus
     the time we spent until now! */
  if (prev_alarm)
  {
    /* there was an alarm() set before us, now put it back */
    timediff_t elapsed_secs = Fetch_timediff(Fetch_now(),
                                            data->conn->created) /
                              1000;

    /* the alarm period is counted in even number of seconds */
    unsigned long alarm_set = (unsigned long)(prev_alarm - elapsed_secs);

    if (!alarm_set ||
        ((alarm_set >= 0x80000000) && (prev_alarm < 0x80000000)))
    {
      /* if the alarm time-left reached zero or turned "negative" (counted
         with unsigned values), we should fire off a SIGALRM here, but we
         will not, and zero would be to switch it off so we never set it to
         less than 1! */
      alarm(1);
      rc = FETCHRESOLV_TIMEDOUT;
      failf(data, "Previous alarm fired off");
    }
    else
      alarm((unsigned int)alarm_set);
  }
#endif /* USE_ALARM_TIMEOUT */

  return rc;
}

/*
 * Fetch_resolv_unlink() releases a reference to the given cached DNS entry.
 * When the reference count reaches 0, the entry is destroyed. It is important
 * that only one unlink is made for each Fetch_resolv() call.
 *
 * May be called with 'data' == NULL for global cache.
 */
void Fetch_resolv_unlink(struct Fetch_easy *data, struct Fetch_dns_entry **pdns)
{
  struct Fetch_dns_entry *dns = *pdns;
  *pdns = NULL;
  if (data && data->share)
    Fetch_share_lock(data, FETCH_LOCK_DATA_DNS, FETCH_LOCK_ACCESS_SINGLE);

  hostcache_unlink_entry(dns);

  if (data && data->share)
    Fetch_share_unlock(data, FETCH_LOCK_DATA_DNS);
}

/*
 * File-internal: release cache dns entry reference, free if inuse drops to 0
 */
static void hostcache_unlink_entry(void *entry)
{
  struct Fetch_dns_entry *dns = (struct Fetch_dns_entry *)entry;
  DEBUGASSERT(dns && (dns->refcount > 0));

  dns->refcount--;
  if (dns->refcount == 0)
  {
    Fetch_freeaddrinfo(dns->addr);
#ifdef USE_HTTPSRR
    if (dns->hinfo)
    {
      free(dns->hinfo->target);
      free(dns->hinfo->ipv4hints);
      free(dns->hinfo->echconfiglist);
      free(dns->hinfo->ipv6hints);
      free(dns->hinfo);
    }
#endif
    free(dns);
  }
}

/*
 * Fetch_init_dnscache() inits a new DNS cache.
 */
void Fetch_init_dnscache(struct Fetch_hash *hash, size_t size)
{
  Fetch_hash_init(hash, size, Fetch_hash_str, Fetch_str_key_compare,
                 hostcache_unlink_entry);
}

/*
 * Fetch_hostcache_clean()
 *
 * This _can_ be called with 'data' == NULL but then of course no locking
 * can be done!
 */

void Fetch_hostcache_clean(struct Fetch_easy *data,
                          struct Fetch_hash *hash)
{
  if (data && data->share)
    Fetch_share_lock(data, FETCH_LOCK_DATA_DNS, FETCH_LOCK_ACCESS_SINGLE);

  Fetch_hash_clean(hash);

  if (data && data->share)
    Fetch_share_unlock(data, FETCH_LOCK_DATA_DNS);
}

FETCHcode Fetch_loadhostpairs(struct Fetch_easy *data)
{
  struct fetch_slist *hostp;
  char *host_end;

  /* Default is no wildcard found */
  data->state.wildcard_resolve = FALSE;

  for (hostp = data->state.resolve; hostp; hostp = hostp->next)
  {
    char entry_id[MAX_HOSTCACHE_LEN];
    if (!hostp->data)
      continue;
    if (hostp->data[0] == '-')
    {
      unsigned long num = 0;
      size_t entry_len;
      size_t hlen = 0;
      host_end = strchr(&hostp->data[1], ':');

      if (host_end)
      {
        hlen = host_end - &hostp->data[1];
        num = strtoul(++host_end, NULL, 10);
        if (!hlen || (num > 0xffff))
          host_end = NULL;
      }
      if (!host_end)
      {
        infof(data, "Bad syntax FETCHOPT_RESOLVE removal entry '%s'",
              hostp->data);
        continue;
      }
      /* Create an entry id, based upon the hostname and port */
      entry_len = create_hostcache_id(&hostp->data[1], hlen, (int)num,
                                      entry_id, sizeof(entry_id));
      if (data->share)
        Fetch_share_lock(data, FETCH_LOCK_DATA_DNS, FETCH_LOCK_ACCESS_SINGLE);

      /* delete entry, ignore if it did not exist */
      Fetch_hash_delete(data->dns.hostcache, entry_id, entry_len + 1);

      if (data->share)
        Fetch_share_unlock(data, FETCH_LOCK_DATA_DNS);
    }
    else
    {
      struct Fetch_dns_entry *dns;
      struct Fetch_addrinfo *head = NULL, *tail = NULL;
      size_t entry_len;
      char address[64];
#if !defined(FETCH_DISABLE_VERBOSE_STRINGS)
      char *addresses = NULL;
#endif
      char *addr_begin;
      char *addr_end;
      char *port_ptr;
      int port = 0;
      char *end_ptr;
      bool permanent = TRUE;
      unsigned long tmp_port;
      bool error = TRUE;
      char *host_begin = hostp->data;
      size_t hlen = 0;

      if (host_begin[0] == '+')
      {
        host_begin++;
        permanent = FALSE;
      }
      host_end = strchr(host_begin, ':');
      if (!host_end)
        goto err;
      hlen = host_end - host_begin;

      port_ptr = host_end + 1;
      tmp_port = strtoul(port_ptr, &end_ptr, 10);
      if (tmp_port > USHRT_MAX || end_ptr == port_ptr || *end_ptr != ':')
        goto err;

      port = (int)tmp_port;
#if !defined(FETCH_DISABLE_VERBOSE_STRINGS)
      addresses = end_ptr + 1;
#endif

      while (*end_ptr)
      {
        size_t alen;
        struct Fetch_addrinfo *ai;

        addr_begin = end_ptr + 1;
        addr_end = strchr(addr_begin, ',');
        if (!addr_end)
          addr_end = addr_begin + strlen(addr_begin);
        end_ptr = addr_end;

        /* allow IP(v6) address within [brackets] */
        if (*addr_begin == '[')
        {
          if (addr_end == addr_begin || *(addr_end - 1) != ']')
            goto err;
          ++addr_begin;
          --addr_end;
        }

        alen = addr_end - addr_begin;
        if (!alen)
          continue;

        if (alen >= sizeof(address))
          goto err;

        memcpy(address, addr_begin, alen);
        address[alen] = '\0';

#ifndef USE_IPV6
        if (strchr(address, ':'))
        {
          infof(data, "Ignoring resolve address '%s', missing IPv6 support.",
                address);
          continue;
        }
#endif

        ai = Fetch_str2addr(address, port);
        if (!ai)
        {
          infof(data, "Resolve address '%s' found illegal", address);
          goto err;
        }

        if (tail)
        {
          tail->ai_next = ai;
          tail = tail->ai_next;
        }
        else
        {
          head = tail = ai;
        }
      }

      if (!head)
        goto err;

      error = FALSE;
    err:
      if (error)
      {
        failf(data, "Couldn't parse FETCHOPT_RESOLVE entry '%s'",
              hostp->data);
        Fetch_freeaddrinfo(head);
        return FETCHE_SETOPT_OPTION_SYNTAX;
      }

      /* Create an entry id, based upon the hostname and port */
      entry_len = create_hostcache_id(host_begin, hlen, port,
                                      entry_id, sizeof(entry_id));

      if (data->share)
        Fetch_share_lock(data, FETCH_LOCK_DATA_DNS, FETCH_LOCK_ACCESS_SINGLE);

      /* See if it is already in our dns cache */
      dns = Fetch_hash_pick(data->dns.hostcache, entry_id, entry_len + 1);

      if (dns)
      {
        infof(data, "RESOLVE %.*s:%d - old addresses discarded",
              (int)hlen, host_begin, port);
        /* delete old entry, there are two reasons for this
         1. old entry may have different addresses.
         2. even if entry with correct addresses is already in the cache,
            but if it is close to expire, then by the time next http
            request is made, it can get expired and pruned because old
            entry is not necessarily marked as permanent.
         3. when adding a non-permanent entry, we want it to remove and
            replace an existing permanent entry.
         4. when adding a non-permanent entry, we want it to get a "fresh"
            timeout that starts _now_. */

        Fetch_hash_delete(data->dns.hostcache, entry_id, entry_len + 1);
      }

      /* put this new host in the cache */
      dns = Fetch_cache_addr(data, head, host_begin, hlen, port, permanent);
      if (dns)
      {
        /* release the returned reference; the cache itself will keep the
         * entry alive: */
        dns->refcount--;
      }

      if (data->share)
        Fetch_share_unlock(data, FETCH_LOCK_DATA_DNS);

      if (!dns)
      {
        Fetch_freeaddrinfo(head);
        return FETCHE_OUT_OF_MEMORY;
      }
#ifndef FETCH_DISABLE_VERBOSE_STRINGS
      infof(data, "Added %.*s:%d:%s to DNS cache%s",
            (int)hlen, host_begin, port, addresses,
            permanent ? "" : " (non-permanent)");
#endif

      /* Wildcard hostname */
      if ((hlen == 1) && (host_begin[0] == '*'))
      {
        infof(data, "RESOLVE *:%d using wildcard", port);
        data->state.wildcard_resolve = TRUE;
      }
    }
  }
  data->state.resolve = NULL; /* dealt with now */

  return FETCHE_OK;
}

#ifndef FETCH_DISABLE_VERBOSE_STRINGS
static void show_resolve_info(struct Fetch_easy *data,
                              struct Fetch_dns_entry *dns)
{
  struct Fetch_addrinfo *a;
  FETCHcode result = FETCHE_OK;
#ifdef FETCHRES_IPV6
  struct dynbuf out[2];
#else
  struct dynbuf out[1];
#endif
  DEBUGASSERT(data);
  DEBUGASSERT(dns);

  if (!data->set.verbose ||
      /* ignore no name or numerical IP addresses */
      !dns->hostname[0] || Fetch_host_is_ipnum(dns->hostname))
    return;

  a = dns->addr;

  infof(data, "Host %s:%d was resolved.",
        (dns->hostname[0] ? dns->hostname : "(none)"), dns->hostport);

  Fetch_dyn_init(&out[0], 1024);
#ifdef FETCHRES_IPV6
  Fetch_dyn_init(&out[1], 1024);
#endif

  while (a)
  {
    if (
#ifdef FETCHRES_IPV6
        a->ai_family == PF_INET6 ||
#endif
        a->ai_family == PF_INET)
    {
      char buf[MAX_IPADR_LEN];
      struct dynbuf *d = &out[(a->ai_family != PF_INET)];
      Fetch_printable_address(a, buf, sizeof(buf));
      if (Fetch_dyn_len(d))
        result = Fetch_dyn_addn(d, ", ", 2);
      if (!result)
        result = Fetch_dyn_add(d, buf);
      if (result)
      {
        infof(data, "too many IP, cannot show");
        goto fail;
      }
    }
    a = a->ai_next;
  }

#ifdef FETCHRES_IPV6
  infof(data, "IPv6: %s",
        (Fetch_dyn_len(&out[1]) ? Fetch_dyn_ptr(&out[1]) : "(none)"));
#endif
  infof(data, "IPv4: %s",
        (Fetch_dyn_len(&out[0]) ? Fetch_dyn_ptr(&out[0]) : "(none)"));

fail:
  Fetch_dyn_free(&out[0]);
#ifdef FETCHRES_IPV6
  Fetch_dyn_free(&out[1]);
#endif
}
#endif

FETCHcode Fetch_resolv_check(struct Fetch_easy *data,
                            struct Fetch_dns_entry **dns)
{
  FETCHcode result;
#if defined(FETCH_DISABLE_DOH) && !defined(FETCHRES_ASYNCH)
  (void)data;
  (void)dns;
#endif
#ifndef FETCH_DISABLE_DOH
  if (data->conn->bits.doh)
  {
    result = Fetch_doh_is_resolved(data, dns);
  }
  else
#endif
    result = Fetch_resolver_is_resolved(data, dns);
  if (*dns)
    show_resolve_info(data, *dns);
  return result;
}

int Fetch_resolv_getsock(struct Fetch_easy *data,
                        fetch_socket_t *socks)
{
#ifdef FETCHRES_ASYNCH
#ifndef FETCH_DISABLE_DOH
  if (data->conn->bits.doh)
    /* nothing to wait for during DoH resolve, those handles have their own
       sockets */
    return GETSOCK_BLANK;
#endif
  return Fetch_resolver_getsock(data, socks);
#else
  (void)data;
  (void)socks;
  return GETSOCK_BLANK;
#endif
}

/* Call this function after Fetch_connect() has returned async=TRUE and
   then a successful name resolve has been received.

   Note: this function disconnects and frees the conn data in case of
   resolve failure */
FETCHcode Fetch_once_resolved(struct Fetch_easy *data, bool *protocol_done)
{
  FETCHcode result;
  struct connectdata *conn = data->conn;

#ifdef USE_FETCH_ASYNC
  if (data->state.async.dns)
  {
    conn->dns_entry = data->state.async.dns;
    data->state.async.dns = NULL;
  }
#endif

  result = Fetch_setup_conn(data, protocol_done);

  if (result)
  {
    Fetch_detach_connection(data);
    Fetch_cpool_disconnect(data, conn, TRUE);
  }
  return result;
}

/*
 * Fetch_resolver_error() calls failf() with the appropriate message after a
 * resolve error
 */

#ifdef USE_FETCH_ASYNC
FETCHcode Fetch_resolver_error(struct Fetch_easy *data)
{
  const char *host_or_proxy;
  FETCHcode result;

#ifndef FETCH_DISABLE_PROXY
  struct connectdata *conn = data->conn;
  if (conn->bits.httpproxy)
  {
    host_or_proxy = "proxy";
    result = FETCHE_COULDNT_RESOLVE_PROXY;
  }
  else
#endif
  {
    host_or_proxy = "host";
    result = FETCHE_COULDNT_RESOLVE_HOST;
  }

  failf(data, "Could not resolve %s: %s", host_or_proxy,
        data->state.async.hostname);

  return result;
}
#endif /* USE_FETCH_ASYNC */
