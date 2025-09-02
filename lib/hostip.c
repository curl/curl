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
#ifndef UNDER_CE
#include <signal.h>
#endif

#include "urldata.h"
#include "sendf.h"
#include "connect.h"
#include "hostip.h"
#include "hash.h"
#include "rand.h"
#include "share.h"
#include "url.h"
#include "curlx/inet_ntop.h"
#include "curlx/inet_pton.h"
#include "multiif.h"
#include "doh.h"
#include "curlx/warnless.h"
#include "select.h"
#include "strcase.h"
#include "easy_lock.h"
#include "curlx/strparse.h"

/* The last 3 #include files should be in this order */
#include "curl_printf.h"
#include "curl_memory.h"
#include "memdebug.h"

#if defined(CURLRES_SYNCH) &&                   \
  defined(HAVE_ALARM) &&                        \
  defined(SIGALRM) &&                           \
  defined(HAVE_SIGSETJMP) &&                    \
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
 * CURLRES_IPV6 - this host has getaddrinfo() and family, and thus we use
 * that. The host may not be able to resolve IPv6, but we do not really have to
 * take that into account. Hosts that are not IPv6-enabled have CURLRES_IPV4
 * defined.
 *
 * CURLRES_ARES - is defined if libcurl is built to use c-ares for
 * asynchronous name resolves. This can be Windows or *nix.
 *
 * CURLRES_THREADED - is defined if libcurl is built to run under (native)
 * Windows, and then the name resolve will be done in a new thread, and the
 * supported API will be the same as for ares-builds.
 *
 * If any of the two previous are defined, CURLRES_ASYNCH is defined too. If
 * libcurl is not built to use an asynchronous resolver, CURLRES_SYNCH is
 * defined.
 *
 * The host*.c sources files are split up like this:
 *
 * hostip.c   - method-independent resolver functions and utility functions
 * hostip4.c  - IPv4 specific functions
 * hostip6.c  - IPv6 specific functions
 * asyn.h     - common functions for all async resolvers
 * The two asynchronous name resolver backends are implemented in:
 * asyn-ares.c - async resolver using c-ares
 * asyn-thread.c - async resolver using POSIX threads
 *
 * The hostip.h is the united header file for all this. It defines the
 * CURLRES_* defines based on the config*.h and curl_setup.h defines.
 */

static void dnscache_entry_free(struct Curl_dns_entry *dns);

#ifndef CURL_DISABLE_VERBOSE_STRINGS
static void show_resolve_info(struct Curl_easy *data,
                              struct Curl_dns_entry *dns);
#else
#define show_resolve_info(x,y) Curl_nop_stmt
#endif

/*
 * Curl_printable_address() stores a printable version of the 1st address
 * given in the 'ai' argument. The result will be stored in the buf that is
 * bufsize bytes big.
 *
 * If the conversion fails, the target buffer is empty.
 */
void Curl_printable_address(const struct Curl_addrinfo *ai, char *buf,
                            size_t bufsize)
{
  DEBUGASSERT(bufsize);
  buf[0] = 0;

  switch(ai->ai_family) {
  case AF_INET: {
    const struct sockaddr_in *sa4 = (const void *)ai->ai_addr;
    const struct in_addr *ipaddr4 = &sa4->sin_addr;
    (void)curlx_inet_ntop(ai->ai_family, (const void *)ipaddr4, buf, bufsize);
    break;
  }
#ifdef USE_IPV6
  case AF_INET6: {
    const struct sockaddr_in6 *sa6 = (const void *)ai->ai_addr;
    const struct in6_addr *ipaddr6 = &sa6->sin6_addr;
    (void)curlx_inet_ntop(ai->ai_family, (const void *)ipaddr6, buf, bufsize);
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
create_dnscache_id(const char *name,
                   size_t nlen, /* 0 or actual name length */
                   int port, char *ptr, size_t buflen)
{
  size_t len = nlen ? nlen : strlen(name);
  DEBUGASSERT(buflen >= MAX_HOSTCACHE_LEN);
  if(len > (buflen - 7))
    len = buflen - 7;
  /* store and lower case the name */
  Curl_strntolower(ptr, name, len);
  return msnprintf(&ptr[len], 7, ":%u", port) + len;
}

struct dnscache_prune_data {
  struct curltime now;
  timediff_t oldest_ms; /* oldest time in cache not pruned. */
  timediff_t max_age_ms;
};

/*
 * This function is set as a callback to be called for every entry in the DNS
 * cache when we want to prune old unused entries.
 *
 * Returning non-zero means remove the entry, return 0 to keep it in the
 * cache.
 */
static int
dnscache_entry_is_stale(void *datap, void *hc)
{
  struct dnscache_prune_data *prune =
    (struct dnscache_prune_data *) datap;
  struct Curl_dns_entry *dns = (struct Curl_dns_entry *) hc;

  if(dns->timestamp.tv_sec || dns->timestamp.tv_usec) {
    /* get age in milliseconds */
    timediff_t age = curlx_timediff(prune->now, dns->timestamp);
    if(!dns->addr)
      age *= 2; /* negative entries age twice as fast */
    if(age >= prune->max_age_ms)
      return TRUE;
    if(age > prune->oldest_ms)
      prune->oldest_ms = age;
  }
  return FALSE;
}

/*
 * Prune the DNS cache. This assumes that a lock has already been taken.
 * Returns the 'age' of the oldest still kept entry - in milliseconds.
 */
static timediff_t
dnscache_prune(struct Curl_hash *hostcache, timediff_t cache_timeout_ms,
               struct curltime now)
{
  struct dnscache_prune_data user;

  user.max_age_ms = cache_timeout_ms;
  user.now = now;
  user.oldest_ms = 0;

  Curl_hash_clean_with_criterium(hostcache,
                                 (void *) &user,
                                 dnscache_entry_is_stale);

  return user.oldest_ms;
}

static struct Curl_dnscache *dnscache_get(struct Curl_easy *data)
{
  if(data->share && data->share->specifier & (1 << CURL_LOCK_DATA_DNS))
    return &data->share->dnscache;
  if(data->multi)
    return &data->multi->dnscache;
  return NULL;
}

static void dnscache_lock(struct Curl_easy *data,
                          struct Curl_dnscache *dnscache)
{
  if(data->share && dnscache == &data->share->dnscache)
    Curl_share_lock(data, CURL_LOCK_DATA_DNS, CURL_LOCK_ACCESS_SINGLE);
}

static void dnscache_unlock(struct Curl_easy *data,
                            struct Curl_dnscache *dnscache)
{
  if(data->share && dnscache == &data->share->dnscache)
    Curl_share_unlock(data, CURL_LOCK_DATA_DNS);
}

/*
 * Library-wide function for pruning the DNS cache. This function takes and
 * returns the appropriate locks.
 */
void Curl_dnscache_prune(struct Curl_easy *data)
{
  struct Curl_dnscache *dnscache = dnscache_get(data);
  struct curltime now;
  /* the timeout may be set -1 (forever) */
  timediff_t timeout_ms = data->set.dns_cache_timeout_ms;

  if(!dnscache || (timeout_ms == -1))
    /* NULL hostcache means we cannot do it */
    return;

  dnscache_lock(data, dnscache);

  now = curlx_now();

  do {
    /* Remove outdated and unused entries from the hostcache */
    timediff_t oldest_ms = dnscache_prune(&dnscache->entries, timeout_ms, now);

    if(Curl_hash_count(&dnscache->entries) > MAX_DNS_CACHE_SIZE) {
      if(oldest_ms < INT_MAX)
        /* prune the ones over half this age */
        timeout_ms = (int)oldest_ms / 2;
      else
        timeout_ms = INT_MAX/2;
    }
    else
      break;

    /* if the cache size is still too big, use the oldest age as new prune
       limit */
  } while(timeout_ms);

  dnscache_unlock(data, dnscache);
}

void Curl_dnscache_clear(struct Curl_easy *data)
{
  struct Curl_dnscache *dnscache = dnscache_get(data);
  if(dnscache) {
    dnscache_lock(data, dnscache);
    Curl_hash_clean(&dnscache->entries);
    dnscache_unlock(data, dnscache);
  }
}

#ifdef USE_ALARM_TIMEOUT
/* Beware this is a global and unique instance. This is used to store the
   return address that we can jump back to from inside a signal handler. This
   is not thread-safe stuff. */
static sigjmp_buf curl_jmpenv;
static curl_simple_lock curl_jmpenv_lock;
#endif

/* lookup address, returns entry if found and not stale */
static struct Curl_dns_entry *fetch_addr(struct Curl_easy *data,
                                         struct Curl_dnscache *dnscache,
                                         const char *hostname,
                                         int port,
                                         int ip_version)
{
  struct Curl_dns_entry *dns = NULL;
  char entry_id[MAX_HOSTCACHE_LEN];
  size_t entry_len;

  if(!dnscache)
    return NULL;

  /* Create an entry id, based upon the hostname and port */
  entry_len = create_dnscache_id(hostname, 0, port,
                                 entry_id, sizeof(entry_id));

  /* See if it is already in our dns cache */
  dns = Curl_hash_pick(&dnscache->entries, entry_id, entry_len + 1);

  /* No entry found in cache, check if we might have a wildcard entry */
  if(!dns && data->state.wildcard_resolve) {
    entry_len = create_dnscache_id("*", 1, port, entry_id, sizeof(entry_id));

    /* See if it is already in our dns cache */
    dns = Curl_hash_pick(&dnscache->entries, entry_id, entry_len + 1);
  }

  if(dns && (data->set.dns_cache_timeout_ms != -1)) {
    /* See whether the returned entry is stale. Done before we release lock */
    struct dnscache_prune_data user;

    user.now = curlx_now();
    user.max_age_ms = data->set.dns_cache_timeout_ms;
    user.oldest_ms = 0;

    if(dnscache_entry_is_stale(&user, dns)) {
      infof(data, "Hostname in DNS cache was stale, zapped");
      dns = NULL; /* the memory deallocation is being handled by the hash */
      Curl_hash_delete(&dnscache->entries, entry_id, entry_len + 1);
    }
  }

  /* See if the returned entry matches the required resolve mode */
  if(dns && ip_version != CURL_IPRESOLVE_WHATEVER) {
    int pf = PF_INET;
    bool found = FALSE;
    struct Curl_addrinfo *addr = dns->addr;

#ifdef PF_INET6
    if(ip_version == CURL_IPRESOLVE_V6)
      pf = PF_INET6;
#endif

    while(addr) {
      if(addr->ai_family == pf) {
        found = TRUE;
        break;
      }
      addr = addr->ai_next;
    }

    if(!found) {
      infof(data, "Hostname in DNS cache does not have needed family, zapped");
      dns = NULL; /* the memory deallocation is being handled by the hash */
      Curl_hash_delete(&dnscache->entries, entry_id, entry_len + 1);
    }
  }
  return dns;
}

/*
 * Curl_dnscache_get() fetches a 'Curl_dns_entry' already in the DNS cache.
 *
 * Curl_resolv() checks initially and multi_runsingle() checks each time
 * it discovers the handle in the state WAITRESOLVE whether the hostname
 * has already been resolved and the address has already been stored in
 * the DNS cache. This short circuits waiting for a lot of pending
 * lookups for the same hostname requested by different handles.
 *
 * Returns the Curl_dns_entry entry pointer or NULL if not in the cache.
 *
 * The returned data *MUST* be "released" with Curl_resolv_unlink() after
 * use, or we will leak memory!
 */
struct Curl_dns_entry *
Curl_dnscache_get(struct Curl_easy *data,
                  const char *hostname,
                  int port,
                  int ip_version)
{
  struct Curl_dnscache *dnscache = dnscache_get(data);
  struct Curl_dns_entry *dns = NULL;

  dnscache_lock(data, dnscache);

  dns = fetch_addr(data, dnscache, hostname, port, ip_version);
  if(dns)
    dns->refcount++; /* we use it! */

  dnscache_unlock(data, dnscache);

  return dns;
}

#ifndef CURL_DISABLE_SHUFFLE_DNS
/*
 * Return # of addresses in a Curl_addrinfo struct
 */
static int num_addresses(const struct Curl_addrinfo *addr)
{
  int i = 0;
  while(addr) {
    addr = addr->ai_next;
    i++;
  }
  return i;
}

UNITTEST CURLcode Curl_shuffle_addr(struct Curl_easy *data,
                                    struct Curl_addrinfo **addr);
/*
 * Curl_shuffle_addr() shuffles the order of addresses in a 'Curl_addrinfo'
 * struct by re-linking its linked list.
 *
 * The addr argument should be the address of a pointer to the head node of a
 * `Curl_addrinfo` list and it will be modified to point to the new head after
 * shuffling.
 *
 * Not declared static only to make it easy to use in a unit test!
 *
 * @unittest: 1608
 */
UNITTEST CURLcode Curl_shuffle_addr(struct Curl_easy *data,
                                    struct Curl_addrinfo **addr)
{
  CURLcode result = CURLE_OK;
  const int num_addrs = num_addresses(*addr);

  if(num_addrs > 1) {
    struct Curl_addrinfo **nodes;
    infof(data, "Shuffling %i addresses", num_addrs);

    nodes = malloc(num_addrs*sizeof(*nodes));
    if(nodes) {
      int i;
      unsigned int *rnd;
      const size_t rnd_size = num_addrs * sizeof(*rnd);

      /* build a plain array of Curl_addrinfo pointers */
      nodes[0] = *addr;
      for(i = 1; i < num_addrs; i++) {
        nodes[i] = nodes[i-1]->ai_next;
      }

      rnd = malloc(rnd_size);
      if(rnd) {
        /* Fisher-Yates shuffle */
        if(Curl_rand(data, (unsigned char *)rnd, rnd_size) == CURLE_OK) {
          struct Curl_addrinfo *swap_tmp;
          for(i = num_addrs - 1; i > 0; i--) {
            swap_tmp = nodes[rnd[i] % (unsigned int)(i + 1)];
            nodes[rnd[i] % (unsigned int)(i + 1)] = nodes[i];
            nodes[i] = swap_tmp;
          }

          /* relink list in the new order */
          for(i = 1; i < num_addrs; i++) {
            nodes[i-1]->ai_next = nodes[i];
          }

          nodes[num_addrs-1]->ai_next = NULL;
          *addr = nodes[0];
        }
        free(rnd);
      }
      else
        result = CURLE_OUT_OF_MEMORY;
      free(nodes);
    }
    else
      result = CURLE_OUT_OF_MEMORY;
  }
  return result;
}
#endif

struct Curl_dns_entry *
Curl_dnscache_mk_entry(struct Curl_easy *data,
                       struct Curl_addrinfo *addr,
                       const char *hostname,
                       size_t hostlen, /* length or zero */
                       int port,
                       bool permanent)
{
  struct Curl_dns_entry *dns;

#ifndef CURL_DISABLE_SHUFFLE_DNS
  /* shuffle addresses if requested */
  if(data->set.dns_shuffle_addresses) {
    CURLcode result = Curl_shuffle_addr(data, &addr);
    if(result) {
      Curl_freeaddrinfo(addr);
      return NULL;
    }
  }
#else
  (void)data;
#endif
  if(!hostlen)
    hostlen = strlen(hostname);

  /* Create a new cache entry */
  dns = calloc(1, sizeof(struct Curl_dns_entry) + hostlen);
  if(!dns) {
    Curl_freeaddrinfo(addr);
    return NULL;
  }

  dns->refcount = 1; /* the cache has the first reference */
  dns->addr = addr; /* this is the address(es) */
  if(permanent) {
    dns->timestamp.tv_sec = 0; /* an entry that never goes stale */
    dns->timestamp.tv_usec = 0; /* an entry that never goes stale */
  }
  else {
    dns->timestamp = curlx_now();
  }
  dns->hostport = port;
  if(hostlen)
    memcpy(dns->hostname, hostname, hostlen);

  return dns;
}

static struct Curl_dns_entry *
dnscache_add_addr(struct Curl_easy *data,
                  struct Curl_dnscache *dnscache,
                  struct Curl_addrinfo *addr,
                  const char *hostname,
                  size_t hlen, /* length or zero */
                  int port,
                  bool permanent)
{
  char entry_id[MAX_HOSTCACHE_LEN];
  size_t entry_len;
  struct Curl_dns_entry *dns;
  struct Curl_dns_entry *dns2;

  dns = Curl_dnscache_mk_entry(data, addr, hostname, hlen, port, permanent);
  if(!dns)
    return NULL;

  /* Create an entry id, based upon the hostname and port */
  entry_len = create_dnscache_id(hostname, hlen, port,
                                 entry_id, sizeof(entry_id));

  /* Store the resolved data in our DNS cache. */
  dns2 = Curl_hash_add(&dnscache->entries, entry_id, entry_len + 1,
                       (void *)dns);
  if(!dns2) {
    dnscache_entry_free(dns);
    return NULL;
  }

  dns = dns2;
  dns->refcount++;         /* mark entry as in-use */
  return dns;
}

CURLcode Curl_dnscache_add(struct Curl_easy *data,
                           struct Curl_dns_entry *entry)
{
  struct Curl_dnscache *dnscache = dnscache_get(data);
  char id[MAX_HOSTCACHE_LEN];
  size_t idlen;

  if(!dnscache)
    return CURLE_FAILED_INIT;
  /* Create an entry id, based upon the hostname and port */
  idlen = create_dnscache_id(entry->hostname, 0, entry->hostport,
                             id, sizeof(id));

  /* Store the resolved data in our DNS cache and up ref count */
  dnscache_lock(data, dnscache);
  if(!Curl_hash_add(&dnscache->entries, id, idlen + 1, (void *)entry)) {
    dnscache_unlock(data, dnscache);
    return CURLE_OUT_OF_MEMORY;
  }
  entry->refcount++;
  dnscache_unlock(data, dnscache);
  return CURLE_OK;
}

#ifdef USE_IPV6
/* return a static IPv6 ::1 for the name */
static struct Curl_addrinfo *get_localhost6(int port, const char *name)
{
  struct Curl_addrinfo *ca;
  const size_t ss_size = sizeof(struct sockaddr_in6);
  const size_t hostlen = strlen(name);
  struct sockaddr_in6 sa6;
  unsigned char ipv6[16];
  unsigned short port16 = (unsigned short)(port & 0xffff);
  ca = calloc(1, sizeof(struct Curl_addrinfo) + ss_size + hostlen + 1);
  if(!ca)
    return NULL;

  sa6.sin6_family = AF_INET6;
  sa6.sin6_port = htons(port16);
  sa6.sin6_flowinfo = 0;
#ifdef HAVE_SOCKADDR_IN6_SIN6_SCOPE_ID
  sa6.sin6_scope_id = 0;
#endif

  (void)curlx_inet_pton(AF_INET6, "::1", ipv6);
  memcpy(&sa6.sin6_addr, ipv6, sizeof(ipv6));

  ca->ai_flags     = 0;
  ca->ai_family    = AF_INET6;
  ca->ai_socktype  = SOCK_STREAM;
  ca->ai_protocol  = IPPROTO_TCP;
  ca->ai_addrlen   = (curl_socklen_t)ss_size;
  ca->ai_next      = NULL;
  ca->ai_addr = (void *)((char *)ca + sizeof(struct Curl_addrinfo));
  memcpy(ca->ai_addr, &sa6, ss_size);
  ca->ai_canonname = (char *)ca->ai_addr + ss_size;
  strcpy(ca->ai_canonname, name);
  return ca;
}
#else
#define get_localhost6(x,y) NULL
#endif

/* return a static IPv4 127.0.0.1 for the given name */
static struct Curl_addrinfo *get_localhost(int port, const char *name)
{
  struct Curl_addrinfo *ca;
  struct Curl_addrinfo *ca6;
  const size_t ss_size = sizeof(struct sockaddr_in);
  const size_t hostlen = strlen(name);
  struct sockaddr_in sa;
  unsigned int ipv4;
  unsigned short port16 = (unsigned short)(port & 0xffff);

  /* memset to clear the sa.sin_zero field */
  memset(&sa, 0, sizeof(sa));
  sa.sin_family = AF_INET;
  sa.sin_port = htons(port16);
  if(curlx_inet_pton(AF_INET, "127.0.0.1", (char *)&ipv4) < 1)
    return NULL;
  memcpy(&sa.sin_addr, &ipv4, sizeof(ipv4));

  ca = calloc(1, sizeof(struct Curl_addrinfo) + ss_size + hostlen + 1);
  if(!ca)
    return NULL;
  ca->ai_flags     = 0;
  ca->ai_family    = AF_INET;
  ca->ai_socktype  = SOCK_STREAM;
  ca->ai_protocol  = IPPROTO_TCP;
  ca->ai_addrlen   = (curl_socklen_t)ss_size;
  ca->ai_addr = (void *)((char *)ca + sizeof(struct Curl_addrinfo));
  memcpy(ca->ai_addr, &sa, ss_size);
  ca->ai_canonname = (char *)ca->ai_addr + ss_size;
  strcpy(ca->ai_canonname, name);

  ca6 = get_localhost6(port, name);
  if(!ca6)
    return ca;
  ca6->ai_next = ca;
  return ca6;
}

#ifdef USE_IPV6
/*
 * Curl_ipv6works() returns TRUE if IPv6 seems to work.
 */
bool Curl_ipv6works(struct Curl_easy *data)
{
  if(data) {
    /* the nature of most system is that IPv6 status does not come and go
       during a program's lifetime so we only probe the first time and then we
       have the info kept for fast reuse */
    DEBUGASSERT(data);
    DEBUGASSERT(data->multi);
    if(data->multi->ipv6_up == IPV6_UNKNOWN) {
      bool works = Curl_ipv6works(NULL);
      data->multi->ipv6_up = works ? IPV6_WORKS : IPV6_DEAD;
    }
    return data->multi->ipv6_up == IPV6_WORKS;
  }
  else {
    int ipv6_works = -1;
    /* probe to see if we have a working IPv6 stack */
    curl_socket_t s = socket(PF_INET6, SOCK_DGRAM, 0);
    if(s == CURL_SOCKET_BAD)
      /* an IPv6 address was requested but we cannot get/use one */
      ipv6_works = 0;
    else {
      ipv6_works = 1;
      sclose(s);
    }
    return ipv6_works > 0;
  }
}
#endif /* USE_IPV6 */

/*
 * Curl_host_is_ipnum() returns TRUE if the given string is a numerical IPv4
 * (or IPv6 if supported) address.
 */
bool Curl_host_is_ipnum(const char *hostname)
{
  struct in_addr in;
#ifdef USE_IPV6
  struct in6_addr in6;
#endif
  if(curlx_inet_pton(AF_INET, hostname, &in) > 0
#ifdef USE_IPV6
     || curlx_inet_pton(AF_INET6, hostname, &in6) > 0
#endif
    )
    return TRUE;
  return FALSE;
}


/* return TRUE if 'part' is a case insensitive tail of 'full' */
static bool tailmatch(const char *full, size_t flen,
                      const char *part, size_t plen)
{
  if(plen > flen)
    return FALSE;
  return curl_strnequal(part, &full[flen - plen], plen);
}

static struct Curl_addrinfo *
convert_ipaddr_direct(const char *hostname, int port, bool *is_ipaddr)
{
  struct in_addr in;
  *is_ipaddr = FALSE;
  /* First check if this is an IPv4 address string */
  if(curlx_inet_pton(AF_INET, hostname, &in) > 0) {
    /* This is a dotted IP address 123.123.123.123-style */
    *is_ipaddr = TRUE;
#ifdef USE_RESOLVE_ON_IPS
    (void)port;
    return NULL;
#else
    return Curl_ip2addr(AF_INET, &in, hostname, port);
#endif
  }
#ifdef USE_IPV6
  else {
    struct in6_addr in6;
    /* check if this is an IPv6 address string */
    if(curlx_inet_pton(AF_INET6, hostname, &in6) > 0) {
      /* This is an IPv6 address literal */
      *is_ipaddr = TRUE;
#ifdef USE_RESOLVE_ON_IPS
      return NULL;
#else
      return Curl_ip2addr(AF_INET6, &in6, hostname, port);
#endif
    }
  }
#endif /* USE_IPV6 */
  return NULL;
}

static bool can_resolve_ip_version(struct Curl_easy *data, int ip_version)
{
#ifdef CURLRES_IPV6
  if(ip_version == CURL_IPRESOLVE_V6 && !Curl_ipv6works(data))
    return FALSE;
#elif defined(CURLRES_IPV4)
  (void)data;
  if(ip_version == CURL_IPRESOLVE_V6)
    return FALSE;
#else
#error either CURLRES_IPV6 or CURLRES_IPV4 need to be defined
#endif
  return TRUE;
}

static CURLcode store_negative_resolve(struct Curl_easy *data,
                                       const char *host,
                                       int port)
{
  struct Curl_dnscache *dnscache = dnscache_get(data);
  struct Curl_dns_entry *dns;
  DEBUGASSERT(dnscache);
  if(!dnscache)
    return CURLE_FAILED_INIT;

  /* put this new host in the cache */
  dns = dnscache_add_addr(data, dnscache, NULL, host, 0, port, FALSE);
  if(dns) {
    /* release the returned reference; the cache itself will keep the
     * entry alive: */
    dns->refcount--;
    infof(data, "Store negative name resolve for %s:%d", host, port);
    return CURLE_OK;
  }
  return CURLE_OUT_OF_MEMORY;
}

/*
 * Curl_resolv() is the main name resolve function within libcurl. It resolves
 * a name and returns a pointer to the entry in the 'entry' argument (if one
 * is provided). This function might return immediately if we are using asynch
 * resolves. See the return codes.
 *
 * The cache entry we return will get its 'inuse' counter increased when this
 * function is used. You MUST call Curl_resolv_unlink() later (when you are
 * done using this struct) to decrease the reference counter again.
 *
 * Return codes:
 * CURLE_OK = success, *entry set to non-NULL
 * CURLE_AGAIN = resolving in progress, *entry == NULL
 * CURLE_COULDNT_RESOLVE_HOST = error, *entry == NULL
 * CURLE_OPERATION_TIMEDOUT = timeout expired, *entry == NULL
 */
CURLcode Curl_resolv(struct Curl_easy *data,
                     const char *hostname,
                     int port,
                     int ip_version,
                     bool allowDOH,
                     struct Curl_dns_entry **entry)
{
  struct Curl_dnscache *dnscache = dnscache_get(data);
  struct Curl_dns_entry *dns = NULL;
  struct Curl_addrinfo *addr = NULL;
  int respwait = 0;
  bool is_ipaddr;
  size_t hostname_len;

#ifndef CURL_DISABLE_DOH
  data->conn->bits.doh = FALSE; /* default is not */
#else
  (void)allowDOH;
#endif
  if(!dnscache)
    goto error;

  /* We should intentionally error and not resolve .onion TLDs */
  hostname_len = strlen(hostname);
  if(hostname_len >= 7 &&
     (curl_strequal(&hostname[hostname_len - 6], ".onion") ||
      curl_strequal(&hostname[hostname_len - 7], ".onion."))) {
    failf(data, "Not resolving .onion address (RFC 7686)");
    goto error;
  }

  /* Let's check our DNS cache first */
  dnscache_lock(data, dnscache);
  dns = fetch_addr(data, dnscache, hostname, port, ip_version);
  if(dns)
    dns->refcount++; /* we pass out the reference. */
  dnscache_unlock(data, dnscache);
  if(dns) {
    infof(data, "Hostname %s was found in DNS cache", hostname);
    goto out;
  }

  /* No luck, we need to resolve hostname. Notify user callback. */
  if(data->set.resolver_start) {
    void *resolver = NULL;
    int st;
#ifdef CURLRES_ASYNCH
    if(Curl_async_get_impl(data, &resolver))
      goto error;
#endif
    Curl_set_in_callback(data, TRUE);
    st = data->set.resolver_start(resolver, NULL,
                                  data->set.resolver_start_client);
    Curl_set_in_callback(data, FALSE);
    if(st)
      goto error;
  }

  /* shortcut literal IP addresses, if we are not told to resolve them. */
  addr = convert_ipaddr_direct(hostname, port, &is_ipaddr);
  if(addr)
    goto out;

#ifndef USE_RESOLVE_ON_IPS
  /* allowed to convert, hostname is IP address, then NULL means error */
  if(is_ipaddr)
    goto error;
#endif

  /* Really need a resolver for hostname. */
  if(ip_version == CURL_IPRESOLVE_V6 && !Curl_ipv6works(data))
    goto error;

  if(!is_ipaddr &&
     (curl_strequal(hostname, "localhost") ||
      curl_strequal(hostname, "localhost.") ||
      tailmatch(hostname, hostname_len, STRCONST(".localhost")) ||
      tailmatch(hostname, hostname_len, STRCONST(".localhost.")))) {
    addr = get_localhost(port, hostname);
  }
#ifndef CURL_DISABLE_DOH
  else if(!is_ipaddr && allowDOH && data->set.doh) {
    addr = Curl_doh(data, hostname, port, ip_version, &respwait);
  }
#endif
  else {
    /* Can we provide the requested IP specifics in resolving? */
    if(!can_resolve_ip_version(data, ip_version))
      goto error;

#ifdef CURLRES_ASYNCH
    addr = Curl_async_getaddrinfo(data, hostname, port, ip_version, &respwait);
#else
    respwait = 0; /* no async waiting here */
    addr = Curl_sync_getaddrinfo(data, hostname, port, ip_version);
#endif
  }

out:
  /* We either have found a `dns` or looked up the `addr`
   * or `respwait` is set for an async operation.
   * Everything else is a failure to resolve. */
  if(dns) {
    if(!dns->addr) {
      infof(data, "Negative DNS entry");
      dns->refcount--;
      return CURLE_COULDNT_RESOLVE_HOST;
    }
    *entry = dns;
    return CURLE_OK;
  }
  else if(addr) {
    /* we got a response, create a dns entry, add to cache, return */
    dns = Curl_dnscache_mk_entry(data, addr, hostname, 0, port, FALSE);
    if(!dns)
      goto error;
    if(Curl_dnscache_add(data, dns))
      goto error;
    show_resolve_info(data, dns);
    *entry = dns;
    return CURLE_OK;
  }
  else if(respwait) {
    if(!Curl_resolv_check(data, &dns)) {
      *entry = dns;
      return dns ? CURLE_OK : CURLE_AGAIN;
    }
  }
error:
  if(dns)
    Curl_resolv_unlink(data, &dns);
  *entry = NULL;
  Curl_async_shutdown(data);
  store_negative_resolve(data, hostname, port);
  return CURLE_COULDNT_RESOLVE_HOST;
}

CURLcode Curl_resolv_blocking(struct Curl_easy *data,
                              const char *hostname,
                              int port,
                              int ip_version,
                              struct Curl_dns_entry **dnsentry)
{
  CURLcode result;

  *dnsentry = NULL;
  result = Curl_resolv(data, hostname, port, ip_version, FALSE, dnsentry);
  switch(result) {
  case CURLE_OK:
    DEBUGASSERT(*dnsentry);
    return CURLE_OK;
  case CURLE_AGAIN:
    DEBUGASSERT(!*dnsentry);
    result = Curl_async_await(data, dnsentry);
    if(result || !*dnsentry) {
      /* close the connection, since we cannot return failure here without
         cleaning up this connection properly. */
      connclose(data->conn, "async resolve failed");
    }
    return result;
  default:
    return result;
  }
}

#ifdef USE_ALARM_TIMEOUT
/*
 * This signal handler jumps back into the main libcurl code and continues
 * execution. This effectively causes the remainder of the application to run
 * within a signal handler which is nonportable and could lead to problems.
 */
CURL_NORETURN static
void alarmfunc(int sig)
{
  (void)sig;
  siglongjmp(curl_jmpenv, 1);
}
#endif /* USE_ALARM_TIMEOUT */

/*
 * Curl_resolv_timeout() is the same as Curl_resolv() but specifies a
 * timeout. This function might return immediately if we are using asynch
 * resolves. See the return codes.
 *
 * The cache entry we return will get its 'inuse' counter increased when this
 * function is used. You MUST call Curl_resolv_unlink() later (when you are
 * done using this struct) to decrease the reference counter again.
 *
 * If built with a synchronous resolver and use of signals is not
 * disabled by the application, then a nonzero timeout will cause a
 * timeout after the specified number of milliseconds. Otherwise, timeout
 * is ignored.
 *
 * Return codes:
 * CURLE_OK = success, *entry set to non-NULL
 * CURLE_AGAIN = resolving in progress, *entry == NULL
 * CURLE_COULDNT_RESOLVE_HOST = error, *entry == NULL
 * CURLE_OPERATION_TIMEDOUT = timeout expired, *entry == NULL
 */

CURLcode Curl_resolv_timeout(struct Curl_easy *data,
                             const char *hostname,
                             int port,
                             int ip_version,
                             struct Curl_dns_entry **entry,
                             timediff_t timeoutms)
{
#ifdef USE_ALARM_TIMEOUT
#ifdef HAVE_SIGACTION
  struct sigaction keep_sigact;   /* store the old struct here */
  volatile bool keep_copysig = FALSE; /* whether old sigact has been saved */
  struct sigaction sigact;
#else
#ifdef HAVE_SIGNAL
  void (*keep_sigact)(int);       /* store the old handler here */
#endif /* HAVE_SIGNAL */
#endif /* HAVE_SIGACTION */
  volatile long timeout;
  volatile unsigned int prev_alarm = 0;
#endif /* USE_ALARM_TIMEOUT */
  CURLcode result;

  *entry = NULL;

  if(timeoutms < 0)
    /* got an already expired timeout */
    return CURLE_OPERATION_TIMEDOUT;

#ifdef USE_ALARM_TIMEOUT
  if(data->set.no_signal)
    /* Ignore the timeout when signals are disabled */
    timeout = 0;
  else
    timeout = (timeoutms > LONG_MAX) ? LONG_MAX : (long)timeoutms;

  if(!timeout
#ifndef CURL_DISABLE_DOH
     || data->set.doh
#endif
    )
    /* USE_ALARM_TIMEOUT defined, but no timeout actually requested or resolve
       done using DoH */
    return Curl_resolv(data, hostname, port, ip_version, TRUE, entry);

  if(timeout < 1000) {
    /* The alarm() function only provides integer second resolution, so if
       we want to wait less than one second we must bail out already now. */
    failf(data,
        "remaining timeout of %ld too small to resolve via SIGALRM method",
        timeout);
    return CURLE_OPERATION_TIMEDOUT;
  }
  /* This allows us to time-out from the name resolver, as the timeout
     will generate a signal and we will siglongjmp() from that here.
     This technique has problems (see alarmfunc).
     This should be the last thing we do before calling Curl_resolv(),
     as otherwise we would have to worry about variables that get modified
     before we invoke Curl_resolv() (and thus use "volatile"). */
  curl_simple_lock_lock(&curl_jmpenv_lock);

  if(sigsetjmp(curl_jmpenv, 1)) {
    /* this is coming from a siglongjmp() after an alarm signal */
    failf(data, "name lookup timed out");
    result = CURLE_OPERATION_TIMEDOUT;
    goto clean_up;
  }
  else {
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
    prev_alarm = alarm(curlx_sltoui(timeout/1000L));
  }

#ifdef DEBUGBUILD
  Curl_resolve_test_delay();
#endif

#else /* !USE_ALARM_TIMEOUT */
#ifndef CURLRES_ASYNCH
  if(timeoutms)
    infof(data, "timeout on name lookup is not supported");
#else
  (void)timeoutms;
#endif
#endif /* USE_ALARM_TIMEOUT */

  /* Perform the actual name resolution. This might be interrupted by an
   * alarm if it takes too long.
   */
  result = Curl_resolv(data, hostname, port, ip_version, TRUE, entry);

#ifdef USE_ALARM_TIMEOUT
clean_up:

  if(!prev_alarm)
    /* deactivate a possibly active alarm before uninstalling the handler */
    alarm(0);

#ifdef HAVE_SIGACTION
  if(keep_copysig) {
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

  curl_simple_lock_unlock(&curl_jmpenv_lock);

  /* switch back the alarm() to either zero or to what it was before minus
     the time we spent until now! */
  if(prev_alarm) {
    /* there was an alarm() set before us, now put it back */
    timediff_t elapsed_secs = curlx_timediff(curlx_now(),
                                            data->conn->created) / 1000;

    /* the alarm period is counted in even number of seconds */
    unsigned long alarm_set = (unsigned long)(prev_alarm - elapsed_secs);

    if(!alarm_set ||
       ((alarm_set >= 0x80000000) && (prev_alarm < 0x80000000)) ) {
      /* if the alarm time-left reached zero or turned "negative" (counted
         with unsigned values), we should fire off a SIGALRM here, but we
         will not, and zero would be to switch it off so we never set it to
         less than 1! */
      alarm(1);
      result = CURLE_OPERATION_TIMEDOUT;
      failf(data, "Previous alarm fired off");
    }
    else
      alarm((unsigned int)alarm_set);
  }
#endif /* USE_ALARM_TIMEOUT */

  return result;
}

static void dnscache_entry_free(struct Curl_dns_entry *dns)
{
  Curl_freeaddrinfo(dns->addr);
#ifdef USE_HTTPSRR
  if(dns->hinfo) {
    Curl_httpsrr_cleanup(dns->hinfo);
    free(dns->hinfo);
  }
#endif
  free(dns);
}

/*
 * Curl_resolv_unlink() releases a reference to the given cached DNS entry.
 * When the reference count reaches 0, the entry is destroyed. It is important
 * that only one unlink is made for each Curl_resolv() call.
 *
 * May be called with 'data' == NULL for global cache.
 */
void Curl_resolv_unlink(struct Curl_easy *data, struct Curl_dns_entry **pdns)
{
  if(*pdns) {
    struct Curl_dnscache *dnscache = dnscache_get(data);
    struct Curl_dns_entry *dns = *pdns;
    *pdns = NULL;
    dnscache_lock(data, dnscache);
    dns->refcount--;
    if(dns->refcount == 0)
      dnscache_entry_free(dns);
    dnscache_unlock(data, dnscache);
  }
}

static void dnscache_entry_dtor(void *entry)
{
  struct Curl_dns_entry *dns = (struct Curl_dns_entry *) entry;
  DEBUGASSERT(dns && (dns->refcount > 0));
  dns->refcount--;
  if(dns->refcount == 0)
    dnscache_entry_free(dns);
}

/*
 * Curl_dnscache_init() inits a new DNS cache.
 */
void Curl_dnscache_init(struct Curl_dnscache *dns, size_t size)
{
  Curl_hash_init(&dns->entries, size, Curl_hash_str, curlx_str_key_compare,
                 dnscache_entry_dtor);
}

void Curl_dnscache_destroy(struct Curl_dnscache *dns)
{
  Curl_hash_destroy(&dns->entries);
}

CURLcode Curl_loadhostpairs(struct Curl_easy *data)
{
  struct Curl_dnscache *dnscache = dnscache_get(data);
  struct curl_slist *hostp;

  if(!dnscache)
    return CURLE_FAILED_INIT;

  /* Default is no wildcard found */
  data->state.wildcard_resolve = FALSE;

  for(hostp = data->state.resolve; hostp; hostp = hostp->next) {
    char entry_id[MAX_HOSTCACHE_LEN];
    const char *host = hostp->data;
    struct Curl_str source;
    if(!host)
      continue;
    if(*host == '-') {
      curl_off_t num = 0;
      size_t entry_len;
      host++;
      if(!curlx_str_single(&host, '[')) {
        if(curlx_str_until(&host, &source, MAX_IPADR_LEN, ']') ||
           curlx_str_single(&host, ']') ||
           curlx_str_single(&host, ':'))
          continue;
      }
      else {
        if(curlx_str_until(&host, &source, 4096, ':') ||
           curlx_str_single(&host, ':')) {
          continue;
        }
      }

      if(!curlx_str_number(&host, &num, 0xffff)) {
        /* Create an entry id, based upon the hostname and port */
        entry_len = create_dnscache_id(curlx_str(&source),
                                       curlx_strlen(&source), (int)num,
                                       entry_id, sizeof(entry_id));
        dnscache_lock(data, dnscache);
        /* delete entry, ignore if it did not exist */
        Curl_hash_delete(&dnscache->entries, entry_id, entry_len + 1);
        dnscache_unlock(data, dnscache);
      }
    }
    else {
      struct Curl_dns_entry *dns;
      struct Curl_addrinfo *head = NULL, *tail = NULL;
      size_t entry_len;
      char address[64];
#ifndef CURL_DISABLE_VERBOSE_STRINGS
      const char *addresses = NULL;
#endif
      curl_off_t port = 0;
      bool permanent = TRUE;
      bool error = TRUE;

      if(*host == '+') {
        host++;
        permanent = FALSE;
      }
      if(!curlx_str_single(&host, '[')) {
        if(curlx_str_until(&host, &source, MAX_IPADR_LEN, ']') ||
           curlx_str_single(&host, ']'))
          continue;
      }
      else {
        if(curlx_str_until(&host, &source, 4096, ':'))
          continue;
      }
      if(curlx_str_single(&host, ':') ||
         curlx_str_number(&host, &port, 0xffff) ||
         curlx_str_single(&host, ':'))
        goto err;

#ifndef CURL_DISABLE_VERBOSE_STRINGS
      addresses = host;
#endif

      /* start the address section */
      while(*host) {
        struct Curl_str target;
        struct Curl_addrinfo *ai;

        if(!curlx_str_single(&host, '[')) {
          if(curlx_str_until(&host, &target, MAX_IPADR_LEN, ']') ||
             curlx_str_single(&host, ']'))
            goto err;
        }
        else {
          if(curlx_str_until(&host, &target, 4096, ',')) {
            if(curlx_str_single(&host, ','))
              goto err;
            /* survive nothing but just a comma */
            continue;
          }
        }
#ifndef USE_IPV6
        if(memchr(target.str, ':', target.len)) {
          infof(data, "Ignoring resolve address '%s', missing IPv6 support.",
                address);
          if(curlx_str_single(&host, ','))
            goto err;
          continue;
        }
#endif

        if(curlx_strlen(&target) >= sizeof(address))
          goto err;

        memcpy(address, curlx_str(&target), curlx_strlen(&target));
        address[curlx_strlen(&target)] = '\0';

        ai = Curl_str2addr(address, (int)port);
        if(!ai) {
          infof(data, "Resolve address '%s' found illegal", address);
          goto err;
        }

        if(tail) {
          tail->ai_next = ai;
          tail = tail->ai_next;
        }
        else {
          head = tail = ai;
        }
        if(curlx_str_single(&host, ','))
          break;
      }

      if(!head)
        goto err;

      error = FALSE;
err:
      if(error) {
        failf(data, "Couldn't parse CURLOPT_RESOLVE entry '%s'",
              hostp->data);
        Curl_freeaddrinfo(head);
        return CURLE_SETOPT_OPTION_SYNTAX;
      }

      /* Create an entry id, based upon the hostname and port */
      entry_len = create_dnscache_id(curlx_str(&source), curlx_strlen(&source),
                                     (int)port,
                                     entry_id, sizeof(entry_id));

      dnscache_lock(data, dnscache);

      /* See if it is already in our dns cache */
      dns = Curl_hash_pick(&dnscache->entries, entry_id, entry_len + 1);

      if(dns) {
        infof(data, "RESOLVE %.*s:%" CURL_FORMAT_CURL_OFF_T
              " - old addresses discarded", (int)curlx_strlen(&source),
              curlx_str(&source), port);
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

        Curl_hash_delete(&dnscache->entries, entry_id, entry_len + 1);
      }

      /* put this new host in the cache */
      dns = dnscache_add_addr(data, dnscache, head, curlx_str(&source),
                              curlx_strlen(&source), (int)port, permanent);
      if(dns) {
        /* release the returned reference; the cache itself will keep the
         * entry alive: */
        dns->refcount--;
      }

      dnscache_unlock(data, dnscache);

      if(!dns)
        return CURLE_OUT_OF_MEMORY;

#ifndef CURL_DISABLE_VERBOSE_STRINGS
      infof(data, "Added %.*s:%" CURL_FORMAT_CURL_OFF_T ":%s to DNS cache%s",
            (int)curlx_strlen(&source), curlx_str(&source), port, addresses,
            permanent ? "" : " (non-permanent)");
#endif

      /* Wildcard hostname */
      if(curlx_str_casecompare(&source, "*")) {
        infof(data, "RESOLVE *:%" CURL_FORMAT_CURL_OFF_T " using wildcard",
              port);
        data->state.wildcard_resolve = TRUE;
      }
    }
  }
  data->state.resolve = NULL; /* dealt with now */

  return CURLE_OK;
}

#ifndef CURL_DISABLE_VERBOSE_STRINGS
static void show_resolve_info(struct Curl_easy *data,
                              struct Curl_dns_entry *dns)
{
  struct Curl_addrinfo *a;
  CURLcode result = CURLE_OK;
#ifdef CURLRES_IPV6
  struct dynbuf out[2];
#else
  struct dynbuf out[1];
#endif
  DEBUGASSERT(data);
  DEBUGASSERT(dns);

  if(!data->set.verbose ||
     /* ignore no name or numerical IP addresses */
     !dns->hostname[0] || Curl_host_is_ipnum(dns->hostname))
    return;

  a = dns->addr;

  infof(data, "Host %s:%d was resolved.",
        (dns->hostname[0] ? dns->hostname : "(none)"), dns->hostport);

  curlx_dyn_init(&out[0], 1024);
#ifdef CURLRES_IPV6
  curlx_dyn_init(&out[1], 1024);
#endif

  while(a) {
    if(
#ifdef CURLRES_IPV6
       a->ai_family == PF_INET6 ||
#endif
       a->ai_family == PF_INET) {
      char buf[MAX_IPADR_LEN];
      struct dynbuf *d = &out[(a->ai_family != PF_INET)];
      Curl_printable_address(a, buf, sizeof(buf));
      if(curlx_dyn_len(d))
        result = curlx_dyn_addn(d, ", ", 2);
      if(!result)
        result = curlx_dyn_add(d, buf);
      if(result) {
        infof(data, "too many IP, cannot show");
        goto fail;
      }
    }
    a = a->ai_next;
  }

#ifdef CURLRES_IPV6
  infof(data, "IPv6: %s",
        (curlx_dyn_len(&out[1]) ? curlx_dyn_ptr(&out[1]) : "(none)"));
#endif
  infof(data, "IPv4: %s",
        (curlx_dyn_len(&out[0]) ? curlx_dyn_ptr(&out[0]) : "(none)"));

fail:
  curlx_dyn_free(&out[0]);
#ifdef CURLRES_IPV6
  curlx_dyn_free(&out[1]);
#endif
}
#endif

#ifdef USE_CURL_ASYNC
CURLcode Curl_resolv_check(struct Curl_easy *data,
                           struct Curl_dns_entry **dns)
{
  CURLcode result;

  /* If async resolving is ongoing, this must be set */
  if(!data->state.async.hostname)
    return CURLE_FAILED_INIT;

  /* check if we have the name resolved by now (from someone else) */
  *dns = Curl_dnscache_get(data, data->state.async.hostname,
                           data->state.async.port,
                           data->state.async.ip_version);
  if(*dns) {
    /* Tell a possibly async resolver we no longer need the results. */
    infof(data, "Hostname '%s' was found in DNS cache",
          data->state.async.hostname);
    Curl_async_shutdown(data);
    data->state.async.dns = *dns;
    data->state.async.done = TRUE;
    return CURLE_OK;
  }

#ifndef CURL_DISABLE_DOH
  if(data->conn->bits.doh) {
    result = Curl_doh_is_resolved(data, dns);
    if(result)
      Curl_resolver_error(data, NULL);
  }
  else
#endif
  result = Curl_async_is_resolved(data, dns);
  if(*dns)
    show_resolve_info(data, *dns);
  if(result)
    store_negative_resolve(data, data->state.async.hostname,
                           data->state.async.port);
  return result;
}
#endif

CURLcode Curl_resolv_pollset(struct Curl_easy *data,
                             struct easy_pollset *ps)
{
#ifdef CURLRES_ASYNCH
#ifndef CURL_DISABLE_DOH
  if(data->conn->bits.doh)
    /* nothing to wait for during DoH resolve, those handles have their own
       sockets */
    return CURLE_OK;
#endif
  return Curl_async_pollset(data, ps);
#else
  (void)data;
  (void)ps;
  return CURLE_OK;
#endif
}

/* Call this function after Curl_connect() has returned async=TRUE and
   then a successful name resolve has been received.

   Note: this function disconnects and frees the conn data in case of
   resolve failure */
CURLcode Curl_once_resolved(struct Curl_easy *data,
                            struct Curl_dns_entry *dns,
                            bool *protocol_done)
{
  CURLcode result;
  struct connectdata *conn = data->conn;

#ifdef USE_CURL_ASYNC
  if(data->state.async.dns) {
    DEBUGASSERT(data->state.async.dns == dns);
    data->state.async.dns = NULL;
  }
#endif

  result = Curl_setup_conn(data, dns, protocol_done);

  if(result) {
    Curl_detach_connection(data);
    Curl_conn_terminate(data, conn, TRUE);
  }
  return result;
}

/*
 * Curl_resolver_error() calls failf() with the appropriate message after a
 * resolve error
 */

#ifdef USE_CURL_ASYNC
CURLcode Curl_resolver_error(struct Curl_easy *data, const char *detail)
{
  struct connectdata *conn = data->conn;
  const char *host_or_proxy = "host";
  const char *name = conn->host.dispname;
  CURLcode result = CURLE_COULDNT_RESOLVE_HOST;

#ifndef CURL_DISABLE_PROXY
  if(conn->bits.proxy) {
    host_or_proxy = "proxy";
    result = CURLE_COULDNT_RESOLVE_PROXY;
    name = conn->socks_proxy.host.name ? conn->socks_proxy.host.dispname :
      conn->http_proxy.host.dispname;
  }
#endif

  failf(data, "Could not resolve %s: %s%s%s%s", host_or_proxy, name,
        detail ? " (" : "", detail ? detail : "", detail ? ")" : "");
  return result;
}
#endif /* USE_CURL_ASYNC */

#ifdef DEBUGBUILD
#include "curlx/wait.h"

void Curl_resolve_test_delay(void)
{
  const char *p = getenv("CURL_DNS_DELAY_MS");
  if(p) {
    curl_off_t l;
    if(!curlx_str_number(&p, &l, TIME_T_MAX) && l) {
      curlx_wait_ms((timediff_t)l);
    }
  }
}
#endif
