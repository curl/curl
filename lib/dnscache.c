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

#include "urldata.h"
#include "curl_addrinfo.h"
#include "curl_share.h"
#include "curl_trc.h"
#include "dnscache.h"
#include "hash.h"
#include "httpsrr.h"
#include "progress.h"
#include "rand.h"
#include "strcase.h"
#include "curlx/inet_ntop.h"
#include "curlx/inet_pton.h"
#include "curlx/strcopy.h"
#include "curlx/strparse.h"

#define MAX_HOSTCACHE_LEN (255 + 7) /* max FQDN + colon + port number + zero */

#define MAX_DNS_CACHE_SIZE 29999

#ifdef CURLVERBOSE
static const char *dnscache_ipv_str(uint8_t ip_version)
{
  switch(ip_version) {
  case CURL_IPRESOLVE_WHATEVER:
    return "A+AAAA";
  case CURL_IPRESOLVE_V4:
    return "A";
#ifdef PF_INET6
  case CURL_IPRESOLVE_V6:
    return "AAAA";
#endif
  default:
    DEBUGASSERT(0);
    return "???";
  }
}
#endif

static void dnscache_entry_free(struct Curl_dns_entry *dns)
{
  Curl_freeaddrinfo(dns->addr);
#ifdef USE_HTTPSRR
  if(dns->hinfo) {
    Curl_httpsrr_cleanup(dns->hinfo);
    curlx_free(dns->hinfo);
  }
#endif
  curlx_free(dns);
}

/*
 * Create a hostcache id string for the provided host + port, to be used by
 * the DNS caching. Without alloc. Return length of the id string.
 */
static size_t create_dnscache_id(const char *name,
                                 size_t nlen, /* 0 or actual name length */
                                 uint16_t port, char *ptr, size_t buflen)
{
  size_t len = nlen ? nlen : strlen(name);
  DEBUGASSERT(buflen >= MAX_HOSTCACHE_LEN);
  if(len > (buflen - 7))
    len = buflen - 7;
  /* store and lower case the name */
  Curl_strntolower(ptr, name, len);
  return curl_msnprintf(&ptr[len], 7, ":%u", port) + len;
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
static int dnscache_entry_is_stale(void *datap, void *hc)
{
  struct dnscache_prune_data *prune = (struct dnscache_prune_data *)datap;
  struct Curl_dns_entry *dns = (struct Curl_dns_entry *)hc;

  if(dns->timestamp.tv_sec || dns->timestamp.tv_usec) {
    /* get age in milliseconds */
    timediff_t age = curlx_ptimediff_ms(&prune->now, &dns->timestamp);
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
static timediff_t dnscache_prune(struct Curl_hash *hostcache,
                                 timediff_t cache_timeout_ms,
                                 struct curltime now)
{
  struct dnscache_prune_data user;

  user.max_age_ms = cache_timeout_ms;
  user.now = now;
  user.oldest_ms = 0;

  Curl_hash_clean_with_criterium(hostcache,
                                 (void *)&user,
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
  /* This is not completely sane. Due to the flexibility of easy handle
   * having shares, different shares or none, we can run into situations
   * where we update `Curl_dns_entry`s that once originated from a shared
   * cache into multiple threads but we no longer have a way to use
   * a common lock again. */
  if(data->share && ((dnscache == &data->share->dnscache) || !dnscache))
    Curl_share_lock(data, CURL_LOCK_DATA_DNS, CURL_LOCK_ACCESS_SINGLE);
}

static void dnscache_unlock(struct Curl_easy *data,
                            struct Curl_dnscache *dnscache)
{
  if(data->share && ((dnscache == &data->share->dnscache) || !dnscache))
    Curl_share_unlock(data, CURL_LOCK_DATA_DNS);
}

/*
 * Library-wide function for pruning the DNS cache. This function takes and
 * returns the appropriate locks.
 */
void Curl_dnscache_prune(struct Curl_easy *data)
{
  struct Curl_dnscache *dnscache = dnscache_get(data);
  /* the timeout may be set -1 (forever) */
  timediff_t timeout_ms = data->set.dns_cache_timeout_ms;

  if(!dnscache || (timeout_ms == -1))
    /* NULL hostcache means we cannot do it */
    return;

  dnscache_lock(data, dnscache);

  do {
    /* Remove outdated and unused entries from the hostcache */
    timediff_t oldest_ms =
      dnscache_prune(&dnscache->entries, timeout_ms, *Curl_pgrs_now(data));

    if(Curl_hash_count(&dnscache->entries) > MAX_DNS_CACHE_SIZE)
      /* prune the ones over half this age */
      timeout_ms = oldest_ms / 2;
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

/* lookup address, returns entry if found and not stale */
static CURLcode fetch_addr(struct Curl_easy *data,
                           struct Curl_dnscache *dnscache,
                           const char *hostname,
                           uint16_t port,
                           uint8_t ip_version,
                           struct Curl_dns_entry **pdns)
{
  struct Curl_dns_entry *dns = NULL;
  char entry_id[MAX_HOSTCACHE_LEN];
  size_t entry_len;
  CURLcode result = CURLE_OK;

  *pdns = NULL;
  if(!dnscache)
    return CURLE_OK;

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

    user.now = *Curl_pgrs_now(data);
    user.max_age_ms = data->set.dns_cache_timeout_ms;
    user.oldest_ms = 0;

    if(dnscache_entry_is_stale(&user, dns)) {
      infof(data, "Hostname in DNS cache was stale, zapped");
      dns = NULL; /* the memory deallocation is being handled by the hash */
      Curl_hash_delete(&dnscache->entries, entry_id, entry_len + 1);
    }
  }

  if(dns && dns->ip_version != ip_version) {
    switch(dns->ip_version) {
    case CURL_IPRESOLVE_WHATEVER: {
      /* Do we have addresses that match the requested ip version? */
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
        /* We assume that CURL_IPRESOLVE_WHATEVER means we tried to
         * get addresses for all supported types, but there are none
         * for the ip version we need. This is a negative resolve. */
        CURL_TRC_DNS(data, "cache entry does not have type=%s addresses",
                     dnscache_ipv_str(ip_version));
        dns = NULL;
        result = CURLE_COULDNT_RESOLVE_HOST;
      }
      break;
    }
    default:
      /* different families, we return NULL + OK, so a new resolve
       * attempt may get started. */
      dns = NULL;
      break;
    }
  }

  if(dns && !dns->addr) { /* negative entry */
    dns = NULL;
    result = CURLE_COULDNT_RESOLVE_HOST;
  }
  *pdns = dns;
  return result;
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
 * The returned data *MUST* be "released" with Curl_dns_entry_unlink() after
 * use, or we will leak memory!
 */
CURLcode Curl_dnscache_get(struct Curl_easy *data,
                           const char *hostname,
                           uint16_t port,
                           uint8_t ip_version,
                           struct Curl_dns_entry **pentry)
{
  struct Curl_dnscache *dnscache = dnscache_get(data);
  struct Curl_dns_entry *dns = NULL;
  CURLcode result = CURLE_OK;

  if(dnscache) {
    dnscache_lock(data, dnscache);
    result = fetch_addr(data, dnscache, hostname, port, ip_version, &dns);
    if(!result && dns)
      dns->refcount++; /* we pass out a reference */
    else if(result) {
      DEBUGASSERT(!dns);
      dns = NULL;
    }
    dnscache_unlock(data, dnscache);
  }
  *pentry = dns;
  return result;
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
    CURL_TRC_DNS(data, "Shuffling %i addresses", num_addrs);

    nodes = curlx_malloc(num_addrs * sizeof(*nodes));
    if(nodes) {
      int i;
      unsigned int *rnd;
      const size_t rnd_size = num_addrs * sizeof(*rnd);

      /* build a plain array of Curl_addrinfo pointers */
      nodes[0] = *addr;
      for(i = 1; i < num_addrs; i++) {
        nodes[i] = nodes[i - 1]->ai_next;
      }

      rnd = curlx_malloc(rnd_size);
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
            nodes[i - 1]->ai_next = nodes[i];
          }

          nodes[num_addrs - 1]->ai_next = NULL;
          *addr = nodes[0];
        }
        curlx_free(rnd);
      }
      else
        result = CURLE_OUT_OF_MEMORY;
      curlx_free(nodes);
    }
    else
      result = CURLE_OUT_OF_MEMORY;
  }
  return result;
}
#endif

static struct Curl_dns_entry *
dnscache_entry_create(struct Curl_easy *data,
                      struct Curl_dnscache *cache,
                      struct Curl_addrinfo **paddr,
                      const char *hostname,
                      size_t hostlen, /* length or zero */
                      uint16_t port,
                      uint8_t ip_version,
                      bool permanent)
{
  struct Curl_dns_entry *dns = NULL;

#ifndef CURL_DISABLE_SHUFFLE_DNS
  /* shuffle addresses if requested */
  if(data->set.dns_shuffle_addresses && paddr) {
    CURLcode result = Curl_shuffle_addr(data, paddr);
    if(result)
      goto out;
  }
#else
  (void)data;
#endif
  if(!hostlen)
    hostlen = strlen(hostname);

  /* Create a new cache entry */
  dns = curlx_calloc(1, sizeof(struct Curl_dns_entry) + hostlen);
  if(!dns)
    goto out;

  dns->cache = cache;
  dns->refcount = 1; /* the cache has the first reference */
  dns->addr = paddr ? *paddr : NULL; /* this is the address(es) */
  if(permanent) {
    dns->timestamp.tv_sec = 0; /* an entry that never goes stale */
    dns->timestamp.tv_usec = 0; /* an entry that never goes stale */
  }
  else {
    dns->timestamp = *Curl_pgrs_now(data);
  }
  dns->port = port;
  dns->ip_version = ip_version;
  if(hostlen)
    memcpy(dns->hostname, hostname, hostlen);

out:
  if(paddr) {
    if(!dns)
      Curl_freeaddrinfo(*paddr);
    *paddr = NULL;
  }
  return dns;
}

struct Curl_dns_entry *
Curl_dns_entry_create(struct Curl_easy *data,
                      struct Curl_addrinfo **paddr,
                      const char *hostname,
                      uint16_t port,
                      uint8_t ip_version)
{
  return dnscache_entry_create(data, NULL, paddr, hostname, 0,
                               port, ip_version, FALSE);
}

static struct Curl_dns_entry *
dnscache_add_addr(struct Curl_easy *data,
                  struct Curl_dnscache *dnscache,
                  struct Curl_addrinfo **paddr,
                  const char *hostname,
                  size_t hlen, /* length or zero */
                  uint16_t port,
                  uint8_t ip_version,
                  bool permanent)
{
  char entry_id[MAX_HOSTCACHE_LEN];
  size_t entry_len;
  struct Curl_dns_entry *dns;
  struct Curl_dns_entry *dns2;

  dns = dnscache_entry_create(data, dnscache, paddr, hostname, hlen, port,
                              ip_version, permanent);
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
  /* If entry is from another cache, do not add here. This would
   * only be asking for trouble. Ignore add instead. */
  if(entry->cache && (entry->cache != dnscache))
    return CURLE_OK;

  /* Create an entry id, based upon the hostname and port */
  idlen = create_dnscache_id(entry->hostname, 0, entry->port, id, sizeof(id));

  /* Store the resolved data in our DNS cache and up ref count */
  dnscache_lock(data, dnscache);
  if(!Curl_hash_add(&dnscache->entries, id, idlen + 1, (void *)entry)) {
    dnscache_unlock(data, dnscache);
    return CURLE_OUT_OF_MEMORY;
  }
  entry->refcount++;
  if(!entry->cache)
    entry->cache = dnscache; /* now owned in this cache */
  dnscache_unlock(data, dnscache);
  return CURLE_OK;
}

CURLcode Curl_dnscache_add_negative(struct Curl_easy *data,
                                    const char *host,
                                    uint16_t port,
                                    uint8_t ip_version)
{
  struct Curl_dnscache *dnscache = dnscache_get(data);
  struct Curl_dns_entry *dns;
  DEBUGASSERT(dnscache);
  if(!dnscache)
    return CURLE_FAILED_INIT;

  /* put this new host in the cache */
  dns = dnscache_add_addr(data, dnscache, NULL, host, 0,
                          port, ip_version, FALSE);
  if(dns) {
    /* release the returned reference; the cache itself will keep the
     * entry alive: */
    dns->refcount--;
    CURL_TRC_DNS(data, "cache negative name resolve for %s:%d type=%s",
                 host, port, dnscache_ipv_str(ip_version));
    return CURLE_OK;
  }
  return CURLE_OUT_OF_MEMORY;
}

struct Curl_dns_entry *Curl_dns_entry_link(struct Curl_easy *data,
                                           struct Curl_dns_entry *dns)
{
  if(!dns)
    return NULL;
  else {
    dnscache_lock(data, dns->cache);
    dns->refcount++;
    dnscache_unlock(data, dns->cache);
    return dns;
  }
}

/*
 * Curl_dns_entry_unlink() releases a reference to the given cached DNS entry.
 * When the reference count reaches 0, the entry is destroyed. It is important
 * that only one unlink is made for each Curl_resolv() call.
 *
 * May be called with 'data' == NULL for global cache.
 */
void Curl_dns_entry_unlink(struct Curl_easy *data,
                           struct Curl_dns_entry **pdns)
{
  if(*pdns) {
    struct Curl_dns_entry *dns = *pdns;
    struct Curl_dnscache *dnscache = dns ? dns->cache : NULL;
    *pdns = NULL;
    dnscache_lock(data, dnscache);
    dns->refcount--;
    if(dns->refcount == 0)
      dnscache_entry_free(dns);
    dnscache_unlock(data, dnscache);
  }
}

/* Destructor called from the hash when it removes elements */
static void dnscache_entry_dtor(void *entry)
{
  struct Curl_dns_entry *dns = (struct Curl_dns_entry *)entry;
  DEBUGASSERT(dns && (dns->refcount > 0));
  dns->refcount--;
  if(dns->refcount == 0)
    dnscache_entry_free(dns);
  else { /* entry is linked to in other places, connections most likely */
    dns->cache = NULL;
  }
}

/*
 * Curl_dnscache_init() inits a new DNS cache.
 */
void Curl_dnscache_init(struct Curl_dnscache *cache, size_t size)
{
  Curl_hash_init(&cache->entries, size, Curl_hash_str, curlx_str_key_compare,
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
                                       curlx_strlen(&source), (uint16_t)num,
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
      curl_off_t tmpofft = 0;
      uint16_t port = 0;
      bool permanent = TRUE;
      bool error = TRUE;
      VERBOSE(const char *addresses = NULL);

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
         curlx_str_number(&host, &tmpofft, 0xffff) ||
         curlx_str_single(&host, ':'))
        goto err;
      port = (uint16_t)tmpofft;

      VERBOSE(addresses = host);

      /* start the address section */
      while(*host) {
        struct Curl_str target;
        struct Curl_addrinfo *ai;
        CURLcode result;

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
        if(memchr(curlx_str(&target), ':', curlx_strlen(&target))) {
          infof(data, "Ignoring resolve address '%.*s', missing IPv6 support.",
                (int)curlx_strlen(&target), curlx_str(&target));
          if(curlx_str_single(&host, ','))
            goto err;
          continue;
        }
#endif

        if(curlx_strlen(&target) >= sizeof(address))
          goto err;

        memcpy(address, curlx_str(&target), curlx_strlen(&target));
        address[curlx_strlen(&target)] = '\0';

        result = Curl_str2addr(address, port, &ai);
        if(result) {
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
        failf(data, "Could not parse CURLOPT_RESOLVE entry '%s'", hostp->data);
        Curl_freeaddrinfo(head);
        return CURLE_SETOPT_OPTION_SYNTAX;
      }

      /* Create an entry id, based upon the hostname and port */
      entry_len = create_dnscache_id(curlx_str(&source), curlx_strlen(&source),
                                     port, entry_id, sizeof(entry_id));

      dnscache_lock(data, dnscache);

      /* See if it is already in our dns cache */
      dns = Curl_hash_pick(&dnscache->entries, entry_id, entry_len + 1);

      if(dns) {
        infof(data, "RESOLVE %.*s:%u - old addresses discarded",
              (int)curlx_strlen(&source),
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
      dns = dnscache_add_addr(data, dnscache, &head, curlx_str(&source),
                              curlx_strlen(&source), port,
                              CURL_IPRESOLVE_WHATEVER, permanent);
      if(dns)
        /* release the returned reference; the cache itself will keep the
         * entry alive: */
        dns->refcount--;

      dnscache_unlock(data, dnscache);

      if(!dns)
        return CURLE_OUT_OF_MEMORY;

      infof(data, "Added %.*s:%u:%s to DNS cache%s",
            (int)curlx_strlen(&source), curlx_str(&source), port, addresses,
            permanent ? "" : " (non-permanent)");

      /* Wildcard hostname */
      if(curlx_str_casecompare(&source, "*")) {
        infof(data, "RESOLVE *:%u using wildcard", port);
        data->state.wildcard_resolve = TRUE;
      }
    }
  }
  data->state.resolve = NULL; /* dealt with now */

  return CURLE_OK;
}
