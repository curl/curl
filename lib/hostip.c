/***************************************************************************
 *                                  _   _ ____  _     
 *  Project                     ___| | | |  _ \| |    
 *                             / __| | | | |_) | |    
 *                            | (__| |_| |  _ <| |___ 
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) 1998 - 2003, Daniel Stenberg, <daniel@haxx.se>, et al.
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

#include "setup.h"

#include <string.h>
#include <errno.h>

#define _REENTRANT

#if defined(WIN32) && !defined(__GNUC__) || defined(__MINGW32__)
#include <malloc.h>
#else
#ifdef HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif
#ifdef HAVE_SYS_SOCKET_H
#include <sys/socket.h>
#endif
#ifdef HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif
#ifdef HAVE_NETDB_H
#include <netdb.h>
#endif
#ifdef HAVE_ARPA_INET_H
#include <arpa/inet.h>
#endif
#ifdef HAVE_STDLIB_H
#include <stdlib.h>	/* required for free() prototypes */
#endif
#ifdef	VMS
#include <in.h>
#include <inet.h>
#include <stdlib.h>
#endif
#endif

#ifdef HAVE_SETJMP_H
#include <setjmp.h>
#endif

#include "urldata.h"
#include "sendf.h"
#include "hostip.h"
#include "hash.h"
#include "share.h"
#include "url.h"

#define _MPRINTF_REPLACE /* use our functions only */
#include <curl/mprintf.h>

#if defined(HAVE_INET_NTOA_R) && !defined(HAVE_INET_NTOA_R_DECL)
#include "inet_ntoa_r.h"
#endif

/* The last #include file should be: */
#ifdef CURLDEBUG
#include "memdebug.h"
#endif

static curl_hash hostname_cache;
static int host_cache_initialized;

static Curl_addrinfo *my_getaddrinfo(struct connectdata *conn,
                                     char *hostname,
                                     int port,
                                     int *waitp);
#if !defined(HAVE_GETHOSTBYNAME_R) || defined(USE_ARES)
static struct hostent* pack_hostent(char** buf, struct hostent* orig);
#endif

void Curl_global_host_cache_init(void)
{
  if (!host_cache_initialized) {
    Curl_hash_init(&hostname_cache, 7, Curl_freednsinfo);
    host_cache_initialized = 1;
  }
}

curl_hash *Curl_global_host_cache_get(void)
{
  return &hostname_cache;
}

void Curl_global_host_cache_dtor(void)
{
  if (host_cache_initialized) {
    Curl_hash_clean(&hostname_cache);
    host_cache_initialized = 0;
  }
}

/* count the number of characters that an integer takes up */
static int _num_chars(int i)
{
  int chars = 0;

  /* While the number divided by 10 is greater than one, 
   * re-divide the number by 10, and increment the number of 
   * characters by 1.
   *
   * this relies on the fact that for every multiple of 10, 
   * a new digit is added onto every number
   */
  do {
    chars++;

    i = (int) i / 10;
  } while (i >= 1);

  return chars;
}

/* Create a hostcache id */
static char *
create_hostcache_id(char *server, int port, ssize_t *entry_len)
{
  char *id = NULL;

  /* Get the length of the new entry id */
  *entry_len = *entry_len + /* Hostname length */
    1 +                     /* ':' seperator */
    _num_chars(port);       /* number of characters the port will take up */
  
  /* Allocate the new entry id */
  id = malloc(*entry_len + 1);
  if (!id)
    return NULL;

  /* Create the new entry */
  /* If sprintf() doesn't return the entry length, that signals failure */
  if (sprintf(id, "%s:%d", server, port) != *entry_len) {
    /* Free the allocated id, set length to zero and return NULL */
    *entry_len = 0;
    free(id);
    return NULL;
  }

  return id;
}

struct hostcache_prune_data {
  int cache_timeout;
  int now;
};

static int
hostcache_timestamp_remove(void *datap, void *hc)
{
  struct hostcache_prune_data *data = 
    (struct hostcache_prune_data *) datap;
  struct Curl_dns_entry *c = (struct Curl_dns_entry *) hc;
  
  if ((data->now - c->timestamp < data->cache_timeout) ||
      c->inuse) {
    /* please don't remove */
    return 0;
  }
  
  /* fine, remove */
  return 1;
}

static void
hostcache_prune(curl_hash *hostcache, int cache_timeout, int now)
{
  struct hostcache_prune_data user;

  user.cache_timeout = cache_timeout;
  user.now = now;
  
  Curl_hash_clean_with_criterium(hostcache, 
                                 (void *) &user, 
                                 hostcache_timestamp_remove);
}

#ifdef HAVE_SIGSETJMP
/* Beware this is a global and unique instance */
sigjmp_buf curl_jmpenv;
#endif


/* When calling Curl_resolv() has resulted in a response with a returned
   address, we call this function to store the information in the dns
   cache etc */

static struct Curl_dns_entry *
cache_resolv_response(struct SessionHandle *data,
                      Curl_addrinfo *addr,
                      char *hostname,
                      int port)
{
  char *entry_id;
  ssize_t entry_len;
  struct Curl_dns_entry *dns;
  time_t now;

  /* Create an entry id, based upon the hostname and port */
  entry_len = strlen(hostname);
  entry_id = create_hostcache_id(hostname, port, &entry_len);
  /* If we can't create the entry id, fail */
  if (!entry_id)
    return NULL;

  /* Create a new cache entry */
  dns = (struct Curl_dns_entry *) malloc(sizeof(struct Curl_dns_entry));
  if (!dns) {
    Curl_freeaddrinfo(addr);
    free(entry_id);
    return NULL;
  }

  dns->inuse = 0;   /* init to not used */
  dns->addr = addr; /* this is the address(es) */

  /* Store the resolved data in our DNS cache. This function may return a
     pointer to an existing struct already present in the hash, and it may
     return the same argument we pass in. Make no assumptions. */
  dns = Curl_hash_add(data->hostcache, entry_id, entry_len+1, (void *) dns);
  if(!dns) {
    /* major badness, run away! */
    Curl_freeaddrinfo(addr);
    free(entry_id);
    return NULL;
  }
  time(&now);

  dns->timestamp = now; /* used now */
  dns->inuse++;         /* mark entry as in-use */

    
  /* Remove outdated and unused entries from the hostcache */
  hostcache_prune(data->hostcache, 
                  data->set.dns_cache_timeout, 
                  now);

  /* free the allocated entry_id again */
  free(entry_id);

  return dns;
}

/* Resolve a name and return a pointer in the 'entry' argument if one
   is available.

   Return codes:

   -1 = error, no pointer
   0 = OK, pointer provided
   1 = waiting for response, no pointer
*/
int Curl_resolv(struct connectdata *conn,
                char *hostname,
                int port,
                struct Curl_dns_entry **entry)
{
  char *entry_id = NULL;
  struct Curl_dns_entry *dns = NULL;
  ssize_t entry_len;
  int wait;
  struct SessionHandle *data = conn->data;

  /* default to failure */
  int rc = -1;
  *entry = NULL;

#ifdef HAVE_SIGSETJMP
  /* this allows us to time-out from the name resolver, as the timeout
     will generate a signal and we will siglongjmp() from that here */
  if(!data->set.no_signal && sigsetjmp(curl_jmpenv, 1)) {
    /* this is coming from a siglongjmp() */
    failf(data, "name lookup timed out");
    return -1;
  }
#endif

  /* Create an entry id, based upon the hostname and port */
  entry_len = strlen(hostname);
  entry_id = create_hostcache_id(hostname, port, &entry_len);
  /* If we can't create the entry id, fail */
  if (!entry_id)
    return -1;

  if(data->share)
    Curl_share_lock(data, CURL_LOCK_DATA_DNS, CURL_LOCK_ACCESS_SINGLE);

  /* See if its already in our dns cache */
  dns = Curl_hash_pick(data->hostcache, entry_id, entry_len+1);
  
  if(data->share)
    Curl_share_unlock(data, CURL_LOCK_DATA_DNS);

  /* free the allocated entry_id again */
  free(entry_id);

  if (!dns) {
    /* The entry was not in the cache. Resolve it to IP address */
      
    /* If my_getaddrinfo() returns NULL, 'wait' might be set to a non-zero
       value indicating that we need to wait for the response to the resolve
       call */
    Curl_addrinfo *addr = my_getaddrinfo(conn, hostname, port, &wait);
    
    if (!addr) {
      if(wait) {
        /* the response to our resolve call will come asynchronously at 
           a later time, good or bad */
        /* First, check that we haven't received the info by now */
        (void)Curl_is_resolved(conn, &dns);
        if(dns)
          rc = 0; /* pointer provided */
        else
          rc = 1; /* no info yet */
      }
    }
    else
    {
      if(data->share)
        Curl_share_lock(data, CURL_LOCK_DATA_DNS, CURL_LOCK_ACCESS_SINGLE);

      /* we got a response, store it in the cache */
      dns = cache_resolv_response(data, addr, hostname, port);
      
      if(data->share)
        Curl_share_unlock(data, CURL_LOCK_DATA_DNS);

      if(!dns) {
        /* returned failure, bail out nicely */
        Curl_freeaddrinfo(addr);
      }
    }
  }


  *entry = dns;

  return rc;
}

void Curl_resolv_unlock(struct SessionHandle *data, struct Curl_dns_entry *dns)
{
  if(data->share)
    Curl_share_lock(data, CURL_LOCK_DATA_DNS, CURL_LOCK_ACCESS_SINGLE);

  dns->inuse--;

  if(data->share)
    Curl_share_unlock(data, CURL_LOCK_DATA_DNS);

}

/*
 * This is a wrapper function for freeing name information in a protocol
 * independent way. This takes care of using the appropriate underlaying
 * function.
 */
void Curl_freeaddrinfo(Curl_addrinfo *p)
{
#ifdef ENABLE_IPV6
  freeaddrinfo(p);
#else
  free(p); /* works fine for the ARES case too */
#endif
}

/*
 * Free a cache dns entry.
 */
void Curl_freednsinfo(void *freethis)
{
  struct Curl_dns_entry *p = (struct Curl_dns_entry *) freethis;

  Curl_freeaddrinfo(p->addr);

  free(p);
}

/* --- resolve name or IP-number --- */

/* Allocate enough memory to hold the full name information structs and
 * everything. OSF1 is known to require at least 8872 bytes. The buffer
 * required for storing all possible aliases and IP numbers is according to
 * Stevens' Unix Network Programming 2nd edition, p. 304: 8192 bytes!
 */
#define CURL_NAMELOOKUP_SIZE 9000

#ifdef USE_ARES

CURLcode Curl_multi_ares_fdset(struct connectdata *conn,
                               fd_set *read_fd_set,
                               fd_set *write_fd_set,
                               int *max_fdp)

{
  int max = ares_fds(conn->data->state.areschannel,
                     read_fd_set, write_fd_set);
  *max_fdp = max;

  return CURLE_OK;
}

/* called to check if the name is resolved now */
CURLcode Curl_is_resolved(struct connectdata *conn,
                          struct Curl_dns_entry **dns)
{
  fd_set read_fds, write_fds;
  static const struct timeval tv={0,0};
  int count;
  struct SessionHandle *data = conn->data;
  int nfds;

  FD_ZERO(&read_fds);
  FD_ZERO(&write_fds);
  nfds = ares_fds(data->state.areschannel, &read_fds, &write_fds);

  count = select(nfds, &read_fds, &write_fds, NULL,
                 (struct timeval *)&tv);

  if(count)
    ares_process(data->state.areschannel, &read_fds, &write_fds);

  *dns = NULL;

  if(conn->async.done) {
    if(!conn->async.dns)
      return CURLE_COULDNT_RESOLVE_HOST;
    *dns = conn->async.dns;
  }

  return CURLE_OK;
}

/* This is a function that locks and waits until the name resolve operation
   has completed.

   If 'entry' is non-NULL, make it point to the resolved dns entry

   Return CURLE_COULDNT_RESOLVE_HOST if the host was not resolved, and
   CURLE_OPERATION_TIMEDOUT if a time-out occurred.
*/
CURLcode Curl_wait_for_resolv(struct connectdata *conn,
                              struct Curl_dns_entry **entry)
{
  CURLcode rc=CURLE_OK;
  struct SessionHandle *data = conn->data;
    
  /* Wait for the name resolve query to complete. */
  while (1) {
    int nfds=0;
    fd_set read_fds, write_fds;
    struct timeval *tvp, tv;
    int count;
    
    FD_ZERO(&read_fds);
    FD_ZERO(&write_fds);
    nfds = ares_fds(data->state.areschannel, &read_fds, &write_fds);
    if (nfds == 0)
      break;
    tvp = ares_timeout(data->state.areschannel,
                       NULL, /* pass in our maximum time here */
                       &tv);
    count = select(nfds, &read_fds, &write_fds, NULL, tvp);
    if (count < 0 && errno != EINVAL)
      break;

    ares_process(data->state.areschannel, &read_fds, &write_fds);
  }

  /* Operation complete, if the lookup was successful we now have the entry
     in the cache. */
    
  /* this destroys the channel and we cannot use it anymore after this */
  ares_destroy(data->state.areschannel);

  if(entry)
    *entry = conn->async.dns;

  if(!conn->async.dns) {
    /* a name was not resolved */
    if(conn->async.done) {
      failf(data, "Could not resolve host: %s", conn->name);
      rc = CURLE_COULDNT_RESOLVE_HOST;
    }
    else
      rc = CURLE_OPERATION_TIMEDOUT;

    /* close the connection, since we can't return failure here without
       cleaning up this connection properly */
    Curl_disconnect(conn);
  }
  
  return rc;
}

/* this function gets called by ares when we got the name resolved */
static void host_callback(void *arg, /* "struct connectdata *" */
                          int status,
                          struct hostent *hostent)
{
  struct connectdata *conn = (struct connectdata *)arg;
  struct Curl_dns_entry *dns = NULL;

  conn->async.done = TRUE;
  conn->async.status = status;

  if(ARES_SUCCESS == status) {
    /* we got a resolved name in 'hostent' */
    char *bufp = (char *)malloc(CURL_NAMELOOKUP_SIZE);
    if(bufp) {

      /* pack_hostent() copies to and shrinks the target buffer */
      struct hostent *he = pack_hostent(&bufp, hostent);

      struct SessionHandle *data = conn->data;

      if(data->share)
        Curl_share_lock(data, CURL_LOCK_DATA_DNS, CURL_LOCK_ACCESS_SINGLE);

      dns = cache_resolv_response(data, he,
                                  conn->async.hostname, conn->async.port);

      if(data->share)
        Curl_share_unlock(data, CURL_LOCK_DATA_DNS);
    }
  }

  conn->async.dns = dns;

  /* The input hostent struct will be freed by ares when we return from this
     function */
}

/*
 * Return name information about the given hostname and port number. If
 * successful, the 'hostent' is returned and the forth argument will point to
 * memory we need to free after use. That meory *MUST* be freed with
 * Curl_freeaddrinfo(), nothing else.
 */
static Curl_addrinfo *my_getaddrinfo(struct connectdata *conn,
                                     char *hostname,
                                     int port,
                                     int *waitp)
{
  int rc;
  char *bufp;
  struct SessionHandle *data = conn->data;

  rc = ares_init(&data->state.areschannel);

  *waitp = FALSE;
  
  if(!rc) {
    /* only if success */

    bufp = strdup(hostname);

    if(bufp) {
      Curl_safefree(conn->async.hostname);
      conn->async.hostname = bufp;
      conn->async.port = port;
      conn->async.done = FALSE; /* not done */
      conn->async.status = 0;   /* clear */
      conn->async.dns = NULL;   /* clear */
      
      ares_gethostbyname(data->state.areschannel, hostname, PF_INET,
                         host_callback, conn);

      
      *waitp = TRUE; /* please wait for the response */
    }
    else
      ares_destroy(data->state.areschannel);
  }

  return NULL; /* no struct yet */
  
}
#else
/* For builds without ARES, Curl_resolv() can never return wait==TRUE,
   so this function will never be called. If it still gets called, we
   return failure at once. */
CURLcode Curl_wait_for_resolv(struct connectdata *conn,
                              struct Curl_dns_entry **entry)
{
  (void)conn;
  *entry=NULL;
  return CURLE_COULDNT_RESOLVE_HOST;
}

CURLcode Curl_multi_ares_fdset(struct connectdata *conn,
                               fd_set *read_fd_set,
                               fd_set *write_fd_set,
                               int *max_fdp)
{
  (void)conn;
  (void)read_fd_set;
  (void)write_fd_set;
  (void)max_fdp;
  return CURLE_OK;
}

CURLcode Curl_is_resolved(struct connectdata *conn,
                          struct Curl_dns_entry **dns)
{
  (void)conn;
  *dns = NULL;

  return CURLE_COULDNT_RESOLVE_HOST;
}

#endif

#if defined(ENABLE_IPV6) && !defined(USE_ARES)

#ifdef CURLDEBUG
/* These two are strictly for memory tracing and are using the same
 * style as the family otherwise present in memdebug.c. I put these ones
 * here since they require a bunch of struct types I didn't wanna include
 * in memdebug.c
 */
int curl_getaddrinfo(char *hostname, char *service,
                     struct addrinfo *hints,
                     struct addrinfo **result,
                     int line, const char *source)
{
  int res=(getaddrinfo)(hostname, service, hints, result);
  if(0 == res) {
    /* success */
    if(logfile)
      fprintf(logfile, "ADDR %s:%d getaddrinfo() = %p\n",
              source, line, (void *)*result);
  }
  else {
    if(logfile)
      fprintf(logfile, "ADDR %s:%d getaddrinfo() failed\n",
              source, line);
  }
  return res;
}

void curl_freeaddrinfo(struct addrinfo *freethis,
                       int line, const char *source)
{
  (freeaddrinfo)(freethis);
  if(logfile)
    fprintf(logfile, "ADDR %s:%d freeaddrinfo(%p)\n",
            source, line, (void *)freethis);
}

#endif

/*
 * Return name information about the given hostname and port number. If
 * successful, the 'addrinfo' is returned and the forth argument will point to
 * memory we need to free after use. That meory *MUST* be freed with
 * Curl_freeaddrinfo(), nothing else.
 */
static Curl_addrinfo *my_getaddrinfo(struct connectdata *conn,
                                     char *hostname,
                                     int port,
                                     int *waitp)
{
  struct addrinfo hints, *res;
  int error;
  char sbuf[NI_MAXSERV];
  int s, pf;
  struct SessionHandle *data = conn->data;

  *waitp=0; /* don't wait, we have the response now */

  /* see if we have an IPv6 stack */
  s = socket(PF_INET6, SOCK_DGRAM, 0);
  if (s < 0)
    /* Some non-IPv6 stacks have been found to make very slow name resolves
     * when PF_UNSPEC is used, so thus we switch to a mere PF_INET lookup if
     * the stack seems to be a non-ipv6 one. */
    pf = PF_INET;
  else {
    /* This seems to be an IPv6-capable stack, use PF_UNSPEC for the widest
     * possible checks. And close the socket again.
     */
    sclose(s);

    /*
     * Check if a more limited name resolve has been requested.
     */
    switch(data->set.ip_version) {
    case CURL_IPRESOLVE_V4:
      pf = PF_INET;
      break;
    case CURL_IPRESOLVE_V6:
      pf = PF_INET6;
      break;
    default:
      pf = PF_UNSPEC;
      break;
    }
  }
 
  memset(&hints, 0, sizeof(hints));
  hints.ai_family = pf;
  hints.ai_socktype = SOCK_STREAM;
  hints.ai_flags = AI_CANONNAME;
  snprintf(sbuf, sizeof(sbuf), "%d", port);
  error = getaddrinfo(hostname, sbuf, &hints, &res);
  if (error) {
    infof(data, "getaddrinfo(3) failed for %s:%d\n", hostname, port);    
    return NULL;
  }

  return res;
}
#else /* following code is IPv4-only */

#if !defined(HAVE_GETHOSTBYNAME_R) || defined(USE_ARES)
static void hostcache_fixoffset(struct hostent *h, int offset);
/*
 * Performs a "deep" copy of a hostent into a buffer (returns a pointer to the
 * copy). Make absolutely sure the destination buffer is big enough!
 */
static struct hostent* pack_hostent(char** buf, struct hostent* orig)
{
  char *bufptr;
  char *newbuf;
  struct hostent* copy;

  int i;
  char *str;
  int len;

  bufptr = *buf;
  copy = (struct hostent*)bufptr;

  bufptr += sizeof(struct hostent);
  copy->h_name = bufptr;
  len = strlen(orig->h_name) + 1;
  strncpy(bufptr, orig->h_name, len);
  bufptr += len;

  /* we align on even 64bit boundaries for safety */
#define MEMALIGN(x) ((x)+(8-(((unsigned long)(x))&0x7)))

  /* This must be aligned properly to work on many CPU architectures! */
  bufptr = MEMALIGN(bufptr);
  
  copy->h_aliases = (char**)bufptr;

  /* Figure out how many aliases there are */
  for (i = 0; orig->h_aliases && orig->h_aliases[i]; ++i);

  /* Reserve room for the array */
  bufptr += (i + 1) * sizeof(char*);

  /* Clone all known aliases */
  if(orig->h_aliases) {
    for(i = 0; (str = orig->h_aliases[i]); i++) {
      len = strlen(str) + 1;
      strncpy(bufptr, str, len);
      copy->h_aliases[i] = bufptr;
      bufptr += len;
    }
  }
  /* if(!orig->h_aliases) i was already set to 0 */

  /* Terminate the alias list with a NULL */
  copy->h_aliases[i] = NULL;

  copy->h_addrtype = orig->h_addrtype;
  copy->h_length = orig->h_length;
    
  /* align it for (at least) 32bit accesses */
  bufptr = MEMALIGN(bufptr);

  copy->h_addr_list = (char**)bufptr;

  /* Figure out how many addresses there are */
  for (i = 0; orig->h_addr_list[i] != NULL; ++i);

  /* Reserve room for the array */
  bufptr += (i + 1) * sizeof(char*);

  i = 0;
  len = orig->h_length;
  str = orig->h_addr_list[i];
  while (str != NULL) {
    memcpy(bufptr, str, len);
    copy->h_addr_list[i] = bufptr;
    bufptr += len;
    str = orig->h_addr_list[++i];
  }
  copy->h_addr_list[i] = NULL;

  /* now, shrink the allocated buffer to the size we actually need, which
     most often is only a fraction of the original alloc */
  newbuf=(char *)realloc(*buf, (int)bufptr-(int)(*buf));

  /* if the alloc moved, we need to adjust things again */
  if(newbuf != *buf)
    hostcache_fixoffset((struct hostent*)newbuf, (int)newbuf-(int)*buf);

  /* setup the return */
  *buf = newbuf;
  copy = (struct hostent*)newbuf;

  return copy;
}
#endif

static void hostcache_fixoffset(struct hostent *h, int offset)
{
  int i=0;

  h->h_name=(char *)((long)h->h_name+offset);
  if(h->h_aliases) {
    /* only relocate aliases if there are any! */
    h->h_aliases=(char **)((long)h->h_aliases+offset);
    while(h->h_aliases[i]) {
      h->h_aliases[i]=(char *)((long)h->h_aliases[i]+offset);
      i++;
    }
  }

  h->h_addr_list=(char **)((long)h->h_addr_list+offset);
  i=0;
  while(h->h_addr_list[i]) {
    h->h_addr_list[i]=(char *)((long)h->h_addr_list[i]+offset);
    i++;
  }
}

#ifndef USE_ARES

static char *MakeIP(unsigned long num, char *addr, int addr_len)
{
#if defined(HAVE_INET_NTOA) || defined(HAVE_INET_NTOA_R)
  struct in_addr in;
  in.s_addr = htonl(num);

#if defined(HAVE_INET_NTOA_R)
  inet_ntoa_r(in,addr,addr_len);
#else
  strncpy(addr,inet_ntoa(in),addr_len);
#endif
#else
  unsigned char *paddr;

  num = htonl(num);  /* htonl() added to avoid endian probs */
  paddr = (unsigned char *)&num;
  sprintf(addr, "%u.%u.%u.%u", paddr[0], paddr[1], paddr[2], paddr[3]);
#endif
  return (addr);
}

/* The original code to this function was once stolen from the Dancer source
   code, written by Bjorn Reese, it has since been patched and modified
   considerably. */
static Curl_addrinfo *my_getaddrinfo(struct connectdata *conn,
                                     char *hostname,
                                     int port,
                                     int *waitp)
{
  struct hostent *h = NULL;
  in_addr_t in;
  int ret; /* this variable is unused on several platforms but used on some */
  struct SessionHandle *data = conn->data;

  (void)port; /* unused in IPv4 code */
  ret = 0; /* to prevent the compiler warning */

  *waitp = 0; /* don't wait, we act synchronously */

  in=inet_addr(hostname);
  if (in != CURL_INADDR_NONE) {
    struct in_addr *addrentry;
    struct namebuf {
        struct hostent hostentry;
        char *h_addr_list[2];
        struct in_addr addrentry;
        char h_name[128];
    } *buf = (struct namebuf *)malloc(sizeof(struct namebuf));
    if(!buf)
      return NULL; /* major failure */

    h = &buf->hostentry;
    h->h_addr_list = &buf->h_addr_list[0];
    addrentry = &buf->addrentry;
    addrentry->s_addr = in;
    h->h_addr_list[0] = (char*)addrentry;
    h->h_addr_list[1] = NULL;
    h->h_addrtype = AF_INET;
    h->h_length = sizeof(*addrentry);
    h->h_name = &buf->h_name[0];
    MakeIP(ntohl(in), (char *)h->h_name, sizeof(buf->h_name));
  }
#if defined(HAVE_GETHOSTBYNAME_R)
  else {
    int h_errnop;
    int res=ERANGE;
    int step_size=200;
    int *buf = (int *)malloc(CURL_NAMELOOKUP_SIZE);
    if(!buf)
      return NULL; /* major failure */

     /* Workaround for gethostbyname_r bug in qnx nto. It is also _required_
        for some of these functions. */
    memset(buf, 0, CURL_NAMELOOKUP_SIZE);
#ifdef HAVE_GETHOSTBYNAME_R_5
    /* Solaris, IRIX and more */
    (void)res; /* prevent compiler warning */
    while(!h) {
      h = gethostbyname_r(hostname,
                          (struct hostent *)buf,
                          (char *)buf + sizeof(struct hostent),
                          step_size - sizeof(struct hostent),
                          &h_errnop);

      /* If the buffer is too small, it returns NULL and sets errno to
         ERANGE. The errno is thread safe if this is compiled with
         -D_REENTRANT as then the 'errno' variable is a macro defined to
         get used properly for threads. */

      if(h || (errno != ERANGE))
        break;
      
      step_size+=200;
    }

#ifdef CURLDEBUG
    infof(data, "gethostbyname_r() uses %d bytes\n", step_size);
#endif

    if(h) {
      int offset;
      h=(struct hostent *)realloc(buf, step_size);
      offset=(long)h-(long)buf;
      hostcache_fixoffset(h, offset);
      buf=(int *)h;
    }
    else
#endif /* HAVE_GETHOSTBYNAME_R_5 */
#ifdef HAVE_GETHOSTBYNAME_R_6
    /* Linux */
    do {
      res=gethostbyname_r(hostname,
			  (struct hostent *)buf,
			  (char *)buf + sizeof(struct hostent),
			  step_size - sizeof(struct hostent),
			  &h, /* DIFFERENCE */
			  &h_errnop);
      /* Redhat 8, using glibc 2.2.93 changed the behavior. Now all of a
         sudden this function returns EAGAIN if the given buffer size is too
         small. Previous versions are known to return ERANGE for the same
         problem.

         This wouldn't be such a big problem if older versions wouldn't
         sometimes return EAGAIN on a common failure case. Alas, we can't
         assume that EAGAIN *or* ERANGE means ERANGE for any given version of
         glibc.

         For now, we do that and thus we may call the function repeatedly and
         fail for older glibc versions that return EAGAIN, until we run out
         of buffer size (step_size grows beyond CURL_NAMELOOKUP_SIZE).

         If anyone has a better fix, please tell us!
      */

      if((ERANGE == res) || (EAGAIN == res)) {
	step_size+=200;
	continue;
      }
      break;
    } while(step_size <= CURL_NAMELOOKUP_SIZE);

    if(!h) /* failure */
      res=1;
    
#ifdef CURLDEBUG
    infof(data, "gethostbyname_r() uses %d bytes\n", step_size);
#endif
    if(!res) {
      int offset;
      h=(struct hostent *)realloc(buf, step_size);
      offset=(long)h-(long)buf;
      hostcache_fixoffset(h, offset);
      buf=(int *)h;
    }
    else
#endif/* HAVE_GETHOSTBYNAME_R_6 */
#ifdef HAVE_GETHOSTBYNAME_R_3
    /* AIX, Digital Unix, HPUX 10, more? */

    /* For AIX 4.3 or later, we don't use gethostbyname_r() at all, because of
       the plain fact that it does not return unique full buffers on each
       call, but instead several of the pointers in the hostent structs will
       point to the same actual data! This have the unfortunate down-side that
       our caching system breaks down horribly. Luckily for us though, AIX 4.3
       and more recent versions have a completely thread-safe libc where all
       the data is stored in thread-specific memory areas making calls to the
       plain old gethostbyname() work fine even for multi-threaded programs.
       
       This AIX 4.3 or later detection is all made in the configure script.

       Troels Walsted Hansen helped us work this out on March 3rd, 2003. */

    if(CURL_NAMELOOKUP_SIZE >=
       (sizeof(struct hostent)+sizeof(struct hostent_data)))

      /* August 22nd, 2000: Albert Chin-A-Young brought an updated version
       * that should work! September 20: Richard Prescott worked on the buffer
       * size dilemma. */

      ret = gethostbyname_r(hostname,
                            (struct hostent *)buf,
                            (struct hostent_data *)((char *)buf +
                                                    sizeof(struct hostent)));
    else
      ret = -1; /* failure, too smallish buffer size */
    
    /* result expected in h */
    h = (struct hostent*)buf;
    h_errnop= errno; /* we don't deal with this, but set it anyway */
    if(ret)
#endif /* HAVE_GETHOSTBYNAME_R_3 */
      {
      infof(data, "gethostbyname_r(2) failed for %s\n", hostname);
      h = NULL; /* set return code to NULL */
      free(buf);
    }
#else /* HAVE_GETHOSTBYNAME_R */
  else {
    if ((h = gethostbyname(hostname)) == NULL ) {
      infof(data, "gethostbyname(2) failed for %s\n", hostname);
    }
    else 
    {
      char *buf=(char *)malloc(CURL_NAMELOOKUP_SIZE);
      /* we make a copy of the hostent right now, right here, as the
         static one we got a pointer to might get removed when we don't
         want/expect that */
      h = pack_hostent(&buf, h);
    }
#endif /*HAVE_GETHOSTBYNAME_R */
  }

  return (h);
}

#endif /* end of IPv4-specific code */

#endif /* end of !USE_ARES */
