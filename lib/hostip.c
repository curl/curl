/*****************************************************************************
 *                                  _   _ ____  _     
 *  Project                     ___| | | |  _ \| |    
 *                             / __| | | | |_) | |    
 *                            | (__| |_| |  _ <| |___ 
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) 2001, Daniel Stenberg, <daniel@haxx.se>, et al.
 *
 * In order to be useful for every potential user, curl and libcurl are
 * dual-licensed under the MPL and the MIT/X-derivate licenses.
 *
 * You may opt to use, copy, modify, merge, publish, distribute and/or sell
 * copies of the Software, and permit persons to whom the Software is
 * furnished to do so, under the terms of the MPL or the MIT/X-derivate
 * licenses. You may pick one of these licenses.
 *
 * This software is distributed on an "AS IS" basis, WITHOUT WARRANTY OF ANY
 * KIND, either express or implied.
 *
 * $Id$
 *****************************************************************************/

#include "setup.h"

#include <string.h>
#include <errno.h>

#define _REENTRANT

#if defined(WIN32) && !defined(__GNUC__) || defined(__MINGW32__)
#include <winsock.h>
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
#include <inet.h>
#include <stdlib.h>
#endif
#endif

#include "urldata.h"
#include "sendf.h"
#include "hostip.h"
#include "hash.h"

#define _MPRINTF_REPLACE /* use our functions only */
#include <curl/mprintf.h>

#if defined(HAVE_INET_NTOA_R) && !defined(HAVE_INET_NTOA_R_DECL)
#include "inet_ntoa_r.h"
#endif

/* The last #include file should be: */
#ifdef MALLOCDEBUG
#include "memdebug.h"
#endif

static curl_hash hostname_cache;
static int host_cache_initialized;

void Curl_global_host_cache_init(void)
{
  if (!host_cache_initialized) {
    curl_hash_init(&hostname_cache, 7, Curl_freeaddrinfo);
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
    curl_hash_clean(&hostname_cache);
    host_cache_initialized = 0;
  }
}

struct curl_dns_cache_entry {
  Curl_addrinfo *addr;
  time_t timestamp;
};

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
  } while (i > 1);

  return chars;
}

/* Create a hostcache id */
static char *
_create_hostcache_id(char *server, int port, ssize_t *entry_len)
{
  char *id = NULL;

  /* Get the length of the new entry id */
  *entry_len = *entry_len +      /* Hostname length */
               1 +               /* The ':' seperator */
               _num_chars(port); /* The number of characters the port will take up */
  
  /* Allocate the new entry id */
  id = malloc(*entry_len + 1);
  if (!id) {
    return NULL;
  }

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

/* Macro to save redundant free'ing of entry_id */
#define _hostcache_return(__v) \
{ \
  free(entry_id); \
  return (__v); \
}

Curl_addrinfo *Curl_resolv(struct SessionHandle *data,
                           char *hostname,
                           int port,
                           char **bufp)
{
  char *entry_id = NULL;
  struct curl_dns_cache_entry *p = NULL;
  ssize_t entry_len;
  time_t now;

  /* If the host cache timeout is 0, we don't do DNS cach'ing
     so fall through */
  if (data->set.dns_cache_timeout == 0) {
    return Curl_getaddrinfo(data, hostname, port, bufp);
  }

  /* Create an entry id, based upon the hostname and port */
  entry_len = strlen(hostname);
  entry_id = _create_hostcache_id(hostname, port, &entry_len);
  /* If we can't create the entry id, don't cache, just fall-through
     to the plain Curl_getaddrinfo() */
  if (!entry_id) {
    return Curl_getaddrinfo(data, hostname, port, bufp);
  }
  
  time(&now);
  /* See if its already in our dns cache */
  if (entry_id && curl_hash_find(data->hostcache, entry_id, entry_len+1, (void **) &p)) {
    /* Do we need to check for a cache timeout? */
    if (data->set.dns_cache_timeout != -1) {
      /* Return if the entry has not timed out */
      if ((now - p->timestamp) < data->set.dns_cache_timeout) {
        _hostcache_return(p->addr);
      }
    }
    else {
      _hostcache_return(p->addr);
    }
  }

  /* Create a new cache entry */
  p = (struct curl_dns_cache_entry *) malloc(sizeof(struct curl_dns_cache_entry));
  if (!p) {
   _hostcache_return(NULL);
  }

  p->addr = Curl_getaddrinfo(data, hostname, port, bufp);
  if (!p->addr) {
    free(p);
    _hostcache_return(NULL);
  }
  p->timestamp = now;

  /* Save it in our host cache */
  curl_hash_update(data->hostcache, entry_id, entry_len+1, (const void *) p);

  _hostcache_return(p->addr);
}

/*
 * This is a wrapper function for freeing name information in a protocol
 * independent way. This takes care of using the appropriate underlaying
 * proper function.
 */
void Curl_freeaddrinfo(void *freethis)
{
  struct curl_dns_cache_entry *p = (struct curl_dns_cache_entry *) freethis;

#ifdef ENABLE_IPV6
  freeaddrinfo(p->addr);
#else
  free(p->addr);
#endif

  free(p);
}

/* --- resolve name or IP-number --- */

#ifdef ENABLE_IPV6

#ifdef MALLOCDEBUG
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
Curl_addrinfo *Curl_getaddrinfo(struct SessionHandle *data,
                                char *hostname,
                                int port,
                                char **bufp)
{
  struct addrinfo hints, *res;
  int error;
  char sbuf[NI_MAXSERV];

  memset(&hints, 0, sizeof(hints));
  hints.ai_family = PF_UNSPEC;
  hints.ai_socktype = SOCK_STREAM;
  hints.ai_flags = AI_CANONNAME;
  snprintf(sbuf, sizeof(sbuf), "%d", port);
  error = getaddrinfo(hostname, sbuf, &hints, &res);
  if (error) {
    infof(data, "getaddrinfo(3) failed for %s\n", hostname);    
    return NULL;
  }
  *bufp=(char *)res; /* make it point to the result struct */

  return res;
}
#else /* following code is IPv4-only */

#ifndef HAVE_GETHOSTBYNAME_R
/**
 * Performs a "deep" copy of a hostent into a buffer (returns a pointer to the
 * copy). Make absolutely sure the destination buffer is big enough!
 *
 * Keith McGuigan 
 * 10/3/2001 */
static struct hostent* pack_hostent(char* buf, struct hostent* orig)
{
  char* bufptr;
  struct hostent* copy;

  int i;
  char* str;
  int len;

  bufptr = buf;
  copy = (struct hostent*)bufptr;

  bufptr += sizeof(struct hostent);
  copy->h_name = bufptr;
  len = strlen(orig->h_name) + 1;
  strncpy(bufptr, orig->h_name, len);
  bufptr += len;

  /* we align on even 64bit boundaries for safety */
#define MEMALIGN(x) (((unsigned long)(x)&0xfffffff8)+8)

  /* This must be aligned properly to work on many CPU architectures! */
  copy->h_aliases = (char**)MEMALIGN(bufptr);

  /* Figure out how many aliases there are */
  for (i = 0; orig->h_aliases[i] != NULL; ++i);

  /* Reserve room for the array */
  bufptr += (i + 1) * sizeof(char*);

  /* Clone all known aliases */
  for(i = 0; (str = orig->h_aliases[i]); i++) {
    len = strlen(str) + 1;
    strncpy(bufptr, str, len);
    copy->h_aliases[i] = bufptr;
    bufptr += len;
  }
  /* Terminate the alias list with a NULL */
  copy->h_aliases[i] = NULL;

  copy->h_addrtype = orig->h_addrtype;
  copy->h_length = orig->h_length;
    
  /* align it for (at least) 32bit accesses */
  bufptr = (char *)MEMALIGN(bufptr);

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

  return copy;
}
#endif

static char *MakeIP(unsigned long num,char *addr, int addr_len)
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

#ifndef INADDR_NONE
#define INADDR_NONE (unsigned long) ~0
#endif

Curl_addrinfo *Curl_getaddrinfo(struct SessionHandle *data,
                                char *hostname,
                                int port,
                                char **bufp)
{
  struct hostent *h = NULL;
  in_addr_t in;
  int ret; /* this variable is unused on several platforms but used on some */

#define CURL_NAMELOOKUP_SIZE 9000
  /* Allocate enough memory to hold the full name information structs and
   * everything. OSF1 is known to require at least 8872 bytes. The buffer
   * required for storing all possible aliases and IP numbers is according to
   * Stevens' Unix Network Programming 2nd editor, p. 304: 8192 bytes! */
  int *buf = (int *)malloc(CURL_NAMELOOKUP_SIZE);
  if(!buf)
    return NULL; /* major failure */
  *bufp = (char *)buf;

  port=0; /* unused in IPv4 code */
  ret = 0; /* to prevent the compiler warning */

  if ( (in=inet_addr(hostname)) != INADDR_NONE ) {
    struct in_addr *addrentry;

    h = (struct hostent*)buf;
    h->h_addr_list = (char**)(buf + sizeof(*h));
    addrentry = (struct in_addr*)(h->h_addr_list + 2);
    addrentry->s_addr = in;
    h->h_addr_list[0] = (char*)addrentry;
    h->h_addr_list[1] = NULL;
    h->h_addrtype = AF_INET;
    h->h_length = sizeof(*addrentry);
    h->h_name = *(h->h_addr_list) + h->h_length;
    /* bad one h->h_name = (char*)(h->h_addr_list + h->h_length); */
    MakeIP(ntohl(in),h->h_name, CURL_NAMELOOKUP_SIZE - (long)(h->h_name) + (long)buf);
  }
#if defined(HAVE_GETHOSTBYNAME_R)
  else {
    int h_errnop;
     /* Workaround for gethostbyname_r bug in qnx nto. It is also _required_
        for some of these functions. */
    memset(buf, 0, CURL_NAMELOOKUP_SIZE);
#ifdef HAVE_GETHOSTBYNAME_R_5
    /* Solaris, IRIX and more */
    if ((h = gethostbyname_r(hostname,
                             (struct hostent *)buf,
                             (char *)buf + sizeof(struct hostent),
                             CURL_NAMELOOKUP_SIZE - sizeof(struct hostent),
                             &h_errnop)) == NULL )
#endif
#ifdef HAVE_GETHOSTBYNAME_R_6
    /* Linux */
    if( gethostbyname_r(hostname,
                        (struct hostent *)buf,
                        buf + sizeof(struct hostent),
                        CURL_NAMELOOKUP_SIZE - sizeof(struct hostent),
                        &h, /* DIFFERENCE */
                        &h_errnop))
#endif
#ifdef HAVE_GETHOSTBYNAME_R_3
    /* AIX, Digital Unix, HPUX 10, more? */

    if(CURL_NAMELOOKUP_SIZE >=
       (sizeof(struct hostent)+sizeof(struct hostent_data)))

      /* August 22nd, 2000: Albert Chin-A-Young brought an updated version
       * that should work! September 20: Richard Prescott worked on the buffer
       * size dilemma. */

      ret = gethostbyname_r(hostname,
                          (struct hostent *)buf,
                          (struct hostent_data *)(buf + sizeof(struct hostent)));
    else
      ret = -1; /* failure, too smallish buffer size */
    
    /* result expected in h */
    h = (struct hostent*)buf;
    h_errnop= errno; /* we don't deal with this, but set it anyway */
    if(ret)
#endif
      {
      infof(data, "gethostbyname_r(2) failed for %s\n", hostname);
      h = NULL; /* set return code to NULL */
      free(buf);
      *bufp=NULL;
    }
#else
  else {
    if ((h = gethostbyname(hostname)) == NULL ) {
      infof(data, "gethostbyname(2) failed for %s\n", hostname);
      free(buf);
      *bufp=NULL;
    }
    else 
      /* we make a copy of the hostent right now, right here, as the
         static one we got a pointer to might get removed when we don't
         want/expect that */
      h = pack_hostent(buf, h);
#endif
  }
  return (h);
}

#endif /* end of IPv4-specific code */

/*
 * local variables:
 * eval: (load-file "../curl-mode.el")
 * end:
 * vim600: fdm=marker
 * vim: et sw=2 ts=2 sts=2 tw=78
 */
 
