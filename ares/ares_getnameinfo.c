/* $Id$ */

/* Copyright 2005 by Dominick Meglio
 *
 * Permission to use, copy, modify, and distribute this
 * software and its documentation for any purpose and without
 * fee is hereby granted, provided that the above copyright
 * notice appear in all copies and that both that copyright
 * notice and this permission notice appear in supporting
 * documentation, and that the name of M.I.T. not be used in
 * advertising or publicity pertaining to distribution of the
 * software without specific, written prior permission.
 * M.I.T. makes no representations about the suitability of
 * this software for any purpose.  It is provided "as is"
 * without express or implied warranty.
 */
#include "setup.h"

#if defined(WIN32) && !defined(WATT32)
#include "nameser.h"
#else
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <arpa/nameser.h>
#ifdef HAVE_ARPA_NAMESER_COMPAT_H
#include <arpa/nameser_compat.h>
#endif
#endif

#ifdef HAVE_NET_IF_H
#include <net/if.h>
#endif

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "ares.h"
#include "ares_private.h"
#include "ares_ipv6.h"
#include "inet_ntop.h"

#ifdef WATT32
#undef WIN32
#endif

struct nameinfo_query {
  ares_nameinfo_callback callback;
  void *arg;
  union {
    struct sockaddr_in addr4;
    struct sockaddr_in6 addr6;
  } addr;
  int family;
  int flags;
  int timeouts;
};

#ifdef HAVE_SOCKADDR_IN6_SIN6_SCOPE_ID
#define IPBUFSIZ 40+IF_NAMESIZE
#else
#define IPBUFSIZ 40
#endif

static void nameinfo_callback(void *arg, int status, int timeouts, struct hostent *host);
static char *lookup_service(unsigned short port, int flags,
                            char *buf, size_t buflen);
#ifdef HAVE_SOCKADDR_IN6_SIN6_SCOPE_ID
static void append_scopeid(struct sockaddr_in6 *addr6, unsigned int scopeid,
                           char *buf, size_t buflen);
#endif
static char *ares_striendstr(const char *s1, const char *s2);

void ares_getnameinfo(ares_channel channel, const struct sockaddr *sa, socklen_t salen,
                      int flags, ares_nameinfo_callback callback, void *arg)
{
  struct sockaddr_in *addr = NULL;
  struct sockaddr_in6 *addr6 = NULL;
  struct nameinfo_query *niquery;

  /* Verify the buffer size */
  if (salen == sizeof(struct sockaddr_in))
    addr = (struct sockaddr_in *)sa;
  else if (salen == sizeof(struct sockaddr_in6))
    addr6 = (struct sockaddr_in6 *)sa;
  else
    {
      callback(arg, ARES_ENOTIMP, 0, NULL, NULL);
      return;
    }

  /* If neither, assume they want a host */
  if (!(flags & ARES_NI_LOOKUPSERVICE) && !(flags & ARES_NI_LOOKUPHOST))
    flags |= ARES_NI_LOOKUPHOST;

  /* All they want is a service, no need for DNS */
  if ((flags & ARES_NI_LOOKUPSERVICE) && !(flags & ARES_NI_LOOKUPHOST))
    {
      char buf[33], *service;
      unsigned int port = 0;

      if (salen == sizeof(struct sockaddr_in))
        port = addr->sin_port;
      else
        port = addr6->sin6_port;
      service = lookup_service((unsigned short)(port & 0xffff),
                               flags, buf, sizeof(buf));
      callback(arg, ARES_SUCCESS, 0, NULL, service);
      return;
    }

  /* They want a host lookup */
  if ((flags & ARES_NI_LOOKUPHOST))
    {
     /* A numeric host can be handled without DNS */
     if ((flags & ARES_NI_NUMERICHOST))
      {
        unsigned int port = 0;
        char ipbuf[IPBUFSIZ];
        char srvbuf[33];
        char *service = NULL;
        ipbuf[0] = 0;

        /* Specifying not to lookup a host, but then saying a host
         * is required has to be illegal.
         */
        if (flags & ARES_NI_NAMEREQD)
          {
            callback(arg, ARES_EBADFLAGS, 0, NULL, NULL);
            return;
          }
        if (salen == sizeof(struct sockaddr_in6))
          {
            ares_inet_ntop(AF_INET6, &addr6->sin6_addr, ipbuf, IPBUFSIZ);
            port = addr6->sin6_port;
            /* If the system supports scope IDs, use it */
#ifdef HAVE_SOCKADDR_IN6_SIN6_SCOPE_ID
            append_scopeid(addr6, flags, ipbuf, sizeof(ipbuf));
#endif
          }
        else
          {
            ares_inet_ntop(AF_INET, &addr->sin_addr, ipbuf, IPBUFSIZ);
            port = addr->sin_port;
          }
        /* They also want a service */
        if (flags & ARES_NI_LOOKUPSERVICE)
          service = lookup_service((unsigned short)(port & 0xffff),
                                   flags, srvbuf, sizeof(srvbuf));
        callback(arg, ARES_SUCCESS, 0, ipbuf, service);
        return;
      }
    /* This is where a DNS lookup becomes necessary */
    else
      {
        niquery = malloc(sizeof(struct nameinfo_query));
        if (!niquery)
          {
            callback(arg, ARES_ENOMEM, 0, NULL, NULL);
            return;
          }
        niquery->callback = callback;
        niquery->arg = arg;
        niquery->flags = flags;
        niquery->timeouts = 0;
        if (sa->sa_family == AF_INET)
          {
            niquery->family = AF_INET;
            memcpy(&niquery->addr.addr4, addr, sizeof(addr));
            ares_gethostbyaddr(channel, &addr->sin_addr, sizeof(struct in_addr), AF_INET,
                               nameinfo_callback, niquery);
          }
        else
          {
            niquery->family = AF_INET6;
            memcpy(&niquery->addr.addr6, addr6, sizeof(addr6));
            ares_gethostbyaddr(channel, &addr6->sin6_addr, sizeof(struct in6_addr), AF_INET6,
                               nameinfo_callback, niquery);
          }
      }
    }
}

static void nameinfo_callback(void *arg, int status, int timeouts, struct hostent *host)
{
  struct nameinfo_query *niquery = (struct nameinfo_query *) arg;
  char srvbuf[33];
  char *service = NULL;

  niquery->timeouts += timeouts;
  if (status == ARES_SUCCESS)
    {
      /* They want a service too */
      if (niquery->flags & ARES_NI_LOOKUPSERVICE)
        {
          if (niquery->family == AF_INET)
            service = lookup_service(niquery->addr.addr4.sin_port,
                                     niquery->flags, srvbuf, sizeof(srvbuf));
          else
            service = lookup_service(niquery->addr.addr6.sin6_port,
                                     niquery->flags, srvbuf, sizeof(srvbuf));
        }
      /* NOFQDN means we have to strip off the domain name portion.
         We do this by determining our own domain name, then searching the string
         for this domain name and removing it.
       */
      if (niquery->flags & ARES_NI_NOFQDN)
        {
           char buf[255];
           char *domain;
           gethostname(buf, 255);
           if ((domain = strchr(buf, '.')))
             {
               char *end = ares_striendstr(host->h_name, domain);
               if (end)
                 *end = 0;
             }
        }
      niquery->callback(niquery->arg, ARES_SUCCESS, niquery->timeouts, (char *)(host->h_name),
                        service);
      return;
    }
  /* We couldn't find the host, but it's OK, we can use the IP */
  else if (status == ARES_ENOTFOUND && !(niquery->flags & ARES_NI_NAMEREQD))
    {
      char ipbuf[IPBUFSIZ];
      if (niquery->family == AF_INET)
        ares_inet_ntop(AF_INET, &niquery->addr.addr4.sin_addr, ipbuf, IPBUFSIZ);
      else
        {
          ares_inet_ntop(AF_INET6, &niquery->addr.addr6.sin6_addr, ipbuf, IPBUFSIZ);
#ifdef HAVE_SOCKADDR_IN6_SIN6_SCOPE_ID
          append_scopeid(&niquery->addr.addr6, niquery->flags, ipbuf, sizeof(ipbuf));
#endif
        }
      /* They want a service too */
      if (niquery->flags & ARES_NI_LOOKUPSERVICE)
        {
          if (niquery->family == AF_INET)
            service = lookup_service(niquery->addr.addr4.sin_port,
                                     niquery->flags, srvbuf, sizeof(srvbuf));
          else
            service = lookup_service(niquery->addr.addr6.sin6_port,
                                     niquery->flags, srvbuf, sizeof(srvbuf));
        }
      niquery->callback(niquery->arg, ARES_SUCCESS, 0, ipbuf, service);
      return;
    }
  niquery->callback(niquery->arg, status, 0, NULL, NULL);
  free(niquery);
}

static char *lookup_service(unsigned short port, int flags,
                            char *buf, size_t buflen)
{
  const char *proto;
  struct servent *sep;
#ifdef HAVE_GETSERVBYPORT_R
  struct servent se;
#endif
  char tmpbuf[4096];

  if (port)
    {
      if (flags & ARES_NI_NUMERICSERV)
        sep = NULL;
      else
        {
          if (flags & ARES_NI_UDP)
            proto = "udp";
          else if (flags & ARES_NI_SCTP)
            proto = "sctp";
          else if (flags & ARES_NI_DCCP)
            proto = "dccp";
          else
            proto = "tcp";
#ifdef HAVE_GETSERVBYPORT_R
          sep = &se;
          memset(tmpbuf, 0, sizeof(tmpbuf));
#if GETSERVBYPORT_R_ARGS == 6
          if (getservbyport_r(port, proto, &se, (void *)tmpbuf, sizeof(tmpbuf), &sep) != 0)
            sep = NULL;
#elif GETSERVBYPORT_R_ARGS == 5
          sep = getservbyport_r(port, proto, &se, (void *)tmpbuf, sizeof(tmpbuf));
#elif GETSERVBYPORT_R_ARGS == 4
          if (getservbyport_r(port, proto, &se, (void *)tmpbuf) != 0)
            sep = NULL;
#else
          /* Lets just hope the OS uses TLS! */
          sep = getservbyport(port, proto);
#endif
#else
          /* Lets just hope the OS uses TLS! */
#if (defined(NETWARE) && !defined(__NOVELL_LIBC__))
          sep = getservbyport(port, (char*)proto);
#else
          sep = getservbyport(port, proto);
#endif
#endif
        }
      if (sep && sep->s_name)
        /* get service name */
        strcpy(tmpbuf, sep->s_name);
      else
        /* get port as a string */
        sprintf(tmpbuf, "%u", (unsigned int)ntohs(port));
      if (strlen(tmpbuf) < buflen)
        /* return it if buffer big enough */
        strcpy(buf, tmpbuf);
      else
        /* avoid reusing previous one */
        buf[0] = '\0';
      return buf;
    }
  buf[0] = '\0';
  return NULL;
}

#ifdef HAVE_SOCKADDR_IN6_SIN6_SCOPE_ID
static void append_scopeid(struct sockaddr_in6 *addr6, unsigned int flags,
                           char *buf, size_t buflen)
{
#ifdef HAVE_IF_INDEXTONAME
  int is_ll, is_mcll;
#endif
  char fmt_u[] = "%u";
  char fmt_lu[] = "%lu";
  char tmpbuf[IF_NAMESIZE + 2];
  size_t bufl;
  char *fmt = (sizeof(addr6->sin6_scope_id) > sizeof(unsigned int))?fmt_lu:fmt_u;

  tmpbuf[0] = '%';

#ifdef HAVE_IF_INDEXTONAME
  is_ll = IN6_IS_ADDR_LINKLOCAL(&addr6->sin6_addr);
  is_mcll = IN6_IS_ADDR_MC_LINKLOCAL(&addr6->sin6_addr);
  if ((flags & ARES_NI_NUMERICSCOPE) ||
      (!is_ll && !is_mcll))
    {
       sprintf(&tmpbuf[1], fmt, addr6->sin6_scope_id);
    }
  else
    {
      if (if_indextoname(addr6->sin6_scope_id, &tmpbuf[1]) == NULL)
        sprintf(&tmpbuf[1], fmt, addr6->sin6_scope_id);
    }
#else
  sprintf(&tmpbuf[1], fmt, addr6->sin6_scope_id);
  (void) flags;
#endif
  tmpbuf[IF_NAMESIZE + 1] = '\0';
  bufl = strlen(buf);

  if(bufl + strlen(tmpbuf) < buflen)
    /* only append the scopeid string if it fits in the target buffer */
    strcpy(&buf[bufl], tmpbuf);
}
#endif

/* Determines if s1 ends with the string in s2 (case-insensitive) */
static char *ares_striendstr(const char *s1, const char *s2)
{
  const char *c1, *c2, *c1_begin;
  int lo1, lo2;
  size_t s1_len = strlen(s1), s2_len = strlen(s2);

  /* If the substr is longer than the full str, it can't match */
  if (s2_len > s1_len)
    return NULL;

  /* Jump to the end of s1 minus the length of s2 */
  c1_begin = s1+s1_len-s2_len;
  c1 = (const char *)c1_begin;
  c2 = s2;
  while (c2 < s2+s2_len)
    {
      lo1 = tolower(*c1);
      lo2 = tolower(*c2);
      if (lo1 != lo2)
        return NULL;
      else
        {
          c1++;
          c2++;
        }
    }
  if (c2 == c1 && c2 == NULL)
    return (char *)c1_begin;
  return NULL;
}
