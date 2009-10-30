/* Id$ */

/* Copyright 1998 by the Massachusetts Institute of Technology.
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

/*
 * ares_parse_srv_reply created by Jakub Hrozek <jhrozek@redhat.com>
 *      on behalf of Red Hat - http://www.redhat.com
 */

#include "setup.h"

#ifdef HAVE_SYS_SOCKET_H
#  include <sys/socket.h>
#endif
#ifdef HAVE_NETINET_IN_H
#  include <netinet/in.h>
#endif
#ifdef HAVE_NETDB_H
#  include <netdb.h>
#endif
#ifdef HAVE_ARPA_INET_H
#  include <arpa/inet.h>
#endif
#ifdef HAVE_ARPA_NAMESER_H
#  include <arpa/nameser.h>
#else
#  include "nameser.h"
#endif
#ifdef HAVE_ARPA_NAMESER_COMPAT_H
#  include <arpa/nameser_compat.h>
#endif

#include <stdlib.h>
#include <string.h>
#include "ares.h"
#include "ares_dns.h"
#include "ares_private.h"

/* AIX portability check */
#ifndef T_SRV
#  define T_SRV 33 /* server selection */
#endif

int
ares_parse_srv_reply (const unsigned char *abuf, int alen,
                      struct ares_srv_reply **srv_out, int *nsrvreply)
{
  unsigned int qdcount, ancount;
  const unsigned char *aptr;
  int status, i, rr_type, rr_class, rr_len;
  long len;
  char *hostname = NULL, *rr_name = NULL;
  struct ares_srv_reply *srv = NULL;

  /* Set *srv_out to NULL for all failure cases. */
  *srv_out = NULL;

  /* Same with *nsrvreply. */
  *nsrvreply = 0;

  /* Give up if abuf doesn't have room for a header. */
  if (alen < HFIXEDSZ)
    return ARES_EBADRESP;

  /* Fetch the question and answer count from the header. */
  qdcount = DNS_HEADER_QDCOUNT (abuf);
  ancount = DNS_HEADER_ANCOUNT (abuf);
  if (qdcount != 1)
    return ARES_EBADRESP;
  if (ancount == 0)
    return ARES_ENODATA;

  /* Expand the name from the question, and skip past the question. */
  aptr = abuf + HFIXEDSZ;
  status = ares_expand_name (aptr, abuf, alen, &hostname, &len);
  if (status != ARES_SUCCESS)
    return status;

  if (aptr + len + QFIXEDSZ > abuf + alen)
    {
      free (hostname);
      return ARES_EBADRESP;
    }
  aptr += len + QFIXEDSZ;

  /* Allocate ares_srv_reply array; ancount gives an upper bound */
  srv = malloc ((ancount) * sizeof (struct ares_srv_reply));
  if (!srv)
    {
      free (hostname);
      return ARES_ENOMEM;
    }

  /* Examine each answer resource record (RR) in turn. */
  for (i = 0; i < (int) ancount; i++)
    {
      /* Decode the RR up to the data field. */
      status = ares_expand_name (aptr, abuf, alen, &rr_name, &len);
      if (status != ARES_SUCCESS)
        {
          break;
        }
      aptr += len;
      if (aptr + RRFIXEDSZ > abuf + alen)
        {
          status = ARES_EBADRESP;
          break;
        }
      rr_type = DNS_RR_TYPE (aptr);
      rr_class = DNS_RR_CLASS (aptr);
      rr_len = DNS_RR_LEN (aptr);
      aptr += RRFIXEDSZ;

      /* Check if we are really looking at a SRV record */
      if (rr_class == C_IN && rr_type == T_SRV)
        {
          /* parse the SRV record itself */
          if (rr_len < 6)
            {
              status = ARES_EBADRESP;
              break;
            }

          srv[i].priority = ntohs (*((unsigned short *)aptr));
          aptr += sizeof(unsigned short);
          srv[i].weight = ntohs (*((unsigned short *)aptr));
          aptr += sizeof(unsigned short);
          srv[i].port = ntohs (*((unsigned short *)aptr));
          aptr += sizeof(unsigned short);

          status = ares_expand_name (aptr, abuf, alen, &srv[i].host, &len);
          if (status != ARES_SUCCESS)
            break;

          /* Move on to the next record */
          aptr += len;

          /* Don't lose memory in the next iteration */
          free (rr_name);
          rr_name = NULL;
        }
    }

  /* clean up on error */
  if (status != ARES_SUCCESS)
    {
      free (srv);
      free (hostname);
      free (rr_name);
      return status;
    }

  /* everything looks fine, return the data */
  *srv_out = srv;
  *nsrvreply = ancount;

  free (hostname);
  free (rr_name);
  return status;
}
