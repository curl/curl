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

#include "setup.h"
#include <sys/types.h>

#if defined(WIN32) && !defined(WATT32)
#include "nameser.h"
#else
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <arpa/nameser.h>
#endif

#include <stdlib.h>
#include <string.h>
#include "ares.h"
#include "ares_dns.h"
#include "ares_private.h"

int ares_parse_a_reply(const unsigned char *abuf, int alen,
		       struct hostent **host)
{
  unsigned int qdcount, ancount;
  int status, i, rr_type, rr_class, rr_len, naddrs;
  int naliases;
  long len;
  const unsigned char *aptr;
  char *hostname, *rr_name, *rr_data, **aliases;
  struct in_addr *addrs;
  struct hostent *hostent;

  /* Set *host to NULL for all failure cases. */
  *host = NULL;

  /* Give up if abuf doesn't have room for a header. */
  if (alen < HFIXEDSZ)
    return ARES_EBADRESP;

  /* Fetch the question and answer count from the header. */
  qdcount = DNS_HEADER_QDCOUNT(abuf);
  ancount = DNS_HEADER_ANCOUNT(abuf);
  if (qdcount != 1)
    return ARES_EBADRESP;

  /* Expand the name from the question, and skip past the question. */
  aptr = abuf + HFIXEDSZ;
  status = ares_expand_name(aptr, abuf, alen, &hostname, &len);
  if (status != ARES_SUCCESS)
    return status;
  if (aptr + len + QFIXEDSZ > abuf + alen)
    {
      free(hostname);
      return ARES_EBADRESP;
    }
  aptr += len + QFIXEDSZ;

  /* Allocate addresses and aliases; ancount gives an upper bound for both. */
  addrs = malloc(ancount * sizeof(struct in_addr));
  if (!addrs)
    {
      free(hostname);
      return ARES_ENOMEM;
    }
  aliases = malloc((ancount + 1) * sizeof(char *));
  if (!aliases)
    {
      free(hostname);
      free(addrs);
      return ARES_ENOMEM;
    }
  naddrs = 0;
  naliases = 0;

  /* Examine each answer resource record (RR) in turn. */
  for (i = 0; i < (int)ancount; i++)
    {
      /* Decode the RR up to the data field. */
      status = ares_expand_name(aptr, abuf, alen, &rr_name, &len);
      if (status != ARES_SUCCESS)
	break;
      aptr += len;
      if (aptr + RRFIXEDSZ > abuf + alen)
	{
	  status = ARES_EBADRESP;
	  break;
	}
      rr_type = DNS_RR_TYPE(aptr);
      rr_class = DNS_RR_CLASS(aptr);
      rr_len = DNS_RR_LEN(aptr);
      aptr += RRFIXEDSZ;

      if (rr_class == C_IN && rr_type == T_A
	  && rr_len == sizeof(struct in_addr)
	  && strcasecmp(rr_name, hostname) == 0)
	{
	  memcpy(&addrs[naddrs], aptr, sizeof(struct in_addr));
	  naddrs++;
	  status = ARES_SUCCESS;
	}

      if (rr_class == C_IN && rr_type == T_CNAME)
	{
	  /* Record the RR name as an alias. */
	  aliases[naliases] = rr_name;
	  naliases++;

	  /* Decode the RR data and replace the hostname with it. */
	  status = ares_expand_name(aptr, abuf, alen, &rr_data, &len);
	  if (status != ARES_SUCCESS)
	    break;
	  free(hostname);
	  hostname = rr_data;
	}
      else
	free(rr_name);

      aptr += rr_len;
      if (aptr > abuf + alen)
	{
	  status = ARES_EBADRESP;
	  break;
	}
    }

  if (status == ARES_SUCCESS && naddrs == 0)
    status = ARES_ENODATA;
  if (status == ARES_SUCCESS)
    {
      /* We got our answer.  Allocate memory to build the host entry. */
      aliases[naliases] = NULL;
      hostent = malloc(sizeof(struct hostent));
      if (hostent)
	{
	  hostent->h_addr_list = malloc((naddrs + 1) * sizeof(char *));
	  if (hostent->h_addr_list)
	    {
	      /* Fill in the hostent and return successfully. */
	      hostent->h_name = hostname;
	      hostent->h_aliases = aliases;
	      hostent->h_addrtype = AF_INET;
	      hostent->h_length = sizeof(struct in_addr);
	      for (i = 0; i < naddrs; i++)
		hostent->h_addr_list[i] = (char *) &addrs[i];
	      hostent->h_addr_list[naddrs] = NULL;
	      *host = hostent;
	      return ARES_SUCCESS;
	    }
	  free(hostent);
	}
      status = ARES_ENOMEM;
    }
  for (i = 0; i < naliases; i++)
    free(aliases[i]);
  free(aliases);
  free(addrs);
  free(hostname);
  return status;
}
