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
#include <netinet/in.h>
#include <arpa/nameser.h>
#endif

#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "ares.h"
#include "ares_dns.h"
#include "ares_private.h"

void ares_send(ares_channel channel, const unsigned char *qbuf, int qlen,
	       ares_callback callback, void *arg)
{
  struct query *query;
  int i;
  time_t now;

  /* Verify that the query is at least long enough to hold the header. */
  if (qlen < HFIXEDSZ || qlen >= (1 << 16))
    {
      callback(arg, ARES_EBADQUERY, NULL, 0);
      return;
    }

  /* Allocate space for query and allocated fields. */
  query = malloc(sizeof(struct query));
  if (!query)
    {
      callback(arg, ARES_ENOMEM, NULL, 0);
      return;
    }
  query->tcpbuf = malloc(qlen + 2);
  if (!query->tcpbuf)
    {
      free(query);
      callback(arg, ARES_ENOMEM, NULL, 0);
      return;
    }
  query->skip_server = malloc(channel->nservers * sizeof(int));
  if (!query->skip_server)
    {
      free(query->tcpbuf);
      free(query);
      callback(arg, ARES_ENOMEM, NULL, 0);
      return;
    }

  /* Compute the query ID.  Start with no timeout. */
  query->qid = DNS_HEADER_QID(qbuf);
  query->timeout = 0;

  /* Form the TCP query buffer by prepending qlen (as two
   * network-order bytes) to qbuf.
   */
  query->tcpbuf[0] = (qlen >> 8) & 0xff;
  query->tcpbuf[1] = qlen & 0xff;
  memcpy(query->tcpbuf + 2, qbuf, qlen);
  query->tcplen = qlen + 2;

  /* Fill in query arguments. */
  query->qbuf = query->tcpbuf + 2;
  query->qlen = qlen;
  query->callback = callback;
  query->arg = arg;

  /* Initialize query status. */
  query->try = 0;
  query->server = 0;
  for (i = 0; i < channel->nservers; i++)
    query->skip_server[i] = 0;
  query->using_tcp = (channel->flags & ARES_FLAG_USEVC) || qlen > PACKETSZ;
  query->error_status = ARES_ECONNREFUSED;

  /* Chain the query into this channel's query list. */
  query->next = channel->queries;
  channel->queries = query;

  /* Perform the first query action. */
  time(&now);
  ares__send_query(channel, query, now);
}
