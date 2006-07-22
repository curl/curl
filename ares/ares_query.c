/* $Id: */

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
#ifdef HAVE_ARPA_NAMESER_COMPAT_H
#include <arpa/nameser_compat.h>
#endif
#endif

#include <stdlib.h>
#include "ares.h"
#include "ares_dns.h"
#include "ares_private.h"

struct qquery {
  ares_callback callback;
  void *arg;
};

static void qcallback(void *arg, int status, unsigned char *abuf, int alen);

void ares_query(ares_channel channel, const char *name, int dnsclass,
                int type, ares_callback callback, void *arg)
{
  struct qquery *qquery;
  unsigned char *qbuf;
  int qlen, rd, status;

  /* Compose the query. */
  rd = !(channel->flags & ARES_FLAG_NORECURSE);
  status = ares_mkquery(name, dnsclass, type, channel->next_id, rd, &qbuf,
                        &qlen);
  channel->next_id++;
  if (status != ARES_SUCCESS)
    {
      callback(arg, status, NULL, 0);
      return;
    }

  /* Allocate and fill in the query structure. */
  qquery = malloc(sizeof(struct qquery));
  if (!qquery)
    {
      ares_free_string(qbuf);
      callback(arg, ARES_ENOMEM, NULL, 0);
      return;
    }
  qquery->callback = callback;
  qquery->arg = arg;

  /* Send it off.  qcallback will be called when we get an answer. */
  ares_send(channel, qbuf, qlen, qcallback, qquery);
  ares_free_string(qbuf);
}

static void qcallback(void *arg, int status, unsigned char *abuf, int alen)
{
  struct qquery *qquery = (struct qquery *) arg;
  unsigned int ancount;
  int rcode;

  if (status != ARES_SUCCESS)
    qquery->callback(qquery->arg, status, abuf, alen);
  else
    {
      /* Pull the response code and answer count from the packet. */
      rcode = DNS_HEADER_RCODE(abuf);
      ancount = DNS_HEADER_ANCOUNT(abuf);

      /* Convert errors. */
      switch (rcode)
        {
        case NOERROR:
          status = (ancount > 0) ? ARES_SUCCESS : ARES_ENODATA;
          break;
        case FORMERR:
          status = ARES_EFORMERR;
          break;
        case SERVFAIL:
          status = ARES_ESERVFAIL;
          break;
        case NXDOMAIN:
          status = ARES_ENOTFOUND;
          break;
        case NOTIMP:
          status = ARES_ENOTIMP;
          break;
        case REFUSED:
          status = ARES_EREFUSED;
          break;
        }
      qquery->callback(qquery->arg, status, abuf, alen);
    }
  free(qquery);
}
