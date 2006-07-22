/* $Id$ */

/* Copyright (C) 2004 by Daniel Stenberg et al
 *
 * Permission to use, copy, modify, and distribute this software and its
 * documentation for any purpose and without fee is hereby granted, provided
 * that the above copyright notice appear in all copies and that both that
 * copyright notice and this permission notice appear in supporting
 * documentation, and that the name of M.I.T. not be used in advertising or
 * publicity pertaining to distribution of the software without specific,
 * written prior permission.  M.I.T. makes no representations about the
 * suitability of this software for any purpose.  It is provided "as is"
 * without express or implied warranty.
 */

#include "setup.h"
#include <stdlib.h>
#include "ares.h"
#include "ares_private.h"

/*
 * ares_cancel() cancels a ongoing request/resolve that might be going on on
 * the given channel. It does NOT kill the channel, use ares_destroy() for
 * that.
 */
void ares_cancel(ares_channel channel)
{
  struct query *query, *next;
  int i;

  for (query = channel->queries; query; query = next)
  {
    next = query->next;
    query->callback(query->arg, ARES_ETIMEOUT, NULL, 0);
    free(query->tcpbuf);
    free(query->skip_server);
    free(query);
  }
  channel->queries = NULL;
  if (!(channel->flags & ARES_FLAG_STAYOPEN))
  {
    for (i = 0; i < channel->nservers; i++)
      ares__close_sockets(channel, &channel->servers[i]);
  }
}
