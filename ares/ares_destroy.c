/* $Id$ */

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
#include <stdlib.h>
#include "ares.h"
#include "ares_private.h"

void ares_destroy_options(struct ares_options *options)
{
  int i;

  free(options->servers);
  for (i = 0; i < options->ndomains; i++)
    free(options->domains[i]);
  free(options->domains);
  if(options->sortlist)
    free(options->sortlist);
  free(options->lookups);
}

void ares_destroy(ares_channel channel)
{
  int i;
  struct query *query;

  if (!channel)
    return;

  if (channel->servers) {
    for (i = 0; i < channel->nservers; i++)
      ares__close_sockets(channel, &channel->servers[i]);
    free(channel->servers);
  }

  if (channel->domains) {
    for (i = 0; i < channel->ndomains; i++)
      free(channel->domains[i]);
    free(channel->domains);
  }

  if(channel->sortlist)
    free(channel->sortlist);

  if (channel->lookups)
    free(channel->lookups);

  while (channel->queries) {
    query = channel->queries;
    channel->queries = query->next;
    query->callback(query->arg, ARES_EDESTRUCTION, 0, NULL, 0);
    if (query->tcpbuf)
      free(query->tcpbuf);
    if (query->server_info)
      free(query->server_info);
    free(query);
  }

  free(channel);
}
