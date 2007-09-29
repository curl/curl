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

#ifdef HAVE_SYS_TIME_H
#include <sys/time.h>
#endif

#include <time.h>

#include "ares.h"
#include "ares_private.h"

/* WARNING: Beware that this is linear in the number of outstanding
 * requests! You are probably far better off just calling ares_process()
 * once per second, rather than calling ares_timeout() to figure out
 * when to next call ares_process().
 */
struct timeval *ares_timeout(ares_channel channel, struct timeval *maxtv,
                             struct timeval *tvbuf)
{
  struct query *query;
  struct list_node* list_head;
  struct list_node* list_node;
  time_t now;
  time_t offset, min_offset; /* these use time_t since some 32 bit systems
                                still use 64 bit time_t! (like VS2005) */

  /* No queries, no timeout (and no fetch of the current time). */
  if (ares__is_list_empty(&(channel->all_queries)))
    return maxtv;

  /* Find the minimum timeout for the current set of queries. */
  time(&now);
  min_offset = -1;

  list_head = &(channel->all_queries);
  for (list_node = list_head->next; list_node != list_head;
       list_node = list_node->next)
    {
      query = list_node->data;
      if (query->timeout == 0)
        continue;
      offset = query->timeout - now;
      if (offset < 0)
        offset = 0;
      if (min_offset == -1 || offset < min_offset)
        min_offset = offset;
    }

  /* If we found a minimum timeout and it's sooner than the one
   * specified in maxtv (if any), return it.  Otherwise go with
   * maxtv.
   */
  if (min_offset != -1 && (!maxtv || min_offset <= maxtv->tv_sec))
    {
      tvbuf->tv_sec = (long)min_offset;
      tvbuf->tv_usec = 0;
      return tvbuf;
    }
  else
    return maxtv;
}
