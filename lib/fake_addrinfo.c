/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
 *
 * This software is licensed as described in the file COPYING, which
 * you should have received as part of this distribution. The terms
 * are also available at https://curl.se/docs/copyright.html.
 *
 * You may opt to use, copy, modify, merge, publish, distribute and/or sell
 * copies of the Software, and permit persons to whom the Software is
 * furnished to do so, under the terms of the COPYING file.
 *
 * This software is distributed on an "AS IS" basis, WITHOUT WARRANTY OF ANY
 * KIND, either express or implied.
 *
 * SPDX-License-Identifier: curl
 *
 ***************************************************************************/

#include "curl_setup.h"
#include "fake_addrinfo.h"

#ifdef USE_FAKE_GETADDRINFO

#include <string.h>
#include <stdlib.h>
#include <ares.h>

/* The last 3 #include files should be in this order */
#include "curl_printf.h"
#include "curl_memory.h"
#include "memdebug.h"

void r_freeaddrinfo(struct addrinfo *cahead)
{
  struct addrinfo *canext;
  struct addrinfo *ca;

  for(ca = cahead; ca; ca = canext) {
    canext = ca->ai_next;
    free(ca);
  }
}

struct context {
  struct ares_addrinfo *result;
};

static void async_addrinfo_cb(void *userp, int status, int timeouts,
                              struct ares_addrinfo *result)
{
  struct context *ctx = (struct context *)userp;
  (void)timeouts;
  if(ARES_SUCCESS == status) {
    ctx->result = result;
  }
}

/* convert the c-ares version into the "native" version */
static struct addrinfo *mk_getaddrinfo(const struct ares_addrinfo *aihead)
{
  const struct ares_addrinfo_node *ai;
  struct addrinfo *ca;
  struct addrinfo *cafirst = NULL;
  struct addrinfo *calast = NULL;
  const char *name = aihead->name;

  /* traverse the addrinfo list */
  for(ai = aihead->nodes; ai != NULL; ai = ai->ai_next) {
    size_t ss_size;
    size_t namelen = name ? strlen(name) + 1 : 0;
    /* ignore elements with unsupported address family, */
    /* settle family-specific sockaddr structure size.  */
    if(ai->ai_family == AF_INET)
      ss_size = sizeof(struct sockaddr_in);
    else if(ai->ai_family == AF_INET6)
      ss_size = sizeof(struct sockaddr_in6);
    else
      continue;

    /* ignore elements without required address info */
    if(!ai->ai_addr || !(ai->ai_addrlen > 0))
      continue;

    /* ignore elements with bogus address size */
    if((size_t)ai->ai_addrlen < ss_size)
      continue;

    ca = malloc(sizeof(struct addrinfo) + ss_size + namelen);
    if(!ca) {
      r_freeaddrinfo(cafirst);
      return NULL;
    }

    /* copy each structure member individually, member ordering, */
    /* size, or padding might be different for each platform.    */

    ca->ai_flags     = ai->ai_flags;
    ca->ai_family    = ai->ai_family;
    ca->ai_socktype  = ai->ai_socktype;
    ca->ai_protocol  = ai->ai_protocol;
    ca->ai_addrlen   = (curl_socklen_t)ss_size;
    ca->ai_addr      = NULL;
    ca->ai_canonname = NULL;
    ca->ai_next      = NULL;

    ca->ai_addr = (void *)((char *)ca + sizeof(struct addrinfo));
    memcpy(ca->ai_addr, ai->ai_addr, ss_size);

    if(namelen) {
      ca->ai_canonname = (void *)((char *)ca->ai_addr + ss_size);
      memcpy(ca->ai_canonname, name, namelen);

      /* the name is only pointed to by the first entry in the "real"
         addrinfo chain, so stop now */
      name = NULL;
    }

    /* if the return list is empty, this becomes the first element */
    if(!cafirst)
      cafirst = ca;

    /* add this element last in the return list */
    if(calast)
      calast->ai_next = ca;
    calast = ca;
  }

  return cafirst;
}

/*
  RETURN VALUE

  getaddrinfo() returns 0 if it succeeds, or one of the following nonzero
  error codes:

  ...
*/
int r_getaddrinfo(const char *node,
                  const char *service,
                  const struct addrinfo *hints,
                  struct addrinfo **res)
{
  int status;
  struct context ctx;
  struct ares_options options;
  int optmask = 0;
  struct ares_addrinfo_hints ahints;
  ares_channel channel;
  int rc = 0;

  memset(&options, 0, sizeof(options));
  optmask      |= ARES_OPT_EVENT_THREAD;
  options.evsys = ARES_EVSYS_DEFAULT;

  memset(&ahints, 0, sizeof(ahints));
  memset(&ctx, 0, sizeof(ctx));

  if(hints) {
    ahints.ai_flags = hints->ai_flags;
    ahints.ai_family = hints->ai_family;
    ahints.ai_socktype = hints->ai_socktype;
    ahints.ai_protocol = hints->ai_protocol;
  }

  status = ares_init_options(&channel, &options, optmask);
  if(status)
    return EAI_MEMORY; /* major problem */

  else {
    const char *env = getenv("CURL_DNS_SERVER");
    if(env) {
      rc = ares_set_servers_ports_csv(channel, env);
      if(rc) {
        fprintf(stderr, "ares_set_servers_ports_csv failed: %d", rc);
        /* Cleanup */
        ares_destroy(channel);
        return EAI_MEMORY; /* we can't run */
      }
    }
  }

  ares_getaddrinfo(channel, node, service, &ahints,
                   async_addrinfo_cb, &ctx);

  /* Wait until no more requests are left to be processed */
  ares_queue_wait_empty(channel, -1);

  if(ctx.result) {
    /* convert the c-ares version */
    *res = mk_getaddrinfo(ctx.result);
    /* free the old */
    ares_freeaddrinfo(ctx.result);
  }
  else
    rc = EAI_NONAME; /* got nothing */

  /* Cleanup */
  ares_destroy(channel);

  return rc;
}

#endif /* USE_FAKE_GETADDRINFO */
