/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) 1998 - 2016, Daniel Stenberg, <daniel@haxx.se>, et al.
 *
 * This software is licensed as described in the file COPYING, which
 * you should have received as part of this distribution. The terms
 * are also available at https://curl.haxx.se/docs/copyright.html.
 *
 * You may opt to use, copy, modify, merge, publish, distribute and/or sell
 * copies of the Software, and permit persons to whom the Software is
 * furnished to do so, under the terms of the COPYING file.
 *
 * This software is distributed on an "AS IS" basis, WITHOUT WARRANTY OF ANY
 * KIND, either express or implied.
 *
 ***************************************************************************/
#include "curlcheck.h"

#ifdef HAVE_NETINET_IN_H
#  include <netinet/in.h>
#endif
#ifdef HAVE_NETDB_H
#  include <netdb.h>
#endif
#ifdef HAVE_ARPA_INET_H
#  include <arpa/inet.h>
#endif

#define ENABLE_CURLX_PRINTF
#include "curlx.h"

#include "hash.h"
#include "hostip.h"

#include "memdebug.h" /* LAST include file */

static struct SessionHandle *data;
static struct curl_hash hp;
static char *data_key;
static struct Curl_dns_entry *data_node;

static CURLcode unit_setup(void)
{
  int rc;
  data = curl_easy_init();
  if(!data)
    return CURLE_OUT_OF_MEMORY;

  rc = Curl_mk_dnscache(&hp);
  if(rc) {
    curl_easy_cleanup(data);
    curl_global_cleanup();
    return CURLE_OUT_OF_MEMORY;
  }
  return CURLE_OK;
}

static void unit_stop(void)
{
  if(data_node) {
    Curl_freeaddrinfo(data_node->addr);
    free(data_node);
  }
  free(data_key);
  Curl_hash_destroy(&hp);

  curl_easy_cleanup(data);
  curl_global_cleanup();
}

static Curl_addrinfo *fake_ai(void)
{
  static Curl_addrinfo *ai;
  int ss_size;

  ss_size = sizeof (struct sockaddr_in);

  if((ai = calloc(1, sizeof(Curl_addrinfo))) == NULL)
    return NULL;

  if((ai->ai_canonname = strdup("dummy")) == NULL) {
    free(ai);
    return NULL;
  }

  if((ai->ai_addr = calloc(1, ss_size)) == NULL) {
    free(ai->ai_canonname);
    free(ai);
    return NULL;
  }

  ai->ai_family = AF_INET;
  ai->ai_addrlen = ss_size;

  return ai;
}

static CURLcode create_node(void)
{
  data_key = aprintf("%s:%d", "dummy", 0);
  if(!data_key)
    return CURLE_OUT_OF_MEMORY;

  data_node = calloc(1, sizeof(struct Curl_dns_entry));
  if(!data_node)
    return CURLE_OUT_OF_MEMORY;

  data_node->addr = fake_ai();
  if(!data_node->addr)
    return CURLE_OUT_OF_MEMORY;

  return CURLE_OK;
}


UNITTEST_START

  struct Curl_dns_entry *nodep;
  size_t key_len;

  /* Test 1305 exits without adding anything to the hash */
  if(strcmp(arg, "1305") != 0) {
    CURLcode rc = create_node();
    abort_unless(rc == CURLE_OK, "data node creation failed");
    key_len = strlen(data_key);

    data_node->inuse = 1; /* hash will hold the reference */
    nodep = Curl_hash_add(&hp, data_key, key_len+1, data_node);
    abort_unless(nodep, "insertion into hash failed");
    /* Freeing will now be done by Curl_hash_destroy */
    data_node = NULL;
  }

UNITTEST_STOP
