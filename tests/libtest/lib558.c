/*****************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * $Id$
 */

#include "test.h"

#ifdef HAVE_NETDB_H
#include <netdb.h>
#endif
#ifdef HAVE_ARPA_INET_H
#include <arpa/inet.h>
#endif

#define ENABLE_CURLX_PRINTF
#include "curlx.h"

#include "hash.h"
#include "hostip.h"

#include "memory.h"
#include "memdebug.h"

int test(char *URL)
{
  CURL *easyh;
  struct curl_hash *hp;
  char *data_key;
  struct Curl_dns_entry *data_node;
  struct Curl_dns_entry *nodep;
  size_t key_len;
 
  (void)URL; /* not used */

  easyh = curl_easy_init();
  if(!easyh) {
    printf("easy handle init failed\n");
    return TEST_ERR_MAJOR_BAD;
  }
  printf("easy handle init OK\n");

  printf("creating hash...\n");
  hp = Curl_mk_dnscache();
  if(!hp) {
    printf("hash creation failed\n");
    return TEST_ERR_MAJOR_BAD;
  }
  printf("hash creation OK\n");

  /**/

  data_key = aprintf("%s:%d", "dummy", 0);
  if(!data_key) {
    printf("data key creation failed\n");
    return TEST_ERR_MAJOR_BAD;
  }
  key_len = strlen(data_key);

  data_node = calloc(1, sizeof(struct Curl_dns_entry));
  if(!data_node) {
    printf("data node creation failed\n");
    return TEST_ERR_MAJOR_BAD;
  }

  data_node->addr = Curl_ip2addr(INADDR_ANY, "dummy", 0);
  if(!data_node->addr) {
    printf("actual data creation failed\n");
    return TEST_ERR_MAJOR_BAD;
  }

  nodep = Curl_hash_add(hp, data_key, key_len+1, (void *)data_node);
  if(!nodep) {
    printf("insertion into hash failed\n");
    return TEST_ERR_MAJOR_BAD;
  }

  free(data_key);

  /**/

  printf("destroying hash...\n");
  Curl_hash_destroy(hp);
  printf("hash destruction OK\n");

  printf("destroying easy handle...\n");
  curl_easy_cleanup(easyh);
  printf("easy handle destruction OK\n");

  curl_global_cleanup();

  return 0; /* OK */
}

