/*****************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 */

#include "test.h"

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

#define ENABLE_CURLX_PRINTF
#include "curlx.h"

#include "hash.h"
#include "hostip.h"

#include "curl_memory.h"
#include "memdebug.h"

/* This source file is used for test # 558 and 559 */

/*
 * This hacky test bypasses the library external API,
 * using internal only libcurl functions. So don't be
 * surprised if we cannot run it when the library has
 * been built with hidden symbols, exporting only the
 * ones in the public API.
 */

#if defined(CURL_HIDDEN_SYMBOLS)
#  define SKIP_TEST 1
#elif defined(WIN32) && !defined(CURL_STATICLIB)
#  define SKIP_TEST 1
#else
#  undef  SKIP_TEST
#endif


#if !defined(SKIP_TEST)

#ifdef LIB559
static Curl_addrinfo *fake_ai(void)
{
  Curl_addrinfo *ai;
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
#endif /* LIB559 */


int test(char *URL)
{
  CURL *easyh = NULL;
  struct curl_hash *hp = NULL;
  int result = 0;

  if(!strcmp(URL, "check")) {
    /* test harness script verifying if this test can run */
    return 0; /* sure, run this! */
  }

  easyh = curl_easy_init();
  if(!easyh) {
    fprintf(stdout, "easy handle init failed\n");
    result = TEST_ERR_MAJOR_BAD;
    goto cleanup;
  }
  fprintf(stdout, "easy handle init OK\n");

  fprintf(stdout, "creating hash...\n");
  hp = Curl_mk_dnscache();
  if(!hp) {
    fprintf(stdout, "hash creation failed\n");
    result = TEST_ERR_MAJOR_BAD;
    goto cleanup;
  }
  fprintf(stdout, "hash creation OK\n");

  /**/
#ifdef LIB559
  {
    char *data_key;
    struct Curl_dns_entry *data_node;
    struct Curl_dns_entry *nodep;
    size_t key_len;

    data_key = aprintf("%s:%d", "dummy", 0);
    if(!data_key) {
      fprintf(stdout, "data key creation failed\n");
      result = TEST_ERR_MAJOR_BAD;
      goto cleanup;
    }
    key_len = strlen(data_key);

    data_node = calloc(1, sizeof(struct Curl_dns_entry));
    if(!data_node) {
      fprintf(stdout, "data node creation failed\n");
      result = TEST_ERR_MAJOR_BAD;
      free(data_key);
      goto cleanup;
    }

    data_node->addr = fake_ai();
    if(!data_node->addr) {
      fprintf(stdout, "actual data creation failed\n");
      result = TEST_ERR_MAJOR_BAD;
      free(data_node);
      free(data_key);
      goto cleanup;
    }

    nodep = Curl_hash_add(hp, data_key, key_len+1, (void *)data_node);
    if(!nodep) {
      fprintf(stdout, "insertion into hash failed\n");
      result = TEST_ERR_MAJOR_BAD;
      Curl_freeaddrinfo(data_node->addr);
      free(data_node);
      free(data_key);
      goto cleanup;
    }

    free(data_key);
  }
#endif /* LIB559 */
  /**/

cleanup:

  fprintf(stdout, "destroying hash...\n");
  Curl_hash_destroy(hp);
  fprintf(stdout, "hash destruction OK\n");

  fprintf(stdout, "destroying easy handle...\n");
  curl_easy_cleanup(easyh);
  fprintf(stdout, "easy handle destruction OK\n");

  curl_global_cleanup();

  return result;
}


#else /* !defined(SKIP_TEST) */


int test(char *URL)
{
  (void)URL;
  fprintf(stdout, "libcurl built with hidden symbols");
  return 1; /* skip test */
}


#endif /* !defined(SKIP_TEST) */
