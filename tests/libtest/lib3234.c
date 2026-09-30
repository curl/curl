/* Copyright (C) Albert Peschar, <albert@peschar.net>
 * SPDX-License-Identifier: curl
 */
/* Parsed CA stores shared between otherwise independent multi handles. */
#include "first.h"

#ifdef USE_OPENSSL
#include "urldata.h"
#include <openssl/ssl.h>

struct t3234_state {
  CURL *easy;
  X509_STORE *store;
  int resumed;
};

static size_t t3234_write(char *ptr, size_t size, size_t nmemb, void *userp)
{
  struct t3234_state *s = userp;
  const struct curl_tlssessioninfo *info = NULL;
  (void)ptr;
  if(!s->store &&
     !curl_easy_getinfo(s->easy, CURLINFO_TLS_SSL_PTR, &info) &&
     info && info->internals) {
    SSL *ssl = info->internals;
    X509_STORE *store = SSL_CTX_get_cert_store(SSL_get_SSL_CTX(ssl));
    if(!X509_STORE_up_ref(store))
      return 0;
    s->store = store;
    s->resumed = SSL_session_reused(ssl);
  }
  return size * nmemb;
}

static int t3234_locks;
static int t3234_unlocks;

static void t3234_lock(CURL *easy, curl_lock_data data,
                       curl_lock_access access, void *userp)
{
  (void)easy;
  (void)access;
  (void)userp;
  if(data == CURL_LOCK_DATA_CA)
    ++t3234_locks;
}

static void t3234_unlock(CURL *easy, curl_lock_data data, void *userp)
{
  (void)easy;
  (void)userp;
  if(data == CURL_LOCK_DATA_CA)
    ++t3234_unlocks;
}

static CURLcode t3234_fetch(const char *url, CURLSH *share, X509_STORE **store)
{
  struct t3234_state s;
  CURLcode result = CURLE_FAILED_INIT;
  long connects = 0;

  memset(&s, 0, sizeof(s));
  *store = NULL;
  s.easy = curl_easy_init();
  if(!s.easy)
    return result;

  easy_setopt(s.easy, CURLOPT_URL, url);
  easy_setopt(s.easy, CURLOPT_CAINFO, libtest_arg2);
  easy_setopt(s.easy, CURLOPT_CAPATH, NULL);
  /* NULL CAPATH normally restores the build-time default. Suppress that
   * fallback in this white-box test so only CAINFO populates the store. */
  ((struct Curl_easy *)s.easy)->set.ssl.custom_capath = TRUE;
  easy_setopt(s.easy, CURLOPT_SHARE, share);
  easy_setopt(s.easy, CURLOPT_WRITEFUNCTION, t3234_write);
  easy_setopt(s.easy, CURLOPT_WRITEDATA, &s);

  /* A fresh easy handle creates its own internal multi handle. */
  result = curl_easy_perform(s.easy);
  if(result) {
    curl_mfprintf(stderr, "fetch failed: %s\n", curl_easy_strerror(result));
    goto test_cleanup;
  }
  result = curl_easy_getinfo(s.easy, CURLINFO_NUM_CONNECTS, &connects);
  if(!result && (!s.store || connects != 1 || s.resumed)) {
    curl_mfprintf(stderr, "expected a CA store and a fresh TLS connection\n");
    result = CURLE_FAILED_INIT;
  }

test_cleanup:
  curl_easy_cleanup(s.easy);
  *store = s.store;
  return result;
}

static CURLcode test_lib3234(const char *URL)
{
  CURLSH *share = NULL;
  X509_STORE *first = NULL, *second = NULL, *private_store = NULL;
  CURLcode result = curl_global_init(CURL_GLOBAL_ALL);
  if(result)
    return result;

  t3234_locks = t3234_unlocks = 0;
  share = curl_share_init();
  if(!share ||
     curl_share_setopt(share, CURLSHOPT_SHARE, CURL_LOCK_DATA_CA) ||
     curl_share_setopt(share, CURLSHOPT_LOCKFUNC, t3234_lock) ||
     curl_share_setopt(share, CURLSHOPT_UNLOCKFUNC, t3234_unlock)) {
    curl_mfprintf(stderr, "CA share setup failed\n");
    result = CURLE_FAILED_INIT;
    goto test_cleanup;
  }

#define T3234_CHECK(cond, message) do { \
  if(!(cond)) { \
    curl_mfprintf(stderr, "%s\n", message); \
    result = CURLE_FAILED_INIT; \
    goto test_cleanup; \
  } \
} while(0)

  result = t3234_fetch(URL, share, &first);
  if(result)
    goto test_cleanup;
  result = t3234_fetch(URL, share, &second);
  if(result)
    goto test_cleanup;
  T3234_CHECK(first == second, "shared handles used different CA stores");

  result = t3234_fetch(URL, NULL, &private_store);
  if(result)
    goto test_cleanup;
  T3234_CHECK(first != private_store,
              "unshared handle reused shared CA store");
  T3234_CHECK(t3234_locks > 0 && t3234_locks == t3234_unlocks,
              "CA share locks missing or unbalanced");

  T3234_CHECK(!curl_share_setopt(share, CURLSHOPT_UNSHARE, CURL_LOCK_DATA_CA),
              "CA unshare failed");
  T3234_CHECK(!curl_share_setopt(share, CURLSHOPT_SHARE, CURL_LOCK_DATA_CA),
              "CA re-share failed");
  X509_STORE_free(second);
  second = NULL;
  result = t3234_fetch(URL, share, &second);
  if(result)
    goto test_cleanup;
  T3234_CHECK(first != second, "unshare did not clear the CA cache");
  T3234_CHECK(t3234_locks == t3234_unlocks, "CA share locks unbalanced");
  curl_mprintf("CA sharing: OK; connections and TLS sessions isolated\n");

test_cleanup:
  X509_STORE_free(private_store);
  X509_STORE_free(second);
  X509_STORE_free(first);
  curl_share_cleanup(share);
  curl_global_cleanup();
  return result;
#undef T3234_CHECK
}
#else
static CURLcode test_lib3234(const char *URL)
{
  (void)URL;
  return CURLE_OK;
}
#endif
