/* Copyright (C) Albert Peschar, <albert@peschar.net>
 * SPDX-License-Identifier: curl
 */
/* Parsed CA stores shared between otherwise independent multi handles. */
#include "first.h"

#ifdef USE_OPENSSL
#include "urldata.h"

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

static size_t t3234_write(char *ptr, size_t size, size_t nmemb, void *userp)
{
  (void)ptr;
  (void)userp;
  return size * nmemb;
}

static bool t3234_copy_ca(const char *source, const char *target)
{
  FILE *src = curlx_fopen(source, "rb");
  FILE *dst;
  char buf[4096];
  size_t n;
  bool ok = TRUE;

  if(!src)
    return FALSE;
  dst = curlx_fopen(target, "wb");
  if(!dst) {
    curlx_fclose(src);
    return FALSE;
  }
  while((n = fread(buf, 1, sizeof(buf), src))) {
    if(fwrite(buf, 1, n, dst) != n) {
      ok = FALSE;
      break;
    }
  }
  if(ferror(src))
    ok = FALSE;
  curlx_fclose(src);
  if(curlx_fclose(dst))
    ok = FALSE;
  return ok;
}

static CURLcode t3234_fetch(const char *url, CURLSH *share)
{
  CURL *easy = curl_easy_init();
  CURLcode result = CURLE_FAILED_INIT;
  long connects = 0;
  if(!easy)
    return result;

  easy_setopt(easy, CURLOPT_URL, url);
  easy_setopt(easy, CURLOPT_CAINFO, libtest_arg3);
  easy_setopt(easy, CURLOPT_CAPATH, NULL);
  /* NULL CAPATH normally restores the build-time default. Suppress that
   * fallback in this white-box test so only CAINFO populates the store. */
  ((struct Curl_easy *)easy)->set.ssl.custom_capath = TRUE;
  easy_setopt(easy, CURLOPT_CA_CACHE_TIMEOUT, -1L);
  easy_setopt(easy, CURLOPT_SHARE, share);
  easy_setopt(easy, CURLOPT_WRITEFUNCTION, t3234_write);

  /* A fresh easy handle creates its own internal multi handle. Certificate
   * and hostname verification remain enabled. */
  result = curl_easy_perform(easy);
  if(!result) {
    result = curl_easy_getinfo(easy, CURLINFO_NUM_CONNECTS, &connects);
    if(!result && connects != 1) {
      curl_mfprintf(stderr, "expected a fresh connection\n");
      result = CURLE_FAILED_INIT;
    }
  }

test_cleanup:
  curl_easy_cleanup(easy);
  return result;
}

static CURLcode test_lib3234(const char *URL)
{
  CURLSH *share = NULL;
  CURLcode result;

  if(!libtest_arg2 || !libtest_arg3 || !strcmp(libtest_arg2, libtest_arg3))
    return TEST_ERR_USAGE;
  result = curl_global_init(CURL_GLOBAL_ALL);
  if(result)
    return result;

#define T3234_CHECK(cond, message) do { \
  if(!(cond)) { \
    curl_mfprintf(stderr, "%s\n", message); \
    result = CURLE_FAILED_INIT; \
    goto test_cleanup; \
  } \
} while(0)

  t3234_locks = t3234_unlocks = 0;
  T3234_CHECK(t3234_copy_ca(libtest_arg2, libtest_arg3), "CA copy failed");
  share = curl_share_init();
  T3234_CHECK(share &&
              !curl_share_setopt(share, CURLSHOPT_SHARE, CURL_LOCK_DATA_CA) &&
              !curl_share_setopt(share, CURLSHOPT_LOCKFUNC, t3234_lock) &&
              !curl_share_setopt(share, CURLSHOPT_UNLOCKFUNC, t3234_unlock),
              "CA share setup failed");

  result = t3234_fetch(URL, share);
  T3234_CHECK(!result, "initial fetch failed");
  T3234_CHECK(!remove(libtest_arg3), "CA removal failed");

  /* Only the shared cache can supply the now-missing CA file. */
  result = t3234_fetch(URL, share);
  T3234_CHECK(!result, "shared handle did not reuse the cached CA store");
  result = t3234_fetch(URL, NULL);
  T3234_CHECK(result == CURLE_SSL_CACERT_BADFILE,
              "unshared handle did not fail for the missing CA file");
  T3234_CHECK(t3234_locks > 0 && t3234_locks == t3234_unlocks,
              "CA share locks missing or unbalanced");

  T3234_CHECK(!curl_share_setopt(share, CURLSHOPT_UNSHARE, CURL_LOCK_DATA_CA),
              "CA unshare failed");
  T3234_CHECK(!curl_share_setopt(share, CURLSHOPT_SHARE, CURL_LOCK_DATA_CA),
              "CA re-share failed");
  result = t3234_fetch(URL, share);
  T3234_CHECK(result == CURLE_SSL_CACERT_BADFILE,
              "unshare did not clear the CA cache");
  T3234_CHECK(t3234_locks == t3234_unlocks, "CA share locks unbalanced");
  result = CURLE_OK;
  curl_mprintf("CA sharing: OK\n");

test_cleanup:
  (void)remove(libtest_arg3);
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
