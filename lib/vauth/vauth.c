/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) Steve Holme, <steve_holme@hotmail.com>.
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

#include "../curl_setup.h"

#include <curl/curl.h>

#include "vauth.h"
#include "../strdup.h"
#include "../urldata.h"
#include "../curlx/multibyte.h"
#include "../curl_printf.h"
#include "../url.h"

/* The last #include files should be: */
#include "../curl_memory.h"
#include "../memdebug.h"

/*
 * Curl_auth_build_spn()
 *
 * This is used to build an SPN string in the following formats:
 *
 * service/host@realm (Not currently used)
 * service/host       (Not used by GSS-API)
 * service@realm      (Not used by Windows SSPI)
 *
 * Parameters:
 *
 * service  [in] - The service type such as http, smtp, pop or imap.
 * host     [in] - The hostname.
 * realm    [in] - The realm.
 *
 * Returns a pointer to the newly allocated SPN.
 */
#ifndef USE_WINDOWS_SSPI
char *Curl_auth_build_spn(const char *service, const char *host,
                          const char *realm)
{
  char *spn = NULL;

  /* Generate our SPN */
  if(host && realm)
    spn = aprintf("%s/%s@%s", service, host, realm);
  else if(host)
    spn = aprintf("%s/%s", service, host);
  else if(realm)
    spn = aprintf("%s@%s", service, realm);

  /* Return our newly allocated SPN */
  return spn;
}
#else
TCHAR *Curl_auth_build_spn(const char *service, const char *host,
                           const char *realm)
{
  char *utf8_spn = NULL;
  TCHAR *tchar_spn = NULL;
  TCHAR *dupe_tchar_spn = NULL;

  (void)realm;

  /* Note: We could use DsMakeSPN() or DsClientMakeSpnForTargetServer() rather
     than doing this ourselves but the first is only available in Windows XP
     and Windows Server 2003 and the latter is only available in Windows 2000
     but not Windows95/98/ME or Windows NT4.0 unless the Active Directory
     Client Extensions are installed. As such it is far simpler for us to
     formulate the SPN instead. */

  /* Generate our UTF8 based SPN */
  utf8_spn = aprintf("%s/%s", service, host);
  if(!utf8_spn)
    return NULL;

  /* Allocate and return a TCHAR based SPN. Since curlx_convert_UTF8_to_tchar
     must be freed by curlx_unicodefree we will dupe the result so that the
     pointer this function returns can be normally free'd. */
  tchar_spn = curlx_convert_UTF8_to_tchar(utf8_spn);
  free(utf8_spn);
  if(!tchar_spn)
    return NULL;
  dupe_tchar_spn = _tcsdup(tchar_spn);
  curlx_unicodefree(tchar_spn);
  return dupe_tchar_spn;
}
#endif /* USE_WINDOWS_SSPI */

/*
 * Curl_auth_user_contains_domain()
 *
 * This is used to test if the specified user contains a Windows domain name as
 * follows:
 *
 * Domain\User (Down-level Logon Name)
 * Domain/User (curl Down-level format - for compatibility with existing code)
 * User@Domain (User Principal Name)
 *
 * Note: The username may be empty when using a GSS-API library or Windows
 * SSPI as the user and domain are either obtained from the credentials cache
 * when using GSS-API or via the currently logged in user's credentials when
 * using Windows SSPI.
 *
 * Parameters:
 *
 * user  [in] - The username.
 *
 * Returns TRUE on success; otherwise FALSE.
 */
bool Curl_auth_user_contains_domain(const char *user)
{
  bool valid = FALSE;

  if(user && *user) {
    /* Check we have a domain name or UPN present */
    char *p = strpbrk(user, "\\/@");

    valid = (p != NULL && p > user && p < user + strlen(user) - 1);
  }
#if defined(HAVE_GSSAPI) || defined(USE_WINDOWS_SSPI)
  else
    /* User and domain are obtained from the GSS-API credentials cache or the
       currently logged in user from Windows */
    valid = TRUE;
#endif

  return valid;
}

/*
 * Curl_auth_ollowed_to_host() tells if authentication, cookies or other
 * "sensitive data" can (still) be sent to this host.
 */
bool Curl_auth_allowed_to_host(struct Curl_easy *data)
{
  struct connectdata *conn = data->conn;
  return !data->state.this_is_a_follow ||
         data->set.allow_auth_to_other_hosts ||
         (data->state.first_host &&
          curl_strequal(data->state.first_host, conn->host.name) &&
          (data->state.first_remote_port == conn->remote_port) &&
          (data->state.first_remote_protocol == conn->handler->protocol));
}

#ifdef USE_NTLM

static void ntlm_conn_dtor(void *key, size_t klen, void *entry)
{
  struct ntlmdata *ntlm = entry;
  (void)key;
  (void)klen;
  DEBUGASSERT(ntlm);
  Curl_auth_cleanup_ntlm(ntlm);
  free(ntlm);
}

struct ntlmdata *Curl_auth_ntlm_get(struct connectdata *conn, bool proxy)
{
  const char *key = proxy ? CURL_META_NTLM_PROXY_CONN :
                    CURL_META_NTLM_CONN;
  struct ntlmdata *ntlm = Curl_conn_meta_get(conn, key);
  if(!ntlm) {
    ntlm = calloc(1, sizeof(*ntlm));
    if(!ntlm ||
       Curl_conn_meta_set(conn, key, ntlm, ntlm_conn_dtor))
      return NULL;
  }
  return ntlm;
}

void Curl_auth_ntlm_remove(struct connectdata *conn, bool proxy)
{
  Curl_conn_meta_remove(conn, proxy ?
    CURL_META_NTLM_PROXY_CONN : CURL_META_NTLM_CONN);
}

#endif /* USE_NTLM */

#ifdef USE_KERBEROS5

static void krb5_conn_dtor(void *key, size_t klen, void *entry)
{
  struct kerberos5data *krb5 = entry;
  (void)key;
  (void)klen;
  DEBUGASSERT(krb5);
  Curl_auth_cleanup_gssapi(krb5);
  free(krb5);
}

struct kerberos5data *Curl_auth_krb5_get(struct connectdata *conn)
{
  struct kerberos5data *krb5 = Curl_conn_meta_get(conn, CURL_META_KRB5_CONN);
  if(!krb5) {
    krb5 = calloc(1, sizeof(*krb5));
    if(!krb5 ||
       Curl_conn_meta_set(conn, CURL_META_KRB5_CONN, krb5, krb5_conn_dtor))
      return NULL;
  }
  return krb5;
}

#endif /* USE_KERBEROS5 */

#ifdef USE_GSASL

static void gsasl_conn_dtor(void *key, size_t klen, void *entry)
{
  struct gsasldata *gsasl = entry;
  (void)key;
  (void)klen;
  DEBUGASSERT(gsasl);
  Curl_auth_gsasl_cleanup(gsasl);
  free(gsasl);
}

struct gsasldata *Curl_auth_gsasl_get(struct connectdata *conn)
{
  struct gsasldata *gsasl = Curl_conn_meta_get(conn, CURL_META_GSASL_CONN);
  if(!gsasl) {
    gsasl = calloc(1, sizeof(*gsasl));
    if(!gsasl ||
       Curl_conn_meta_set(conn, CURL_META_GSASL_CONN, gsasl, gsasl_conn_dtor))
      return NULL;
  }
  return gsasl;
}

#endif /* USE_GSASL */

#ifdef USE_SPNEGO

static void nego_conn_dtor(void *key, size_t klen, void *entry)
{
  struct negotiatedata *nego = entry;
  (void)key;
  (void)klen;
  DEBUGASSERT(nego);
  Curl_auth_cleanup_spnego(nego);
  free(nego);
}

struct negotiatedata *Curl_auth_nego_get(struct connectdata *conn, bool proxy)
{
  const char *key = proxy ? CURL_META_NEGO_PROXY_CONN :
                    CURL_META_NEGO_CONN;
  struct negotiatedata *nego = Curl_conn_meta_get(conn, key);
  if(!nego) {
    nego = calloc(1, sizeof(*nego));
    if(!nego ||
       Curl_conn_meta_set(conn, key, nego, nego_conn_dtor))
      return NULL;
  }
  return nego;
}

#endif /* USE_SPNEGO */
