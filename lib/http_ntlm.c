/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) 1998 - 2011, Daniel Stenberg, <daniel@haxx.se>, et al.
 *
 * This software is licensed as described in the file COPYING, which
 * you should have received as part of this distribution. The terms
 * are also available at http://curl.haxx.se/docs/copyright.html.
 *
 * You may opt to use, copy, modify, merge, publish, distribute and/or sell
 * copies of the Software, and permit persons to whom the Software is
 * furnished to do so, under the terms of the COPYING file.
 *
 * This software is distributed on an "AS IS" basis, WITHOUT WARRANTY OF ANY
 * KIND, either express or implied.
 *
 ***************************************************************************/

#include "setup.h"

/* NTLM details:

   http://davenport.sourceforge.net/ntlm.html
   http://www.innovation.ch/java/ntlm.html
*/

#ifndef CURL_DISABLE_HTTP
#ifdef USE_NTLM

#define DEBUG_ME 0

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#ifdef HAVE_SYS_WAIT_H
#include <sys/wait.h>
#endif
#ifdef HAVE_SIGNAL_H
#include <signal.h>
#endif

#if (defined(NETWARE) && !defined(__NOVELL_LIBC__))
#include <netdb.h>
#endif

#include "urldata.h"
#include "non-ascii.h"  /* for Curl_convert_... prototypes */
#include "sendf.h"
#include "select.h"
#include "rawstr.h"
#include "curl_base64.h"
#include "http_ntlm.h"
#include "url.h"
#include "strerror.h"
#include "curl_gethostname.h"
#include "curl_memory.h"

#define _MPRINTF_REPLACE /* use our functions only */
#include <curl/mprintf.h>

#if defined(USE_NSS)
#include "nssg.h"
#elif defined(USE_WINDOWS_SSPI)
#include "curl_sspi.h"
#endif

/* The last #include file should be: */
#include "memdebug.h"

#if DEBUG_ME
# define DEBUG_OUT(x) x
#else
# define DEBUG_OUT(x)
#endif

CURLcode Curl_input_ntlm(struct connectdata *conn,
                         bool proxy,         /* if proxy or not */
                         const char *header) /* rest of the www-authenticate:
                                                header */
{
  /* point to the correct struct with this */
  struct ntlmdata *ntlm;
  CURLcode result = CURLE_OK;

#ifdef USE_NSS
  result = Curl_nss_force_init(conn->data);
  if(result)
    return result;
#endif

  ntlm = proxy ? &conn->proxyntlm : &conn->ntlm;

  /* skip initial whitespaces */
  while(*header && ISSPACE(*header))
    header++;

  if(checkprefix("NTLM", header)) {
    header += strlen("NTLM");

    while(*header && ISSPACE(*header))
      header++;

    if(*header) {
      result = Curl_ntlm_decode_type2_message(conn->data, header, ntlm);
      if(CURLE_OK != result)
        return result;

      ntlm->state = NTLMSTATE_TYPE2; /* We got a type-2 message */
    }
    else {
      if(ntlm->state >= NTLMSTATE_TYPE1) {
        infof(conn->data, "NTLM handshake failure (internal error)\n");
        return CURLE_REMOTE_ACCESS_DENIED;
      }

      ntlm->state = NTLMSTATE_TYPE1; /* We should send away a type-1 */
    }
  }

  return result;
}

#ifdef WINBIND_NTLM_AUTH_ENABLED
static void sso_ntlm_close(struct connectdata *conn)
{
  if(conn->ntlm_auth_hlpr_socket != CURL_SOCKET_BAD) {
    sclose(conn->ntlm_auth_hlpr_socket);
    conn->ntlm_auth_hlpr_socket = CURL_SOCKET_BAD;
  }

  if(conn->ntlm_auth_hlpr_pid) {
    int i;
    for(i = 0; i < 4; i++) {
      pid_t ret = waitpid(conn->ntlm_auth_hlpr_pid, NULL, WNOHANG);
      if(ret == conn->ntlm_auth_hlpr_pid || errno == ECHILD)
        break;
      switch(i) {
      case 0:
        kill(conn->ntlm_auth_hlpr_pid, SIGTERM);
        break;
      case 1:
        /* Give the process another moment to shut down cleanly before
           bringing down the axe */
        Curl_wait_ms(1);
        break;
      case 2:
        kill(conn->ntlm_auth_hlpr_pid, SIGKILL);
        break;
      case 3:
        break;
      }
    }
    conn->ntlm_auth_hlpr_pid = 0;
  }

  Curl_safefree(conn->challenge_header);
  conn->challenge_header = NULL;
  Curl_safefree(conn->response_header);
  conn->response_header = NULL;
}

static CURLcode sso_ntlm_initiate(struct connectdata *conn,
                                  const char *userp)
{
  curl_socket_t sockfds[2];
  pid_t child_pid;
  const char *username;
  char *slash, *domain = NULL;
  const char *ntlm_auth = NULL;
  char *ntlm_auth_alloc = NULL;
  int error;

  /* Return if communication with ntlm_auth already set up */
  if(conn->ntlm_auth_hlpr_socket != CURL_SOCKET_BAD ||
     conn->ntlm_auth_hlpr_pid)
    return CURLE_OK;

  username = userp;
  slash = strpbrk(username, "\\/");
  if(slash) {
    if((domain = strdup(username)) == NULL)
      return CURLE_OUT_OF_MEMORY;
    slash = domain + (slash - username);
    *slash = '\0';
    username = username + (slash - domain) + 1;
  }

  /* For testing purposes, when DEBUGBUILD is defined and environment
     variable CURL_NTLM_AUTH is set a fake_ntlm is used to perform
     NTLM challenge/response which only accepts commands and output
     strings pre-written in test case definitions */
#ifdef DEBUGBUILD
  ntlm_auth_alloc = curl_getenv("CURL_NTLM_AUTH");
  if(ntlm_auth_alloc)
    ntlm_auth = ntlm_auth_alloc;
  else
#endif
    ntlm_auth = WINBIND_NTLM_AUTH_FILE;

  if(access(ntlm_auth, X_OK) != 0) {
    error = ERRNO;
    failf(conn->data, "Could not access ntlm_auth: %s errno %d: %s",
          ntlm_auth, error, Curl_strerror(conn, error));
    goto done;
  }

  if(socketpair(AF_UNIX, SOCK_STREAM, 0, sockfds)) {
    error = ERRNO;
    failf(conn->data, "Could not open socket pair. errno %d: %s",
          error, Curl_strerror(conn, error));
    goto done;
  }

  child_pid = fork();
  if(child_pid == -1) {
    error = ERRNO;
    sclose(sockfds[0]);
    sclose(sockfds[1]);
    failf(conn->data, "Could not fork. errno %d: %s",
          error, Curl_strerror(conn, error));
    goto done;
  }
  else if(!child_pid) {
    /*
     * child process
     */

    sclose(sockfds[0]);

    if(dup2(sockfds[1], STDIN_FILENO) == -1) {
      error = ERRNO;
      failf(conn->data, "Could not redirect child stdin. errno %d: %s",
            error, Curl_strerror(conn, error));
      exit(1);
    }

    if(dup2(sockfds[1], STDOUT_FILENO) == -1) {
      error = ERRNO;
      failf(conn->data, "Could not redirect child stdout. errno %d: %s",
            error, Curl_strerror(conn, error));
      exit(1);
    }

    if(domain)
      execl(ntlm_auth, ntlm_auth,
            "--helper-protocol", "ntlmssp-client-1",
            "--use-cached-creds",
            "--username", username,
            "--domain", domain,
            NULL);
    else
      execl(ntlm_auth, ntlm_auth,
            "--helper-protocol", "ntlmssp-client-1",
            "--use-cached-creds",
            "--username", username,
            NULL);

    error = ERRNO;
    sclose(sockfds[1]);
    failf(conn->data, "Could not execl(). errno %d: %s",
          error, Curl_strerror(conn, error));
    exit(1);
  }

  sclose(sockfds[1]);
  conn->ntlm_auth_hlpr_socket = sockfds[0];
  conn->ntlm_auth_hlpr_pid = child_pid;
  Curl_safefree(domain);
  Curl_safefree(ntlm_auth_alloc);
  return CURLE_OK;

done:
  Curl_safefree(domain);
  Curl_safefree(ntlm_auth_alloc);
  return CURLE_REMOTE_ACCESS_DENIED;
}

static CURLcode sso_ntlm_response(struct connectdata *conn,
                                  const char *input, curlntlm state)
{
  ssize_t size;
  char buf[200]; /* enough, type 1, 3 message length is less then 200 */
  char *tmpbuf = buf;
  size_t len_in = strlen(input), len_out = sizeof(buf);

  while(len_in > 0) {
    ssize_t written = swrite(conn->ntlm_auth_hlpr_socket, input, len_in);
    if(written == -1) {
      /* Interrupted by a signal, retry it */
      if(errno == EINTR)
        continue;
      /* write failed if other errors happen */
      goto done;
    }
    input += written;
    len_in -= written;
  }
  /* Read one line */
  while(len_out > 0) {
    size = sread(conn->ntlm_auth_hlpr_socket, tmpbuf, len_out);
    if(size == -1) {
      if(errno == EINTR)
        continue;
      goto done;
    }
    else if(size == 0)
      goto done;
    else if(tmpbuf[size - 1] == '\n') {
      tmpbuf[size - 1] = '\0';
      goto wrfinish;
    }
    tmpbuf += size;
    len_out -= size;
  }
  goto done;
wrfinish:
  /* Samba/winbind installed but not configured */
  if(state == NTLMSTATE_TYPE1 &&
     size == 3 &&
     buf[0] == 'P' && buf[1] == 'W')
    return CURLE_REMOTE_ACCESS_DENIED;
  /* invalid response */
  if(size < 4)
    goto done;
  if(state == NTLMSTATE_TYPE1 &&
     (buf[0]!='Y' || buf[1]!='R' || buf[2]!=' '))
    goto done;
  if(state == NTLMSTATE_TYPE2 &&
     (buf[0]!='K' || buf[1]!='K' || buf[2]!=' ') &&
     (buf[0]!='A' || buf[1]!='F' || buf[2]!=' '))
    goto done;

  conn->response_header = aprintf("NTLM %.*s", size - 4, buf + 3);
  return CURLE_OK;
done:
  return CURLE_REMOTE_ACCESS_DENIED;
}

/*
 * This is for creating ntlm header output by delegating challenge/response
 * to a Samba's daemon helper ntlm_auth
 */
CURLcode Curl_output_ntlm_sso(struct connectdata *conn,
                              bool proxy)
{
  /* point to the address of the pointer that holds the string to sent to the
     server, which is for a plain host or for a HTTP proxy */
  char **allocuserpwd;
  /* point to the name and password for this */
  const char *userp;
  /* point to the correct struct with this */
  struct ntlmdata *ntlm;
  struct auth *authp;

  CURLcode res = CURLE_OK;
  char *input;

  DEBUGASSERT(conn);
  DEBUGASSERT(conn->data);

  if(proxy) {
    allocuserpwd = &conn->allocptr.proxyuserpwd;
    userp = conn->proxyuser;
    ntlm = &conn->proxyntlm;
    authp = &conn->data->state.authproxy;
  }
  else {
    allocuserpwd = &conn->allocptr.userpwd;
    userp = conn->user;
    ntlm = &conn->ntlm;
    authp = &conn->data->state.authhost;
  }
  authp->done = FALSE;

  /* not set means empty */
  if(!userp)
    userp="";

  switch(ntlm->state) {
  case NTLMSTATE_TYPE1:
  default:
    /* Use Samba's 'winbind' daemon to support NTLM single-sign-on,
     * by delegating the NTLM challenge/response protocal to a helper
     * in ntlm_auth.
     * http://devel.squid-cache.org/ntlm/squid_helper_protocol.html
     * http://www.samba.org/samba/docs/man/manpages-3/winbindd.8.html
     * http://www.samba.org/samba/docs/man/manpages-3/ntlm_auth.1.html
     * Preprocessor symbol 'WINBIND_NTLM_AUTH_ENABLED' is defined when
     * this feature is enabled and 'WINBIND_NTLM_AUTH_FILE' symbol holds
     * absolute filename of ntlm_auth helper.
     * If NTLM single-sign-on fails, go back to original request
     * handling process.
     */
    /* Create communication with ntlm_auth */
    res = sso_ntlm_initiate(conn, userp);
    if(res)
      return res;
    res = sso_ntlm_response(conn, "YR\n", ntlm->state);
    if(res)
      return res;

    Curl_safefree(*allocuserpwd);
    *allocuserpwd = aprintf("%sAuthorization: %s\r\n",
                            proxy ? "Proxy-" : "",
                            conn->response_header);
    DEBUG_OUT(fprintf(stderr, "**** Header %s\n ", *allocuserpwd));
    Curl_safefree(conn->response_header);
    conn->response_header = NULL;
    break;
  case NTLMSTATE_TYPE2:
    input = aprintf("TT %s", conn->challenge_header);
    if(!input)
      return CURLE_OUT_OF_MEMORY;
    res = sso_ntlm_response(conn,
                            input,
                            ntlm->state);
    free(input);
    input = NULL;
    if(res)
      return res;

    Curl_safefree(*allocuserpwd);
    *allocuserpwd = aprintf("%sAuthorization: %s\r\n",
                            proxy ? "Proxy-" : "",
                            conn->response_header);
    DEBUG_OUT(fprintf(stderr, "**** %s\n ", *allocuserpwd));
    ntlm->state = NTLMSTATE_TYPE3; /* we sent a type-3 */
    authp->done = TRUE;
    sso_ntlm_close(conn);
    break;
  case NTLMSTATE_TYPE3:
    /* connection is already authenticated,
     * don't send a header in future requests */
    if(*allocuserpwd) {
      free(*allocuserpwd);
      *allocuserpwd=NULL;
    }
    authp->done = TRUE;
    break;
  }

  return CURLE_OK;
}
#endif /* WINBIND_NTLM_AUTH_ENABLED */

/*
 * This is for creating ntlm header output
 */
CURLcode Curl_output_ntlm(struct connectdata *conn,
                          bool proxy)
{
  char *base64 = NULL;
  CURLcode error;

  /* point to the address of the pointer that holds the string to send to the
     server, which is for a plain host or for a HTTP proxy */
  char **allocuserpwd;

  /* point to the name and password for this */
  const char *userp;
  const char *passwdp;

  /* point to the correct struct with this */
  struct ntlmdata *ntlm;
  struct auth *authp;

  DEBUGASSERT(conn);
  DEBUGASSERT(conn->data);

#ifdef USE_NSS
  if(CURLE_OK != Curl_nss_force_init(conn->data))
    return CURLE_OUT_OF_MEMORY;
#endif

  if(proxy) {
    allocuserpwd = &conn->allocptr.proxyuserpwd;
    userp = conn->proxyuser;
    passwdp = conn->proxypasswd;
    ntlm = &conn->proxyntlm;
    authp = &conn->data->state.authproxy;
  }
  else {
    allocuserpwd = &conn->allocptr.userpwd;
    userp = conn->user;
    passwdp = conn->passwd;
    ntlm = &conn->ntlm;
    authp = &conn->data->state.authhost;
  }
  authp->done = FALSE;

  /* not set means empty */
  if(!userp)
    userp = "";

  if(!passwdp)
    passwdp = "";

#ifdef USE_WINDOWS_SSPI
  if(s_hSecDll == NULL) {
    /* not thread safe and leaks - use curl_global_init() to avoid */
    CURLcode err = Curl_sspi_global_init();
    if(s_hSecDll == NULL)
      return err;
  }
#endif

  switch(ntlm->state) {
  case NTLMSTATE_TYPE1:
  default: /* for the weird cases we (re)start here */
    /* Create a type-1 message */
    error = Curl_ntlm_create_type1_message(userp, passwdp, ntlm, &base64);
    if(error)
      return error;

    if(base64) {
      Curl_safefree(*allocuserpwd);
      *allocuserpwd = aprintf("%sAuthorization: NTLM %s\r\n",
                              proxy ? "Proxy-" : "",
                              base64);
      DEBUG_OUT(fprintf(stderr, "**** Header %s\n ", *allocuserpwd));
      free(base64);
    }
    break;

  case NTLMSTATE_TYPE2:
    /* We already received the type-2 message, create a type-3 message */
    error = Curl_ntlm_create_type3_message(conn->data, userp, passwdp,
                                           ntlm, &base64);
    if(error)
      return error;

    if(base64) {
      Curl_safefree(*allocuserpwd);
      *allocuserpwd = aprintf("%sAuthorization: NTLM %s\r\n",
                              proxy ? "Proxy-" : "",
                              base64);
      DEBUG_OUT(fprintf(stderr, "**** %s\n ", *allocuserpwd));
      free(base64);

      ntlm->state = NTLMSTATE_TYPE3; /* we send a type-3 */
      authp->done = TRUE;
    }
    break;

  case NTLMSTATE_TYPE3:
    /* connection is already authenticated,
     * don't send a header in future requests */
    if(*allocuserpwd) {
      free(*allocuserpwd);
      *allocuserpwd = NULL;
    }
    authp->done = TRUE;
    break;
  }

  return CURLE_OK;
}

void Curl_http_ntlm_cleanup(struct connectdata *conn)
{
#ifdef USE_WINDOWS_SSPI
  Curl_ntlm_sspi_cleanup(&conn->ntlm);
  Curl_ntlm_sspi_cleanup(&conn->proxyntlm);
#elif defined(WINBIND_NTLM_AUTH_ENABLED)
  sso_ntlm_close(conn);
#else
  (void)conn;
#endif
}

#endif /* USE_NTLM */
#endif /* !CURL_DISABLE_HTTP */
