/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) 1998 - 2020, Daniel Stenberg, <daniel@haxx.se>, et al.
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

#include "curl_setup.h"

#if defined(USE_NTLM) && defined(NTLM_WB_ENABLED)

/* Use Samba's 'winbind' daemon to support NTLM authentication,
 * by delegating the NTLM challenge/response protocol to a helper
 * in ntlm_auth.
 * http://devel.squid-cache.org/ntlm/squid_helper_protocol.html
 * https://www.samba.org/samba/docs/man/manpages-3/winbindd.8.html
 * https://www.samba.org/samba/docs/man/manpages-3/ntlm_auth.1.html
 * Preprocessor symbol 'NTLM_WB_ENABLED' is defined when this
 * feature is enabled and 'NTLM_WB_FILE' symbol holds absolute
 * filename of ntlm_auth helper.
 * If NTLM authentication using winbind fails, go back to original
 * request handling process.
 */

#ifdef HAVE_SYS_WAIT_H
#include <sys/wait.h>
#endif
#ifdef HAVE_SIGNAL_H
#include <signal.h>
#endif
#ifdef HAVE_PWD_H
#include <pwd.h>
#endif

#include "urldata.h"
#include "sendf.h"
#include "select.h"
#include "strerror.h"
#include "strdup.h"
#include "vauth/vauth.h"
#include "vauth/ntlm.h"

/* The last #include files should be: */
#include "curl_printf.h"
#include "curl_memory.h"
#include "memdebug.h"

/* If the response is larger than this then something is seriously wrong */
#define MAX_NTLM_WB_RESPONSE 100000

/* Portable 'sclose_nolog' used only in child process instead of 'sclose'
   to avoid fooling the socket leak detector */
#if defined(HAVE_CLOSESOCKET)
#define sclose_nolog(x)  closesocket((x))
#elif defined(HAVE_CLOSESOCKET_CAMEL)
#define sclose_nolog(x)  CloseSocket((x))
#else
#define sclose_nolog(x)  close((x))
#endif

static CURLcode ntlm_wb_init(struct Curl_easy *data, struct ntlmdata *ntlm,
                             const char *userp)
{
  curl_socket_t sockfds[2];
  pid_t child_pid;
  const char *username;
  char *slash, *domain = NULL;
  const char *ntlm_auth = NULL;
  char *ntlm_auth_alloc = NULL;
#if defined(HAVE_GETPWUID_R) && defined(HAVE_GETEUID)
  struct passwd pw, *pw_res;
  char pwbuf[1024];
#endif
  char buffer[STRERROR_LEN];

#if defined(CURL_DISABLE_VERBOSE_STRINGS)
  (void) data;
#endif

  /* Return if communication with ntlm_auth already set up */
  if(ntlm->ntlm_auth_hlpr_socket != CURL_SOCKET_BAD ||
    ntlm->ntlm_auth_hlpr_pid)
    return CURLE_OK;

  username = userp;
  /* The real ntlm_auth really doesn't like being invoked with an
     empty username. It won't make inferences for itself, and expects
     the client to do so (mostly because it's really designed for
     servers like squid to use for auth, and client support is an
     afterthought for it). So try hard to provide a suitable username
     if we don't already have one. But if we can't, provide the
     empty one anyway. Perhaps they have an implementation of the
     ntlm_auth helper which *doesn't* need it so we might as well try */
  if(!username || !username[0]) {
    username = getenv("NTLMUSER");
    if(!username || !username[0])
      username = getenv("LOGNAME");
    if(!username || !username[0])
      username = getenv("USER");
#if defined(HAVE_GETPWUID_R) && defined(HAVE_GETEUID)
    if((!username || !username[0]) &&
      !getpwuid_r(geteuid(), &pw, pwbuf, sizeof(pwbuf), &pw_res) &&
      pw_res) {
      username = pw.pw_name;
    }
#endif
    if(!username || !username[0])
      username = userp;
  }
  slash = strpbrk(username, "\\/");
  if(slash) {
    domain = strdup(username);
    if(!domain)
      return CURLE_OUT_OF_MEMORY;
    slash = domain + (slash - username);
    *slash = '\0';
    username = username + (slash - domain) + 1;
  }

  /* For testing purposes, when DEBUGBUILD is defined and environment
     variable CURL_NTLM_WB_FILE is set a fake_ntlm is used to perform
     NTLM challenge/response which only accepts commands and output
     strings pre-written in test case definitions */
#ifdef DEBUGBUILD
  ntlm_auth_alloc = curl_getenv("CURL_NTLM_WB_FILE");
  if(ntlm_auth_alloc)
    ntlm_auth = ntlm_auth_alloc;
  else
#endif
    ntlm_auth = NTLM_WB_FILE;

  if(access(ntlm_auth, X_OK) != 0) {
    failf(data, "Could not access ntlm_auth: %s errno %d: %s",
      ntlm_auth, errno, Curl_strerror(errno, buffer, sizeof(buffer)));
    goto done;
  }

  if(Curl_socketpair(AF_UNIX, SOCK_STREAM, 0, sockfds)) {
    failf(data, "Could not open socket pair. errno %d: %s",
      errno, Curl_strerror(errno, buffer, sizeof(buffer)));
    goto done;
  }

  child_pid = fork();
  if(child_pid == -1) {
    sclose(sockfds[0]);
    sclose(sockfds[1]);
    failf(data, "Could not fork. errno %d: %s",
      errno, Curl_strerror(errno, buffer, sizeof(buffer)));
    goto done;
  }
  else if(!child_pid) {
    /*
     * child process
     */

    /* Don't use sclose in the child since it fools the socket leak detector */
    sclose_nolog(sockfds[0]);
    if(dup2(sockfds[1], STDIN_FILENO) == -1) {
      failf(data, "Could not redirect child stdin. errno %d: %s",
        errno, Curl_strerror(errno, buffer, sizeof(buffer)));
      exit(1);
    }

    if(dup2(sockfds[1], STDOUT_FILENO) == -1) {
      failf(data, "Could not redirect child stdout. errno %d: %s",
        errno, Curl_strerror(errno, buffer, sizeof(buffer)));
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

    sclose_nolog(sockfds[1]);
    failf(data, "Could not execl(). errno %d: %s",
      errno, Curl_strerror(errno, buffer, sizeof(buffer)));
    exit(1);
  }

  sclose(sockfds[1]);
  ntlm->ntlm_auth_hlpr_socket = sockfds[0];
  ntlm->ntlm_auth_hlpr_pid = child_pid;
  free(domain);
  free(ntlm_auth_alloc);
  return CURLE_OK;

done:
  free(domain);
  free(ntlm_auth_alloc);
  return CURLE_REMOTE_ACCESS_DENIED;
}

static CURLcode ntlm_wb_response(struct Curl_easy *data, struct ntlmdata *ntlm,
                                 const char *input, char **outptr,
                                 size_t *outlen, curlntlm state)
{
  char *buf = NULL;
  char *base64data = NULL;
  size_t len_in = strlen(input), len_out = 0;

#if defined(CURL_DISABLE_VERBOSE_STRINGS)
  (void) data;
#endif

  *outptr = NULL;
  *outlen = 0;

  buf = malloc(NTLM_BUFSIZE);
  if(!buf)
    return CURLE_OUT_OF_MEMORY;

  while(len_in > 0) {
    ssize_t written = swrite(ntlm->ntlm_auth_hlpr_socket, input, len_in);
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
  while(1) {
    ssize_t size;
    char *newbuf;

    size = sread(ntlm->ntlm_auth_hlpr_socket, buf + len_out, NTLM_BUFSIZE);
    if(size == -1) {
      if(errno == EINTR)
        continue;
      goto done;
    }
    else if(size == 0)
      goto done;

    len_out += size;
    if(buf[len_out - 1] == '\n') {
      buf[len_out - 1] = '\0';
      break;
    }

    if(len_out > MAX_NTLM_WB_RESPONSE) {
      failf(data, "too large ntlm_wb response!");
      free(buf);
      return CURLE_OUT_OF_MEMORY;
    }

    newbuf = Curl_saferealloc(buf, len_out + NTLM_BUFSIZE);
    if(!newbuf)
      return CURLE_OUT_OF_MEMORY;

    buf = newbuf;
  }

  /* Samba/winbind installed but not configured */
  if(state == NTLMSTATE_TYPE1 &&
     len_out == 3 &&
     buf[0] == 'P' && buf[1] == 'W')
    goto done;
  /* invalid response */
  if(len_out < 4)
    goto done;
  if(state == NTLMSTATE_TYPE1 &&
     (buf[0] != 'Y' || buf[1] != 'R' || buf[2] != ' '))
    goto done;
  if(state == NTLMSTATE_TYPE2 &&
     (buf[0] != 'K' || buf[1] != 'K' || buf[2] != ' ') &&
     (buf[0] != 'A' || buf[1] != 'F' || buf[2] != ' '))
    goto done;

  base64data = aprintf("%.*s", len_out - 4, buf + 3);
  free(buf);
  if(!base64data)
    return CURLE_OUT_OF_MEMORY;

  /* Return the pointer to the new data (allocated memory) */
  *outptr = base64data;

  /* Return the length of the new data */
  *outlen = strlen(base64data);

  return CURLE_OK;

done:
  free(buf);
  return CURLE_REMOTE_ACCESS_DENIED;
}

/*
 * Curl_auth_create_ntlm_wb_type1_message()
 *
 * This is used to generate an already encoded NTLM type-1 message ready for
 * sending to the recipient.
 *
 * Parameters:
 *
 * data    [in]     - The session handle.
 * userp   [in]     - The user name in the format User or Domain\User.
 * ntlm    [in/out] - The NTLM data struct being used and modified.
 * outptr  [in/out] - The address where a pointer to newly allocated memory
 *                    holding the result will be stored upon completion.
 * outlen  [out]    - The length of the output message.
 *
 * Returns CURLE_OK on success.
 */
CURLcode Curl_auth_create_ntlm_wb_type1_message(struct Curl_easy *data,
                                                const char *userp,
                                                struct ntlmdata *ntlm,
                                                char **outptr, size_t *outlen)
{
  CURLcode result;

  /* Initialise the ntlm_auth helper */
  result = ntlm_wb_init(data, ntlm, userp);
  if(result)
    return result;

  /* Generate our type-1 message */
  result = ntlm_wb_response(data, ntlm, "YR\n", outptr, outlen,
                            NTLMSTATE_TYPE1);

  return result;
}

/*
 * Curl_auth_decode_ntlm_wb_type2_message()
 *
 * This is used to decode an already encoded NTLM type-2 message. The message
 * is first decoded from a base64 string into a raw NTLM message and checked
 * for validity before the appropriate data for creating a type-3 message is
 * written to the given NTLM data structure.
 *
 * Parameters:
 *
 * type2msg [in]     - The base64 encoded type-2 message.
 * ntlm     [in/out] - The NTLM data struct being used and modified.
 *
 * Returns CURLE_OK on success.
 */
CURLcode Curl_auth_decode_ntlm_wb_type2_message(const char *type2msg,
                                                struct ntlmdata *ntlm)
{
  CURLcode result = CURLE_OK;

  /* Extract the challage and store for when we generate the type-3 message */
  ntlm->challenge = strdup(type2msg);
  if(!ntlm->challenge)
    result = CURLE_OUT_OF_MEMORY;

  return result;
}

/*
 * Curl_auth_create_ntlm_wb_type3_message()
 *
 * This is used to generate an already encoded NTLM type-3 message ready for
 * sending to the recipient using the appropriate compile time crypto API.
 *
 * Parameters:
 *
 * data    [in]     - The session handle.
 * ntlm    [in/out] - The NTLM data struct being used and modified.
 * outptr  [in/out] - The address where a pointer to newly allocated memory
 *                    holding the result will be stored upon completion.
 * outlen  [out]    - The length of the output message.
 *
 * Returns CURLE_OK on success.
 */
CURLcode Curl_auth_create_ntlm_wb_type3_message(struct Curl_easy *data,
                                                struct ntlmdata *ntlm,
                                                char **outptr, size_t *outlen)
{
  CURLcode result = CURLE_OK;
  char *input;

  /* Format the challenge for the ntlm_auth helper */
  input = aprintf("TT %s\n", ntlm->challenge);
  if(!input)
    return CURLE_OUT_OF_MEMORY;

  /* Generate our type-3 message */
  result = ntlm_wb_response(data, ntlm, input, outptr, outlen,
                            NTLMSTATE_TYPE3);
  free(input);

  Curl_auth_cleanup_ntlm_wb(ntlm);

  return result;
}

/*
 * Curl_auth_cleanup_ntlm_wb()
 *
 * This is used to clean up the NTLM specific data.
 *
 * Parameters:
 *
 * ntlm    [in/out] - The NTLM data struct being cleaned up.
 *
 */
void Curl_auth_cleanup_ntlm_wb(struct ntlmdata *ntlm)
{
  if(ntlm->ntlm_auth_hlpr_socket != CURL_SOCKET_BAD) {
    sclose(ntlm->ntlm_auth_hlpr_socket);
    ntlm->ntlm_auth_hlpr_socket = CURL_SOCKET_BAD;
  }

  if(ntlm->ntlm_auth_hlpr_pid) {
    int i;
    for(i = 0; i < 4; i++) {
      pid_t ret = waitpid(ntlm->ntlm_auth_hlpr_pid, NULL, WNOHANG);
      if(ret == ntlm->ntlm_auth_hlpr_pid || errno == ECHILD)
        break;
      switch(i) {
      case 0:
        kill(ntlm->ntlm_auth_hlpr_pid, SIGTERM);
        break;
      case 1:
        /* Give the process another moment to shut down cleanly before
           bringing down the axe */
        Curl_wait_ms(1);
        break;
      case 2:
        kill(ntlm->ntlm_auth_hlpr_pid, SIGKILL);
        break;
      case 3:
        break;
      }
    }
    ntlm->ntlm_auth_hlpr_pid = 0;
  }

  Curl_safefree(ntlm->challenge);
}

#endif /* USE_NTLM && NTLM_WB_ENABLED */
