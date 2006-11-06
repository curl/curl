/***************************************************************************
*                                  _   _ ____  _
*  Project                     ___| | | |  _ \| |
*                             / __| | | | |_) | |
*                            | (__| |_| |  _ <| |___
*                             \___|\___/|_| \_\_____|
*
* Copyright (C) 1998 - 2006, Daniel Stenberg, <daniel@haxx.se>, et al.
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
* $Id$
***************************************************************************/

#define CURL_LIBSSH2_DEBUG

#include "setup.h"

#ifdef USE_LIBSSH2
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdarg.h>
#include <ctype.h>
#include <limits.h>

#include <libssh2.h>
#include <libssh2_sftp.h>

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif

#ifdef HAVE_FCNTL_H
#include <fcntl.h>
#endif

#ifdef HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif
#ifdef HAVE_SYS_STAT_H
#include <sys/stat.h>
#endif

#ifdef WIN32

#else /* probably some kind of unix */
#ifdef HAVE_SYS_SOCKET_H
#include <sys/socket.h>
#endif
#include <sys/types.h>
#ifdef HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif
#ifdef HAVE_ARPA_INET_H
#include <arpa/inet.h>
#endif
#ifdef HAVE_UTSNAME_H
#include <sys/utsname.h>
#endif
#ifdef HAVE_NETDB_H
#include <netdb.h>
#endif
#ifdef  VMS
#include <in.h>
#include <inet.h>
#endif
#endif

#if (defined(NETWARE) && defined(__NOVELL_LIBC__))
#undef in_addr_t
#define in_addr_t unsigned long
#endif

#include <curl/curl.h>
#include "urldata.h"
#include "sendf.h"
#include "easyif.h" /* for Curl_convert_... prototypes */

#include "if2ip.h"
#include "hostip.h"
#include "progress.h"
#include "transfer.h"
#include "escape.h"
#include "http.h" /* for HTTP proxy tunnel stuff */
#include "ssh.h"
#include "url.h"
#include "speedcheck.h"
#include "getinfo.h"

#include "strtoofft.h"
#include "strequal.h"
#include "sslgen.h"
#include "connect.h"
#include "strerror.h"
#include "memory.h"
#include "inet_ntop.h"
#include "select.h"
#include "parsedate.h" /* for the week day and month names */
#include "sockaddr.h" /* required for Curl_sockaddr_storage */
#include "multiif.h"

#if defined(HAVE_INET_NTOA_R) && !defined(HAVE_INET_NTOA_R_DECL)
#include "inet_ntoa_r.h"
#endif

#define _MPRINTF_REPLACE /* use our functions only */
#include <curl/mprintf.h>

#if defined(WIN32) || defined(MSDOS) || defined(__EMX__)
#define DIRSEP '\\'
#else
#define DIRSEP '/'
#endif

#define _MPRINTF_REPLACE /* use our functions only */
#include <curl/mprintf.h>

/* The last #include file should be: */
#ifdef CURLDEBUG
#include "memdebug.h"
#endif

#ifndef S_IRGRP
#define S_IRGRP  0
#endif

#ifndef S_IROTH
#define S_IROTH 0
#endif

static LIBSSH2_ALLOC_FUNC(libssh2_malloc);
static LIBSSH2_REALLOC_FUNC(libssh2_realloc);
static LIBSSH2_FREE_FUNC(libssh2_free);

struct auth_
{
  const char * user;
  const char * pw;
} auth;

static void
kbd_callback(const char *name, int name_len, const char *instruction,
             int instruction_len, int num_prompts,
             const LIBSSH2_USERAUTH_KBDINT_PROMPT *prompts,
             LIBSSH2_USERAUTH_KBDINT_RESPONSE *responses,
             void **abstract)
{
#ifdef CURL_LIBSSH2_DEBUG
  fprintf(stderr, "name=%s\n", name);
  fprintf(stderr, "name_len=%d\n", name_len);
  fprintf(stderr, "instruction=%s\n", instruction);
  fprintf(stderr, "instruction_len=%d\n", instruction_len);
  fprintf(stderr, "num_prompts=%d\n", num_prompts);
#endif  /* CURL_LIBSSH2_DEBUG */
  if (num_prompts == 1) {
    responses[0].text = strdup(auth.pw);
    responses[0].length = strlen(auth.pw);
  }
  (void)prompts;
  (void)abstract;
  return;
} /* kbd_callback */

static CURLcode libssh2_error_to_CURLE(struct connectdata *conn)
{
  int errorcode;
  struct SCPPROTO *scp = conn->data->reqdata.proto.scp;

  /* Get the libssh2 error code and string */
  errorcode = libssh2_session_last_error(scp->scpSession, &scp->errorstr, NULL,
                                         0);
  if (errorcode == LIBSSH2_FX_OK)
    return CURLE_OK;

  infof(conn->data, "libssh2 error %d, '%s'\n", errorcode, scp->errorstr);

  /* TODO: map some of the libssh2 errors to the more appropriate CURLcode
     error code, and possibly add a few new SSH-related one. We must however
     not return or even depend on libssh2 errors in the public libcurl API */

  return CURLE_SSH;
}

static LIBSSH2_ALLOC_FUNC(libssh2_malloc)
{
  return malloc(count);
  (void)abstract;
}

static LIBSSH2_REALLOC_FUNC(libssh2_realloc)
{
  return realloc(ptr, count);
  (void)abstract;
}

static LIBSSH2_FREE_FUNC(libssh2_free)
{
  free(ptr);
  (void)abstract;
}

static CURLcode scp_init(struct connectdata *conn)
{
  struct SessionHandle *data = conn->data;
  struct SCPPROTO *scp;
  if (data->reqdata.proto.scp)
    return CURLE_OK;

  scp = (struct SCPPROTO *)calloc(sizeof(struct SCPPROTO), 1);
  if (!scp)
    return CURLE_OUT_OF_MEMORY;

  data->reqdata.proto.scp = scp;

  /* get some initial data into the scp struct */
  scp->bytecountp = &data->reqdata.keep.bytecount;

  /* no need to duplicate them, this connectdata struct won't change */
  scp->user = conn->user;
  scp->passwd = conn->passwd;

  scp->errorstr = NULL;

  return CURLE_OK;
}

/*
 * Curl_scp_connect() gets called from Curl_protocol_connect() to allow us to
 * do protocol-specific actions at connect-time.
 */
CURLcode Curl_scp_connect(struct connectdata *conn, bool *done)
{
  int i;
  struct SCPPROTO *scp;
  const char *fingerprint;
  const char *authlist;
  char *home;
  char rsa_pub[PATH_MAX];
  char rsa[PATH_MAX];
  curl_socket_t sock;
  char *real_path;
  char *working_path;
  bool authed = FALSE;
  CURLcode result;
  struct SessionHandle *data = conn->data;

  result = scp_init(conn);
  if (result)
    return result;

  rsa_pub[0] = rsa[0] = '\0';

  scp = data->reqdata.proto.scp;

  working_path = curl_easy_unescape(data, data->reqdata.path, 0, NULL);
  if (!working_path)
    return CURLE_OUT_OF_MEMORY;

  real_path = (char *)malloc(strlen(working_path)+1);
  if (real_path == NULL) {
    Curl_safefree(working_path);
    return CURLE_OUT_OF_MEMORY;
  }
  /* Check for /~/ , indicating realative to the users home directory */
  if (working_path[1] == '~')
    /* It is referenced to the home directory, so strip the leading '/' */
    memcpy(real_path, working_path+1, 1+strlen(working_path)-1);
  else
    memcpy(real_path, working_path, 1+strlen(working_path));

  Curl_safefree(working_path);
  scp->path = real_path;

#ifdef CURL_LIBSSH2_DEBUG
  if (scp->user) {
    infof(data, "User: %s\n", scp->user);
  }
  if (scp->passwd) {
    infof(data, "Password: %s\n", scp->passwd);
  }
#endif /* CURL_LIBSSH2_DEBUG */
  sock = conn->sock[FIRSTSOCKET];
  scp->scpSession = libssh2_session_init_ex(libssh2_malloc, libssh2_free,
                                            libssh2_realloc, NULL);
  if (scp->scpSession == NULL) {
    failf(data, "Failure initialising ssh session\n");
    return CURLE_FAILED_INIT;
  }
#ifdef CURL_LIBSSH2_DEBUG
  infof(data, "Socket: %d\n", sock);
#endif /* CURL_LIBSSH2_DEBUG */

  if (libssh2_session_startup(scp->scpSession, sock)) {
    failf(data, "Failure establishing ssh session\n");
    return CURLE_FAILED_INIT;
  }

  /*
   * Before we authenticate we should check the hostkey's fingerprint against
   * our known hosts. How that is handled (reading from file, whatever) is
   * up to us. As for know not much is implemented, besides showing how to
   * get the fingerprint.
   */
  fingerprint = libssh2_hostkey_hash(scp->scpSession,
                                     LIBSSH2_HOSTKEY_HASH_MD5);

#ifdef CURL_LIBSSH2_DEBUG
  /* The fingerprint points to static storage (!), don't free() it. */
  for (i = 0; i < 16; i++) {
    infof(data, "%02X ", (unsigned char) fingerprint[i]);
  }
  infof(data, "\n");
#endif /* CURL_LIBSSH2_DEBUG */

  /* TBD - methods to check the host keys need to be done */

  /*
   * Figure out authentication methods
   * NB: As soon as we have provided a username to an openssh server we must
   * never change it later. Thus, always specify the correct username here,
   * even though the libssh2 docs kind of indicate that it should be possible
   * to get a 'generic' list (not user-specific) of authentication methods,
   * presumably with a blank username. That won't work in my experience.
   * So always specify it here.
   */
  authlist = libssh2_userauth_list(scp->scpSession, scp->user,
                                   strlen(scp->user));

  /*
   * Check the supported auth types in the order I feel is most secure with the
   * requested type of authentication
   */
  if ((data->set.ssh_auth_types & CURLSSH_AUTH_PUBLICKEY) &&
      (strstr(authlist, "publickey") != NULL)) {
    /* To ponder about: should really the lib be messing about with the HOME
       environment variable etc? */
    home = curl_getenv("HOME");

    if (data->set.ssh_public_key)
      snprintf(rsa_pub, sizeof(rsa_pub), "%s", data->set.ssh_public_key);
    else if(home)
      snprintf(rsa_pub, sizeof(rsa_pub), "%s/.ssh/id_dsa.pub", home);

    if(data->set.ssh_private_key)
      snprintf(rsa, sizeof(rsa), "%s", data->set.ssh_private_key);
    else if(home) {
      snprintf(rsa, sizeof(rsa), "%s/.ssh/id_dsa", home);
    }

    curl_free(home);

    if (rsa_pub[0]) {
      /* The function below checks if the files exists, no need to stat() here.
       */
      if (libssh2_userauth_publickey_fromfile(scp->scpSession, scp->user,
                                              rsa_pub, rsa, "") == 0) {
        authed = TRUE;
      }
    }
  }
  if (!authed &&
      (data->set.ssh_auth_types & CURLSSH_AUTH_PASSWORD) &&
      (strstr(authlist, "password") != NULL)) {
    if (libssh2_userauth_password(scp->scpSession, scp->user, scp->passwd)
        == 0) {
      authed = TRUE;
    }
  }
  if (!authed && (data->set.ssh_auth_types & CURLSSH_AUTH_HOST) &&
      (strstr(authlist, "hostbased") != NULL)) {
  }
  if (!authed && (data->set.ssh_auth_types & CURLSSH_AUTH_KEYBOARD)
      && (strstr(authlist, "keyboard-interactive") != NULL)) {
    /* Authentication failed. Continue with keyboard-interactive now. */
    auth.user = scp->user;
    auth.pw   = scp->passwd;
    if (libssh2_userauth_keyboard_interactive_ex(scp->scpSession, scp->user,
                                                 strlen(scp->user),
                                                 &kbd_callback) == 0) {
      authed = TRUE;
    }
  }

  if (!authed) {
    failf(data, "Authentication failure\n");
    return CURLE_FAILED_INIT;
  }

  /*
   * At this point we have an authenticated ssh session.
   */
  conn->sockfd = sock;
  conn->writesockfd = CURL_SOCKET_BAD;

  *done = TRUE;
  return CURLE_OK;
}

CURLcode Curl_scp_do(struct connectdata *conn, bool *done)
{
  struct stat sb;
  struct SCPPROTO *scp = conn->data->reqdata.proto.scp;
  CURLcode res = CURLE_OK;

  *done = TRUE; /* unconditionally */

  if (conn->data->set.upload) {
    /*
     * NOTE!!!  libssh2 requires that the destination path is a full path
     *          that includes the destination file and name OR ends in a "/" .
     *          If this is not done the destination file will be named the
     *          same name as the last directory in the path.
     */
    scp->scpChannel = libssh2_scp_send_ex(scp->scpSession, scp->path,
                                          S_IRUSR|S_IWUSR|S_IRGRP|S_IROTH,
                                          conn->data->set.infilesize, 0, 0);
    if (scp->scpChannel == NULL) {
      return CURLE_FAILED_INIT;
    }
    conn->writesockfd = conn->sockfd;
    conn->sockfd = CURL_SOCKET_BAD;
  }
  else {
    /*
     * We must check the remote file, if it is a directory I have no idea
     * what I will do until the scp "-r" option is supported
     */
    memset(&sb, 0, sizeof(struct stat));
    if ((scp->scpChannel = libssh2_scp_recv(scp->scpSession, scp->path, &sb))
        == NULL) {
      if ((sb.st_mode == 0) && (sb.st_atime == 0) && (sb.st_mtime == 0) &&
          (sb.st_size == 0)) {
        /* Since sb is still empty, it is likely the file was not found */
        return CURLE_REMOTE_FILE_NOT_FOUND;
      }
      return libssh2_error_to_CURLE(conn);
    }
    conn->data->reqdata.size = sb.st_size;
    conn->data->reqdata.maxdownload = sb.st_size;
  }

  return res;
}

CURLcode Curl_scp_done(struct connectdata *conn, CURLcode status)
{
  struct SCPPROTO *scp = conn->data->reqdata.proto.scp;

  Curl_safefree(scp->freepath);
  scp->freepath = NULL;

  if (scp->scpChannel) {
    if (libssh2_channel_close(scp->scpChannel) < 0) {
      failf(conn->data, "Failed to stop libssh2 channel subsystem\n");
    }
  }

  if (scp->scpSession) {
    libssh2_session_disconnect(scp->scpSession, "Shutdown");
    libssh2_session_free(scp->scpSession);
  }

  free(conn->data->reqdata.proto.scp);
  conn->data->reqdata.proto.scp = NULL;
  Curl_pgrsDone(conn);

  (void)status; /* unused */

  return CURLE_OK;
}

/* return number of received (decrypted) bytes */
int Curl_scp_send(struct connectdata *conn, int sockindex,
                  void *mem, size_t len)
{
  ssize_t nwrite;

  nwrite = libssh2_channel_write(conn->data->reqdata.proto.scp->scpChannel,
                                 mem, len);
  (void)sockindex;
  return nwrite;
}

/*
 * If the read would block (EWOULDBLOCK) we return -1. Otherwise we return
 * a regular CURLcode value.
 */
int Curl_scp_recv(struct connectdata *conn, int sockindex,
                  char *mem, size_t len)
{
  ssize_t nread;

  nread = libssh2_channel_read(conn->data->reqdata.proto.scp->scpChannel,
                               mem, len);
  (void)sockindex;
  return nread;
}

#endif /* USE_LIBSSH2 */
