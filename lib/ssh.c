/***************************************************************************
*                                  _   _ ____  _
*  Project                     ___| | | |  _ \| |
*                             / __| | | | |_) | |
*                            | (__| |_| |  _ <| |___
*                             \___|\___/|_| \_\_____|
*
* Copyright (C) 1998 - 2007, Daniel Stenberg, <daniel@haxx.se>, et al.
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

/* #define CURL_LIBSSH2_DEBUG */

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

#ifdef HAVE_TIME_H
#include <time.h>
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

#ifndef LIBSSH2_SFTP_S_IRUSR
/* Here's a work-around for those of you who happend to run a libssh2 version
   that is 0.14 or older. We should remove this kludge as soon as we can
   require a more recent libssh2 release. */
#ifndef S_IRGRP
#define S_IRGRP  0
#endif

#ifndef S_IROTH
#define S_IROTH 0
#endif

#define LIBSSH2_SFTP_S_IRUSR S_IRUSR
#define LIBSSH2_SFTP_S_IWUSR S_IWUSR
#define LIBSSH2_SFTP_S_IRGRP S_IRGRP
#define LIBSSH2_SFTP_S_IROTH S_IROTH
#define LIBSSH2_SFTP_S_IRUSR S_IRUSR
#define LIBSSH2_SFTP_S_IWUSR S_IWUSR
#define LIBSSH2_SFTP_S_IRGRP S_IRGRP
#define LIBSSH2_SFTP_S_IROTH S_IROTH
#define LIBSSH2_SFTP_S_IFMT S_IFMT
#define LIBSSH2_SFTP_S_IFDIR S_IFDIR
#define LIBSSH2_SFTP_S_IFLNK S_IFLNK
#define LIBSSH2_SFTP_S_IFSOCK S_IFSOCK
#define LIBSSH2_SFTP_S_IFCHR S_IFCHR
#define LIBSSH2_SFTP_S_IFBLK S_IFBLK
#define LIBSSH2_SFTP_S_IXUSR S_IXUSR
#define LIBSSH2_SFTP_S_IWGRP S_IWGRP
#define LIBSSH2_SFTP_S_IXGRP S_IXGRP
#define LIBSSH2_SFTP_S_IWOTH S_IWOTH
#define LIBSSH2_SFTP_S_IXOTH S_IXOTH
#endif

static LIBSSH2_ALLOC_FUNC(libssh2_malloc);
static LIBSSH2_REALLOC_FUNC(libssh2_realloc);
static LIBSSH2_FREE_FUNC(libssh2_free);

static void
kbd_callback(const char *name, int name_len, const char *instruction,
             int instruction_len, int num_prompts,
             const LIBSSH2_USERAUTH_KBDINT_PROMPT *prompts,
             LIBSSH2_USERAUTH_KBDINT_RESPONSE *responses,
             void **abstract)
{
  struct SSHPROTO *ssh = (struct SSHPROTO *)*abstract;

#ifdef CURL_LIBSSH2_DEBUG
  fprintf(stderr, "name=%s\n", name);
  fprintf(stderr, "name_len=%d\n", name_len);
  fprintf(stderr, "instruction=%s\n", instruction);
  fprintf(stderr, "instruction_len=%d\n", instruction_len);
  fprintf(stderr, "num_prompts=%d\n", num_prompts);
#else
  (void)name;
  (void)name_len;
  (void)instruction;
  (void)instruction_len;
#endif  /* CURL_LIBSSH2_DEBUG */
  if (num_prompts == 1) {
    responses[0].text = strdup(ssh->passwd);
    responses[0].length = strlen(ssh->passwd);
  }
  (void)prompts;
  (void)abstract;
} /* kbd_callback */

static CURLcode libssh2_error_to_CURLE(struct connectdata *conn)
{
  int errorcode;
  struct SSHPROTO *scp = conn->data->reqdata.proto.ssh;

  /* Get the libssh2 error code and string */
  errorcode = libssh2_session_last_error(scp->ssh_session, &scp->errorstr,
                                         NULL, 0);
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

static CURLcode ssh_init(struct connectdata *conn)
{
  struct SessionHandle *data = conn->data;
  struct SSHPROTO *ssh;
  if (data->reqdata.proto.ssh)
    return CURLE_OK;

  ssh = (struct SSHPROTO *)calloc(sizeof(struct SSHPROTO), 1);
  if (!ssh)
    return CURLE_OUT_OF_MEMORY;

  data->reqdata.proto.ssh = ssh;

  /* get some initial data into the ssh struct */
  ssh->bytecountp = &data->reqdata.keep.bytecount;

  /* no need to duplicate them, this connectdata struct won't change */
  ssh->user = conn->user;
  ssh->passwd = conn->passwd;

  ssh->errorstr = NULL;

  ssh->ssh_session = NULL;
  ssh->ssh_channel = NULL;
  ssh->sftp_session = NULL;
  ssh->sftp_handle = NULL;

  return CURLE_OK;
}

/*
 * Curl_ssh_connect() gets called from Curl_protocol_connect() to allow us to
 * do protocol-specific actions at connect-time.
 */
CURLcode Curl_ssh_connect(struct connectdata *conn, bool *done)
{
  int i;
  struct SSHPROTO *ssh;
  const char *fingerprint;
  const char *authlist;
  char *home;
  char rsa_pub[PATH_MAX];
  char rsa[PATH_MAX];
  char tempHome[PATH_MAX];
  curl_socket_t sock;
  char *real_path;
  char *working_path;
  int working_path_len;
  bool authed = FALSE;
  CURLcode result;
  struct SessionHandle *data = conn->data;

  rsa_pub[0] = rsa[0] = '\0';

  result = ssh_init(conn);
  if (result)
    return result;

  ssh = data->reqdata.proto.ssh;

  working_path = curl_easy_unescape(data, data->reqdata.path, 0,
                                    &working_path_len);
  if (!working_path)
    return CURLE_OUT_OF_MEMORY;

#ifdef CURL_LIBSSH2_DEBUG
  if (ssh->user) {
    infof(data, "User: %s\n", ssh->user);
  }
  if (ssh->passwd) {
    infof(data, "Password: %s\n", ssh->passwd);
  }
#endif /* CURL_LIBSSH2_DEBUG */
  sock = conn->sock[FIRSTSOCKET];
  ssh->ssh_session = libssh2_session_init_ex(libssh2_malloc, libssh2_free,
                                            libssh2_realloc, ssh);
  if (ssh->ssh_session == NULL) {
    failf(data, "Failure initialising ssh session\n");
    Curl_safefree(ssh->path);
    return CURLE_FAILED_INIT;
  }
#ifdef CURL_LIBSSH2_DEBUG
  infof(data, "SSH socket: %d\n", sock);
#endif /* CURL_LIBSSH2_DEBUG */

  if (libssh2_session_startup(ssh->ssh_session, sock)) {
    failf(data, "Failure establishing ssh session\n");
    libssh2_session_free(ssh->ssh_session);
    ssh->ssh_session = NULL;
    Curl_safefree(ssh->path);
    return CURLE_FAILED_INIT;
  }

  /*
   * Before we authenticate we should check the hostkey's fingerprint against
   * our known hosts. How that is handled (reading from file, whatever) is
   * up to us. As for know not much is implemented, besides showing how to
   * get the fingerprint.
   */
  fingerprint = libssh2_hostkey_hash(ssh->ssh_session,
                                     LIBSSH2_HOSTKEY_HASH_MD5);

#ifdef CURL_LIBSSH2_DEBUG
  /* The fingerprint points to static storage (!), don't free() it. */
  infof(data, "Fingerprint: ");
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
  authlist = libssh2_userauth_list(ssh->ssh_session, ssh->user,
                                   strlen(ssh->user));

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
    else if (home)
      snprintf(rsa_pub, sizeof(rsa_pub), "%s/.ssh/id_dsa.pub", home);

    if (data->set.ssh_private_key)
      snprintf(rsa, sizeof(rsa), "%s", data->set.ssh_private_key);
    else if (home)
      snprintf(rsa, sizeof(rsa), "%s/.ssh/id_dsa", home);

    curl_free(home);

    if (rsa_pub[0]) {
      /* The function below checks if the files exists, no need to stat() here.
      */
      if (libssh2_userauth_publickey_fromfile(ssh->ssh_session, ssh->user,
                                              rsa_pub, rsa, "") == 0) {
        authed = TRUE;
      }
    }
  }
  if (!authed &&
      (data->set.ssh_auth_types & CURLSSH_AUTH_PASSWORD) &&
      (strstr(authlist, "password") != NULL)) {
    if (!libssh2_userauth_password(ssh->ssh_session, ssh->user, ssh->passwd))
      authed = TRUE;
  }
  if (!authed && (data->set.ssh_auth_types & CURLSSH_AUTH_HOST) &&
      (strstr(authlist, "hostbased") != NULL)) {
  }
  if (!authed && (data->set.ssh_auth_types & CURLSSH_AUTH_KEYBOARD)
      && (strstr(authlist, "keyboard-interactive") != NULL)) {
    /* Authentication failed. Continue with keyboard-interactive now. */
    if (libssh2_userauth_keyboard_interactive_ex(ssh->ssh_session, ssh->user,
                                                 strlen(ssh->user),
                                                 &kbd_callback) == 0) {
      authed = TRUE;
    }
  }

  if (!authed) {
    failf(data, "Authentication failure\n");
    libssh2_session_free(ssh->ssh_session);
    ssh->ssh_session = NULL;
    Curl_safefree(ssh->path);
    return CURLE_FAILED_INIT;
  }

  /*
   * At this point we have an authenticated ssh session.
   */
  conn->sockfd = sock;
  conn->writesockfd = CURL_SOCKET_BAD;

  if (conn->protocol == PROT_SFTP) {
    /*
     * Start the libssh2 sftp session
     */
    ssh->sftp_session = libssh2_sftp_init(ssh->ssh_session);
    if (ssh->sftp_session == NULL) {
      failf(data, "Failure initialising sftp session\n");
      libssh2_sftp_shutdown(ssh->sftp_session);
      ssh->sftp_session = NULL;
      libssh2_session_free(ssh->ssh_session);
      ssh->ssh_session = NULL;
      return CURLE_FAILED_INIT;
    }

    /*
     * Get the "home" directory
     */
    i = libssh2_sftp_realpath(ssh->sftp_session, ".", tempHome, PATH_MAX-1);
    if (i > 0) {
      /* It seems that this string is not always NULL terminated */
      tempHome[i] = '\0';
      ssh->homedir = (char *)strdup(tempHome);
      if (!ssh->homedir) {
        libssh2_sftp_shutdown(ssh->sftp_session);
        ssh->sftp_session = NULL;
        libssh2_session_free(ssh->ssh_session);
        ssh->ssh_session = NULL;
        return CURLE_OUT_OF_MEMORY;
      }
    }
    else {
      /* Return the error type */
      i = libssh2_sftp_last_error(ssh->sftp_session);
      DEBUGF(infof(data, "error = %d\n", i));
    }
  }

  /* Check for /~/ , indicating realative to the users home directory */
  if (conn->protocol == PROT_SCP) {
    real_path = (char *)malloc(working_path_len+1);
    if (real_path == NULL) {
      Curl_safefree(working_path);
      libssh2_session_free(ssh->ssh_session);
      ssh->ssh_session = NULL;
      return CURLE_OUT_OF_MEMORY;
    }
    if (working_path[1] == '~')
      /* It is referenced to the home directory, so strip the leading '/' */
      memcpy(real_path, working_path+1, 1 + working_path_len-1);
    else
      memcpy(real_path, working_path, 1 + working_path_len);
  }
  else if (conn->protocol == PROT_SFTP) {
    if (working_path[1] == '~') {
      real_path = (char *)malloc(strlen(ssh->homedir) +
                                 working_path_len + 1);
      if (real_path == NULL) {
        libssh2_sftp_shutdown(ssh->sftp_session);
        ssh->sftp_session = NULL;
        libssh2_session_free(ssh->ssh_session);
        ssh->ssh_session = NULL;
        Curl_safefree(working_path);
        return CURLE_OUT_OF_MEMORY;
      }
      /* It is referenced to the home directory, so strip the leading '/' */
      memcpy(real_path, ssh->homedir, strlen(ssh->homedir));
      real_path[strlen(ssh->homedir)] = '/';
      real_path[strlen(ssh->homedir)+1] = '\0';
      if (working_path_len > 3) {
        memcpy(real_path+strlen(ssh->homedir)+1, working_path + 3,
               1 + working_path_len -3);
      }
    }
    else {
      real_path = (char *)malloc(working_path_len+1);
      if (real_path == NULL) {
        libssh2_session_free(ssh->ssh_session);
        ssh->ssh_session = NULL;
        Curl_safefree(working_path);
        return CURLE_OUT_OF_MEMORY;
      }
      memcpy(real_path, working_path, 1+working_path_len);
    }
  }
  else
    return CURLE_FAILED_INIT;

  Curl_safefree(working_path);
  ssh->path = real_path;

  *done = TRUE;
  return CURLE_OK;
}

CURLcode Curl_scp_do(struct connectdata *conn, bool *done)
{
  struct stat sb;
  struct SSHPROTO *scp = conn->data->reqdata.proto.ssh;
  CURLcode res = CURLE_OK;

  *done = TRUE; /* unconditionally */

  if (conn->data->set.upload) {
    /*
     * NOTE!!!  libssh2 requires that the destination path is a full path
     *          that includes the destination file and name OR ends in a "/" .
     *          If this is not done the destination file will be named the
     *          same name as the last directory in the path.
     */
    scp->ssh_channel = libssh2_scp_send_ex(scp->ssh_session, scp->path,
                                           LIBSSH2_SFTP_S_IRUSR|
                                           LIBSSH2_SFTP_S_IWUSR|
                                           LIBSSH2_SFTP_S_IRGRP|
                                           LIBSSH2_SFTP_S_IROTH,
                                           conn->data->set.infilesize, 0, 0);
    if (!scp->ssh_channel)
      return CURLE_FAILED_INIT;

    /* upload data */
    res = Curl_setup_transfer(conn, -1, -1, FALSE, NULL, FIRSTSOCKET, NULL);
  }
  else {
    /*
     * We must check the remote file, if it is a directory no vaules will
     * be set in sb
     */
    curl_off_t bytecount;
    memset(&sb, 0, sizeof(struct stat));
    scp->ssh_channel = libssh2_scp_recv(scp->ssh_session, scp->path, &sb);
    if (!scp->ssh_channel) {
      if ((sb.st_mode == 0) && (sb.st_atime == 0) && (sb.st_mtime == 0) &&
          (sb.st_size == 0)) {
        /* Since sb is still empty, it is likely the file was not found */
        return CURLE_REMOTE_FILE_NOT_FOUND;
      }
      return libssh2_error_to_CURLE(conn);
    }
    /* download data */
    bytecount = (curl_off_t) sb.st_size;
    conn->data->reqdata.maxdownload =  (curl_off_t) sb.st_size;
    res = Curl_setup_transfer(conn, FIRSTSOCKET,
                              bytecount, FALSE, NULL, -1, NULL);
  }

  return res;
}

CURLcode Curl_scp_done(struct connectdata *conn, CURLcode status,
                       bool premature)
{
  struct SSHPROTO *scp = conn->data->reqdata.proto.ssh;
  (void)premature; /* not used */

  Curl_safefree(scp->path);
  scp->path = NULL;

  if (scp->ssh_channel) {
    if (libssh2_channel_close(scp->ssh_channel) < 0) {
      infof(conn->data, "Failed to stop libssh2 channel subsystem\n");
    }
  }

  if (scp->ssh_session) {
    libssh2_session_disconnect(scp->ssh_session, "Shutdown");
    libssh2_session_free(scp->ssh_session);
    scp->ssh_session = NULL;
  }

  free(conn->data->reqdata.proto.ssh);
  conn->data->reqdata.proto.ssh = NULL;
  Curl_pgrsDone(conn);

  (void)status; /* unused */

  return CURLE_OK;
}

/* return number of received (decrypted) bytes */
ssize_t Curl_scp_send(struct connectdata *conn, int sockindex,
                      void *mem, size_t len)
{
  ssize_t nwrite;

  /* libssh2_channel_write() returns int
   *
   * NOTE: we should not store nor rely on connection-related data to be
   * in the SessionHandle struct
   */
  nwrite = (ssize_t)
    libssh2_channel_write(conn->data->reqdata.proto.ssh->ssh_channel,
                          mem, len);
  (void)sockindex;
  return nwrite;
}

/*
 * If the read would block (EWOULDBLOCK) we return -1. Otherwise we return
 * a regular CURLcode value.
 */
ssize_t Curl_scp_recv(struct connectdata *conn, int sockindex,
                  char *mem, size_t len)
{
  ssize_t nread;

  /* libssh2_channel_read() returns int
   *
   * NOTE: we should not store nor rely on connection-related data to be
   * in the SessionHandle struct
   */

  nread = (ssize_t)
    libssh2_channel_read(conn->data->reqdata.proto.ssh->ssh_channel,
                         mem, len);
  (void)sockindex;
  return nread;
}

/*
 * =============== SFTP ===============
 */

CURLcode Curl_sftp_do(struct connectdata *conn, bool *done)
{
  LIBSSH2_SFTP_ATTRIBUTES attrs;
  struct SSHPROTO *sftp = conn->data->reqdata.proto.ssh;
  CURLcode res = CURLE_OK;
  struct SessionHandle *data = conn->data;
  curl_off_t bytecount = 0;
  char *buf = data->state.buffer;

  *done = TRUE; /* unconditionally */

  if (data->set.upload) {
    /*
     * NOTE!!!  libssh2 requires that the destination path is a full path
     *          that includes the destination file and name OR ends in a "/" .
     *          If this is not done the destination file will be named the
     *          same name as the last directory in the path.
     */
    sftp->sftp_handle =
      libssh2_sftp_open(sftp->sftp_session, sftp->path,
                        LIBSSH2_FXF_WRITE|LIBSSH2_FXF_CREAT,
                        LIBSSH2_SFTP_S_IRUSR|LIBSSH2_SFTP_S_IWUSR|
                        LIBSSH2_SFTP_S_IRGRP|LIBSSH2_SFTP_S_IROTH);
    if (!sftp->sftp_handle)
      return CURLE_FAILED_INIT;

    /* upload data */
    res = Curl_setup_transfer(conn, -1, -1, FALSE, NULL, FIRSTSOCKET, NULL);
  }
  else {
    if (sftp->path[strlen(sftp->path)-1] == '/') {
      /*
       * This is a directory that we are trying to get, so produce a
       * directory listing
       *
       * **BLOCKING behaviour** This should be made into a state machine and
       * get a separate function called from Curl_sftp_recv() when there is
       * data to read from the network, instead of "hanging" here.
       */
      char filename[PATH_MAX+1];
      int len, totalLen, currLen;
      char *line;

      sftp->sftp_handle =
        libssh2_sftp_opendir(sftp->sftp_session, sftp->path);
      if (!sftp->sftp_handle)
        return CURLE_SSH;

      while ((len = libssh2_sftp_readdir(sftp->sftp_handle, filename,
                                         PATH_MAX, &attrs)) > 0) {
        filename[len] = '\0';

        if (data->set.ftp_list_only) {
          if ((attrs.flags & LIBSSH2_SFTP_ATTR_PERMISSIONS) &&
              ((attrs.permissions & LIBSSH2_SFTP_S_IFMT) ==
               LIBSSH2_SFTP_S_IFDIR)) {
            infof(data, "%s\n", filename);
          }
        }
        else {
          totalLen = 80 + len;
          line = (char *)malloc(totalLen);
          if (!line)
            return CURLE_OUT_OF_MEMORY;

          if (!(attrs.flags & LIBSSH2_SFTP_ATTR_UIDGID))
            attrs.uid = attrs.gid =0;

          currLen = snprintf(line, totalLen, "----------   1 %5d %5d",
                             attrs.uid, attrs.gid);

          if (attrs.flags & LIBSSH2_SFTP_ATTR_PERMISSIONS) {
            if ((attrs.permissions & LIBSSH2_SFTP_S_IFMT) ==
                LIBSSH2_SFTP_S_IFDIR) {
              line[0] = 'd';
            }
            else if ((attrs.permissions & LIBSSH2_SFTP_S_IFMT) ==
                     LIBSSH2_SFTP_S_IFLNK) {
              line[0] = 'l';
            }
            else if ((attrs.permissions & LIBSSH2_SFTP_S_IFMT) ==
                     LIBSSH2_SFTP_S_IFSOCK) {
              line[0] = 's';
            }
            else if ((attrs.permissions & LIBSSH2_SFTP_S_IFMT) ==
                     LIBSSH2_SFTP_S_IFCHR) {
              line[0] = 'c';
            }
            else if ((attrs.permissions & LIBSSH2_SFTP_S_IFMT) ==
                     LIBSSH2_SFTP_S_IFBLK) {
              line[0] = 'b';
            }
            if (attrs.permissions & LIBSSH2_SFTP_S_IRUSR) {
              line[1] = 'r';
            }
            if (attrs.permissions & LIBSSH2_SFTP_S_IWUSR) {
              line[2] = 'w';
            }
            if (attrs.permissions & LIBSSH2_SFTP_S_IXUSR) {
              line[3] = 'x';
            }
            if (attrs.permissions & LIBSSH2_SFTP_S_IRGRP) {
              line[4] = 'r';
            }
            if (attrs.permissions & LIBSSH2_SFTP_S_IWGRP) {
              line[5] = 'w';
            }
            if (attrs.permissions & LIBSSH2_SFTP_S_IXGRP) {
              line[6] = 'x';
            }
            if (attrs.permissions & LIBSSH2_SFTP_S_IROTH) {
              line[7] = 'r';
            }
            if (attrs.permissions & LIBSSH2_SFTP_S_IWOTH) {
              line[8] = 'w';
            }
            if (attrs.permissions & LIBSSH2_SFTP_S_IXOTH) {
              line[9] = 'x';
            }
          }
          if (attrs.flags & LIBSSH2_SFTP_ATTR_SIZE) {
            currLen += snprintf(line+currLen, totalLen-currLen, "%11lld",
                                attrs.filesize);
          }
          if (attrs.flags & LIBSSH2_SFTP_ATTR_ACMODTIME) {
            const char *months[12] = {
              "Jan", "Feb", "Mar", "Apr", "May", "Jun",
              "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"};
            struct tm *nowParts;
            time_t now, remoteTime;

            now = time(NULL);
            remoteTime = (time_t)attrs.mtime;
            nowParts = localtime(&remoteTime);

            if ((time_t)attrs.mtime > (now - (3600 * 24 * 180))) {
              currLen += snprintf(line+currLen, totalLen-currLen,
                                  " %s %2d %2d:%02d", months[nowParts->tm_mon],
                                  nowParts->tm_mday, nowParts->tm_hour,
                                  nowParts->tm_min);
            }
            else {
              currLen += snprintf(line+currLen, totalLen-currLen,
                                  " %s %2d %5d", months[nowParts->tm_mon],
                                  nowParts->tm_mday, 1900+nowParts->tm_year);
            }
          }
          currLen += snprintf(line+currLen, totalLen-currLen, " %s", filename);
          if ((attrs.flags & LIBSSH2_SFTP_ATTR_PERMISSIONS) &&
              ((attrs.permissions & LIBSSH2_SFTP_S_IFMT) ==
               LIBSSH2_SFTP_S_IFLNK)) {
            char linkPath[PATH_MAX + 1];

            snprintf(linkPath, PATH_MAX, "%s%s", sftp->path, filename);
            len = libssh2_sftp_readlink(sftp->sftp_session, linkPath, filename,
                                        PATH_MAX);
            line = realloc(line, totalLen + 4 + len);
            if (!line)
              return CURLE_OUT_OF_MEMORY;

            currLen += snprintf(line+currLen, totalLen-currLen, " -> %s",
                                filename);
          }

          currLen += snprintf(line+currLen, totalLen-currLen, "\n");
          res = Curl_client_write(conn, CLIENTWRITE_BODY, line, 0);
          free(line);
        }
      }
      libssh2_sftp_closedir(sftp->sftp_handle);
      sftp->sftp_handle = NULL;

      /* no data to transfer */
      res = Curl_setup_transfer(conn, -1, -1, FALSE, NULL, -1, NULL);
    }
    else {
      /*
       * Work on getting the specified file
       */
      sftp->sftp_handle =
        libssh2_sftp_open(sftp->sftp_session, sftp->path, LIBSSH2_FXF_READ,
                          LIBSSH2_SFTP_S_IRUSR|LIBSSH2_SFTP_S_IWUSR|
                          LIBSSH2_SFTP_S_IRGRP|LIBSSH2_SFTP_S_IROTH);
      if (!sftp->sftp_handle)
        return CURLE_SSH;

      if (libssh2_sftp_stat(sftp->sftp_session, sftp->path, &attrs)) {
        /*
         * libssh2_sftp_open() didn't return an error, so maybe the server
         * just doesn't support stat()
         */
        data->reqdata.size = -1;
        data->reqdata.maxdownload = -1;
      }
      else {
        data->reqdata.size = attrs.filesize;
        data->reqdata.maxdownload = attrs.filesize;
        Curl_pgrsSetDownloadSize(data, attrs.filesize);
      }

      Curl_pgrsTime(data, TIMER_STARTTRANSFER);

      /* Now download data. The libssh2 0.14 doesn't offer any way to do this
         without using this BLOCKING approach, so here's room for improvement
         once libssh2 can return EWOULDBLOCK to us. */
#if 0
      /* code left here just because this is what this function will use the
         day libssh2 is improved */
      res = Curl_setup_transfer(conn, FIRSTSOCKET,
                                bytecount, FALSE, NULL, -1, NULL);
#endif
      while (res == CURLE_OK) {
        size_t nread;
        /* NOTE: most *read() functions return ssize_t but this returns size_t
           which normally is unsigned! */
        nread = libssh2_sftp_read(data->reqdata.proto.ssh->sftp_handle,
                                  buf, BUFSIZE-1);

        if (nread > 0)
          buf[nread] = 0;

        /* this check can be changed to a <= 0 when nread is changed to a
           signed variable type */
        if ((nread == 0) || (nread == (size_t)~0))
          break;

        bytecount += nread;

        res = Curl_client_write(conn, CLIENTWRITE_BODY, buf, nread);
        if(res)
          return res;

        Curl_pgrsSetDownloadCounter(data, bytecount);

        if(Curl_pgrsUpdate(conn))
          res = CURLE_ABORTED_BY_CALLBACK;
        else {
          struct timeval now = Curl_tvnow();
          res = Curl_speedcheck(data, now);
        }
      }
      if(Curl_pgrsUpdate(conn))
        res = CURLE_ABORTED_BY_CALLBACK;

      /* no (more) data to transfer */
      res = Curl_setup_transfer(conn, -1, -1, FALSE, NULL, -1, NULL);
    }
  }

  return res;
}

CURLcode Curl_sftp_done(struct connectdata *conn, CURLcode status,
                        bool premature)
{
  struct SSHPROTO *sftp = conn->data->reqdata.proto.ssh;
  (void)premature; /* not used */

  Curl_safefree(sftp->path);
  sftp->path = NULL;

  Curl_safefree(sftp->homedir);
  sftp->homedir = NULL;

  if (sftp->sftp_handle) {
    if (libssh2_sftp_close(sftp->sftp_handle) < 0) {
      infof(conn->data, "Failed to close libssh2 file\n");
    }
  }

  if (sftp->sftp_session) {
    if (libssh2_sftp_shutdown(sftp->sftp_session) < 0) {
      infof(conn->data, "Failed to stop libssh2 sftp subsystem\n");
    }
  }

  if (sftp->ssh_channel) {
    if (libssh2_channel_close(sftp->ssh_channel) < 0) {
      infof(conn->data, "Failed to stop libssh2 channel subsystem\n");
    }
  }

  if (sftp->ssh_session) {
    libssh2_session_disconnect(sftp->ssh_session, "Shutdown");
    libssh2_session_free(sftp->ssh_session);
    sftp->ssh_session = NULL;
  }

  free(conn->data->reqdata.proto.ssh);
  conn->data->reqdata.proto.ssh = NULL;
  Curl_pgrsDone(conn);

  (void)status; /* unused */

  return CURLE_OK;
}

/* return number of received (decrypted) bytes */
ssize_t Curl_sftp_send(struct connectdata *conn, int sockindex,
                       void *mem, size_t len)
{
  ssize_t nwrite;

  /* libssh2_sftp_write() returns size_t !*/

  nwrite = (ssize_t)
    libssh2_sftp_write(conn->data->reqdata.proto.ssh->sftp_handle, mem, len);
  (void)sockindex;
  return nwrite;
}

/*
 * If the read would block (EWOULDBLOCK) we return -1. Otherwise we return
 * a regular CURLcode value.
 */
ssize_t Curl_sftp_recv(struct connectdata *conn, int sockindex,
                   char *mem, size_t len)
{
  ssize_t nread;

  /* libssh2_sftp_read() returns size_t !*/

  nread = (ssize_t)
    libssh2_sftp_read(conn->data->reqdata.proto.ssh->sftp_handle, mem, len);
  (void)sockindex;
  return nread;
}

#endif /* USE_LIBSSH2 */
