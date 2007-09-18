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

#if !defined(LIBSSH2_VERSION_NUM) || (LIBSSH2_VERSION_NUM < 0x001000)
#error "this requires libssh2 0.16 or later"
#endif

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif

#ifdef HAVE_FCNTL_H
#include <fcntl.h>
#endif

#ifdef HAVE_TIME_H
#include <time.h>
#endif

#ifndef WIN32
#ifdef HAVE_SYS_SOCKET_H
#include <sys/socket.h>
#endif
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
#endif /* !WIN32 */

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

#define _MPRINTF_REPLACE /* use our functions only */
#include <curl/mprintf.h>

/* The last #include file should be: */
#ifdef CURLDEBUG
#include "memdebug.h"
#endif

#ifndef PATH_MAX
#define PATH_MAX 1024 /* just an extra precaution since there are systems that
                         have their definition hidden well */
#endif

/* Local functions: */
static const char *sftp_libssh2_strerror(unsigned long err);
static LIBSSH2_ALLOC_FUNC(libssh2_malloc);
static LIBSSH2_REALLOC_FUNC(libssh2_realloc);
static LIBSSH2_FREE_FUNC(libssh2_free);

static int get_pathname(const char **cpp, char **path);

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

static CURLcode sftp_libssh2_error_to_CURLE(unsigned long err)
{
  switch (err) {
    case LIBSSH2_FX_OK:
      return CURLE_OK;

    case LIBSSH2_FX_NO_SUCH_FILE:
    case LIBSSH2_FX_NO_SUCH_PATH:
      return CURLE_REMOTE_FILE_NOT_FOUND;

    case LIBSSH2_FX_PERMISSION_DENIED:
    case LIBSSH2_FX_WRITE_PROTECT:
    case LIBSSH2_FX_LOCK_CONFlICT:
      return CURLE_REMOTE_ACCESS_DENIED;

    case LIBSSH2_FX_NO_SPACE_ON_FILESYSTEM:
    case LIBSSH2_FX_QUOTA_EXCEEDED:
      return CURLE_REMOTE_DISK_FULL;

    case LIBSSH2_FX_FILE_ALREADY_EXISTS:
      return CURLE_REMOTE_FILE_EXISTS;

    case LIBSSH2_FX_DIR_NOT_EMPTY:
      return CURLE_QUOTE_ERROR;

    default:
      break;
  }

  return CURLE_SSH;
}

static CURLcode libssh2_session_error_to_CURLE(int err)
{
  if (err == LIBSSH2_ERROR_ALLOC)
    return CURLE_OUT_OF_MEMORY;

  /* TODO: map some more of the libssh2 errors to the more appropriate CURLcode
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

/*
 * SSH State machine related code
 */
/* This is the ONLY way to change SSH state! */
static void state(struct connectdata *conn, sshstate state)
{
#if defined(CURLDEBUG) && !defined(CURL_DISABLE_VERBOSE_STRINGS)
  /* for debug purposes */
  static const char * const names[] = {
    "SSH_STOP",
    "SSH_S_STARTUP",
    "SSH_AUTHLIST",
    "SSH_AUTH_PKEY_INIT",
    "SSH_AUTH_PKEY",
    "SSH_AUTH_PASS_INIT",
    "SSH_AUTH_PASS",
    "SSH_AUTH_HOST_INIT",
    "SSH_AUTH_HOST",
    "SSH_AUTH_KEY_INIT",
    "SSH_AUTH_KEY",
    "SSH_AUTH_DONE",
    "SSH_SFTP_INIT",
    "SSH_SFTP_REALPATH",
    "SSH_GET_WORKINGPATH",
    "SSH_SFTP_QUOTE_INIT",
    "SSH_SFTP_POSTQUOTE_INIT",
    "SSH_SFTP_QUOTE",
    "SSH_SFTP_NEXT_QUOTE",
    "SSH_SFTP_QUOTE_STAT",
    "SSH_SFTP_QUOTE_SETSTAT",
    "SSH_SFTP_QUOTE_SYMLINK",
    "SSH_SFTP_QUOTE_MKDIR",
    "SSH_SFTP_QUOTE_RENAME",
    "SSH_SFTP_QUOTE_RMDIR",
    "SSH_SFTP_QUOTE_UNLINK",
    "SSH_SFTP_TRANS_INIT",
    "SSH_SFTP_UPLOAD_INIT",
    "SSH_SFTP_CREATE_DIRS_INIT",
    "SSH_SFTP_CREATE_DIRS",
    "SSH_SFTP_CREATE_DIRS_MKDIR",
    "SSH_SFTP_READDIR_INIT",
    "SSH_SFTP_READDIR",
    "SSH_SFTP_READDIR_LINK",
    "SSH_SFTP_READDIR_BOTTOM",
    "SSH_SFTP_READDIR_DONE",
    "SSH_SFTP_DOWNLOAD_INIT",
    "SSH_SFTP_DOWNLOAD_STAT",
    "SSH_SFTP_CLOSE",
    "SSH_SFTP_SHUTDOWN",
    "SSH_SCP_TRANS_INIT",
    "SSH_SCP_UPLOAD_INIT",
    "SSH_SCP_DOWNLOAD_INIT",
    "SSH_SCP_DONE",
    "SSH_SCP_SEND_EOF",
    "SSH_SCP_WAIT_EOF",
    "SSH_SCP_WAIT_CLOSE",
    "SSH_SCP_CHANNEL_FREE",
    "SSH_CHANNEL_CLOSE",
    "SSH_SESSION_DISCONECT",
    "SSH_SESSION_FREE",
    "QUIT"
  };
#endif
  struct ssh_conn *sshc = &conn->proto.sshc;

#if defined(CURLDEBUG) && !defined(CURL_DISABLE_VERBOSE_STRINGS)
  if (sshc->state != state) {
    infof(conn->data, "SFTP %p state change from %s to %s\n",
          sshc, names[sshc->state], names[state]);
  }
#endif

  sshc->state = state;
}

static CURLcode ssh_statemach_act(struct connectdata *conn)
{
  CURLcode result = CURLE_OK;
  struct SessionHandle *data = conn->data;
  struct SSHPROTO *sftp_scp = data->reqdata.proto.ssh;
  struct ssh_conn *sshc = &conn->proto.sshc;
  curl_socket_t sock = conn->sock[FIRSTSOCKET];
#ifdef CURL_LIBSSH2_DEBUG
  const char *fingerprint;
#endif /* CURL_LIBSSH2_DEBUG */
  int rc;
  long err;

  switch(sshc->state) {
    case SSH_S_STARTUP:
      sshc->secondCreateDirs = 0;
      sshc->nextState = SSH_NO_STATE;
      sshc->actualCode = CURLE_OK;

      rc = libssh2_session_startup(sftp_scp->ssh_session, sock);
      if (rc == LIBSSH2_ERROR_EAGAIN) {
        break;
      }
      else if (rc) {
        failf(data, "Failure establishing ssh session");
        state(conn, SSH_SESSION_FREE);
        sshc->actualCode = CURLE_FAILED_INIT;
        break;
      }

      /* Set libssh2 to non-blocking, since cURL is all non-blocking */
      libssh2_session_set_blocking(sftp_scp->ssh_session, 0);

#ifdef CURL_LIBSSH2_DEBUG
      /*
       * Before we authenticate we should check the hostkey's fingerprint
       * against our known hosts. How that is handled (reading from file,
       * whatever) is up to us. As for know not much is implemented, besides
       * showing how to get the fingerprint.
       */
      fingerprint = libssh2_hostkey_hash(sftp_scp->ssh_session,
                                         LIBSSH2_HOSTKEY_HASH_MD5);

      /* The fingerprint points to static storage (!), don't free() it. */
      infof(data, "Fingerprint: ");
      for (rc = 0; rc < 16; rc++) {
        infof(data, "%02X ", (unsigned char) fingerprint[rc]);
      }
      infof(data, "\n");
#endif /* CURL_LIBSSH2_DEBUG */

      state(conn, SSH_AUTHLIST);
      break;

    case SSH_AUTHLIST:
      /* TBD - methods to check the host keys need to be done */

      /*
       * Figure out authentication methods
       * NB: As soon as we have provided a username to an openssh server we
       * must never change it later. Thus, always specify the correct username
       * here, even though the libssh2 docs kind of indicate that it should be
       * possible to get a 'generic' list (not user-specific) of authentication
       * methods, presumably with a blank username. That won't work in my
       * experience.
       * So always specify it here.
       */
      sshc->authlist = libssh2_userauth_list(sftp_scp->ssh_session,
                                             sftp_scp->user,
                                             strlen(sftp_scp->user));

      if (!sshc->authlist) {
        if ((err = libssh2_session_last_errno(sftp_scp->ssh_session)) ==
                        LIBSSH2_ERROR_EAGAIN) {
          break;
        } else {
          state(conn, SSH_SESSION_FREE);
          sshc->actualCode = libssh2_session_error_to_CURLE(err);
          break;
        }
      }
      infof(data, "SSH authentication methods available: %s\n", sshc->authlist);

      state(conn, SSH_AUTH_PKEY_INIT);
      break;

    case SSH_AUTH_PKEY_INIT:
      /*
       * Check the supported auth types in the order I feel is most secure
       * with the requested type of authentication
       */
      sshc->authed = FALSE;

      if ((data->set.ssh_auth_types & CURLSSH_AUTH_PUBLICKEY) &&
          (strstr(sshc->authlist, "publickey") != NULL)) {
        char *home;

        sshc->rsa_pub = sshc->rsa = NULL;

        /* To ponder about: should really the lib be messing about with the
           HOME environment variable etc? */
        home = curl_getenv("HOME");

        if (data->set.str[STRING_SSH_PUBLIC_KEY])
          sshc->rsa_pub = aprintf("%s", data->set.str[STRING_SSH_PUBLIC_KEY]);
        else if (home)
          sshc->rsa_pub = aprintf("%s/.ssh/id_dsa.pub", home);
        else
          /* as a final resort, try current dir! */
          sshc->rsa_pub = strdup("id_dsa.pub");

        if (sshc->rsa_pub == NULL) {
          Curl_safefree(home);
          home = NULL;
          state(conn, SSH_SESSION_FREE);
          sshc->actualCode = CURLE_OUT_OF_MEMORY;
          break;
        }

        if (data->set.str[STRING_SSH_PRIVATE_KEY])
          sshc->rsa = aprintf("%s", data->set.str[STRING_SSH_PRIVATE_KEY]);
        else if (home)
          sshc->rsa = aprintf("%s/.ssh/id_dsa", home);
        else
          /* as a final resort, try current dir! */
          sshc->rsa = strdup("id_dsa");

        if (sshc->rsa == NULL) {
          Curl_safefree(home);
          home = NULL;
          Curl_safefree(sshc->rsa_pub);
          sshc->rsa_pub = NULL;
          state(conn, SSH_SESSION_FREE);
          sshc->actualCode = CURLE_OUT_OF_MEMORY;
          break;
        }

        sshc->passphrase = data->set.str[STRING_KEY_PASSWD];
        if (!sshc->passphrase)
          sshc->passphrase = "";

        Curl_safefree(home);
        home = NULL;

        infof(data, "Using ssh public key file %s\n", sshc->rsa_pub);
        infof(data, "Using ssh private key file %s\n", sshc->rsa);

        state(conn, SSH_AUTH_PKEY);
      } else {
        state(conn, SSH_AUTH_PASS_INIT);
      }
      break;

    case SSH_AUTH_PKEY:
      /* The function below checks if the files exists, no need to stat() here.
       */
      rc = libssh2_userauth_publickey_fromfile(sftp_scp->ssh_session,
                                               sftp_scp->user, sshc->rsa_pub,
                                               sshc->rsa, sshc->passphrase);
      if (rc == LIBSSH2_ERROR_EAGAIN) {
        break;
      }

      Curl_safefree(sshc->rsa_pub);
      sshc->rsa_pub = NULL;
      Curl_safefree(sshc->rsa);
      sshc->rsa = NULL;

      if (rc == 0) {
        sshc->authed = TRUE;
        infof(data, "Initialized SSH public key authentication\n");
        state(conn, SSH_AUTH_DONE);
      } else {
        state(conn, SSH_AUTH_PASS_INIT);
      }
      break;

    case SSH_AUTH_PASS_INIT:
      if ((data->set.ssh_auth_types & CURLSSH_AUTH_PASSWORD) &&
          (strstr(sshc->authlist, "password") != NULL)) {
        state(conn, SSH_AUTH_PASS);
      } else {
        state(conn, SSH_AUTH_HOST_INIT);
      }
      break;

    case SSH_AUTH_PASS:
      rc = libssh2_userauth_password(sftp_scp->ssh_session, sftp_scp->user,
                                     sftp_scp->passwd);
      if (rc == LIBSSH2_ERROR_EAGAIN) {
        break;
      }
      else if (rc == 0) {
        sshc->authed = TRUE;
        infof(data, "Initialized password authentication\n");
        state(conn, SSH_AUTH_DONE);
      } else {
        state(conn, SSH_AUTH_HOST_INIT);
      }
      break;

    case SSH_AUTH_HOST_INIT:
      if ((data->set.ssh_auth_types & CURLSSH_AUTH_HOST) &&
          (strstr(sshc->authlist, "hostbased") != NULL)) {
        state(conn, SSH_AUTH_HOST);
      } else {
        state(conn, SSH_AUTH_KEY_INIT);
      }
      break;

    case SSH_AUTH_HOST:
      state(conn, SSH_AUTH_KEY_INIT);
      break;

    case SSH_AUTH_KEY_INIT:
      if ((data->set.ssh_auth_types & CURLSSH_AUTH_KEYBOARD)
          && (strstr(sshc->authlist, "keyboard-interactive") != NULL)) {
        state(conn, SSH_AUTH_KEY);
      } else {
        state(conn, SSH_AUTH_DONE);
      }
      break;

    case SSH_AUTH_KEY:
      /* Authentication failed. Continue with keyboard-interactive now. */
      rc = libssh2_userauth_keyboard_interactive_ex(sftp_scp->ssh_session,
                                                    sftp_scp->user,
                                                    strlen(sftp_scp->user),
                                                    &kbd_callback);
      if (rc == LIBSSH2_ERROR_EAGAIN) {
        break;
      }
      else if (rc == 0) {
        sshc->authed = TRUE;
        infof(data, "Initialized keyboard interactive authentication\n");
      }
      state(conn, SSH_AUTH_DONE);
      break;

    case SSH_AUTH_DONE:
      if (!sshc->authed) {
        failf(data, "Authentication failure");
        state(conn, SSH_SESSION_FREE);
        sshc->actualCode = CURLE_LOGIN_DENIED;
        break;
      }

      /*
       * At this point we have an authenticated ssh session.
       */
      infof(data, "Authentication complete\n");

      conn->sockfd = sock;
      conn->writesockfd = CURL_SOCKET_BAD;

      if (conn->protocol == PROT_SFTP) {
        state(conn, SSH_SFTP_INIT);
        break;
      }
      state(conn, SSH_GET_WORKINGPATH);
      break;

    case SSH_SFTP_INIT:
      /*
       * Start the libssh2 sftp session
       */
      sftp_scp->sftp_session = libssh2_sftp_init(sftp_scp->ssh_session);
      if (!sftp_scp->sftp_session) {
        if (libssh2_session_last_errno(sftp_scp->ssh_session) ==
            LIBSSH2_ERROR_EAGAIN) {
          break;
        } else {
          failf(data, "Failure initialising sftp session\n");
          state(conn, SSH_SESSION_FREE);
          sshc->actualCode = CURLE_FAILED_INIT;
          break;
        }
      }
      state(conn, SSH_SFTP_REALPATH);
      break;

    case SSH_SFTP_REALPATH:
      {
        char tempHome[PATH_MAX];

        /*
         * Get the "home" directory
         */
        rc = libssh2_sftp_realpath(sftp_scp->sftp_session, ".",
                                   tempHome, PATH_MAX-1);
        if (rc == LIBSSH2_ERROR_EAGAIN) {
          break;
        }
        else if (rc > 0) {
          /* It seems that this string is not always NULL terminated */
          tempHome[rc] = '\0';
          sftp_scp->homedir = (char *)strdup(tempHome);
          if (!sftp_scp->homedir) {
            state(conn, SSH_SFTP_CLOSE);
            sshc->actualCode = CURLE_OUT_OF_MEMORY;
            break;
          }
        } else {
          /* Return the error type */
          result = libssh2_sftp_last_error(sftp_scp->sftp_session);
          DEBUGF(infof(data, "error = %d\n", result));
          state(conn, SSH_STOP);
          break;
        }
        state(conn, SSH_GET_WORKINGPATH);
      }
      break;

    case SSH_GET_WORKINGPATH:
      {
        char *real_path;
        char *working_path;
        int working_path_len;

        working_path = curl_easy_unescape(data, data->reqdata.path, 0,
                                          &working_path_len);
        if (!working_path) {
          result = CURLE_OUT_OF_MEMORY;
          state(conn, SSH_STOP);
          break;
        }

        /* Check for /~/ , indicating relative to the user's home directory */
        if (conn->protocol == PROT_SCP) {
          real_path = (char *)malloc(working_path_len+1);
          if (real_path == NULL) {
            Curl_safefree(working_path);
            working_path = NULL;
            state(conn, SSH_SESSION_FREE);
            sshc->actualCode = CURLE_OUT_OF_MEMORY;
            break;
          }
          if (working_path[1] == '~')
            /* It is referenced to the home directory, so strip the
               leading '/' */
            memcpy(real_path, working_path+1, 1 + working_path_len-1);
          else
            memcpy(real_path, working_path, 1 + working_path_len);
        }
        else if (conn->protocol == PROT_SFTP) {
          if (working_path[1] == '~') {
            real_path = (char *)malloc(strlen(sftp_scp->homedir) +
                                       working_path_len + 1);
            if (real_path == NULL) {
              Curl_safefree(sftp_scp->homedir);
              sftp_scp->homedir = NULL;
              Curl_safefree(working_path);
              working_path = NULL;
              state(conn, SSH_SFTP_CLOSE);
              sshc->actualCode = CURLE_OUT_OF_MEMORY;
              break;
            }
            /* It is referenced to the home directory, so strip the
               leading '/' */
            memcpy(real_path, sftp_scp->homedir, strlen(sftp_scp->homedir));
            real_path[strlen(sftp_scp->homedir)] = '/';
            real_path[strlen(sftp_scp->homedir)+1] = '\0';
            if (working_path_len > 3) {
              memcpy(real_path+strlen(sftp_scp->homedir)+1, working_path + 3,
                     1 + working_path_len -3);
            }
          }
          else {
            real_path = (char *)malloc(working_path_len+1);
            if (real_path == NULL) {
              Curl_safefree(sftp_scp->homedir);
              sftp_scp->homedir = NULL;
              Curl_safefree(working_path);
              working_path = NULL;
              state(conn, SSH_SFTP_CLOSE);
              sshc->actualCode = CURLE_OUT_OF_MEMORY;
              break;
            }
            memcpy(real_path, working_path, 1+working_path_len);
          }
        }
        else {
          Curl_safefree(working_path);
          working_path = NULL;
          state(conn, SSH_SESSION_FREE);
          sshc->actualCode = CURLE_FAILED_INIT;
          break;
        }

        Curl_safefree(working_path);
        working_path = NULL;
        sftp_scp->path = real_path;

        /* Connect is all done */
        state(conn, SSH_STOP);
      }
      break;

    case SSH_SFTP_QUOTE_INIT:
      if (data->set.quote) {
        infof(data, "Sending quote commands\n");
        sshc->quote_item = data->set.quote;
        state(conn, SSH_SFTP_QUOTE);
      } else {
        state(conn, SSH_SFTP_TRANS_INIT);
      }
      break;

    case SSH_SFTP_POSTQUOTE_INIT:
      if (data->set.postquote) {
        infof(data, "Sending quote commands\n");
        sshc->quote_item = data->set.postquote;
        state(conn, SSH_SFTP_QUOTE);
      } else {
        state(conn, SSH_STOP);
      }
      break;

    case SSH_SFTP_QUOTE:
      /* Send any quote commands */
      {
        const char *cp;

        /*
         * Support some of the "FTP" commands
         */
        if (curl_strnequal(sshc->quote_item->data, "PWD", 3)) {
          /* output debug output if that is requested */
          if (data->set.verbose) {
            char tmp[PATH_MAX+1];

            Curl_debug(data, CURLINFO_HEADER_OUT, (char *)"PWD\n", 4, conn);
            snprintf(tmp, PATH_MAX, "257 \"%s\" is current directory.\n",
                     sftp_scp->path);
            Curl_debug(data, CURLINFO_HEADER_IN, tmp, strlen(tmp), conn);
          }
          state(conn, SSH_SFTP_NEXT_QUOTE);
          break;
        }
        else if (sshc->quote_item->data) {
          fprintf(stderr, "data: %s\n", sshc->quote_item->data);
          /*
           * the arguments following the command must be separated from the
           * command with a space so we can check for it unconditionally
           */
          cp = strchr(sshc->quote_item->data, ' ');
          if (cp == NULL) {
            failf(data, "Syntax error in SFTP command. Supply parameter(s)!");
            state(conn, SSH_SFTP_CLOSE);
            sshc->actualCode = CURLE_QUOTE_ERROR;
            break;
          }

          /*
           * also, every command takes at least one argument so we get that
           * first argument right now
           */
          err = get_pathname(&cp, &sshc->quote_path1);
          if (err) {
            if (err == CURLE_OUT_OF_MEMORY)
              failf(data, "Out of memory");
            else
              failf(data, "Syntax error: Bad first parameter");
            state(conn, SSH_SFTP_CLOSE);
            sshc->actualCode = err;
            break;
          }

          /*
           * SFTP is a binary protocol, so we don't send text commands to
           * the server. Instead, we scan for commands for commands used by
           * OpenSSH's sftp program and call the appropriate libssh2
           * functions.
           */
          if (curl_strnequal(sshc->quote_item->data, "chgrp ", 6) ||
              curl_strnequal(sshc->quote_item->data, "chmod ", 6) ||
              curl_strnequal(sshc->quote_item->data, "chown ", 6) ) {
            /* attribute change */

            /* sshc->quote_path1 contains the mode to set */
            /* get the destination */
            err = get_pathname(&cp, &sshc->quote_path2);
            if (err) {
              if (err == CURLE_OUT_OF_MEMORY)
                failf(data, "Out of memory");
              else
                failf(data, "Syntax error in chgrp/chmod/chown: "
                      "Bad second parameter");
              Curl_safefree(sshc->quote_path1);
              sshc->quote_path1 = NULL;
              state(conn, SSH_SFTP_CLOSE);
              sshc->actualCode = err;
              break;
            }
            memset(&sshc->quote_attrs, 0, sizeof(LIBSSH2_SFTP_ATTRIBUTES));
            state(conn, SSH_SFTP_QUOTE_STAT);
            break;
          }
          else if (curl_strnequal(sshc->quote_item->data, "ln ", 3) ||
                   curl_strnequal(sshc->quote_item->data, "symlink ", 8)) {
            /* symbolic linking */
            /* sshc->quote_path1 is the source */
            /* get the destination */
            err = get_pathname(&cp, &sshc->quote_path2);
            if (err) {
              if (err == CURLE_OUT_OF_MEMORY)
                failf(data, "Out of memory");
              else
                failf(data,
                      "Syntax error in ln/symlink: Bad second parameter");
              Curl_safefree(sshc->quote_path1);
              sshc->quote_path1 = NULL;
              state(conn, SSH_SFTP_CLOSE);
              sshc->actualCode = err;
              break;
            }
            state(conn, SSH_SFTP_QUOTE_SYMLINK);
            break;
          }
          else if (curl_strnequal(sshc->quote_item->data, "mkdir ", 6)) {
            /* create dir */
            state(conn, SSH_SFTP_QUOTE_MKDIR);
            break;
          }
          else if (curl_strnequal(sshc->quote_item->data, "rename ", 7)) {
            /* rename file */
            /* first param is the source path */
            /* second param is the dest. path */
            err = get_pathname(&cp, &sshc->quote_path2);
            if (err) {
              if (err == CURLE_OUT_OF_MEMORY)
                failf(data, "Out of memory");
              else
                failf(data, "Syntax error in rename: Bad second parameter");
              Curl_safefree(sshc->quote_path1);
              sshc->quote_path1 = NULL;
              state(conn, SSH_SFTP_CLOSE);
              sshc->actualCode = err;
              break;
            }
            state(conn, SSH_SFTP_QUOTE_RENAME);
            break;
          }
          else if (curl_strnequal(sshc->quote_item->data, "rmdir ", 6)) {
            /* delete dir */
            state(conn, SSH_SFTP_QUOTE_RMDIR);
            break;
          }
          else if (curl_strnequal(sshc->quote_item->data, "rm ", 3)) {
            state(conn, SSH_SFTP_QUOTE_UNLINK);
            break;
          }

          if (sshc->quote_path1) {
            Curl_safefree(sshc->quote_path1);
            sshc->quote_path1 = NULL;
          }
          if (sshc->quote_path2) {
            Curl_safefree(sshc->quote_path2);
            sshc->quote_path2 = NULL;
          }
        }
      }
      if (!sshc->quote_item) {
        state(conn, SSH_SFTP_TRANS_INIT);
      }
      break;

    case SSH_SFTP_NEXT_QUOTE:
      if (sshc->quote_path1) {
        Curl_safefree(sshc->quote_path1);
        sshc->quote_path1 = NULL;
      }
      if (sshc->quote_path2) {
        Curl_safefree(sshc->quote_path2);
        sshc->quote_path2 = NULL;
      }

      sshc->quote_item = sshc->quote_item->next;

      if (sshc->quote_item) {
        state(conn, SSH_SFTP_QUOTE);
      } else {
        if (sshc->nextState != SSH_NO_STATE) {
          state(conn, sshc->nextState);
          sshc->nextState = SSH_NO_STATE;
        } else {
          state(conn, SSH_SFTP_TRANS_INIT);
        }
      }
      break;

    case SSH_SFTP_QUOTE_STAT:
      rc = libssh2_sftp_stat(sftp_scp->sftp_session, sshc->quote_path2,
                             &sshc->quote_attrs);
      if (rc == LIBSSH2_ERROR_EAGAIN) {
        break;
      }
      else if (rc != 0) { /* get those attributes */
        err = libssh2_sftp_last_error(sftp_scp->sftp_session);
        Curl_safefree(sshc->quote_path1);
        sshc->quote_path1 = NULL;
        Curl_safefree(sshc->quote_path2);
        sshc->quote_path2 = NULL;
        failf(data, "Attempt to get SFTP stats failed: %s",
              sftp_libssh2_strerror(err));
        state(conn, SSH_SFTP_CLOSE);
        sshc->actualCode = CURLE_QUOTE_ERROR;
        break;
      }

      /* Now set the new attributes... */
      if (curl_strnequal(sshc->quote_item->data, "chgrp", 5)) {
        sshc->quote_attrs.gid = strtol(sshc->quote_path1, NULL, 10);
        if (sshc->quote_attrs.gid == 0 && !ISDIGIT(sshc->quote_path1[0])) {
          Curl_safefree(sshc->quote_path1);
          sshc->quote_path1 = NULL;
          Curl_safefree(sshc->quote_path2);
          sshc->quote_path2 = NULL;
          failf(data, "Syntax error: chgrp gid not a number");
          state(conn, SSH_SFTP_CLOSE);
          sshc->actualCode = CURLE_QUOTE_ERROR;
          break;
        }
      }
      else if (curl_strnequal(sshc->quote_item->data, "chmod", 5)) {
        sshc->quote_attrs.permissions = strtol(sshc->quote_path1, NULL, 8);
        /* permissions are octal */
        if (sshc->quote_attrs.permissions == 0 &&
            !ISDIGIT(sshc->quote_path1[0])) {
          Curl_safefree(sshc->quote_path1);
          sshc->quote_path1 = NULL;
          Curl_safefree(sshc->quote_path2);
          sshc->quote_path2 = NULL;
          failf(data, "Syntax error: chmod permissions not a number");
          state(conn, SSH_SFTP_CLOSE);
          sshc->actualCode = CURLE_QUOTE_ERROR;
          break;
        }
      }
      else if (curl_strnequal(sshc->quote_item->data, "chown", 5)) {
        sshc->quote_attrs.uid = strtol(sshc->quote_path1, NULL, 10);
        if (sshc->quote_attrs.uid == 0 && !ISDIGIT(sshc->quote_path1[0])) {
          Curl_safefree(sshc->quote_path1);
          sshc->quote_path1 = NULL;
          Curl_safefree(sshc->quote_path2);
          sshc->quote_path2 = NULL;
          failf(data, "Syntax error: chown uid not a number");
          state(conn, SSH_SFTP_CLOSE);
          sshc->actualCode = CURLE_QUOTE_ERROR;
          break;
        }
      }

      /* Now send the completed structure... */
      state(conn, SSH_SFTP_QUOTE_SETSTAT);
      break;

    case SSH_SFTP_QUOTE_SETSTAT:
      rc = libssh2_sftp_setstat(sftp_scp->sftp_session, sshc->quote_path2,
                                &sshc->quote_attrs);
      if (rc == LIBSSH2_ERROR_EAGAIN) {
        break;
      } else if (rc != 0) {
        err = libssh2_sftp_last_error(sftp_scp->sftp_session);
        Curl_safefree(sshc->quote_path1);
        sshc->quote_path1 = NULL;
        Curl_safefree(sshc->quote_path2);
        sshc->quote_path2 = NULL;
        failf(data, "Attempt to set SFTP stats failed: %s",
              sftp_libssh2_strerror(err));
        state(conn, SSH_SFTP_CLOSE);
        sshc->actualCode = CURLE_QUOTE_ERROR;
        break;
      }
      state(conn, SSH_SFTP_NEXT_QUOTE);
      break;

    case SSH_SFTP_QUOTE_SYMLINK:
      rc = libssh2_sftp_symlink(sftp_scp->sftp_session, sshc->quote_path1,
                                sshc->quote_path2);
      if (rc == LIBSSH2_ERROR_EAGAIN) {
        break;
      }
      else if (rc != 0) {
        err = libssh2_sftp_last_error(sftp_scp->sftp_session);
        Curl_safefree(sshc->quote_path1);
        sshc->quote_path1 = NULL;
        Curl_safefree(sshc->quote_path2);
        sshc->quote_path2 = NULL;
        failf(data, "symlink command failed: %s",
              sftp_libssh2_strerror(err));
        state(conn, SSH_SFTP_CLOSE);
        sshc->actualCode = CURLE_QUOTE_ERROR;
        break;
      }
      state(conn, SSH_SFTP_NEXT_QUOTE);
      break;

    case SSH_SFTP_QUOTE_MKDIR:
      rc = libssh2_sftp_mkdir(sftp_scp->sftp_session, sshc->quote_path1, 0755);
      if (rc == LIBSSH2_ERROR_EAGAIN) {
        break;
      }
      else if (rc != 0) {
        err = libssh2_sftp_last_error(sftp_scp->sftp_session);
        Curl_safefree(sshc->quote_path1);
        sshc->quote_path1 = NULL;
        failf(data, "mkdir command failed: %s", sftp_libssh2_strerror(err));
        state(conn, SSH_SFTP_CLOSE);
        sshc->actualCode = CURLE_QUOTE_ERROR;
        break;
      }
      state(conn, SSH_SFTP_NEXT_QUOTE);
      break;

    case SSH_SFTP_QUOTE_RENAME:
      rc = libssh2_sftp_rename(sftp_scp->sftp_session, sshc->quote_path1,
                               sshc->quote_path2);
      if (rc == LIBSSH2_ERROR_EAGAIN) {
        break;
      } else if (rc != 0) {
        err = libssh2_sftp_last_error(sftp_scp->sftp_session);
        Curl_safefree(sshc->quote_path1);
        sshc->quote_path1 = NULL;
        Curl_safefree(sshc->quote_path2);
        sshc->quote_path2 = NULL;
        failf(data, "rename command failed: %s", sftp_libssh2_strerror(err));
        state(conn, SSH_SFTP_CLOSE);
        sshc->actualCode = CURLE_QUOTE_ERROR;
        break;
      }
      state(conn, SSH_SFTP_NEXT_QUOTE);
      break;

    case SSH_SFTP_QUOTE_RMDIR:
      rc = libssh2_sftp_rmdir(sftp_scp->sftp_session, sshc->quote_path1);
      if (rc == LIBSSH2_ERROR_EAGAIN) {
        break;
      }
      else if (rc != 0) {
        err = libssh2_sftp_last_error(sftp_scp->sftp_session);
        Curl_safefree(sshc->quote_path1);
        sshc->quote_path1 = NULL;
        failf(data, "rmdir command failed: %s", sftp_libssh2_strerror(err));
        state(conn, SSH_SFTP_CLOSE);
        sshc->actualCode = CURLE_QUOTE_ERROR;
        break;
      }
      state(conn, SSH_SFTP_NEXT_QUOTE);
      break;

    case SSH_SFTP_QUOTE_UNLINK:
      rc = libssh2_sftp_unlink(sftp_scp->sftp_session, sshc->quote_path1);
      if (rc == LIBSSH2_ERROR_EAGAIN) {
        break;
      }
      else if (rc != 0) {
        err = libssh2_sftp_last_error(sftp_scp->sftp_session);
        Curl_safefree(sshc->quote_path1);
        sshc->quote_path1 = NULL;
        failf(data, "rm command failed: %s", sftp_libssh2_strerror(err));
        state(conn, SSH_SFTP_CLOSE);
        sshc->actualCode = CURLE_QUOTE_ERROR;
        break;
      }
      state(conn, SSH_SFTP_NEXT_QUOTE);
      break;

    case SSH_SFTP_TRANS_INIT:
      if (data->set.upload) {
        state(conn, SSH_SFTP_UPLOAD_INIT);
        break;
      } else {
        if (sftp_scp->path[strlen(sftp_scp->path)-1] == '/') {
          state(conn, SSH_SFTP_READDIR_INIT);
          break;
        } else {
          state(conn, SSH_SFTP_DOWNLOAD_INIT);
          break;
        }
      }
      break;

    case SSH_SFTP_UPLOAD_INIT:
      /*
       * NOTE!!!  libssh2 requires that the destination path is a full path
       *          that includes the destination file and name OR ends in a "/"
       *          If this is not done the destination file will be named the
       *          same name as the last directory in the path.
       */
      sftp_scp->sftp_handle =
        libssh2_sftp_open(sftp_scp->sftp_session, sftp_scp->path,
                          LIBSSH2_FXF_WRITE|LIBSSH2_FXF_CREAT|LIBSSH2_FXF_TRUNC,
                          data->set.new_file_perms);
      if (!sftp_scp->sftp_handle) {
        if (libssh2_session_last_errno(sftp_scp->ssh_session) ==
            LIBSSH2_ERROR_EAGAIN) {
          break;
        } else {
          err = libssh2_sftp_last_error(sftp_scp->sftp_session);
          failf(data, "Upload failed: %s", sftp_libssh2_strerror(err));
          if (sshc->secondCreateDirs) {
            state(conn, SSH_SFTP_CLOSE);
            sshc->actualCode = err;
            break;
          }
          else if (((err == LIBSSH2_FX_NO_SUCH_FILE) ||
                    (err == LIBSSH2_FX_FAILURE) ||
                    (err == LIBSSH2_FX_NO_SUCH_PATH)) &&
                   (data->set.ftp_create_missing_dirs &&
                    (strlen(sftp_scp->path) > 1))) {
            /* try to create the path remotely */
            sshc->secondCreateDirs = 1;
            state(conn, SSH_SFTP_CREATE_DIRS_INIT);
            break;
          }
          state(conn, SSH_SFTP_CLOSE);
          sshc->actualCode = sftp_libssh2_error_to_CURLE(err);
          break;
        }
      }

      /* upload data */
      result = Curl_setup_transfer(conn, -1, -1, FALSE, NULL,
                                   FIRSTSOCKET, NULL);

      if (result) {
        state(conn, SSH_SFTP_CLOSE);
        sshc->actualCode = result;
      } else {
        state(conn, SSH_STOP);
      }
      break;

    case SSH_SFTP_CREATE_DIRS_INIT:
      if (strlen(sftp_scp->path) > 1) {
        sshc->slash_pos = sftp_scp->path + 1; /* ignore the leading '/' */
        state(conn, SSH_SFTP_CREATE_DIRS);
      } else {
        state(conn, SSH_SFTP_UPLOAD_INIT);
      }
      break;

    case SSH_SFTP_CREATE_DIRS:
      if ((sshc->slash_pos = strchr(sshc->slash_pos, '/')) != NULL) {
        *sshc->slash_pos = 0;

        infof(data, "Creating directory '%s'\n", sftp_scp->path);
        state(conn, SSH_SFTP_CREATE_DIRS_MKDIR);
        break;
      } else {
        state(conn, SSH_SFTP_UPLOAD_INIT);
      }
      break;

    case SSH_SFTP_CREATE_DIRS_MKDIR:
      /* 'mode' - parameter is preliminary - default to 0644 */
      rc = libssh2_sftp_mkdir(sftp_scp->sftp_session, sftp_scp->path,
                              data->set.new_directory_perms);
      if (rc == LIBSSH2_ERROR_EAGAIN) {
        break;
      }
      *sshc->slash_pos = '/';
      ++sshc->slash_pos;
      if (rc == -1) {
        unsigned int sftp_err = 0;
        /*
         * abort if failure wasn't that the dir already exists or the
         * permission was denied (creation might succeed further
         * down the path) - retry on unspecific FAILURE also
         */
        sftp_err = libssh2_sftp_last_error(sftp_scp->sftp_session);
        if ((sftp_err != LIBSSH2_FX_FILE_ALREADY_EXISTS) &&
            (sftp_err != LIBSSH2_FX_FAILURE) &&
            (sftp_err != LIBSSH2_FX_PERMISSION_DENIED)) {
          result = sftp_libssh2_error_to_CURLE(sftp_err);
          state(conn, SSH_SFTP_CLOSE);
          sshc->actualCode = result;
          break;
        }
      }
      state(conn, SSH_SFTP_CREATE_DIRS);
      break;

    case SSH_SFTP_READDIR_INIT:
      /*
       * This is a directory that we are trying to get, so produce a
       * directory listing
       */
      sftp_scp->sftp_handle = libssh2_sftp_opendir(sftp_scp->sftp_session,
                                                   sftp_scp->path);
      if (!sftp_scp->sftp_handle) {
        if (libssh2_session_last_errno(sftp_scp->ssh_session) ==
            LIBSSH2_ERROR_EAGAIN) {
          break;
        } else {
          err = libssh2_sftp_last_error(sftp_scp->sftp_session);
          failf(data, "Could not open directory for reading: %s",
                sftp_libssh2_strerror(err));
          state(conn, SSH_SFTP_CLOSE);
          sshc->actualCode = sftp_libssh2_error_to_CURLE(err);
          break;
        }
      }
      if ((sshc->readdir_filename = (char *)malloc(PATH_MAX+1)) == NULL) {
        state(conn, SSH_SFTP_CLOSE);
        sshc->actualCode = CURLE_OUT_OF_MEMORY;
        break;
      }
      if ((sshc->readdir_longentry = (char *)malloc(PATH_MAX+1)) == NULL) {
        Curl_safefree(sshc->readdir_filename);
        sshc->readdir_filename = NULL;
        state(conn, SSH_SFTP_CLOSE);
        sshc->actualCode = CURLE_OUT_OF_MEMORY;
        break;
      }
      state(conn, SSH_SFTP_READDIR);
      break;

    case SSH_SFTP_READDIR:
      sshc->readdir_len = libssh2_sftp_readdir_ex(sftp_scp->sftp_handle,
                                                  sshc->readdir_filename,
                                                  PATH_MAX,
                                                  sshc->readdir_longentry,
                                                  PATH_MAX,
                                                  &sshc->readdir_attrs);
      if (sshc->readdir_len == LIBSSH2_ERROR_EAGAIN) {
        break;
      }
      if (sshc->readdir_len > 0) {
        sshc->readdir_filename[sshc->readdir_len] = '\0';

        if (data->set.ftp_list_only) {
          char *tmpLine;

          tmpLine = aprintf("%s\n", sshc->readdir_filename);
          if (tmpLine == NULL) {
            state(conn, SSH_SFTP_CLOSE);
            sshc->actualCode = CURLE_OUT_OF_MEMORY;
            break;
          }
          result = Curl_client_write(conn, CLIENTWRITE_BODY, tmpLine, 0);
          Curl_safefree(tmpLine);

          /* output debug output if that is requested */
          if (data->set.verbose) {
            Curl_debug(data, CURLINFO_DATA_OUT, sshc->readdir_filename,
                       sshc->readdir_len, conn);
          }
        } else {
          sshc->readdir_currLen = strlen(sshc->readdir_longentry);
          sshc->readdir_totalLen = 80 + sshc->readdir_currLen;
          sshc->readdir_line = (char *)calloc(sshc->readdir_totalLen, 1);
          if (!sshc->readdir_line) {
            Curl_safefree(sshc->readdir_filename);
            sshc->readdir_filename = NULL;
            Curl_safefree(sshc->readdir_longentry);
            sshc->readdir_longentry = NULL;
            state(conn, SSH_SFTP_CLOSE);
            sshc->actualCode = CURLE_OUT_OF_MEMORY;
            break;
          }

          memcpy(sshc->readdir_line, sshc->readdir_longentry,
                 sshc->readdir_currLen);
          if ((sshc->readdir_attrs.flags & LIBSSH2_SFTP_ATTR_PERMISSIONS) &&
              ((sshc->readdir_attrs.permissions & LIBSSH2_SFTP_S_IFMT) ==
               LIBSSH2_SFTP_S_IFLNK)) {
            sshc->readdir_linkPath = (char *)malloc(PATH_MAX + 1);
            if (sshc->readdir_linkPath == NULL) {
              Curl_safefree(sshc->readdir_filename);
              sshc->readdir_filename = NULL;
              Curl_safefree(sshc->readdir_longentry);
              sshc->readdir_longentry = NULL;
              state(conn, SSH_SFTP_CLOSE);
              sshc->actualCode = CURLE_OUT_OF_MEMORY;
              break;
            }

            snprintf(sshc->readdir_linkPath, PATH_MAX, "%s%s", sftp_scp->path,
                     sshc->readdir_filename);
            state(conn, SSH_SFTP_READDIR_LINK);
            break;
          }
          state(conn, SSH_SFTP_READDIR_BOTTOM);
          break;
        }
      }
      else if (sshc->readdir_len == 0) {
        Curl_safefree(sshc->readdir_filename);
        sshc->readdir_filename = NULL;
        Curl_safefree(sshc->readdir_longentry);
        sshc->readdir_longentry = NULL;
        state(conn, SSH_SFTP_READDIR_DONE);
        break;
      }
      else if (sshc->readdir_len <= 0) {
        err = libssh2_sftp_last_error(sftp_scp->sftp_session);
        sshc->actualCode = err;
        failf(data, "Could not open remote file for reading: %s :: %d",
              sftp_libssh2_strerror(err),
              libssh2_session_last_errno(sftp_scp->ssh_session));
        Curl_safefree(sshc->readdir_filename);
        sshc->readdir_filename = NULL;
        Curl_safefree(sshc->readdir_longentry);
        sshc->readdir_longentry = NULL;
        state(conn, SSH_SFTP_CLOSE);
        break;
      }
      break;

    case SSH_SFTP_READDIR_LINK:
      sshc->readdir_len = libssh2_sftp_readlink(sftp_scp->sftp_session,
                                                sshc->readdir_linkPath,
                                                sshc->readdir_filename,
                                                PATH_MAX);
      if (sshc->readdir_len == LIBSSH2_ERROR_EAGAIN) {
        break;
      }
      Curl_safefree(sshc->readdir_linkPath);
      sshc->readdir_linkPath = NULL;
      sshc->readdir_line = realloc(sshc->readdir_line,
                                   sshc->readdir_totalLen + 4 +
                                   sshc->readdir_len);
      if (!sshc->readdir_line) {
        Curl_safefree(sshc->readdir_filename);
        sshc->readdir_filename = NULL;
        Curl_safefree(sshc->readdir_longentry);
        sshc->readdir_longentry = NULL;
        state(conn, SSH_SFTP_CLOSE);
        sshc->actualCode = CURLE_OUT_OF_MEMORY;
        break;
      }

      sshc->readdir_currLen += snprintf(sshc->readdir_line +
                                        sshc->readdir_currLen,
                                        sshc->readdir_totalLen -
                                        sshc->readdir_currLen,
                                        " -> %s",
                                        sshc->readdir_filename);

      state(conn, SSH_SFTP_READDIR_BOTTOM);
      break;

    case SSH_SFTP_READDIR_BOTTOM:
      sshc->readdir_currLen += snprintf(sshc->readdir_line +
                                        sshc->readdir_currLen,
                                        sshc->readdir_totalLen -
                                        sshc->readdir_currLen, "\n");
      result = Curl_client_write(conn, CLIENTWRITE_BODY,
                                 sshc->readdir_line, 0);

      /* output debug output if that is requested */
      if (data->set.verbose) {
        Curl_debug(data, CURLINFO_DATA_OUT, sshc->readdir_line,
                   sshc->readdir_currLen, conn);
      }
      Curl_safefree(sshc->readdir_line);
      sshc->readdir_line = NULL;
      state(conn, SSH_SFTP_READDIR);
      break;

    case SSH_SFTP_READDIR_DONE:
      if (libssh2_sftp_closedir(sftp_scp->sftp_handle) ==
          LIBSSH2_ERROR_EAGAIN) {
        break;
      }
      sftp_scp->sftp_handle = NULL;
      Curl_safefree(sshc->readdir_filename);
      sshc->readdir_filename = NULL;
      Curl_safefree(sshc->readdir_longentry);
      sshc->readdir_longentry = NULL;

      /* no data to transfer */
      result = Curl_setup_transfer(conn, -1, -1, FALSE, NULL, -1, NULL);
      state(conn, SSH_STOP);
      break;

    case SSH_SFTP_DOWNLOAD_INIT:
      /*
       * Work on getting the specified file
       */
      sftp_scp->sftp_handle =
        libssh2_sftp_open(sftp_scp->sftp_session, sftp_scp->path,
                          LIBSSH2_FXF_READ, data->set.new_file_perms);
      if (!sftp_scp->sftp_handle) {
        if (libssh2_session_last_errno(sftp_scp->ssh_session) ==
             LIBSSH2_ERROR_EAGAIN) {
          break;
        } else {
          err = libssh2_sftp_last_error(sftp_scp->sftp_session);
          failf(data, "Could not open remote file for reading: %s",
                sftp_libssh2_strerror(err));
          state(conn, SSH_SFTP_CLOSE);
          sshc->actualCode = sftp_libssh2_error_to_CURLE(err);
          break;
        }
      }
      state(conn, SSH_SFTP_DOWNLOAD_STAT);
      break;

    case SSH_SFTP_DOWNLOAD_STAT:
      {
        LIBSSH2_SFTP_ATTRIBUTES attrs;

        rc = libssh2_sftp_stat(sftp_scp->sftp_session, sftp_scp->path, &attrs);
        if (rc == LIBSSH2_ERROR_EAGAIN) {
          break;
        }
        else if (rc) {
          /*
           * libssh2_sftp_open() didn't return an error, so maybe the server
           * just doesn't support stat()
           */
          data->reqdata.size = -1;
          data->reqdata.maxdownload = -1;
        } else {
          data->reqdata.size = attrs.filesize;
          data->reqdata.maxdownload = attrs.filesize;
          Curl_pgrsSetDownloadSize(data, attrs.filesize);
        }
      }

      /* Setup the actual download */
      result = Curl_setup_transfer(conn, FIRSTSOCKET, data->reqdata.size,
                                   FALSE, NULL, -1, NULL);
      if (result) {
        state(conn, SSH_SFTP_CLOSE);
        sshc->actualCode = result;
      } else {
        state(conn, SSH_STOP);
      }
      break;

    case SSH_SFTP_CLOSE:
      if (sftp_scp->sftp_handle) {
        rc = libssh2_sftp_close(sftp_scp->sftp_handle);
        if (rc == LIBSSH2_ERROR_EAGAIN) {
          break;
        }
        else if (rc < 0) {
          infof(data, "Failed to close libssh2 file\n");
        }
        sftp_scp->sftp_handle = NULL;
      }
      state(conn, SSH_SFTP_SHUTDOWN);
      break;

    case SSH_SFTP_SHUTDOWN:
      if (sftp_scp->sftp_session) {
        rc = libssh2_sftp_shutdown(sftp_scp->sftp_session);
        if (rc == LIBSSH2_ERROR_EAGAIN) {
          break;
        }
        else if (rc < 0) {
          infof(data, "Failed to stop libssh2 sftp subsystem\n");
        }
        sftp_scp->sftp_session = NULL;
      }

      Curl_safefree(sftp_scp->path);
      sftp_scp->path = NULL;

      Curl_safefree(sftp_scp->homedir);
      sftp_scp->homedir = NULL;

      state(conn, SSH_CHANNEL_CLOSE);
      break;

    case SSH_SCP_TRANS_INIT:
      if (data->set.upload) {
        if (data->set.infilesize < 0) {
          failf(data, "SCP requires a known file size for upload");
          sshc->actualCode = CURLE_UPLOAD_FAILED;
          state(conn, SSH_SCP_CHANNEL_FREE);
          break;
        }
        state(conn, SSH_SCP_UPLOAD_INIT);
      } else {
        state(conn, SSH_SCP_DOWNLOAD_INIT);
      }
      break;

    case SSH_SCP_UPLOAD_INIT:
      /*
       * libssh2 requires that the destination path is a full path that
       * includes the destination file and name OR ends in a "/" .  If this is
       * not done the destination file will be named the same name as the last
       * directory in the path.
       */
      sftp_scp->ssh_channel =
                  libssh2_scp_send_ex(sftp_scp->ssh_session, sftp_scp->path,
                                      data->set.new_file_perms,
                                      data->set.infilesize, 0, 0);
      if (!sftp_scp->ssh_channel) {
        if (libssh2_session_last_errno(sftp_scp->ssh_session) ==
            LIBSSH2_ERROR_EAGAIN) {
          break;
        } else {
          int ssh_err;
          char *err_msg;

          ssh_err = libssh2_session_last_error(sftp_scp->ssh_session,
                                               &err_msg, NULL, 0);
          err = libssh2_session_error_to_CURLE(ssh_err);
          failf(conn->data, "%s", err_msg);
          state(conn, SSH_SCP_CHANNEL_FREE);
          sshc->actualCode = err;
          break;
        }
      }

      /* upload data */
      result = Curl_setup_transfer(conn, -1, data->reqdata.size, FALSE, NULL,
                                   FIRSTSOCKET, NULL);

      if (result) {
        state(conn, SSH_SCP_CHANNEL_FREE);
        sshc->actualCode = result;
      } else {
        state(conn, SSH_STOP);
      }
      break;

    case SSH_SCP_DOWNLOAD_INIT:
      {
        /*
         * We must check the remote file; if it is a directory no values will
         * be set in sb
         */
        struct stat sb;
        curl_off_t bytecount;

        memset(&sb, 0, sizeof(struct stat));
        sftp_scp->ssh_channel = libssh2_scp_recv(sftp_scp->ssh_session,
                                                 sftp_scp->path, &sb);
        if (!sftp_scp->ssh_channel) {
          if (libssh2_session_last_errno(sftp_scp->ssh_session) ==
             LIBSSH2_ERROR_EAGAIN) {
            break;
          } else {
            int ssh_err;
            char *err_msg;

            ssh_err = libssh2_session_last_error(sftp_scp->ssh_session,
                                                 &err_msg, NULL, 0);
            err = libssh2_session_error_to_CURLE(ssh_err);
            failf(conn->data, "%s", err_msg);
            state(conn, SSH_SCP_CHANNEL_FREE);
            sshc->actualCode = err;
            break;
          }
        }

        /* download data */
        bytecount = (curl_off_t)sb.st_size;
        data->reqdata.maxdownload =  (curl_off_t)sb.st_size;
        result = Curl_setup_transfer(conn, FIRSTSOCKET,
                                     bytecount, FALSE, NULL, -1, NULL);

        if (result) {
          state(conn, SSH_SCP_CHANNEL_FREE);
          sshc->actualCode = result;
        } else {
          state(conn, SSH_STOP);
        }
      }
      break;

    case SSH_SCP_DONE:
      if (data->set.upload) {
        state(conn, SSH_SCP_SEND_EOF);
      } else {
        state(conn, SSH_SCP_CHANNEL_FREE);
      }
      break;

    case SSH_SCP_SEND_EOF:
      if (sftp_scp->ssh_channel) {
        rc = libssh2_channel_send_eof(sftp_scp->ssh_channel);
        if (rc == LIBSSH2_ERROR_EAGAIN) {
          break;
        }
        else if (rc) {
          infof(data, "Failed to send libssh2 channel EOF\n");
        }
      }
      state(conn, SSH_SCP_WAIT_EOF);
      break;

    case SSH_SCP_WAIT_EOF:
      if (sftp_scp->ssh_channel) {
        rc = libssh2_channel_wait_eof(sftp_scp->ssh_channel);
        if (rc == LIBSSH2_ERROR_EAGAIN) {
          break;
        }
        else if (rc) {
          infof(data, "Failed to get channel EOF\n");
        }
      }
      state(conn, SSH_SCP_WAIT_CLOSE);
      break;

    case SSH_SCP_WAIT_CLOSE:
      if (sftp_scp->ssh_channel) {
        rc = libssh2_channel_wait_closed(sftp_scp->ssh_channel);
        if (rc == LIBSSH2_ERROR_EAGAIN) {
          break;
        }
        else if (rc) {
          infof(data, "Channel failed to close\n");
        }
      }
      state(conn, SSH_SCP_CHANNEL_FREE);
      break;

    case SSH_SCP_CHANNEL_FREE:
      if (sftp_scp->ssh_channel) {
        rc = libssh2_channel_free(sftp_scp->ssh_channel);
        if (rc == LIBSSH2_ERROR_EAGAIN) {
          break;
        }
        else if (rc < 0) {
          infof(data, "Failed to free libssh2 scp subsystem\n");
        }
        sftp_scp->ssh_channel = NULL;
      }
      state(conn, SSH_SESSION_DISCONECT);
      break;

    case SSH_CHANNEL_CLOSE:
      if (sftp_scp->ssh_channel) {
        rc = libssh2_channel_close(sftp_scp->ssh_channel);
        if (rc == LIBSSH2_ERROR_EAGAIN) {
          break;
        }
        else if (rc < 0) {
          infof(data, "Failed to stop libssh2 channel subsystem\n");
        }
        sftp_scp->ssh_channel = NULL;
      }
      state(conn, SSH_SESSION_DISCONECT);
      break;

    case SSH_SESSION_DISCONECT:
      if (sftp_scp->ssh_session) {
        rc = libssh2_session_disconnect(sftp_scp->ssh_session, "Shutdown");
        if (rc == LIBSSH2_ERROR_EAGAIN) {
          break;
        }
        else if (rc < 0) {
          infof(data, "Failed to disconnect libssh2 session\n");
        }
      }

      Curl_safefree(sftp_scp->path);
      sftp_scp->path = NULL;

      Curl_safefree(sftp_scp->homedir);
      sftp_scp->homedir = NULL;

      state(conn, SSH_SESSION_FREE);
      break;

    case SSH_SESSION_FREE:
      if (sftp_scp->ssh_session) {
        rc = libssh2_session_free(sftp_scp->ssh_session);
        if (rc == LIBSSH2_ERROR_EAGAIN) {
          break;
        }
        else if (rc < 0) {
          infof(data, "Failed to free libssh2 session\n");
        }
        sftp_scp->ssh_session = NULL;
      }
      sshc->nextState = SSH_NO_STATE;
      state(conn, SSH_STOP);
      result = sshc->actualCode;
      break;

    case SSH_QUIT:
      /* fallthrough, just stop! */
    default:
      /* internal error */
      sshc->nextState = SSH_NO_STATE;
      state(conn, SSH_STOP);
      break;
  }

  return result;
}

/* called repeatedly until done from multi.c */
CURLcode Curl_ssh_multi_statemach(struct connectdata *conn,
                                  bool *done)
{
  struct ssh_conn *sshc = &conn->proto.sshc;
  CURLcode result = CURLE_OK;

  result = ssh_statemach_act(conn);
  *done = (bool)(sshc->state == SSH_STOP);

  return result;
}

static CURLcode ssh_easy_statemach(struct connectdata *conn)
{
  struct ssh_conn *sshc = &conn->proto.sshc;
  CURLcode result = CURLE_OK;

  while (sshc->state != SSH_STOP) {
    result = ssh_statemach_act(conn);
    if (result) {
      break;
    }
  }

  return result;
}

/*
 * SSH setup and connection
 */
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
  struct SSHPROTO *ssh;
  curl_socket_t sock;
  CURLcode result;
  struct SessionHandle *data = conn->data;

  result = ssh_init(conn);
  if (result)
    return result;

  ssh = data->reqdata.proto.ssh;

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
    failf(data, "Failure initialising ssh session");
    return CURLE_FAILED_INIT;
  }

#ifdef CURL_LIBSSH2_DEBUG
  libssh2_trace(ssh->ssh_session, LIBSSH2_TRACE_CONN|LIBSSH2_TRACE_TRANS|
                LIBSSH2_TRACE_KEX|LIBSSH2_TRACE_AUTH|LIBSSH2_TRACE_SCP|
                LIBSSH2_TRACE_SFTP|LIBSSH2_TRACE_ERROR|
                LIBSSH2_TRACE_PUBLICKEY);
  infof(data, "SSH socket: %d\n", sock);
#endif /* CURL_LIBSSH2_DEBUG */

  state(conn, SSH_S_STARTUP);

  if (data->state.used_interface == Curl_if_multi)
    result = Curl_ssh_multi_statemach(conn, done);
  else {
    result = ssh_easy_statemach(conn);
    if (!result)
      *done = TRUE;
  }

  return result;
}

/*
 ***********************************************************************
 *
 * scp_perform()
 *
 * This is the actual DO function for SCP. Get a file according to
 * the options previously setup.
 */

static
CURLcode scp_perform(struct connectdata *conn,
                      bool *connected,
                      bool *dophase_done)
{
  CURLcode result = CURLE_OK;

  DEBUGF(infof(conn->data, "DO phase starts\n"));

  *dophase_done = FALSE; /* not done yet */

  /* start the first command in the DO phase */
  state(conn, SSH_SCP_TRANS_INIT);

  /* run the state-machine */
  if (conn->data->state.used_interface == Curl_if_multi) {
    result = Curl_ssh_multi_statemach(conn, dophase_done);
  } else {
    result = ssh_easy_statemach(conn);
    *dophase_done = TRUE; /* with the easy interface we are done here */
  }
  *connected = conn->bits.tcpconnect;

  if (*dophase_done) {
    DEBUGF(infof(conn->data, "DO phase is complete\n"));
  }

  return result;
}

/* called from multi.c while DOing */
CURLcode Curl_scp_doing(struct connectdata *conn,
                         bool *dophase_done)
{
  CURLcode result;
  result = Curl_ssh_multi_statemach(conn, dophase_done);

  if (*dophase_done) {
    DEBUGF(infof(conn->data, "DO phase is complete\n"));
  }
  return result;
}


CURLcode Curl_scp_do(struct connectdata *conn, bool *done)
{
  CURLcode res;
  bool connected = 0;
  struct SessionHandle *data = conn->data;

  *done = FALSE; /* default to false */

  /*
   * Since connections can be re-used between SessionHandles, this might be a
   * connection already existing but on a fresh SessionHandle struct so we must
   * make sure we have a good 'struct SSHPROTO' to play with. For new
   * connections, the struct SSHPROTO is allocated and setup in the
   * Curl_ssh_connect() function.
   */
  res = ssh_init(conn);
  if (res) {
    return res;
  }

  data->reqdata.size = -1; /* make sure this is unknown at this point */

  Curl_pgrsSetUploadCounter(data, 0);
  Curl_pgrsSetDownloadCounter(data, 0);
  Curl_pgrsSetUploadSize(data, 0);
  Curl_pgrsSetDownloadSize(data, 0);

  res = scp_perform(conn, &connected,  done);

  if (CURLE_OK == res) {

    if (!done) {
      /* the DO phase has not completed yet */
      return CURLE_OK;
    }
  }

  return res;
}

CURLcode Curl_scp_done(struct connectdata *conn, CURLcode status,
                       bool premature)
{
  CURLcode result = CURLE_OK;
  bool done = FALSE;
  (void)premature; /* not used */
  (void)status; /* unused */

  if (status == CURLE_OK) {
    state(conn, SSH_SCP_DONE);
    /* run the state-machine */
    if (conn->data->state.used_interface == Curl_if_multi) {
      result = Curl_ssh_multi_statemach(conn, &done);
    } else {
      result = ssh_easy_statemach(conn);
      done = TRUE;
    }
  } else {
    result = status;
    done = TRUE;
  }

  if (done) {
    Curl_safefree(conn->data->reqdata.proto.ssh);
    conn->data->reqdata.proto.ssh = NULL;
    Curl_pgrsDone(conn);
  }

  return result;

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
  if (nwrite == LIBSSH2_ERROR_EAGAIN)
    return 0;
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
  (void)sockindex; /* we only support SCP on the fixed known primary socket */

  /* libssh2_channel_read() returns int
   *
   * NOTE: we should not store nor rely on connection-related data to be
   * in the SessionHandle struct
   */
  nread = (ssize_t)
    libssh2_channel_read(conn->data->reqdata.proto.ssh->ssh_channel,
                         mem, len);
  return nread;
}

/*
 * =============== SFTP ===============
 */

/*
 ***********************************************************************
 *
 * sftp_perform()
 *
 * This is the actual DO function for SFTP. Get a file/directory according to
 * the options previously setup.
 */

static
CURLcode sftp_perform(struct connectdata *conn,
                      bool *connected,
                      bool *dophase_done)
{
  CURLcode result = CURLE_OK;

  DEBUGF(infof(conn->data, "DO phase starts\n"));

  *dophase_done = FALSE; /* not done yet */

  /* start the first command in the DO phase */
  state(conn, SSH_SFTP_QUOTE_INIT);

  /* run the state-machine */
  if (conn->data->state.used_interface == Curl_if_multi) {
    result = Curl_ssh_multi_statemach(conn, dophase_done);
  } else {
    result = ssh_easy_statemach(conn);
    *dophase_done = TRUE; /* with the easy interface we are done here */
  }
  *connected = conn->bits.tcpconnect;

  if (*dophase_done) {
    DEBUGF(infof(conn->data, "DO phase is complete\n"));
  }

  return result;
}

/* called from multi.c while DOing */
CURLcode Curl_sftp_doing(struct connectdata *conn,
                         bool *dophase_done)
{
  CURLcode result;
  result = Curl_ssh_multi_statemach(conn, dophase_done);

  if (*dophase_done) {
    DEBUGF(infof(conn->data, "DO phase is complete\n"));
  }
  return result;
}

CURLcode Curl_sftp_do(struct connectdata *conn, bool *done)
{
  CURLcode res;
  bool connected = 0;
  struct SessionHandle *data = conn->data;

  *done = FALSE; /* default to false */

  /*
   * Since connections can be re-used between SessionHandles, this might be a
   * connection already existing but on a fresh SessionHandle struct so we must
   * make sure we have a good 'struct SSHPROTO' to play with. For new
   * connections, the struct SSHPROTO is allocated and setup in the
   * Curl_ssh_connect() function.
   */
  res = ssh_init(conn);
  if (res) {
    return res;
  }

  data->reqdata.size = -1; /* make sure this is unknown at this point */

  Curl_pgrsSetUploadCounter(data, 0);
  Curl_pgrsSetDownloadCounter(data, 0);
  Curl_pgrsSetUploadSize(data, 0);
  Curl_pgrsSetDownloadSize(data, 0);

  res = sftp_perform(conn, &connected,  done);

  if (CURLE_OK == res) {

    if (!done) {
      /* the DO phase has not completed yet */
      return CURLE_OK;
    }
  }

  return res;
}

CURLcode Curl_sftp_done(struct connectdata *conn, CURLcode status,
                        bool premature)
{
  CURLcode result = CURLE_OK;
  bool done = FALSE;
  struct ssh_conn *sshc = &conn->proto.sshc;

  (void)status; /* unused */

  if (status == CURLE_OK) {
    /* Before we shut down, see if there are any post-quote commands to send: */
    if (!status && !premature && conn->data->set.postquote) {
      sshc->nextState = SSH_SFTP_CLOSE;
      state(conn, SSH_SFTP_POSTQUOTE_INIT);
    } else {
      state(conn, SSH_SFTP_CLOSE);
    }

    /* run the state-machine */
    if (conn->data->state.used_interface == Curl_if_multi) {
      result = Curl_ssh_multi_statemach(conn, &done);
    } else {
      result = ssh_easy_statemach(conn);
      done = TRUE;
    }
  } else {
    result = status;
    done = TRUE;
  }

  if (done) {
    Curl_safefree(conn->data->reqdata.proto.ssh);
    conn->data->reqdata.proto.ssh = NULL;
    Curl_pgrsDone(conn);
  }

  return result;
}

/* return number of received (decrypted) bytes */
ssize_t Curl_sftp_send(struct connectdata *conn, int sockindex,
                       void *mem, size_t len)
{
  ssize_t nwrite;   /* libssh2_sftp_write() used to return size_t in 0.14
                       but is changed to ssize_t in 0.15! */

  nwrite = (ssize_t)
    libssh2_sftp_write(conn->data->reqdata.proto.ssh->sftp_handle, mem, len);
  if (nwrite == LIBSSH2_ERROR_EAGAIN)
    return 0;

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
  (void)sockindex;

  /* libssh2_sftp_read() returns size_t !*/
  nread = (ssize_t)
    libssh2_sftp_read(conn->data->reqdata.proto.ssh->sftp_handle, mem, len);

  return nread;
}

/* The get_pathname() function is being borrowed from OpenSSH sftp.c
   version 4.6p1. */
/*
 * Copyright (c) 2001-2004 Damien Miller <djm@openbsd.org>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */
static int
get_pathname(const char **cpp, char **path)
{
  const char *cp = *cpp, *end;
  char quot;
  u_int i, j;
  static const char * const WHITESPACE = " \t\r\n";

  cp += strspn(cp, WHITESPACE);
  if (!*cp) {
    *cpp = cp;
    *path = NULL;
    return CURLE_QUOTE_ERROR;
  }

  *path = malloc(strlen(cp) + 1);
  if (*path == NULL)
    return CURLE_OUT_OF_MEMORY;

  /* Check for quoted filenames */
  if (*cp == '\"' || *cp == '\'') {
    quot = *cp++;

    /* Search for terminating quote, unescape some chars */
    for (i = j = 0; i <= strlen(cp); i++) {
      if (cp[i] == quot) {  /* Found quote */
        i++;
        (*path)[j] = '\0';
        break;
      }
      if (cp[i] == '\0') {  /* End of string */
        /*error("Unterminated quote");*/
        goto fail;
      }
      if (cp[i] == '\\') {  /* Escaped characters */
        i++;
        if (cp[i] != '\'' && cp[i] != '\"' &&
            cp[i] != '\\') {
          /*error("Bad escaped character '\\%c'",
              cp[i]);*/
          goto fail;
        }
      }
      (*path)[j++] = cp[i];
    }

    if (j == 0) {
      /*error("Empty quotes");*/
      goto fail;
    }
    *cpp = cp + i + strspn(cp + i, WHITESPACE);
  }
  else {
    /* Read to end of filename */
    end = strpbrk(cp, WHITESPACE);
    if (end == NULL)
      end = strchr(cp, '\0');
    *cpp = end + strspn(end, WHITESPACE);

    memcpy(*path, cp, end - cp);
    (*path)[end - cp] = '\0';
  }
  return (0);

  fail:
    Curl_safefree(*path);
    *path = NULL;
    return CURLE_QUOTE_ERROR;
}


static const char *sftp_libssh2_strerror(unsigned long err)
{
  switch (err) {
    case LIBSSH2_FX_NO_SUCH_FILE:
      return "No such file or directory";

    case LIBSSH2_FX_PERMISSION_DENIED:
      return "Permission denied";

    case LIBSSH2_FX_FAILURE:
      return "Operation failed";

    case LIBSSH2_FX_BAD_MESSAGE:
      return "Bad message from SFTP server";

    case LIBSSH2_FX_NO_CONNECTION:
      return "Not connected to SFTP server";

    case LIBSSH2_FX_CONNECTION_LOST:
      return "Connection to SFTP server lost";

    case LIBSSH2_FX_OP_UNSUPPORTED:
      return "Operation not supported by SFTP server";

    case LIBSSH2_FX_INVALID_HANDLE:
      return "Invalid handle";

    case LIBSSH2_FX_NO_SUCH_PATH:
      return "No such file or directory";

    case LIBSSH2_FX_FILE_ALREADY_EXISTS:
      return "File already exists";

    case LIBSSH2_FX_WRITE_PROTECT:
      return "File is write protected";

    case LIBSSH2_FX_NO_MEDIA:
      return "No media";

    case LIBSSH2_FX_NO_SPACE_ON_FILESYSTEM:
      return "Disk full";

    case LIBSSH2_FX_QUOTA_EXCEEDED:
      return "User quota exceeded";

    case LIBSSH2_FX_UNKNOWN_PRINCIPLE:
      return "Unknown principle";

    case LIBSSH2_FX_LOCK_CONFlICT:
      return "File lock conflict";

    case LIBSSH2_FX_DIR_NOT_EMPTY:
      return "Directory not empty";

    case LIBSSH2_FX_NOT_A_DIRECTORY:
      return "Not a directory";

    case LIBSSH2_FX_INVALID_FILENAME:
      return "Invalid filename";

    case LIBSSH2_FX_LINK_LOOP:
      return "Link points to itself";
  }
  return "Unknown error in libssh2";
}

#endif /* USE_LIBSSH2 */
