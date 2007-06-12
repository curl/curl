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

/* Local functions: */
static const char *sftp_libssh2_strerror(unsigned long err);
static CURLcode sftp_sendquote(struct connectdata *conn,
                               struct curl_slist *quote);

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

static CURLcode sftp_libssh2_error_to_CURLE(unsigned long err)
{
  if (err == LIBSSH2_FX_OK)
    return CURLE_OK;

  /* TODO: map some of the libssh2 errors to the more appropriate CURLcode
     error code, and possibly add a few new SSH-related one. We must however
     not return or even depend on libssh2 errors in the public libcurl API */

  if (err == LIBSSH2_FX_NO_SUCH_FILE)
     return CURLE_REMOTE_FILE_NOT_FOUND;

  return CURLE_SSH;
}

static CURLcode libssh2_session_error_to_CURLE(int err)
{
  (void)err;
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
static void state(struct connectdata *conn, ftpstate state)
{
#if defined(CURLDEBUG) && !defined(CURL_DISABLE_VERBOSE_STRINGS)
  /* for debug purposes */
  const char *names[]={
    "STOP",
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
    "QUIT"
  };
#endif
  struct ssh_conn *sshc = &conn->proto.sshc;
  
#if defined(CURLDEBUG) && !defined(CURL_DISABLE_VERBOSE_STRINGS)
  if (sshc->state != state) {
    infof(conn->data, "FTP %p state change from %s to %s\n",
          sshc, names[sshc->state], names[state]);
  }
#endif
  
  sshc->state = state;
}

static CURLcode ssh_statemach_act(struct connectdata *conn)
{
  CURLcode result = CURLE_OK;
  struct SessionHandle *data=conn->data;
  struct ssh_conn *sshc = &conn->proto.sshc;
  curl_socket_t sock = conn->sock[FIRSTSOCKET];
  struct SSHPROTO *ssh;
#ifdef CURL_LIBSSH2_DEBUG
  const char *fingerprint;
#endif /* CURL_LIBSSH2_DEBUG */
  int rc;
  
  ssh = data->reqdata.proto.ssh;
  
  switch(sshc->state) {
    case SSH_S_STARTUP:
      rc = libssh2_session_startup(ssh->ssh_session, sock);
      if (rc == LIBSSH2_ERROR_EAGAIN) {
        break;
      }
      else if (rc) {
        failf(data, "Failure establishing ssh session");
        libssh2_session_free(ssh->ssh_session);
        ssh->ssh_session = NULL;
        state(conn, SSH_STOP);
        result = CURLE_FAILED_INIT;
        break;
      }
        
#ifdef CURL_LIBSSH2_DEBUG
      /*
       * Before we authenticate we should check the hostkey's fingerprint
       * against our known hosts. How that is handled (reading from file,
       * whatever) is up to us. As for know not much is implemented, besides
       * showing how to get the fingerprint.
       */
      fingerprint = libssh2_hostkey_hash(ssh->ssh_session,
                                         LIBSSH2_HOSTKEY_HASH_MD5);
      
      /* The fingerprint points to static storage (!), don't free() it. */
      infof(data, "Fingerprint: ");
      for (i = 0; i < 16; i++) {
        infof(data, "%02X ", (unsigned char) fingerprint[i]);
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
      sshc->authlist = libssh2_userauth_list(ssh->ssh_session, ssh->user,
                                       strlen(ssh->user));
      
      if (!sshc->authlist) {
        if (libssh2_session_last_errno(ssh->ssh_session) ==
                        LIBSSH2_ERROR_EAGAIN) {
          break;
        } else {
          libssh2_session_free(ssh->ssh_session);
          ssh->ssh_session = NULL;
          state(conn, SSH_STOP);
          result = CURLE_OUT_OF_MEMORY;
          break;
        }
      }
      infof(data, "SSH authentication methods available: %s\n", sshc->authlist);

      state(conn, SSH_AUTH_PKEY_INIT);
      break;
      
    case SSH_AUTH_PKEY_INIT:
      /*
       * Check the supported auth types in the order I feel is most secure with
       * the requested type of authentication
       */
      sshc->authed = FALSE;
      
      if ((data->set.ssh_auth_types & CURLSSH_AUTH_PUBLICKEY) &&
          (strstr(sshc->authlist, "publickey") != NULL)) {
        char *home;
        
        sshc->rsa_pub[0] = sshc->rsa[0] = '\0';
        
        /* To ponder about: should really the lib be messing about with the
           HOME environment variable etc? */
        home = curl_getenv("HOME");
        
        if (data->set.ssh_public_key)
          snprintf(sshc->rsa_pub, sizeof(sshc->rsa_pub), "%s",
                   data->set.ssh_public_key);
        else if (home)
          snprintf(sshc->rsa_pub, sizeof(sshc->rsa_pub), "%s/.ssh/id_dsa.pub",
                   home);
        
        if (data->set.ssh_private_key)
          snprintf(sshc->rsa, sizeof(sshc->rsa), "%s",
                   data->set.ssh_private_key);
        else if (home)
          snprintf(sshc->rsa, sizeof(sshc->rsa), "%s/.ssh/id_dsa", home);
        
        sshc->passphrase = data->set.key_passwd;
        if (!sshc->passphrase)
          sshc->passphrase = "";
        
        curl_free(home);
        
        infof(conn->data, "Using ssh public key file %s\n", sshc->rsa_pub);
        infof(conn->data, "Using ssh private key file %s\n", sshc->rsa);
        
        if (sshc->rsa_pub[0]) {
          state(conn, SSH_AUTH_PKEY);
        } else {
          state(conn, SSH_AUTH_PASS_INIT);
        }
      } else {
        state(conn, SSH_AUTH_PASS_INIT);
      }
      break;
      
    case SSH_AUTH_PKEY:
      /* The function below checks if the files exists, no need to stat() here.
       */
      rc = libssh2_userauth_publickey_fromfile(ssh->ssh_session, ssh->user,
                                               sshc->rsa_pub, sshc->rsa,
                                               sshc->passphrase);
      if (rc == LIBSSH2_ERROR_EAGAIN) {
        break;
      }
      else if (rc == 0) {
        sshc->authed = TRUE;
        infof(conn->data, "Initialized SSH public key authentication\n");
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
      rc = libssh2_userauth_password(ssh->ssh_session, ssh->user,
                                     ssh->passwd);
      if (rc == LIBSSH2_ERROR_EAGAIN) {
        break;
      }
      else if (rc == 0) {
        sshc->authed = TRUE;
        infof(conn->data, "Initialized password authentication\n");
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
      rc = libssh2_userauth_keyboard_interactive_ex(ssh->ssh_session,
                                                    ssh->user,
                                                    strlen(ssh->user),
                                                    &kbd_callback);
      if (rc == LIBSSH2_ERROR_EAGAIN) {
        break;
      }
      else if (rc == 0) {
        sshc->authed = TRUE;
        infof(conn->data, "Initialized keyboard interactive authentication\n");
      }
      state(conn, SSH_AUTH_DONE);
      break;
      
    case SSH_AUTH_DONE:
      if (!sshc->authed) {
        failf(data, "Authentication failure");
        libssh2_session_free(ssh->ssh_session);
        ssh->ssh_session = NULL;
        state(conn, SSH_STOP);
        result = CURLE_LOGIN_DENIED;
        break;
      }
      
      /*
       * At this point we have an authenticated ssh session.
       */
      infof(conn->data, "Authentication complete\n");
      
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
      ssh->sftp_session = libssh2_sftp_init(ssh->ssh_session);
      if (!ssh->sftp_session) {
        if (libssh2_session_last_errno(ssh->ssh_session) ==
            LIBSSH2_ERROR_EAGAIN) {
          break;
        } else {
          failf(data, "Failure initialising sftp session\n");
          libssh2_session_free(ssh->ssh_session);
          ssh->ssh_session = NULL;
          state(conn, SSH_STOP);
          result = CURLE_FAILED_INIT;
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
        rc = libssh2_sftp_realpath(ssh->sftp_session, ".",
                                   tempHome, PATH_MAX-1);
        if (rc == LIBSSH2_ERROR_EAGAIN) {
          break;
        }
        else if (rc > 0) {
          /* It seems that this string is not always NULL terminated */
          tempHome[rc] = '\0';
          ssh->homedir = (char *)strdup(tempHome);
          if (!ssh->homedir) {
            libssh2_sftp_shutdown(ssh->sftp_session);
            ssh->sftp_session = NULL;
            libssh2_session_free(ssh->ssh_session);
            ssh->ssh_session = NULL;
            state(conn, SSH_STOP);
            result = CURLE_OUT_OF_MEMORY;
            break;
          }
        } else {
          /* Return the error type */
          result = libssh2_sftp_last_error(ssh->sftp_session);
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
          state(conn, SSH_STOP);
          result = CURLE_OUT_OF_MEMORY;
          break;
        }
        
        /* Check for /~/ , indicating relative to the user's home directory */
        if (conn->protocol == PROT_SCP) {
          real_path = (char *)malloc(working_path_len+1);
          if (real_path == NULL) {
            libssh2_session_free(ssh->ssh_session);
            ssh->ssh_session = NULL;
            Curl_safefree(working_path);
            state(conn, SSH_STOP);
            result = CURLE_OUT_OF_MEMORY;
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
            real_path = (char *)malloc(strlen(ssh->homedir) +
                                       working_path_len + 1);
            if (real_path == NULL) {
              libssh2_sftp_shutdown(ssh->sftp_session);
              ssh->sftp_session = NULL;
              libssh2_session_free(ssh->ssh_session);
              ssh->ssh_session = NULL;
              Curl_safefree(ssh->homedir);
              ssh->homedir = NULL;
              Curl_safefree(working_path);
              state(conn, SSH_STOP);
              result = CURLE_OUT_OF_MEMORY;
              break;
            }
            /* It is referenced to the home directory, so strip the
               leading '/' */
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
              libssh2_sftp_shutdown(ssh->sftp_session);
              ssh->sftp_session = NULL;
              libssh2_session_free(ssh->ssh_session);
              ssh->ssh_session = NULL;
              Curl_safefree(ssh->homedir);
              ssh->homedir = NULL;
              Curl_safefree(working_path);
              state(conn, SSH_STOP);
              result = CURLE_OUT_OF_MEMORY;
              break;
            }
            memcpy(real_path, working_path, 1+working_path_len);
          }
        }
        else {
          libssh2_session_free(ssh->ssh_session);
          ssh->ssh_session = NULL;
          Curl_safefree(working_path);
          state(conn, SSH_STOP);
          result = CURLE_FAILED_INIT;
          break;
        }
        
        Curl_safefree(working_path);
        ssh->path = real_path;
        
        /* Connect is all done */
        state(conn, SSH_STOP);
      }
      break;
      
    case SSH_QUIT:
      /* fallthrough, just stop! */
    default:
      /* internal error */
      state(conn, SSH_STOP);
      break;
  }

  return result;
}

/* called repeatedly until done from multi.c */
CURLcode Curl_ssh_multi_statemach(struct connectdata *conn,
                                  bool *done)
{
  curl_socket_t sock = conn->sock[FIRSTSOCKET];
  int rc = 1;
  struct SessionHandle *data=conn->data;
  struct ssh_conn *sshc = &conn->proto.sshc;
  CURLcode result = CURLE_OK;
#if 0
  long timeout_ms = ssh_state_timeout(conn);
#endif
  
  *done = FALSE; /* default to not done yet */
  
#if 0
  if (timeout_ms <= 0) {
    failf(data, "SSH response timeout");
    return CURLE_OPERATION_TIMEDOUT;
  }

  rc = Curl_socket_ready(sshc->sendleft?CURL_SOCKET_BAD:sock, /* reading */
                         sshc->sendleft?sock:CURL_SOCKET_BAD, /* writing */
                         0);
#endif

  if (rc == -1) {
    failf(data, "select/poll error");
    return CURLE_OUT_OF_MEMORY;
  }
  else if (rc != 0) {
    result = ssh_statemach_act(conn);
    *done = (bool)(sshc->state == SSH_STOP);
  }
  /* if rc == 0, then select() timed out */

  return result;
}

static CURLcode ssh_easy_statemach(struct connectdata *conn)
{
  curl_socket_t sock = conn->sock[FIRSTSOCKET];
  int rc = 1;
  struct SessionHandle *data=conn->data;
  struct ssh_conn *sshc = &conn->proto.sshc;
  CURLcode result = CURLE_OK;
  
  while(sshc->state != SSH_STOP) {
#if 0
    long timeout_ms = ssh_state_timeout(conn);
    
    if (timeout_ms <=0 ) {
      failf(data, "SSH response timeout");
      return CURLE_OPERATION_TIMEDOUT; /* already too little time */
    }

    rc = Curl_socket_ready(sshc->sendleft?CURL_SOCKET_BAD:sock, /* reading */
                           sshc->sendleft?sock:CURL_SOCKET_BAD, /* writing */
                           (int)timeout_ms);
#endif

    if (rc == -1) {
      failf(data, "select/poll error");
      return CURLE_OUT_OF_MEMORY;
    }
    else if (rc == 0) {
      result = CURLE_OPERATION_TIMEDOUT;
      break;
    }
    else {
      result = ssh_statemach_act(conn);
      if (result)
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
  int i;
  struct SSHPROTO *ssh;
  const char *fingerprint;
  const char *authlist;
  char tempHome[PATH_MAX];
  curl_socket_t sock;
  char *real_path;
  char *working_path;
  int working_path_len;
  bool authed = FALSE;
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

#if (LIBSSH2_APINO >= 200706012030)
  /* Set libssh2 to non-blocking, since cURL is all non-blocking */
  libssh2_session_set_blocking(ssh->ssh_session, 0);
  
  state(conn, SSH_S_STARTUP);
  
  if (data->state.used_interface == Curl_if_multi)
    result = Curl_ssh_multi_statemach(conn, done);
  else {
    result = ssh_easy_statemach(conn);
    if (!result)
      *done = TRUE;
  }

  return result;
  (void)authed; /* not used */
  (void)working_path; /* not used */
  (void)working_path_len; /* not used */
  (void)real_path; /* not used */
  (void)tempHome; /* not used */
  (void)authlist; /* not used */
  (void)fingerprint; /* not used */
  (void)i; /* not used */
  
#else /* !(LIBSSH2_APINO >= 200706012030) */
  
  if (libssh2_session_startup(ssh->ssh_session, sock)) {
    failf(data, "Failure establishing ssh session");
    libssh2_session_free(ssh->ssh_session);
    ssh->ssh_session = NULL;
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
  if (!authlist) {
    libssh2_session_free(ssh->ssh_session);
    ssh->ssh_session = NULL;
    return CURLE_OUT_OF_MEMORY;
  }
  infof(data, "SSH authentication methods available: %s\n", authlist);

  /*
   * Check the supported auth types in the order I feel is most secure with the
   * requested type of authentication
   */
  if ((data->set.ssh_auth_types & CURLSSH_AUTH_PUBLICKEY) &&
      (strstr(authlist, "publickey") != NULL)) {
    char *home;
    const char *passphrase;
    char rsa_pub[PATH_MAX];
    char rsa[PATH_MAX];

    rsa_pub[0] = rsa[0] = '\0';

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

    passphrase = data->set.key_passwd;
    if (!passphrase)
      passphrase = "";

    curl_free(home);

    infof(conn->data, "Using ssh public key file %s\n", rsa_pub);
    infof(conn->data, "Using ssh private key file %s\n", rsa);

    if (rsa_pub[0]) {
      /* The function below checks if the files exists, no need to stat() here.
      */
      if (libssh2_userauth_publickey_fromfile(ssh->ssh_session, ssh->user,
                                              rsa_pub, rsa, passphrase) == 0) {
        authed = TRUE;
        infof(conn->data, "Initialized SSH public key authentication\n");
      }
    }
  }
  if (!authed &&
      (data->set.ssh_auth_types & CURLSSH_AUTH_PASSWORD) &&
      (strstr(authlist, "password") != NULL)) {
    if (!libssh2_userauth_password(ssh->ssh_session, ssh->user, ssh->passwd)) {
      authed = TRUE;
      infof(conn->data, "Initialized password authentication\n");
    }
  }
  if (!authed && (data->set.ssh_auth_types & CURLSSH_AUTH_HOST) &&
      (strstr(authlist, "hostbased") != NULL)) {
  }
  if (!authed && (data->set.ssh_auth_types & CURLSSH_AUTH_KEYBOARD)
      && (strstr(authlist, "keyboard-interactive") != NULL)) {
    /* Authentication failed. Continue with keyboard-interactive now. */
    if (!libssh2_userauth_keyboard_interactive_ex(ssh->ssh_session, ssh->user,
                                                  strlen(ssh->user),
                                                  &kbd_callback)) {
      authed = TRUE;
      infof(conn->data, "Initialized keyboard interactive authentication\n");
    }
  }
  Curl_safefree((void *)authlist);
  authlist = NULL;

  if (!authed) {
    failf(data, "Authentication failure");
    libssh2_session_free(ssh->ssh_session);
    ssh->ssh_session = NULL;
    return CURLE_LOGIN_DENIED;
  }

  /*
   * At this point we have an authenticated ssh session.
   */
  infof(conn->data, "Authentication complete\n");

  conn->sockfd = sock;
  conn->writesockfd = CURL_SOCKET_BAD;

  if (conn->protocol == PROT_SFTP) {
    /*
     * Start the libssh2 sftp session
     */
    ssh->sftp_session = libssh2_sftp_init(ssh->ssh_session);
    if (ssh->sftp_session == NULL) {
      failf(data, "Failure initialising sftp session\n");
      libssh2_session_free(ssh->ssh_session);
      ssh->ssh_session = NULL;
      return CURLE_FAILED_INIT;
    }

    /*
     * Get the "home" directory
     */
    if (libssh2_sftp_realpath(ssh->sftp_session, ".", tempHome, PATH_MAX-1)
        > 0) {
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

  working_path = curl_easy_unescape(data, data->reqdata.path, 0,
                                    &working_path_len);
  if (!working_path)
    return CURLE_OUT_OF_MEMORY;
  
  /* Check for /~/ , indicating relative to the user's home directory */
  if (conn->protocol == PROT_SCP) {
    real_path = (char *)malloc(working_path_len+1);
    if (real_path == NULL) {
      libssh2_session_free(ssh->ssh_session);
      ssh->ssh_session = NULL;
      Curl_safefree(working_path);
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
        Curl_safefree(ssh->homedir);
        ssh->homedir = NULL;
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
        libssh2_sftp_shutdown(ssh->sftp_session);
        ssh->sftp_session = NULL;
        libssh2_session_free(ssh->ssh_session);
        ssh->ssh_session = NULL;
        Curl_safefree(ssh->homedir);
        ssh->homedir = NULL;
        Curl_safefree(working_path);
        return CURLE_OUT_OF_MEMORY;
      }
      memcpy(real_path, working_path, 1+working_path_len);
    }
  }
  else {
    libssh2_session_free(ssh->ssh_session);
    ssh->ssh_session = NULL;
    Curl_safefree(working_path);
    return CURLE_FAILED_INIT;
  }

  Curl_safefree(working_path);
  ssh->path = real_path;

  *done = TRUE;
  return CURLE_OK;
#endif /* !(LIBSSH2_APINO >= 200706012030) */
}

CURLcode Curl_scp_do(struct connectdata *conn, bool *done)
{
  struct stat sb;
  struct SSHPROTO *scp = conn->data->reqdata.proto.ssh;
  CURLcode res = CURLE_OK;

  *done = TRUE; /* unconditionally */

  if (conn->data->set.upload) {
    if(conn->data->set.infilesize < 0) {
      failf(conn->data, "SCP requries a known file size for upload");
      return CURLE_UPLOAD_FAILED;
    }
    /*
     * libssh2 requires that the destination path is a full path that includes
     * the destination file and name OR ends in a "/" .  If this is not done
     * the destination file will be named the same name as the last directory
     * in the path.
     */
#if (LIBSSH2_APINO >= 200706012030)
    do {
      scp->ssh_channel = libssh2_scp_send_ex(scp->ssh_session, scp->path,
                                             LIBSSH2_SFTP_S_IRUSR|
                                             LIBSSH2_SFTP_S_IWUSR|
                                             LIBSSH2_SFTP_S_IRGRP|
                                             LIBSSH2_SFTP_S_IROTH,
                                             conn->data->set.infilesize, 0, 0);
      if (!scp->ssh_channel &&
          (libssh2_session_last_errno(scp->ssh_session) !=
           LIBSSH2_ERROR_EAGAIN)) {
        return CURLE_FAILED_INIT;
      }
    } while (!scp->ssh_channel);
#else /* !(LIBSSH2_APINO >= 200706012030) */
    scp->ssh_channel = libssh2_scp_send_ex(scp->ssh_session, scp->path,
                                           LIBSSH2_SFTP_S_IRUSR|
                                           LIBSSH2_SFTP_S_IWUSR|
                                           LIBSSH2_SFTP_S_IRGRP|
                                           LIBSSH2_SFTP_S_IROTH,
                                           conn->data->set.infilesize, 0, 0);
    if (!scp->ssh_channel)
      return CURLE_FAILED_INIT;
#endif /* !(LIBSSH2_APINO >= 200706012030) */

    /* upload data */
    res = Curl_setup_transfer(conn, -1, -1, FALSE, NULL, FIRSTSOCKET, NULL);
  }
  else {
    /*
     * We must check the remote file; if it is a directory no values will
     * be set in sb
     */
    curl_off_t bytecount;
    memset(&sb, 0, sizeof(struct stat));
#if (LIBSSH2_APINO >= 200706012030)
    do {
      scp->ssh_channel = libssh2_scp_recv(scp->ssh_session, scp->path, &sb);
      if (!scp->ssh_channel &&
          (libssh2_session_last_errno(scp->ssh_session) !=
           LIBSSH2_ERROR_EAGAIN)) {
        if ((sb.st_mode == 0) && (sb.st_atime == 0) && (sb.st_mtime == 0) &&
            (sb.st_size == 0)) {
          /* Since sb is still empty, it is likely the file was not found */
          return CURLE_REMOTE_FILE_NOT_FOUND;
        }
        return libssh2_session_error_to_CURLE(
          libssh2_session_last_error(scp->ssh_session, NULL, NULL, 0));
      }
    } while (!scp->ssh_channel);
#else /* !(LIBSSH2_APINO >= 200706012030) */
    scp->ssh_channel = libssh2_scp_recv(scp->ssh_session, scp->path, &sb);
    if (!scp->ssh_channel) {
      if ((sb.st_mode == 0) && (sb.st_atime == 0) && (sb.st_mtime == 0) &&
          (sb.st_size == 0)) {
        /* Since sb is still empty, it is likely the file was not found */
        return CURLE_REMOTE_FILE_NOT_FOUND;
      }
      return libssh2_session_error_to_CURLE(
        libssh2_session_last_error(scp->ssh_session, NULL, NULL, 0));
    }
#endif /* !(LIBSSH2_APINO >= 200706012030) */
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
  int rc;
  struct SSHPROTO *scp = conn->data->reqdata.proto.ssh;
  (void)premature; /* not used */

  Curl_safefree(scp->path);
  scp->path = NULL;

  if (scp->ssh_channel) {
#if (LIBSSH2_APINO >= 200706012030)
    if (conn->data->set.upload) {
      while ((rc = libssh2_channel_send_eof(scp->ssh_channel)) ==
             LIBSSH2_ERROR_EAGAIN);
      if (rc) {
        infof(conn->data, "Failed to send libssh2 channel EOF\n");
      }
      while ((rc = libssh2_channel_wait_eof(scp->ssh_channel)) ==
             LIBSSH2_ERROR_EAGAIN);
      if (rc) {
        infof(conn->data, "Failed to get channel EOF\n");
      }
      while ((rc = libssh2_channel_wait_closed(scp->ssh_channel)) ==
             LIBSSH2_ERROR_EAGAIN);
      if (rc) {
        infof(conn->data, "Channel failed to close\n");
      }
    }
#else /* !(LIBSSH2_APINO >= 200706012030) */
    if (conn->data->set.upload &&
        libssh2_channel_send_eof(scp->ssh_channel) < 0) {
      infof(conn->data, "Failed to send libssh2 channel EOF\n");
    }
    if (libssh2_channel_close(scp->ssh_channel) < 0) {
      infof(conn->data, "Failed to stop libssh2 channel subsystem\n");
    }
#endif /* !(LIBSSH2_APINO >= 200706012030) */
    libssh2_channel_free(scp->ssh_channel);
  }

  if (scp->ssh_session) {
#if (LIBSSH2_APINO >= 200706012030)
    while (libssh2_session_disconnect(scp->ssh_session, "Shutdown") ==
           LIBSSH2_ERROR_EAGAIN);
#else /* !(LIBSSH2_APINO >= 200706012030) */
    libssh2_session_disconnect(scp->ssh_session, "Shutdown");
#endif /* !(LIBSSH2_APINO >= 200706012030) */
    libssh2_session_free(scp->ssh_session);
    scp->ssh_session = NULL;
  }

  free(conn->data->reqdata.proto.ssh);
  conn->data->reqdata.proto.ssh = NULL;
  Curl_pgrsDone(conn);

  (void)status; /* unused */
  (void) rc;    /* possiby unused */

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
#if defined(LIBSSH2CHANNEL_EAGAIN) && (LIBSSH2_APINO < 200706012030)
  nwrite = (ssize_t)
    libssh2_channel_writenb(conn->data->reqdata.proto.ssh->ssh_channel,
                            mem, len);
#else
  nwrite = (ssize_t)
    libssh2_channel_write(conn->data->reqdata.proto.ssh->ssh_channel,
                          mem, len);
#endif
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

#if defined(LIBSSH2CHANNEL_EAGAIN) && (LIBSSH2_APINO < 200706012030)
  /* we prefer the non-blocking API but that didn't exist previously */
  nread = (ssize_t)
    libssh2_channel_readnb(conn->data->reqdata.proto.ssh->ssh_channel,
                           mem, len);
#else
  nread = (ssize_t)
    libssh2_channel_read(conn->data->reqdata.proto.ssh->ssh_channel,
                         mem, len);
#endif
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
  unsigned long err = 0;
  int rc;

  *done = TRUE; /* unconditionally */

  /* Send any quote commands */
  if(conn->data->set.quote) {
    infof(conn->data, "Sending quote commands\n");
    res = sftp_sendquote(conn, conn->data->set.quote);
    if (res != CURLE_OK)
      return res;
  }

  if (data->set.upload) {
    /*
     * NOTE!!!  libssh2 requires that the destination path is a full path
     *          that includes the destination file and name OR ends in a "/" .
     *          If this is not done the destination file will be named the
     *          same name as the last directory in the path.
     */
#if (LIBSSH2_APINO >= 200706012030)
    do {
      sftp->sftp_handle =
        libssh2_sftp_open(sftp->sftp_session, sftp->path,
                        LIBSSH2_FXF_WRITE|LIBSSH2_FXF_CREAT|LIBSSH2_FXF_TRUNC,
                        LIBSSH2_SFTP_S_IRUSR|LIBSSH2_SFTP_S_IWUSR|
                        LIBSSH2_SFTP_S_IRGRP|LIBSSH2_SFTP_S_IROTH);
      if (!sftp->sftp_handle &&
          (libssh2_session_last_errno(sftp->ssh_session) !=
           LIBSSH2_ERROR_EAGAIN)) {
        err = libssh2_sftp_last_error(sftp->sftp_session);
        failf(conn->data, "Could not open remote file for writing: %s",
              sftp_libssh2_strerror(err));
        return sftp_libssh2_error_to_CURLE(err);
      }
    } while (!sftp->sftp_handle);
#else /* !(LIBSSH2_APINO >= 200706012030) */
    sftp->sftp_handle =
      libssh2_sftp_open(sftp->sftp_session, sftp->path,
                        LIBSSH2_FXF_WRITE|LIBSSH2_FXF_CREAT|LIBSSH2_FXF_TRUNC,
                        LIBSSH2_SFTP_S_IRUSR|LIBSSH2_SFTP_S_IWUSR|
                        LIBSSH2_SFTP_S_IRGRP|LIBSSH2_SFTP_S_IROTH);
    if (!sftp->sftp_handle) {
      err = libssh2_sftp_last_error(sftp->sftp_session);
      failf(conn->data, "Could not open remote file for writing: %s",
            sftp_libssh2_strerror(err));
      return sftp_libssh2_error_to_CURLE(err);
    }
#endif /* !(LIBSSH2_APINO >= 200706012030) */

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

#if (LIBSSH2_APINO >= 200706012030)
      do {
        sftp->sftp_handle =
          libssh2_sftp_opendir(sftp->sftp_session, sftp->path);
        if (!sftp->sftp_handle &&
            (libssh2_session_last_errno(sftp->ssh_session) !=
             LIBSSH2_ERROR_EAGAIN)) {
          err = libssh2_sftp_last_error(sftp->sftp_session);
          failf(conn->data, "Could not open directory for reading: %s",
                sftp_libssh2_strerror(err));
          return sftp_libssh2_error_to_CURLE(err);
        }
      } while (!sftp->sftp_handle);
#else /* !(LIBSSH2_APINO >= 200706012030) */
      sftp->sftp_handle =
        libssh2_sftp_opendir(sftp->sftp_session, sftp->path);
      if (!sftp->sftp_handle) {
        err = libssh2_sftp_last_error(sftp->sftp_session);
        failf(conn->data, "Could not open directory for reading: %s",
            sftp_libssh2_strerror(err));
        return sftp_libssh2_error_to_CURLE(err);
      }
#endif /* !(LIBSSH2_APINO >= 200706012030) */

      do {
#if (LIBSSH2_APINO >= 200706012030)
        while ((len = libssh2_sftp_readdir(sftp->sftp_handle, filename,
                                           PATH_MAX, &attrs)) ==
               LIBSSH2_ERROR_EAGAIN);
#else /* !(LIBSSH2_APINO >= 200706012030) */
        len = libssh2_sftp_readdir(sftp->sftp_handle, filename,
                                   PATH_MAX, &attrs);
#endif /* !(LIBSSH2_APINO >= 200706012030) */
        if (len > 0) {
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
              static const char * const months[12] = {
                "Jan", "Feb", "Mar", "Apr", "May", "Jun",
                "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"};
              struct tm *nowParts;
              time_t now, remoteTime;

              now = time(NULL);
              remoteTime = (time_t)attrs.mtime;
              nowParts = localtime(&remoteTime);

              if ((time_t)attrs.mtime > (now - (3600 * 24 * 180))) {
                currLen += snprintf(line+currLen, totalLen-currLen,
                                    " %s %2d %2d:%02d",
                                    months[nowParts->tm_mon],
                                    nowParts->tm_mday, nowParts->tm_hour,
                                    nowParts->tm_min);
              }
              else {
                currLen += snprintf(line+currLen, totalLen-currLen,
                                    " %s %2d %5d", months[nowParts->tm_mon],
                                    nowParts->tm_mday, 1900+nowParts->tm_year);
              }
            }
            currLen += snprintf(line+currLen, totalLen-currLen, " %s",
                                filename);
            if ((attrs.flags & LIBSSH2_SFTP_ATTR_PERMISSIONS) &&
                ((attrs.permissions & LIBSSH2_SFTP_S_IFMT) ==
                 LIBSSH2_SFTP_S_IFLNK)) {
              char linkPath[PATH_MAX + 1];

              snprintf(linkPath, PATH_MAX, "%s%s", sftp->path, filename);
              len = libssh2_sftp_readlink(sftp->sftp_session, linkPath,
                                          filename, PATH_MAX);
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
        else if (len <= 0) {
          break;
        }
      } while (1);
#if (LIBSSH2_APINO >= 200706012030)
      while (libssh2_sftp_closedir(sftp->sftp_handle) == LIBSSH2_ERROR_EAGAIN);
#else /* !(LIBSSH2_APINO >= 200706012030) */
      libssh2_sftp_closedir(sftp->sftp_handle);
#endif /* !(LIBSSH2_APINO >= 200706012030) */
      sftp->sftp_handle = NULL;

      /* no data to transfer */
      res = Curl_setup_transfer(conn, -1, -1, FALSE, NULL, -1, NULL);
    }
    else {
      /*
       * Work on getting the specified file
       */
#if (LIBSSH2_APINO >= 200706012030)
      do {
        sftp->sftp_handle =
          libssh2_sftp_open(sftp->sftp_session, sftp->path, LIBSSH2_FXF_READ,
                          LIBSSH2_SFTP_S_IRUSR|LIBSSH2_SFTP_S_IWUSR|
                          LIBSSH2_SFTP_S_IRGRP|LIBSSH2_SFTP_S_IROTH);
        if (!sftp->sftp_handle &&
            (libssh2_session_last_errno(sftp->ssh_session) !=
                                   LIBSSH2_ERROR_EAGAIN)) {
          err = libssh2_sftp_last_error(sftp->sftp_session);
          failf(conn->data, "Could not open remote file for reading: %s",
                sftp_libssh2_strerror(err));
          return sftp_libssh2_error_to_CURLE(err);
        }
      } while (!sftp->sftp_handle);
#else /* !(LIBSSH2_APINO >= 200706012030) */
      sftp->sftp_handle =
        libssh2_sftp_open(sftp->sftp_session, sftp->path, LIBSSH2_FXF_READ,
                          LIBSSH2_SFTP_S_IRUSR|LIBSSH2_SFTP_S_IWUSR|
                          LIBSSH2_SFTP_S_IRGRP|LIBSSH2_SFTP_S_IROTH);
      if (!sftp->sftp_handle) {
        err = libssh2_sftp_last_error(sftp->sftp_session);
        failf(conn->data, "Could not open remote file for reading: %s",
            sftp_libssh2_strerror(err));
        return sftp_libssh2_error_to_CURLE(err);
      }
#endif /* !(LIBSSH2_APINO >= 200706012030) */

#if (LIBSSH2_APINO >= 200706012030)
      while ((rc = libssh2_sftp_stat(sftp->sftp_session, sftp->path, &attrs))
             == LIBSSH2_ERROR_EAGAIN);
#else /* !(LIBSSH2_APINO >= 200706012030) */
      rc = libssh2_sftp_stat(sftp->sftp_session, sftp->path, &attrs);
#endif /* !(LIBSSH2_APINO >= 200706012030) */
      if (rc) {
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
#if (LIBSSH2_APINO >= 200706012030)
        ssize_t nread;

        while ((nread = libssh2_sftp_read(data->reqdata.proto.ssh->sftp_handle,
                                  buf, BUFSIZE-1)) == LIBSSH2_ERROR_EAGAIN);
#else /* !(LIBSSH2_APINO >= 200706012030) */
        size_t nread;
        /* NOTE: most *read() functions return ssize_t but this returns size_t
          which normally is unsigned! */
        nread = libssh2_sftp_read(data->reqdata.proto.ssh->sftp_handle,
                                  buf, BUFSIZE-1);
#endif /* !(LIBSSH2_APINO >= 200706012030) */

        if (nread > 0)
          buf[nread] = 0;

#if (LIBSSH2_APINO >= 200706012030)
        if (nread <= 0)
          break;
#else /* !(LIBSSH2_APINO >= 200706012030) */
        /* this check can be changed to a <= 0 when nread is changed to a
          signed variable type */
        if ((nread == 0) || (nread == (size_t)~0))
          break;
#endif /* !(LIBSSH2_APINO >= 200706012030) */

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
  CURLcode rc = CURLE_OK;
  int ret;
  (void)premature; /* not used */

  Curl_safefree(sftp->path);
  sftp->path = NULL;

  Curl_safefree(sftp->homedir);
  sftp->homedir = NULL;

  if (sftp->sftp_handle) {
#if (LIBSSH2_APINO >= 200706012030)
    while ((ret = libssh2_sftp_close(sftp->sftp_handle)) ==
           LIBSSH2_ERROR_EAGAIN);
    if (ret < 0) {
      infof(conn->data, "Failed to close libssh2 file\n");
    }
#else /* !(LIBSSH2_APINO >= 200706012030) */
    if (libssh2_sftp_close(sftp->sftp_handle) < 0) {
      infof(conn->data, "Failed to close libssh2 file\n");
    }
#endif /* !(LIBSSH2_APINO >= 200706012030) */
  }

  /* Before we shut down, see if there are any post-quote commands to send: */
  if(!status && !premature && conn->data->set.postquote) {
    infof(conn->data, "Sending postquote commands\n");
    rc = sftp_sendquote(conn, conn->data->set.postquote);
  }

  if (sftp->sftp_session) {
    if (libssh2_sftp_shutdown(sftp->sftp_session) < 0) {
      infof(conn->data, "Failed to stop libssh2 sftp subsystem\n");
    }
  }

  if (sftp->ssh_channel) {
#if (LIBSSH2_APINO >= 200706012030)
    while ((ret = libssh2_channel_close(sftp->ssh_channel)) ==
           LIBSSH2_ERROR_EAGAIN);
    if (ret < 0) {
      infof(conn->data, "Failed to stop libssh2 channel subsystem\n");
    }
#else /* !(LIBSSH2_APINO >= 200706012030) */
    if (libssh2_channel_close(sftp->ssh_channel) < 0) {
      infof(conn->data, "Failed to stop libssh2 channel subsystem\n");
    }
#endif /* !(LIBSSH2_APINO >= 200706012030) */
  }

  if (sftp->ssh_session) {
#if (LIBSSH2_APINO >= 200706012030)
    while (libssh2_session_disconnect(sftp->ssh_session, "Shutdown") ==
           LIBSSH2_ERROR_EAGAIN);
#else /* !(LIBSSH2_APINO >= 200706012030) */
    libssh2_session_disconnect(sftp->ssh_session, "Shutdown");
#endif /* !(LIBSSH2_APINO >= 200706012030) */
    libssh2_session_free(sftp->ssh_session);
    sftp->ssh_session = NULL;
  }

  free(conn->data->reqdata.proto.ssh);
  conn->data->reqdata.proto.ssh = NULL;
  Curl_pgrsDone(conn);

  (void)status; /* unused */
  (void)ret;    /* possibly unused */

  return rc;
}

/* return number of received (decrypted) bytes */
ssize_t Curl_sftp_send(struct connectdata *conn, int sockindex,
                       void *mem, size_t len)
{
  ssize_t nwrite;   /* libssh2_sftp_write() used to return size_t in 0.14
                       but is changed to ssize_t in 0.15! */

#if defined(LIBSSH2SFTP_EAGAIN) && (LIBSSH2_APINO < 200706012030)
  /* we prefer the non-blocking API but that didn't exist previously */
  nwrite = (ssize_t)
    libssh2_sftp_writenb(conn->data->reqdata.proto.ssh->sftp_handle, mem, len);
#else
  nwrite = (ssize_t)
    libssh2_sftp_write(conn->data->reqdata.proto.ssh->sftp_handle, mem, len);
#endif
  (void)sockindex;
  return nwrite;
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
    return CURLE_FTP_QUOTE_ERROR;
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
    free(*path);
    *path = NULL;
    return CURLE_FTP_QUOTE_ERROR;
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

/* BLOCKING */
static CURLcode sftp_sendquote(struct connectdata *conn,
                               struct curl_slist *quote)
{
  struct curl_slist *item=quote;
  const char *cp;
  long err;
  struct SessionHandle *data = conn->data;
  LIBSSH2_SFTP *sftp_session = data->reqdata.proto.ssh->sftp_session;
  int ret;

  while (item) {
    if (item->data) {
      char *path1 = NULL;
      char *path2 = NULL;

      /* the arguments following the command must be separated from the
         command with a space so we can check for it unconditionally */
      cp = strchr(item->data, ' ');
      if (cp == NULL) {
        failf(data, "Syntax error in SFTP command. Supply parameter(s)!");
        return CURLE_FTP_QUOTE_ERROR;
      }

      /* also, every command takes at least one argument so we get that first
         argument right now */
      err = get_pathname(&cp, &path1);
      if (err) {
        if (err == CURLE_OUT_OF_MEMORY)
          failf(data, "Out of memory");
        else
          failf(data, "Syntax error: Bad first parameter");
        return err;
      }

      /* SFTP is a binary protocol, so we don't send text commands to the
         server. Instead, we scan for commands for commands used by OpenSSH's
         sftp program and call the appropriate libssh2 functions. */
      if (curl_strnequal(item->data, "chgrp ", 6) ||
          curl_strnequal(item->data, "chmod ", 6) ||
          curl_strnequal(item->data, "chown ", 6) ) { /* attribute change */
        LIBSSH2_SFTP_ATTRIBUTES attrs;

        /* path1 contains the mode to set */
        err = get_pathname(&cp, &path2);  /* get the destination */
        if (err) {
          if (err == CURLE_OUT_OF_MEMORY)
            failf(data, "Out of memory");
          else
            failf(data,
                  "Syntax error in chgrp/chmod/chown: Bad second parameter");
          free(path1);
          return err;
        }
        memset(&attrs, 0, sizeof(LIBSSH2_SFTP_ATTRIBUTES));
        if (libssh2_sftp_stat(sftp_session,
                              path2, &attrs) != 0) { /* get those attributes */
          err = libssh2_sftp_last_error(sftp_session);
          free(path1);
          free(path2);
          failf(data, "Attempt to get SFTP stats failed: %s",
                sftp_libssh2_strerror(err));
          return CURLE_FTP_QUOTE_ERROR;
        }
#if (LIBSSH2_APINO >= 200706012030)
        while ((ret = libssh2_sftp_stat(sftp_session,
                                        path2, &attrs)) ==
               LIBSSH2_ERROR_EAGAIN);
        if (ret != 0) { /* get those attributes */
          err = libssh2_sftp_last_error(sftp_session);
          free(path1);
          free(path2);
          failf(data, "Attempt to get SFTP stats failed: %s",
                sftp_libssh2_strerror(err));
          return CURLE_FTP_QUOTE_ERROR;
        }
#else /* !(LIBSSH2_APINO >= 200706012030) */
        if (libssh2_sftp_stat(sftp_session,
                              path2, &attrs) != 0) { /* get those attributes */
          err = libssh2_sftp_last_error(sftp_session);
          free(path1);
          free(path2);
          failf(data, "Attempt to get SFTP stats failed: %s",
                sftp_libssh2_strerror(err));
          return CURLE_FTP_QUOTE_ERROR;
        }
#endif /* !(LIBSSH2_APINO >= 200706012030) */

        /* Now set the new attributes... */
        if (curl_strnequal(item->data, "chgrp", 5)) {
          attrs.gid = strtol(path1, NULL, 10);
          if (attrs.gid == 0 && !ISDIGIT(path1[0])) {
            free(path1);
            free(path2);
            failf(data, "Syntax error: chgrp gid not a number");
            return CURLE_FTP_QUOTE_ERROR;
          }
        }
        else if (curl_strnequal(item->data, "chmod", 5)) {
          attrs.permissions = strtol(path1, NULL, 8);/* permissions are octal */
          if (attrs.permissions == 0 && !ISDIGIT(path1[0])) {
            free(path1);
            free(path2);
            failf(data, "Syntax error: chmod permissions not a number");
            return CURLE_FTP_QUOTE_ERROR;
          }
        }
        else if (curl_strnequal(item->data, "chown", 5)) {
          attrs.uid = strtol(path1, NULL, 10);
          if (attrs.uid == 0 && !ISDIGIT(path1[0])) {
            free(path1);
            free(path2);
            failf(data, "Syntax error: chown uid not a number");
            return CURLE_FTP_QUOTE_ERROR;
          }
        }

        /* Now send the completed structure... */
#if (LIBSSH2_APINO >= 200706012030)
        while ((ret = libssh2_sftp_setstat(sftp_session, path2, &attrs)) ==
               LIBSSH2_ERROR_EAGAIN);
        if (ret != 0) {
          err = libssh2_sftp_last_error(sftp_session);
          free(path1);
          free(path2);
          failf(data, "Attempt to set SFTP stats failed: %s",
                sftp_libssh2_strerror(err));
          return CURLE_FTP_QUOTE_ERROR;
        }
#else /* !(LIBSSH2_APINO >= 200706012030) */
        if (libssh2_sftp_setstat(sftp_session, path2, &attrs) != 0) {
          err = libssh2_sftp_last_error(sftp_session);
          free(path1);
          free(path2);
          failf(data, "Attempt to set SFTP stats failed: %s",
                sftp_libssh2_strerror(err));
          return CURLE_FTP_QUOTE_ERROR;
        }
#endif /* !(LIBSSH2_APINO >= 200706012030) */
      }
      else if (curl_strnequal(item->data, "ln ", 3) ||
               curl_strnequal(item->data, "symlink ", 8)) {
        /* symbolic linking */
        /* path1 is the source */
        err = get_pathname(&cp, &path2);  /* get the destination */
        if (err) {
          if (err == CURLE_OUT_OF_MEMORY)
            failf(data, "Out of memory");
          else
            failf(data,
                  "Syntax error in ln/symlink: Bad second parameter");
          free(path1);
          return err;
        }
#if (LIBSSH2_APINO >= 200706012030)
        while ((ret = libssh2_sftp_symlink(sftp_session, path1, path2)) ==
               LIBSSH2_ERROR_EAGAIN);
        if (ret != 0) {
          err = libssh2_sftp_last_error(sftp_session);
          free(path1);
          free(path2);
          failf(data, "symlink command failed: %s",
                sftp_libssh2_strerror(err));
          return CURLE_FTP_QUOTE_ERROR;
        }
#else /* !(LIBSSH2_APINO >= 200706012030) */
        if (libssh2_sftp_symlink(sftp_session, path1, path2) != 0) {
          err = libssh2_sftp_last_error(sftp_session);
          free(path1);
          free(path2);
          failf(data, "symlink command failed: %s",
                sftp_libssh2_strerror(err));
          return CURLE_FTP_QUOTE_ERROR;
        }
#endif /* !(LIBSSH2_APINO >= 200706012030) */
      }
      else if (curl_strnequal(item->data, "mkdir ", 6)) { /* create dir */
#if (LIBSSH2_APINO >= 200706012030)
        while ((ret = libssh2_sftp_mkdir(sftp_session, path1, 0744)) ==
               LIBSSH2_ERROR_EAGAIN);
        if (ret != 0) {
          err = libssh2_sftp_last_error(sftp_session);
          free(path1);
          failf(data, "mkdir command failed: %s", sftp_libssh2_strerror(err));
          return CURLE_FTP_QUOTE_ERROR;
        }
#else /* !(LIBSSH2_APINO >= 200706012030) */
        if (libssh2_sftp_mkdir(sftp_session, path1, 0744) != 0) {
          err = libssh2_sftp_last_error(sftp_session);
          free(path1);
          failf(data, "mkdir command failed: %s",
                sftp_libssh2_strerror(err));
          return CURLE_FTP_QUOTE_ERROR;
        }
#endif /* !(LIBSSH2_APINO >= 200706012030) */
      }
      else if (curl_strnequal(item->data, "rename ", 7)) { /* rename file */
        /* first param is the source path */
        err = get_pathname(&cp, &path2);  /* second param is the dest. path */
        if (err) {
          if (err == CURLE_OUT_OF_MEMORY)
            failf(data, "Out of memory");
          else
            failf(data,
                  "Syntax error in rename: Bad second parameter");
          free(path1);
          return err;
        }
#if (LIBSSH2_APINO >= 200706012030)
        while ((ret = libssh2_sftp_rename(sftp_session, path1, path2)) ==
               LIBSSH2_ERROR_EAGAIN);
        if (ret != 0) {
          err = libssh2_sftp_last_error(sftp_session);
          free(path1);
          free(path2);
          failf(data, "rename command failed: %s", sftp_libssh2_strerror(err));
          return CURLE_FTP_QUOTE_ERROR;
        }
#else /* !(LIBSSH2_APINO >= 200706012030) */
        if (libssh2_sftp_rename(sftp_session,
                                path1, path2) != 0) {
          err = libssh2_sftp_last_error(sftp_session);
          free(path1);
          free(path2);
          failf(data, "rename command failed: %s",
                sftp_libssh2_strerror(err));
          return CURLE_FTP_QUOTE_ERROR;
        }
#endif /* !(LIBSSH2_APINO >= 200706012030) */
      }
      else if (curl_strnequal(item->data, "rmdir ", 6)) { /* delete dir */
#if (LIBSSH2_APINO >= 200706012030)
        while ((ret = libssh2_sftp_rmdir(sftp_session, path1)) ==
               LIBSSH2_ERROR_EAGAIN);
        if (ret != 0) {
          err = libssh2_sftp_last_error(sftp_session);
          free(path1);
          failf(data, "rmdir command failed: %s", sftp_libssh2_strerror(err));
          return CURLE_FTP_QUOTE_ERROR;
        }
#else /* !(LIBSSH2_APINO >= 200706012030) */
        if (libssh2_sftp_rmdir(sftp_session,
                               path1) != 0) {
          err = libssh2_sftp_last_error(sftp_session);
          free(path1);
          failf(data, "rmdir command failed: %s",
                sftp_libssh2_strerror(err));
          return CURLE_FTP_QUOTE_ERROR;
        }
#endif /* !(LIBSSH2_APINO >= 200706012030) */
      }
      else if (curl_strnequal(item->data, "rm ", 3)) { /* delete file */
#if (LIBSSH2_APINO >= 200706012030)
        while ((ret = libssh2_sftp_unlink(sftp_session, path1)) ==
               LIBSSH2_ERROR_EAGAIN);
        if (ret != 0) {
          err = libssh2_sftp_last_error(sftp_session);
          free(path1);
          failf(data, "rm command failed: %s", sftp_libssh2_strerror(err));
          return CURLE_FTP_QUOTE_ERROR;
        }
#else /* !(LIBSSH2_APINO >= 200706012030) */
        if (libssh2_sftp_unlink(sftp_session, path1) != 0) {
          err = libssh2_sftp_last_error(sftp_session);
          free(path1);
          failf(data, "rm command failed: %s",
                sftp_libssh2_strerror(err));
          return CURLE_FTP_QUOTE_ERROR;
        }
#endif /* !(LIBSSH2_APINO >= 200706012030) */
      }

      if (path1)
        free(path1);
      if (path2)
        free(path2);
    }
    item = item->next;
  }
  (void)ret;    /* possibly unused */

  return CURLE_OK;
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

#if defined(LIBSSH2SFTP_EAGAIN) && (LIBSSH2_APINO < 200706012030)
  /* we prefer the non-blocking API but that didn't exist previously */
  nread = (ssize_t)
    libssh2_sftp_readnb(conn->data->reqdata.proto.ssh->sftp_handle, mem, len);
#else
  nread = (ssize_t)
    libssh2_sftp_read(conn->data->reqdata.proto.ssh->sftp_handle, mem, len);
#endif
  return nread;
}

#endif /* USE_LIBSSH2 */
