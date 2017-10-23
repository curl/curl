/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) 2017 Red Hat, Inc.
 *
 * Authors: Nikos Mavrogiannopoulos, Tomas Mraz, Stanislav Zidek, Robert Kolcun
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

#ifdef USE_LIBSSH

#ifdef HAVE_LIMITS_H
#include <limits.h>
#endif

#include <libssh/libssh.h>

#ifdef HAVE_FCNTL_H
#include <fcntl.h>
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
#ifdef __VMS
#include <in.h>
#include <inet.h>
#endif

#if (defined(NETWARE) && defined(__NOVELL_LIBC__))
#undef in_addr_t
#define in_addr_t unsigned long
#endif

#include <curl/curl.h>
#include "urldata.h"
#include "sendf.h"
#include "hostip.h"
#include "progress.h"
#include "transfer.h"
#include "escape.h"
#include "http.h"               /* for HTTP proxy tunnel stuff */
#include "ssh.h"
#include "url.h"
#include "speedcheck.h"
#include "getinfo.h"
#include "strdup.h"
#include "strcase.h"
#include "vtls/vtls.h"
#include "connect.h"
#include "strerror.h"
#include "inet_ntop.h"
#include "parsedate.h"          /* for the week day and month names */
#include "sockaddr.h"           /* required for Curl_sockaddr_storage */
#include "strtoofft.h"
#include "multiif.h"
#include "select.h"
#include "warnless.h"

/* The last 3 #include files should be in this order */
#include "curl_printf.h"
#include "curl_memory.h"
#include "memdebug.h"
#include "curl_path.h"

/* Local functions: */
static CURLcode myssh_connect(struct connectdata *conn, bool *done);
static CURLcode myssh_multi_statemach(struct connectdata *conn,
                                      bool *done);
static CURLcode myssh_do_it(struct connectdata *conn, bool *done);

static CURLcode scp_done(struct connectdata *conn,
                         CURLcode, bool premature);
static CURLcode scp_doing(struct connectdata *conn, bool *dophase_done);
static CURLcode scp_disconnect(struct connectdata *conn,
                               bool dead_connection);

static int myssh_getsock(struct connectdata *conn, curl_socket_t *sock,
                         int numsocks);

static int myssh_perform_getsock(const struct connectdata *conn,
                                 curl_socket_t *sock,
                                 int numsocks);

static CURLcode myssh_setup_connection(struct connectdata *conn);

/*
 * SCP protocol handler.
 */

const struct Curl_handler Curl_handler_scp = {
  "SCP",                        /* scheme */
  myssh_setup_connection,       /* setup_connection */
  myssh_do_it,                  /* do_it */
  scp_done,                     /* done */
  ZERO_NULL,                    /* do_more */
  myssh_connect,                /* connect_it */
  myssh_multi_statemach,        /* connecting */
  scp_doing,                    /* doing */
  myssh_getsock,                /* proto_getsock */
  myssh_getsock,                /* doing_getsock */
  ZERO_NULL,                    /* domore_getsock */
  myssh_perform_getsock,        /* perform_getsock */
  scp_disconnect,               /* disconnect */
  ZERO_NULL,                    /* readwrite */
  ZERO_NULL,                    /* connection_check */
  PORT_SSH,                     /* defport */
  CURLPROTO_SCP,                /* protocol */
  PROTOPT_DIRLOCK | PROTOPT_CLOSEACTION | PROTOPT_NOURLQUERY    /* flags */
};

/*
 * SSH State machine related code
 */
/* This is the ONLY way to change SSH state! */
static void state(struct connectdata *conn, sshstate nowstate)
{
  struct ssh_conn *sshc = &conn->proto.sshc;
#if defined(DEBUGBUILD) && !defined(CURL_DISABLE_VERBOSE_STRINGS)
  /* for debug purposes */
  static const char *const names[] = {
    "SSH_STOP",
    "SSH_INIT",
    "SSH_S_STARTUP",
    "SSH_HOSTKEY",
    "SSH_AUTHLIST",
    "SSH_AUTH_PKEY_INIT",
    "SSH_AUTH_PKEY",
    "SSH_AUTH_PASS_INIT",
    "SSH_AUTH_PASS",
    "SSH_AUTH_AGENT_INIT",
    "SSH_AUTH_AGENT_LIST",
    "SSH_AUTH_AGENT",
    "SSH_AUTH_HOST_INIT",
    "SSH_AUTH_HOST",
    "SSH_AUTH_KEY_INIT",
    "SSH_AUTH_KEY",
    "SSH_AUTH_GSSAPI",
    "SSH_AUTH_DONE",
    "SSH_SFTP_INIT",
    "SSH_SFTP_REALPATH",
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
    "SSH_SFTP_QUOTE_STATVFS",
    "SSH_SFTP_GETINFO",
    "SSH_SFTP_FILETIME",
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
    "SSH_SCP_DOWNLOAD",
    "SSH_SCP_DONE",
    "SSH_SCP_SEND_EOF",
    "SSH_SCP_WAIT_EOF",
    "SSH_SCP_WAIT_CLOSE",
    "SSH_SCP_CHANNEL_FREE",
    "SSH_SESSION_DISCONNECT",
    "SSH_SESSION_FREE",
    "QUIT"
  };


  if(sshc->state != nowstate) {
    infof(conn->data, "SSH %p state change from %s to %s\n",
          (void *) sshc, names[sshc->state], names[nowstate]);
  }
#endif

  sshc->state = nowstate;
}

/* Multiple options:
 * 1. data->set.str[STRING_SSH_HOST_PUBLIC_KEY_MD5] is set with an MD5
 *    hash (90s style auth, not sure we should have it here)
 * 2. data->set.ssh_keyfunc callback is set. Then we do trust on first
 *    use. We even save on knownhosts if CURLKHSTAT_FINE_ADD_TO_FILE
 *    is returned by it.
 * 3. none of the above. We only accept if it is present on known hosts.
 *
 * Returns SSH_OK or SSH_ERROR.
 */
static int myssh_is_known(struct connectdata *conn)
{
  int rc;
  struct Curl_easy *data = conn->data;
  struct ssh_conn *sshc = &conn->proto.sshc;
  ssh_key pubkey;
  size_t hlen;
  unsigned char *hash = NULL;
  char *base64 = NULL;
  int vstate;
  enum curl_khmatch keymatch;
  struct curl_khkey foundkey;
  curl_sshkeycallback func =
    data->set.ssh_keyfunc;

  rc = ssh_get_publickey(sshc->ssh_session, &pubkey);
  if(rc != SSH_OK)
    return rc;

  if(data->set.str[STRING_SSH_HOST_PUBLIC_KEY_MD5]) {
    rc = ssh_get_publickey_hash(pubkey, SSH_PUBLICKEY_HASH_MD5,
                                &hash, &hlen);
    if(rc != SSH_OK)
      goto cleanup;

    if(hlen != strlen(data->set.str[STRING_SSH_HOST_PUBLIC_KEY_MD5]) ||
       memcmp(&data->set.str[STRING_SSH_HOST_PUBLIC_KEY_MD5], hash, hlen)) {
          rc = SSH_ERROR;
          goto cleanup;
    }

    rc = SSH_OK;
    goto cleanup;
  }

  if(data->set.ssl.primary.verifyhost != TRUE) {
    rc = SSH_OK;
    goto cleanup;
  }

  vstate = ssh_is_server_known(sshc->ssh_session);
  switch(vstate) {
    case SSH_SERVER_KNOWN_OK:
      keymatch = CURLKHMATCH_OK;
    case SSH_SERVER_FILE_NOT_FOUND:
    case SSH_SERVER_NOT_KNOWN:
      keymatch = CURLKHMATCH_MISSING;
    default:
      keymatch = CURLKHMATCH_MISMATCH;
  }

  if(func) { /* use callback to determine action */
    rc = ssh_pki_export_pubkey_base64(pubkey, &base64);
    if(rc != SSH_OK)
      goto cleanup;

    foundkey.key = base64;
    foundkey.len = strlen(base64);

    switch(ssh_key_type(pubkey)) {
      case SSH_KEYTYPE_RSA:
        foundkey.keytype = CURLKHTYPE_RSA;
        break;
      case SSH_KEYTYPE_RSA1:
        foundkey.keytype = CURLKHTYPE_RSA1;
        break;
      case SSH_KEYTYPE_ECDSA:
        foundkey.keytype = CURLKHTYPE_ECDSA;
        break;
#if LIBSSH_VERSION_INT >= SSH_VERSION_INT(0,7,0)
      case SSH_KEYTYPE_ED25519:
        foundkey.keytype = CURLKHTYPE_ED25519;
        break;
#endif
      case SSH_KEYTYPE_DSS:
        foundkey.keytype = CURLKHTYPE_DSS;
        break;
      default:
        rc = SSH_ERROR;
        goto cleanup;
    }

    /* we don't have anything equivalent to knownkey. Always NULL */
    rc = func(data, NULL, &foundkey, /* from the remote host */
              keymatch, data->set.ssh_keyfunc_userp);

    switch(rc) {
      case CURLKHSTAT_FINE_ADD_TO_FILE:
        rc = ssh_write_knownhost(sshc->ssh_session);
        if(rc != SSH_OK) {
          goto cleanup;
        }
        break;
      case CURLKHSTAT_FINE:
        break;
      default: /* REJECT/DEFER */
        rc = SSH_ERROR;
        goto cleanup;
    }
  }
  else {
    if(keymatch != CURLKHMATCH_OK) {
      rc = SSH_ERROR;
      goto cleanup;
    }
  }
  rc = SSH_OK;

cleanup:
  if(hash)
    ssh_clean_pubkey_hash(&hash);
  ssh_key_free(pubkey);
  return rc;
}

#define MOVE_TO_ERROR_STATE(_r) { \
  state(conn, SSH_SESSION_FREE); \
  sshc->actualcode = _r; \
  rc = SSH_ERROR; \
  break; \
}

#define MOVE_TO_LAST_AUTH \
  if(sshc->auth_methods & SSH_AUTH_METHOD_PASSWORD) { \
    rc = SSH_OK; \
    state(conn, SSH_AUTH_PASS_INIT); \
    break; \
  } \
  else { \
    MOVE_TO_ERROR_STATE(CURLE_LOGIN_DENIED); \
  }

#define MOVE_TO_SECONDARY_AUTH \
  if(sshc->auth_methods & SSH_AUTH_METHOD_GSSAPI_MIC) { \
    rc = SSH_OK; \
    state(conn, SSH_AUTH_GSSAPI); \
    break; \
  } \
  else { \
    MOVE_TO_LAST_AUTH; \
  }


/*
 * ssh_statemach_act() runs the SSH state machine as far as it can without
 * blocking and without reaching the end.  The data the pointer 'block' points
 * to will be set to TRUE if the libssh function returns SSH_AGAIN
 * meaning it wants to be called again when the socket is ready
 */
static CURLcode myssh_statemach_act(struct connectdata *conn, bool *block)
{
  CURLcode result = CURLE_OK;
  struct Curl_easy *data = conn->data;
  struct SSHPROTO *protop = data->req.protop;
  struct ssh_conn *sshc = &conn->proto.sshc;
  int rc = SSH_NO_ERROR;
  const char *err_msg;
  *block = 0;                   /* we're not blocking by default */

  do {

    switch(sshc->state) {
    case SSH_INIT:
      sshc->secondCreateDirs = 0;
      sshc->nextstate = SSH_NO_STATE;
      sshc->actualcode = CURLE_OK;

#if 0
      ssh_set_log_level(SSH_LOG_PACKET);
#endif

      /* Set libssh to non-blocking, since everything internally is
         non-blocking */
      ssh_set_blocking(sshc->ssh_session, 0);

      state(conn, SSH_S_STARTUP);
      /* fall-through */

    case SSH_S_STARTUP:
      rc = ssh_connect(sshc->ssh_session);
      if(rc == SSH_AGAIN)
        break;

      if(rc != SSH_OK) {
        failf(data, "Failure establishing ssh session");
        MOVE_TO_ERROR_STATE(CURLE_FAILED_INIT);
      }

      state(conn, SSH_HOSTKEY);

      /* fall-through */
    case SSH_HOSTKEY:

      rc = myssh_is_known(conn);
      if(rc != SSH_OK) {
        MOVE_TO_ERROR_STATE(CURLE_PEER_FAILED_VERIFICATION);
      }

      state(conn, SSH_AUTHLIST);
      /* fall through */
    case SSH_AUTHLIST:{
        sshc->authed = FALSE;

        rc = ssh_userauth_none(sshc->ssh_session, NULL);
        if(rc == SSH_AUTH_AGAIN) {
          rc = SSH_AGAIN;
          break;
        }

        if(rc == SSH_AUTH_SUCCESS) {
          sshc->authed = TRUE;
          infof(data, "Authenticated with none\n");
          state(conn, SSH_AUTH_DONE);
          break;
        }
        else if(rc == SSH_AUTH_ERROR) {
          MOVE_TO_ERROR_STATE(CURLE_LOGIN_DENIED);
        }

        sshc->auth_methods = ssh_userauth_list(sshc->ssh_session, NULL);
        if(sshc->auth_methods & SSH_AUTH_METHOD_PUBLICKEY) {
          state(conn, SSH_AUTH_PKEY_INIT);
        }
        else if(sshc->auth_methods & SSH_AUTH_METHOD_GSSAPI_MIC) {
          state(conn, SSH_AUTH_GSSAPI);
        }
        else if(sshc->auth_methods & SSH_AUTH_METHOD_PASSWORD) {
          state(conn, SSH_AUTH_PASS_INIT);
        }
        else {                  /* unsupported authentication method */
          MOVE_TO_ERROR_STATE(CURLE_LOGIN_DENIED);
        }

        break;
      }
    case SSH_AUTH_PKEY_INIT:
      if(!(data->set.ssh_auth_types & CURLSSH_AUTH_PUBLICKEY)) {
        MOVE_TO_SECONDARY_AUTH;
      }

      /* Two choices, (1) private key was given on CMD,
       * (2) use the "default" keys. */
      if(data->set.str[STRING_SSH_PRIVATE_KEY]) {
        if(sshc->pubkey && !data->set.ssl.key_passwd) {
          rc = ssh_userauth_try_publickey(sshc->ssh_session, NULL,
                                          sshc->pubkey);
          if(rc == SSH_AUTH_AGAIN) {
            rc = SSH_AGAIN;
            break;
          }

          if(rc != SSH_OK) {
            MOVE_TO_SECONDARY_AUTH;
          }
        }

        rc = ssh_pki_import_privkey_file(data->
                                         set.str[STRING_SSH_PRIVATE_KEY],
                                         data->set.ssl.key_passwd, NULL,
                                         NULL, &sshc->privkey);
        if(rc != SSH_OK) {
          failf(data, "Could not load private key file %s",
                data->set.str[STRING_SSH_PRIVATE_KEY]);
          break;
        }

        state(conn, SSH_AUTH_PKEY);
        break;

      }
      else {
        infof(data, "Authentication using SSH public key file\n");

        rc = ssh_userauth_publickey_auto(sshc->ssh_session, NULL,
                                         data->set.ssl.key_passwd);
        if(rc == SSH_AUTH_AGAIN) {
          rc = SSH_AGAIN;
          break;
        }
        if(rc == SSH_AUTH_SUCCESS) {
          rc = SSH_OK;
          sshc->authed = TRUE;
          infof(data, "Completed public key authentication\n");
          state(conn, SSH_AUTH_DONE);
          break;
        }

        MOVE_TO_SECONDARY_AUTH;
      }
      break;
    case SSH_AUTH_PKEY:
      rc = ssh_userauth_publickey(sshc->ssh_session, NULL, sshc->privkey);
      if(rc == SSH_AUTH_AGAIN) {
        rc = SSH_AGAIN;
        break;
      }

      if(rc == SSH_AUTH_SUCCESS) {
        sshc->authed = TRUE;
        infof(data, "Completed public key authentication\n");
        state(conn, SSH_AUTH_DONE);
        break;
      }
      else {
        infof(data, "Failed public key authentication (rc: %d)\n", rc);
        MOVE_TO_SECONDARY_AUTH;
      }
      break;

    case SSH_AUTH_GSSAPI:
      if(!(data->set.ssh_auth_types & CURLSSH_AUTH_GSSAPI)) {
        MOVE_TO_LAST_AUTH;
      }

      rc = ssh_userauth_gssapi(sshc->ssh_session);
      if(rc == SSH_AUTH_AGAIN) {
        rc = SSH_AGAIN;
        break;
      }

      if(rc == SSH_AUTH_SUCCESS) {
        rc = SSH_OK;
        sshc->authed = TRUE;
        infof(data, "Completed gssapi authentication\n");
        state(conn, SSH_AUTH_DONE);
        break;
      }

      MOVE_TO_LAST_AUTH;
      break;

    case SSH_AUTH_PASS_INIT:
      if(!(data->set.ssh_auth_types & CURLSSH_AUTH_PASSWORD)) {
        /* Host key authentication is intentionally not implemented */
        MOVE_TO_ERROR_STATE(CURLE_LOGIN_DENIED);
      }
      state(conn, SSH_AUTH_PASS);
      /* fall through */

    case SSH_AUTH_PASS:
      rc = ssh_userauth_password(sshc->ssh_session, NULL, conn->passwd);
      if(rc == SSH_AUTH_AGAIN) {
        rc = SSH_AGAIN;
        break;
      }

      if(rc == SSH_AUTH_SUCCESS) {
        sshc->authed = TRUE;
        infof(data, "Completed password authentication\n");
        state(conn, SSH_AUTH_DONE);
      }
      else {
        MOVE_TO_ERROR_STATE(CURLE_LOGIN_DENIED);
      }
      break;

    case SSH_AUTH_DONE:
      if(!sshc->authed) {
        failf(data, "Authentication failure");
        MOVE_TO_ERROR_STATE(CURLE_LOGIN_DENIED);
        break;
      }

      /*
       * At this point we have an authenticated ssh session.
       */
      infof(data, "Authentication complete\n");

      Curl_pgrsTime(conn->data, TIMER_APPCONNECT);      /* SSH is connected */

      conn->sockfd = ssh_get_fd(sshc->ssh_session);
      conn->writesockfd = CURL_SOCKET_BAD;

      infof(data, "SSH CONNECT phase done\n");
      state(conn, SSH_STOP);
      break;

    case SSH_SCP_TRANS_INIT:
      result = Curl_getworkingpath(conn, sshc->homedir, &protop->path);
      if(result) {
        sshc->actualcode = result;
        state(conn, SSH_STOP);
        break;
      }

      /* Functions from the SCP subsystem cannot handle/return SSH_AGAIN */
      ssh_set_blocking(sshc->ssh_session, 1);

      if(data->set.upload) {
        if(data->state.infilesize < 0) {
          failf(data, "SCP requires a known file size for upload");
          sshc->actualcode = CURLE_UPLOAD_FAILED;
          MOVE_TO_ERROR_STATE(CURLE_UPLOAD_FAILED);
        }

        sshc->scp_session =
          ssh_scp_new(sshc->ssh_session, SSH_SCP_WRITE, protop->path);
        state(conn, SSH_SCP_UPLOAD_INIT);
      }
      else {
        sshc->scp_session =
          ssh_scp_new(sshc->ssh_session, SSH_SCP_READ, protop->path);
        state(conn, SSH_SCP_DOWNLOAD_INIT);
      }

      if(!sshc->scp_session) {
        err_msg = ssh_get_error(sshc->ssh_session);
        failf(conn->data, "%s", err_msg);
        MOVE_TO_ERROR_STATE(CURLE_UPLOAD_FAILED);
      }

      break;

    case SSH_SCP_UPLOAD_INIT:

      rc = ssh_scp_init(sshc->scp_session);
      if(rc != SSH_OK) {
        err_msg = ssh_get_error(sshc->ssh_session);
        failf(conn->data, "%s", err_msg);
        MOVE_TO_ERROR_STATE(CURLE_UPLOAD_FAILED);
      }

      rc = ssh_scp_push_file(sshc->scp_session, protop->path,
                             data->state.infilesize,
                             (int)data->set.new_file_perms);
      if(rc != SSH_OK) {
        err_msg = ssh_get_error(sshc->ssh_session);
        failf(conn->data, "%s", err_msg);
        MOVE_TO_ERROR_STATE(CURLE_UPLOAD_FAILED);
      }

      /* upload data */
      Curl_setup_transfer(conn, -1, data->req.size, FALSE, NULL,
                          FIRSTSOCKET, NULL);

      /* not set by Curl_setup_transfer to preserve keepon bits */
      conn->sockfd = conn->writesockfd;

      /* store this original bitmask setup to use later on if we can't
         figure out a "real" bitmask */
      sshc->orig_waitfor = data->req.keepon;

      /* we want to use the _sending_ function even when the socket turns
         out readable as the underlying libssh scp send function will deal
         with both accordingly */
      conn->cselect_bits = CURL_CSELECT_OUT;

      state(conn, SSH_STOP);

      break;

    case SSH_SCP_DOWNLOAD_INIT:

      rc = ssh_scp_init(sshc->scp_session);
      if(rc != SSH_OK) {
        err_msg = ssh_get_error(sshc->ssh_session);
        failf(conn->data, "%s", err_msg);
        MOVE_TO_ERROR_STATE(CURLE_COULDNT_CONNECT);
      }
      state(conn, SSH_SCP_DOWNLOAD);
      /* fall through */

    case SSH_SCP_DOWNLOAD:{
        curl_off_t bytecount;

        rc = ssh_scp_pull_request(sshc->scp_session);
        if(rc != SSH_SCP_REQUEST_NEWFILE) {
          err_msg = ssh_get_error(sshc->ssh_session);
          failf(conn->data, "%s", err_msg);
          MOVE_TO_ERROR_STATE(CURLE_REMOTE_FILE_NOT_FOUND);
          break;
        }

        /* download data */
        bytecount = ssh_scp_request_get_size(sshc->scp_session);
        data->req.maxdownload = (curl_off_t) bytecount;
        Curl_setup_transfer(conn, FIRSTSOCKET, bytecount, FALSE, NULL, -1,
                            NULL);

        /* not set by Curl_setup_transfer to preserve keepon bits */
        conn->writesockfd = conn->sockfd;

        /* we want to use the _receiving_ function even when the socket turns
           out writableable as the underlying libssh recv function will deal
           with both accordingly */
        conn->cselect_bits = CURL_CSELECT_IN;

        state(conn, SSH_STOP);
        break;
      }
    case SSH_SCP_DONE:
      if(data->set.upload)
        state(conn, SSH_SCP_SEND_EOF);
      else
        state(conn, SSH_SCP_CHANNEL_FREE);
      break;

    case SSH_SCP_SEND_EOF:
      if(sshc->scp_session) {
        rc = ssh_scp_close(sshc->scp_session);
        if(rc == SSH_AGAIN) {
          /* Currently the ssh_scp_close handles waiting for EOF in
           * blocking way.
           */
          break;
        }
        if(rc != SSH_OK) {
          infof(data, "Failed to close libssh scp channel: %s\n",
                ssh_get_error(sshc->ssh_session));
        }
      }

      state(conn, SSH_SCP_CHANNEL_FREE);
      break;

    case SSH_SCP_CHANNEL_FREE:
      if(sshc->scp_session) {
        ssh_scp_free(sshc->scp_session);
        sshc->scp_session = NULL;
      }
      DEBUGF(infof(data, "SCP DONE phase complete\n"));

      ssh_set_blocking(sshc->ssh_session, 0);

      state(conn, SSH_SESSION_DISCONNECT);
      /* fall through */

    case SSH_SESSION_DISCONNECT:
      /* during weird times when we've been prematurely aborted, the channel
         is still alive when we reach this state and we MUST kill the channel
         properly first */
      if(sshc->scp_session) {
        ssh_scp_free(sshc->scp_session);
        sshc->scp_session = NULL;
      }

      ssh_disconnect(sshc->ssh_session);

      Curl_safefree(sshc->homedir);
      conn->data->state.most_recent_ftp_entrypath = NULL;

      state(conn, SSH_SESSION_FREE);
      /* fall through */
    case SSH_SESSION_FREE:
      if(sshc->ssh_session) {
        ssh_free(sshc->ssh_session);
        sshc->ssh_session = NULL;
      }

      /* worst-case scenario cleanup */

      DEBUGASSERT(sshc->ssh_session == NULL);
      DEBUGASSERT(sshc->scp_session == NULL);

      if(sshc->privkey)
        ssh_key_free(sshc->privkey);
      if(sshc->pubkey)
        ssh_key_free(sshc->pubkey);

      Curl_safefree(sshc->rsa_pub);
      Curl_safefree(sshc->rsa);

      Curl_safefree(sshc->quote_path1);
      Curl_safefree(sshc->quote_path2);

      Curl_safefree(sshc->homedir);

      Curl_safefree(sshc->readdir_filename);
      Curl_safefree(sshc->readdir_longentry);
      Curl_safefree(sshc->readdir_line);
      Curl_safefree(sshc->readdir_linkPath);

      /* the code we are about to return */
      result = sshc->actualcode;

      memset(sshc, 0, sizeof(struct ssh_conn));

      connclose(conn, "SSH session free");
      sshc->state = SSH_SESSION_FREE;   /* current */
      sshc->nextstate = SSH_NO_STATE;
      state(conn, SSH_STOP);
      break;

    case SSH_QUIT:
      /* fallthrough, just stop! */
    default:
      /* internal error */
      sshc->nextstate = SSH_NO_STATE;
      state(conn, SSH_STOP);
      break;

    }
  } while(!rc && (sshc->state != SSH_STOP));


  if(rc == SSH_AGAIN) {
    /* we would block, we need to wait for the socket to be ready (in the
       right direction too)! */
    *block = TRUE;
  }

  return result;
}


/* called by the multi interface to figure out what socket(s) to wait for and
   for what actions in the DO_DONE, PERFORM and WAITPERFORM states */
static int myssh_perform_getsock(const struct connectdata *conn,
                                 curl_socket_t *sock,  /* points to numsocks
                                                          number of sockets */
                                 int numsocks)
{
  int bitmap = GETSOCK_BLANK;
  (void) numsocks;

  sock[0] = conn->sock[FIRSTSOCKET];

  if(conn->waitfor & KEEP_RECV)
    bitmap |= GETSOCK_READSOCK(FIRSTSOCKET);

  if(conn->waitfor & KEEP_SEND)
    bitmap |= GETSOCK_WRITESOCK(FIRSTSOCKET);

  return bitmap;
}

/* Generic function called by the multi interface to figure out what socket(s)
   to wait for and for what actions during the DOING and PROTOCONNECT states*/
static int myssh_getsock(struct connectdata *conn,
                         curl_socket_t *sock,  /* points to numsocks
                                                   number of sockets */
                         int numsocks)
{
  /* if we know the direction we can use the generic *_getsock() function even
     for the protocol_connect and doing states */
  return myssh_perform_getsock(conn, sock, numsocks);
}

static void myssh_block2waitfor(struct connectdata *conn, bool block)
{
  struct ssh_conn *sshc = &conn->proto.sshc;
  int dir;

  /* If it didn't block, or nothing was returned by ssh_get_poll_flags
   * have the original set */
  conn->waitfor = sshc->orig_waitfor;

  if(block) {
    dir = ssh_get_poll_flags(sshc->ssh_session);
    if(dir & SSH_READ_PENDING) {
      /* translate the libssh2 define bits into our own bit defines */
      conn->waitfor = KEEP_RECV;
    }
    else if(dir & SSH_WRITE_PENDING) {
      conn->waitfor = KEEP_SEND;
    }
  }
}

/* called repeatedly until done from multi.c */
static CURLcode myssh_multi_statemach(struct connectdata *conn,
                                      bool *done)
{
  struct ssh_conn *sshc = &conn->proto.sshc;
  CURLcode result = CURLE_OK;
  bool block;    /* we store the status and use that to provide a ssh_getsock()
                    implementation */

  result = myssh_statemach_act(conn, &block);
  *done = (sshc->state == SSH_STOP) ? TRUE : FALSE;
  myssh_block2waitfor(conn, block);

  return result;
}

static CURLcode myssh_block_statemach(struct connectdata *conn,
                                      bool disconnect)
{
  struct ssh_conn *sshc = &conn->proto.sshc;
  CURLcode result = CURLE_OK;
  struct Curl_easy *data = conn->data;

  while((sshc->state != SSH_STOP) && !result) {
    bool block;
    timediff_t left = 1000;
    struct curltime now = Curl_now();

    result = myssh_statemach_act(conn, &block);
    if(result)
      break;

    if(!disconnect) {
      if(Curl_pgrsUpdate(conn))
        return CURLE_ABORTED_BY_CALLBACK;

      result = Curl_speedcheck(data, now);
      if(result)
        break;

      left = Curl_timeleft(data, NULL, FALSE);
      if(left < 0) {
        failf(data, "Operation timed out");
        return CURLE_OPERATION_TIMEDOUT;
      }
    }

    if(!result && block) {
      curl_socket_t sock = conn->sock[FIRSTSOCKET];
      curl_socket_t fd_read = CURL_SOCKET_BAD;
      fd_read = sock;
      /* wait for the socket to become ready */
      (void) Curl_socket_check(fd_read, CURL_SOCKET_BAD,
                               CURL_SOCKET_BAD, left > 1000 ? 1000 : left);
    }

  }

  return result;
}

/*
 * SSH setup connection
 */
static CURLcode myssh_setup_connection(struct connectdata *conn)
{
  struct SSHPROTO *ssh;

  conn->data->req.protop = ssh = calloc(1, sizeof(struct SSHPROTO));
  if(!ssh)
    return CURLE_OUT_OF_MEMORY;

  return CURLE_OK;
}

static Curl_recv scp_recv;
static Curl_send scp_send;

/*
 * Curl_ssh_connect() gets called from Curl_protocol_connect() to allow us to
 * do protocol-specific actions at connect-time.
 */
static CURLcode myssh_connect(struct connectdata *conn, bool *done)
{
  struct ssh_conn *ssh;
  CURLcode result;
  struct Curl_easy *data = conn->data;
  int rc;

  /* initialize per-handle data if not already */
  if(!data->req.protop)
    myssh_setup_connection(conn);

  /* We default to persistent connections. We set this already in this connect
     function to make the re-use checks properly be able to check this bit. */
  connkeep(conn, "SSH default");

  if(conn->handler->protocol & CURLPROTO_SCP) {
    conn->recv[FIRSTSOCKET] = scp_recv;
    conn->send[FIRSTSOCKET] = scp_send;
  }
  else
    return CURLE_SSH;

  ssh = &conn->proto.sshc;

  ssh->ssh_session = ssh_new();
  if(ssh->ssh_session == NULL) {
    failf(data, "Failure initialising ssh session");
    return CURLE_FAILED_INIT;
  }

  if(conn->user) {
    infof(data, "User: %s\n", conn->user);
    ssh_options_set(ssh->ssh_session, SSH_OPTIONS_USER, conn->user);
  }

  if(data->set.str[STRING_SSH_KNOWNHOSTS]) {
    infof(data, "Known hosts: %s\n", data->set.str[STRING_SSH_KNOWNHOSTS]);
    ssh_options_set(ssh->ssh_session, SSH_OPTIONS_KNOWNHOSTS,
                    data->set.str[STRING_SSH_KNOWNHOSTS]);
  }

  ssh_options_set(ssh->ssh_session, SSH_OPTIONS_HOST, conn->host.name);
  if(conn->remote_port)
    ssh_options_set(ssh->ssh_session, SSH_OPTIONS_PORT,
                    &conn->remote_port);

  if(data->set.ssh_compression) {
    ssh_options_set(ssh->ssh_session, SSH_OPTIONS_COMPRESSION,
                    "zlib,zlib@openssh.com,none");
  }

  ssh->privkey = NULL;
  ssh->pubkey = NULL;

  if(data->set.str[STRING_SSH_PUBLIC_KEY]) {
    rc = ssh_pki_import_pubkey_file(data->set.str[STRING_SSH_PUBLIC_KEY],
                                    &ssh->pubkey);
    if(rc != SSH_OK) {
      failf(data, "Could not load public key file");
      /* ignore */
    }
  }

  /* we do not verify here, we do it at the state machine,
   * after connection */

  state(conn, SSH_INIT);

  result = myssh_multi_statemach(conn, done);

  return result;
}

/* called from multi.c while DOing */
static CURLcode scp_doing(struct connectdata *conn, bool *dophase_done)
{
  CURLcode result;

  result = myssh_multi_statemach(conn, dophase_done);

  if(*dophase_done) {
    DEBUGF(infof(conn->data, "DO phase is complete\n"));
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
                     bool *connected, bool *dophase_done)
{
  CURLcode result = CURLE_OK;

  DEBUGF(infof(conn->data, "DO phase starts\n"));

  *dophase_done = FALSE;        /* not done yet */

  /* start the first command in the DO phase */
  state(conn, SSH_SCP_TRANS_INIT);

  result = myssh_multi_statemach(conn, dophase_done);

  *connected = conn->bits.tcpconnect[FIRSTSOCKET];

  if(*dophase_done) {
    DEBUGF(infof(conn->data, "DO phase is complete\n"));
  }

  return result;
}

static CURLcode myssh_do_it(struct connectdata *conn, bool *done)
{
  CURLcode result;
  bool connected = 0;
  struct Curl_easy *data = conn->data;
  struct ssh_conn *sshc = &conn->proto.sshc;

  *done = FALSE;                /* default to false */

  data->req.size = -1;          /* make sure this is unknown at this point */

  sshc->actualcode = CURLE_OK;  /* reset error code */
  sshc->secondCreateDirs = 0;   /* reset the create dir attempt state
                                   variable */

  Curl_pgrsSetUploadCounter(data, 0);
  Curl_pgrsSetDownloadCounter(data, 0);
  Curl_pgrsSetUploadSize(data, -1);
  Curl_pgrsSetDownloadSize(data, -1);

  if(conn->handler->protocol & CURLPROTO_SCP)
    result = scp_perform(conn, &connected, done);
  else
    result = CURLE_SSH;

  return result;
}

/* BLOCKING, but the function is using the state machine so the only reason
   this is still blocking is that the multi interface code has no support for
   disconnecting operations that takes a while */
static CURLcode scp_disconnect(struct connectdata *conn,
                               bool dead_connection)
{
  CURLcode result = CURLE_OK;
  struct ssh_conn *ssh = &conn->proto.sshc;
  (void) dead_connection;

  if(ssh->ssh_session) {
    /* only if there's a session still around to use! */

    state(conn, SSH_SESSION_DISCONNECT);

    result = myssh_block_statemach(conn, TRUE);
  }

  return result;
}

/* generic done function for both SCP and SFTP called from their specific
   done functions */
static CURLcode myssh_done(struct connectdata *conn, CURLcode status)
{
  CURLcode result = CURLE_OK;
  struct SSHPROTO *protop = conn->data->req.protop;

  if(!status) {
    /* run the state-machine

       TODO: when the multi interface is used, this _really_ should be using
       the ssh_multi_statemach function but we have no general support for
       non-blocking DONE operations!
     */
    result = myssh_block_statemach(conn, FALSE);
  }
  else
    result = status;

  if(protop)
    Curl_safefree(protop->path);
  if(Curl_pgrsDone(conn))
    return CURLE_ABORTED_BY_CALLBACK;

  conn->data->req.keepon = 0;   /* clear all bits */
  return result;
}


static CURLcode scp_done(struct connectdata *conn, CURLcode status,
                         bool premature)
{
  (void) premature;             /* not used */

  if(!status)
    state(conn, SSH_SCP_DONE);

  return myssh_done(conn, status);

}

static ssize_t scp_send(struct connectdata *conn, int sockindex,
                        const void *mem, size_t len, CURLcode *err)
{
  int rc;
  (void) sockindex; /* we only support SCP on the fixed known primary socket */
  (void) err;

  rc = ssh_scp_write(conn->proto.sshc.scp_session, mem, len);

#if 0
  /* The following code is misleading, mostly added as wishful thinking
   * that libssh at some point will implement non-blocking ssh_scp_write/read.
   * Currently rc can only be number of bytes read or SSH_ERROR. */
  myssh_block2waitfor(conn, (rc == SSH_AGAIN) ? TRUE : FALSE);

  if(rc == SSH_AGAIN) {
    *err = CURLE_AGAIN;
    return 0;
  }
  else
#endif
  if(rc != SSH_OK) {
    *err = CURLE_SSH;
    return -1;
  }

  return len;
}

static ssize_t scp_recv(struct connectdata *conn, int sockindex,
                        char *mem, size_t len, CURLcode *err)
{
  ssize_t nread;
  (void) err;
  (void) sockindex; /* we only support SCP on the fixed known primary socket */

  /* libssh returns int */
  nread = ssh_scp_read(conn->proto.sshc.scp_session, mem, len);

#if 0
  /* The following code is misleading, mostly added as wishful thinking
   * that libssh at some point will implement non-blocking ssh_scp_write/read.
   * Currently rc can only be SSH_OK or SSH_ERROR. */

  myssh_block2waitfor(conn, (nread == SSH_AGAIN) ? TRUE : FALSE);
  if(nread == SSH_AGAIN) {
    *err = CURLE_AGAIN;
    nread = -1;
  }
#endif

  return nread;
}

#endif                          /* USE_LIBSSH */
