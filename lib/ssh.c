/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) 1998 - 2010, Daniel Stenberg, <daniel@haxx.se>, et al.
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

/* #define CURL_LIBSSH2_DEBUG */

#include "setup.h"

#ifdef USE_LIBSSH2
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdarg.h>
#include <ctype.h>
#ifdef HAVE_LIMITS_H
#  include <limits.h>
#endif

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
#ifdef __VMS
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
#include "inet_ntop.h"
#include "parsedate.h" /* for the week day and month names */
#include "sockaddr.h" /* required for Curl_sockaddr_storage */
#include "strtoofft.h"
#include "multiif.h"
#include "select.h"

#define _MPRINTF_REPLACE /* use our functions only */
#include <curl/mprintf.h>

#include "curl_memory.h"
/* The last #include file should be: */
#include "memdebug.h"

#ifndef PATH_MAX
#define PATH_MAX 1024 /* just an extra precaution since there are systems that
                         have their definition hidden well */
#endif

/* Local functions: */
static const char *sftp_libssh2_strerror(unsigned long err);
static LIBSSH2_ALLOC_FUNC(libssh2_malloc);
static LIBSSH2_REALLOC_FUNC(libssh2_realloc);
static LIBSSH2_FREE_FUNC(libssh2_free);

static CURLcode get_pathname(const char **cpp, char **path);

static CURLcode ssh_connect(struct connectdata *conn, bool *done);
static CURLcode ssh_multi_statemach(struct connectdata *conn, bool *done);
static CURLcode ssh_do(struct connectdata *conn, bool *done);

static CURLcode ssh_getworkingpath(struct connectdata *conn,
                                   char *homedir, /* when SFTP is used */
                                   char **path);

static CURLcode scp_done(struct connectdata *conn,
                         CURLcode, bool premature);
static CURLcode scp_doing(struct connectdata *conn,
                          bool *dophase_done);
static CURLcode scp_disconnect(struct connectdata *conn);

static CURLcode sftp_done(struct connectdata *conn,
                          CURLcode, bool premature);
static CURLcode sftp_doing(struct connectdata *conn,
                           bool *dophase_done);
static CURLcode sftp_disconnect(struct connectdata *conn);
static
CURLcode sftp_perform(struct connectdata *conn,
                      bool *connected,
                      bool *dophase_done);

static int ssh_getsock(struct connectdata *conn,
                       curl_socket_t *sock, /* points to numsocks number
                                               of sockets */
                       int numsocks);

static int ssh_perform_getsock(const struct connectdata *conn,
                               curl_socket_t *sock, /* points to numsocks
                                                       number of sockets */
                               int numsocks);

/*
 * SCP protocol handler.
 */

const struct Curl_handler Curl_handler_scp = {
  "SCP",                                /* scheme */
  ZERO_NULL,                            /* setup_connection */
  ssh_do,                               /* do_it */
  scp_done,                             /* done */
  ZERO_NULL,                            /* do_more */
  ssh_connect,                          /* connect_it */
  ssh_multi_statemach,                  /* connecting */
  scp_doing,                            /* doing */
  ssh_getsock,                          /* proto_getsock */
  ssh_getsock,                          /* doing_getsock */
  ssh_perform_getsock,                  /* perform_getsock */
  scp_disconnect,                       /* disconnect */
  PORT_SSH,                             /* defport */
  PROT_SCP                              /* protocol */
};


/*
 * SFTP protocol handler.
 */

const struct Curl_handler Curl_handler_sftp = {
  "SFTP",                               /* scheme */
  ZERO_NULL,                            /* setup_connection */
  ssh_do,                               /* do_it */
  sftp_done,                            /* done */
  ZERO_NULL,                            /* do_more */
  ssh_connect,                          /* connect_it */
  ssh_multi_statemach,                  /* connecting */
  sftp_doing,                           /* doing */
  ssh_getsock,                          /* proto_getsock */
  ssh_getsock,                          /* doing_getsock */
  ssh_perform_getsock,                  /* perform_getsock */
  sftp_disconnect,                      /* disconnect */
  PORT_SSH,                             /* defport */
  PROT_SFTP                             /* protocol */
};


static void
kbd_callback(const char *name, int name_len, const char *instruction,
             int instruction_len, int num_prompts,
             const LIBSSH2_USERAUTH_KBDINT_PROMPT *prompts,
             LIBSSH2_USERAUTH_KBDINT_RESPONSE *responses,
             void **abstract)
{
  struct connectdata *conn = (struct connectdata *)*abstract;

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
  if(num_prompts == 1) {
    responses[0].text = strdup(conn->passwd);
    responses[0].length = (unsigned int)strlen(conn->passwd);
  }
  (void)prompts;
  (void)abstract;
} /* kbd_callback */

static CURLcode sftp_libssh2_error_to_CURLE(int err)
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
  switch (err) {
    /* Ordered by order of appearance in libssh2.h */
    case LIBSSH2_ERROR_NONE:
      return CURLE_OK;

    case LIBSSH2_ERROR_SOCKET_NONE:
      return CURLE_COULDNT_CONNECT;

    case LIBSSH2_ERROR_ALLOC:
      return CURLE_OUT_OF_MEMORY;

    case LIBSSH2_ERROR_SOCKET_SEND:
      return CURLE_SEND_ERROR;

    case LIBSSH2_ERROR_HOSTKEY_INIT:
    case LIBSSH2_ERROR_HOSTKEY_SIGN:
    case LIBSSH2_ERROR_PUBLICKEY_UNRECOGNIZED:
    case LIBSSH2_ERROR_PUBLICKEY_UNVERIFIED:
      return CURLE_PEER_FAILED_VERIFICATION;

    case LIBSSH2_ERROR_PASSWORD_EXPIRED:
      return CURLE_LOGIN_DENIED;

    case LIBSSH2_ERROR_SOCKET_TIMEOUT:
    case LIBSSH2_ERROR_TIMEOUT:
      return CURLE_OPERATION_TIMEDOUT;

    case LIBSSH2_ERROR_EAGAIN:
      return CURLE_AGAIN;
  }

  /* TODO: map some more of the libssh2 errors to the more appropriate CURLcode
     error code, and possibly add a few new SSH-related one. We must however
     not return or even depend on libssh2 errors in the public libcurl API */

  return CURLE_SSH;
}

static LIBSSH2_ALLOC_FUNC(libssh2_malloc)
{
  (void)abstract; /* arg not used */
  return malloc(count);
}

static LIBSSH2_REALLOC_FUNC(libssh2_realloc)
{
  (void)abstract; /* arg not used */
  return realloc(ptr, count);
}

static LIBSSH2_FREE_FUNC(libssh2_free)
{
  (void)abstract; /* arg not used */
  free(ptr);
}

/*
 * SSH State machine related code
 */
/* This is the ONLY way to change SSH state! */
static void state(struct connectdata *conn, sshstate nowstate)
{
#if defined(DEBUGBUILD) && !defined(CURL_DISABLE_VERBOSE_STRINGS)
  /* for debug purposes */
  static const char * const names[] = {
    "SSH_STOP",
    "SSH_S_STARTUP",
    "SSH_HOSTKEY",
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
    "SSH_SESSION_DISCONNECT",
    "SSH_SESSION_FREE",
    "QUIT"
  };
#endif
  struct ssh_conn *sshc = &conn->proto.sshc;

#if defined(DEBUGBUILD) && !defined(CURL_DISABLE_VERBOSE_STRINGS)
  if(sshc->state != nowstate) {
    infof(conn->data, "SFTP %p state change from %s to %s\n",
          sshc, names[sshc->state], names[nowstate]);
  }
#endif

  sshc->state = nowstate;
}

/* figure out the path to work with in this particular request */
static CURLcode ssh_getworkingpath(struct connectdata *conn,
                                   char *homedir,  /* when SFTP is used */
                                   char **path) /* returns the  allocated
                                                   real path to work with */
{
  struct SessionHandle *data = conn->data;
  char *real_path = NULL;
  char *working_path;
  int working_path_len;

  working_path = curl_easy_unescape(data, data->state.path, 0,
                                    &working_path_len);
  if(!working_path)
    return CURLE_OUT_OF_MEMORY;

  /* Check for /~/ , indicating relative to the user's home directory */
  if(conn->protocol & PROT_SCP) {
    real_path = malloc(working_path_len+1);
    if(real_path == NULL) {
      free(working_path);
      return CURLE_OUT_OF_MEMORY;
    }
    if((working_path_len > 1) && (working_path[1] == '~'))
      /* It is referenced to the home directory, so strip the leading '/' */
      memcpy(real_path, working_path+1, 1 + working_path_len-1);
    else
      memcpy(real_path, working_path, 1 + working_path_len);
  }
  else if(conn->protocol & PROT_SFTP) {
    if((working_path_len > 1) && (working_path[1] == '~')) {
      size_t homelen = strlen(homedir);
      real_path = malloc(homelen + working_path_len + 1);
      if(real_path == NULL) {
        free(working_path);
        return CURLE_OUT_OF_MEMORY;
      }
      /* It is referenced to the home directory, so strip the
         leading '/' */
      memcpy(real_path, homedir, homelen);
      real_path[homelen] = '/';
      real_path[homelen+1] = '\0';
      if(working_path_len > 3) {
        memcpy(real_path+homelen+1, working_path + 3,
               1 + working_path_len -3);
      }
    }
    else {
      real_path = malloc(working_path_len+1);
      if(real_path == NULL) {
        free(working_path);
        return CURLE_OUT_OF_MEMORY;
      }
      memcpy(real_path, working_path, 1+working_path_len);
    }
  }

  free(working_path);

  /* store the pointer for the caller to receive */
  *path = real_path;

  return CURLE_OK;
}

#ifdef HAVE_LIBSSH2_KNOWNHOST_API
static int sshkeycallback(CURL *easy,
                          const struct curl_khkey *knownkey, /* known */
                          const struct curl_khkey *foundkey, /* found */
                          enum curl_khmatch match,
                          void *clientp)
{
  (void)easy;
  (void)knownkey;
  (void)foundkey;
  (void)clientp;

  /* we only allow perfect matches, and we reject everything else */
  return (match != CURLKHMATCH_OK)?CURLKHSTAT_REJECT:CURLKHSTAT_FINE;
}
#endif

/*
 * Earlier libssh2 versions didn't have the ability to seek to 64bit positions
 * with 32bit size_t.
 */
#ifdef HAVE_LIBSSH2_SFTP_SEEK64
#define SFTP_SEEK(x,y) libssh2_sftp_seek64(x, (libssh2_uint64_t)y)
#else
#define SFTP_SEEK(x,y) libssh2_sftp_seek(x, (size_t)y)
#endif

/*
 * ssh_statemach_act() runs the SSH state machine as far as it can without
 * blocking and without reaching the end.  The data the pointer 'block' points
 * to will be set to TRUE if the libssh2 function returns LIBSSH2_ERROR_EAGAIN
 * meaning it wants to be called again when the socket is ready
 */

static CURLcode ssh_statemach_act(struct connectdata *conn, bool *block)
{
  CURLcode result = CURLE_OK;
  struct SessionHandle *data = conn->data;
  struct SSHPROTO *sftp_scp = data->state.proto.ssh;
  struct ssh_conn *sshc = &conn->proto.sshc;
  curl_socket_t sock = conn->sock[FIRSTSOCKET];
#ifdef CURL_LIBSSH2_DEBUG
  const char *fingerprint;
#endif /* CURL_LIBSSH2_DEBUG */
  const char *host_public_key_md5;
  int rc = LIBSSH2_ERROR_NONE, i;
  int err;
  int seekerr = CURL_SEEKFUNC_OK;
  *block = 0; /* we're not blocking by default */

  do {

    switch(sshc->state) {
    case SSH_S_STARTUP:
      sshc->secondCreateDirs = 0;
      sshc->nextstate = SSH_NO_STATE;
      sshc->actualcode = CURLE_OK;

      rc = libssh2_session_startup(sshc->ssh_session, sock);
      if(rc == LIBSSH2_ERROR_EAGAIN) {
        break;
      }
      else if(rc) {
        failf(data, "Failure establishing ssh session");
        state(conn, SSH_SESSION_FREE);
        sshc->actualcode = CURLE_FAILED_INIT;
        break;
      }

      /* Set libssh2 to non-blocking, since everything internally is
         non-blocking */
      libssh2_session_set_blocking(sshc->ssh_session, 0);

      state(conn, SSH_HOSTKEY);

      /* fall-through */
    case SSH_HOSTKEY:

#ifdef CURL_LIBSSH2_DEBUG
      /*
       * Before we authenticate we should check the hostkey's fingerprint
       * against our known hosts. How that is handled (reading from file,
       * whatever) is up to us. As for know not much is implemented, besides
       * showing how to get the fingerprint.
       */
      fingerprint = libssh2_hostkey_hash(sshc->ssh_session,
                                         LIBSSH2_HOSTKEY_HASH_MD5);

      /* The fingerprint points to static storage (!), don't free() it. */
      infof(data, "Fingerprint: ");
      for (rc = 0; rc < 16; rc++) {
        infof(data, "%02X ", (unsigned char) fingerprint[rc]);
      }
      infof(data, "\n");
#endif /* CURL_LIBSSH2_DEBUG */

      /* Before we authenticate we check the hostkey's MD5 fingerprint
       * against a known fingerprint, if available.  This implementation pulls
       * it from the curl option.
       */
      if(data->set.str[STRING_SSH_HOST_PUBLIC_KEY_MD5] &&
         strlen(data->set.str[STRING_SSH_HOST_PUBLIC_KEY_MD5]) == 32) {
        char buf[33];
        host_public_key_md5 = libssh2_hostkey_hash(sshc->ssh_session,
                                                   LIBSSH2_HOSTKEY_HASH_MD5);
        for (i = 0; i < 16; i++)
          snprintf(&buf[i*2], 3, "%02x",
                   (unsigned char) host_public_key_md5[i]);
        if(!strequal(buf, data->set.str[STRING_SSH_HOST_PUBLIC_KEY_MD5])) {
          failf(data,
                "Denied establishing ssh session: mismatch md5 fingerprint. "
                "Remote %s is not equal to %s",
                buf, data->set.str[STRING_SSH_HOST_PUBLIC_KEY_MD5]);
          state(conn, SSH_SESSION_FREE);
          sshc->actualcode = CURLE_PEER_FAILED_VERIFICATION;
          break;
        }
      }

#ifdef HAVE_LIBSSH2_KNOWNHOST_API
      if(data->set.str[STRING_SSH_KNOWNHOSTS]) {
        /* we're asked to verify the host against a file */
        int keytype;
        size_t keylen;
        const char *remotekey = libssh2_session_hostkey(sshc->ssh_session,
                                                        &keylen, &keytype);
        int keycheck;
        int keybit;

        if(remotekey) {
          /*
           * A subject to figure out is what host name we need to pass in here.
           * What host name does OpenSSH store in its file if an IDN name is
           * used?
           */
          struct libssh2_knownhost *host;
          enum curl_khmatch keymatch;
          curl_sshkeycallback func =
            data->set.ssh_keyfunc?data->set.ssh_keyfunc:sshkeycallback;
          struct curl_khkey knownkey;
          struct curl_khkey *knownkeyp = NULL;
          struct curl_khkey foundkey;

          keybit = (keytype == LIBSSH2_HOSTKEY_TYPE_RSA)?
            LIBSSH2_KNOWNHOST_KEY_SSHRSA:LIBSSH2_KNOWNHOST_KEY_SSHDSS;

          keycheck = libssh2_knownhost_check(sshc->kh,
                                             conn->host.name,
                                             remotekey, keylen,
                                             LIBSSH2_KNOWNHOST_TYPE_PLAIN|
                                             LIBSSH2_KNOWNHOST_KEYENC_RAW|
                                             keybit,
                                             &host);

          infof(data, "SSH host check: %d, key: %s\n", keycheck,
                (keycheck <= LIBSSH2_KNOWNHOST_CHECK_MISMATCH)?
                host->key:"<none>");

          /* setup 'knownkey' */
          if(keycheck <= LIBSSH2_KNOWNHOST_CHECK_MISMATCH) {
            knownkey.key = host->key;
            knownkey.len = 0;
            knownkey.keytype = (keytype == LIBSSH2_HOSTKEY_TYPE_RSA)?
              CURLKHTYPE_RSA : CURLKHTYPE_DSS;
            knownkeyp = &knownkey;
          }

          /* setup 'foundkey' */
          foundkey.key = remotekey;
          foundkey.len = keylen;
          foundkey.keytype = (keytype == LIBSSH2_HOSTKEY_TYPE_RSA)?
            CURLKHTYPE_RSA : CURLKHTYPE_DSS;

          /*
           * if any of the LIBSSH2_KNOWNHOST_CHECK_* defines and the
           * curl_khmatch enum are ever modified, we need to introduce a
           * translation table here!
           */
          keymatch = (enum curl_khmatch)keycheck;

          /* Ask the callback how to behave */
          rc = func(data, knownkeyp, /* from the knownhosts file */
                    &foundkey, /* from the remote host */
                    keymatch, data->set.ssh_keyfunc_userp);
        }
        else
          /* no remotekey means failure! */
          rc = CURLKHSTAT_REJECT;

        switch(rc) {
        default: /* unknown return codes will equal reject */
        case CURLKHSTAT_REJECT:
          state(conn, SSH_SESSION_FREE);
        case CURLKHSTAT_DEFER:
          /* DEFER means bail out but keep the SSH_HOSTKEY state */
          result = sshc->actualcode = CURLE_PEER_FAILED_VERIFICATION;
          break;
        case CURLKHSTAT_FINE:
        case CURLKHSTAT_FINE_ADD_TO_FILE:
          /* proceed */
          if(keycheck != LIBSSH2_KNOWNHOST_CHECK_MATCH) {
            /* the found host+key didn't match but has been told to be fine
               anyway so we add it in memory */
            int addrc = libssh2_knownhost_add(sshc->kh,
                                              conn->host.name, NULL,
                                              remotekey, keylen,
                                              LIBSSH2_KNOWNHOST_TYPE_PLAIN|
                                              LIBSSH2_KNOWNHOST_KEYENC_RAW|
                                              keybit, NULL);
            if(addrc)
              infof(data, "Warning adding the known host %s failed!\n",
                    conn->host.name);
            else if(rc == CURLKHSTAT_FINE_ADD_TO_FILE) {
              /* now we write the entire in-memory list of known hosts to the
                 known_hosts file */
              int wrc =
                libssh2_knownhost_writefile(sshc->kh,
                                            data->set.str[STRING_SSH_KNOWNHOSTS],
                                            LIBSSH2_KNOWNHOST_FILE_OPENSSH);
              if(wrc) {
                infof(data, "Warning, writing %s failed!\n",
                      data->set.str[STRING_SSH_KNOWNHOSTS]);
              }
            }
          }
          break;
        }
      }
#endif /* HAVE_LIBSSH2_KNOWNHOST_API */

      state(conn, SSH_AUTHLIST);
      break;

    case SSH_AUTHLIST:
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
      sshc->authlist = libssh2_userauth_list(sshc->ssh_session,
                                             conn->user,
                                             (unsigned int)strlen(conn->user));

      if(!sshc->authlist) {
        if((err = libssh2_session_last_errno(sshc->ssh_session)) ==
           LIBSSH2_ERROR_EAGAIN) {
          rc = LIBSSH2_ERROR_EAGAIN;
          break;
        }
        else {
          state(conn, SSH_SESSION_FREE);
          sshc->actualcode = libssh2_session_error_to_CURLE(err);
          break;
        }
      }
      infof(data, "SSH authentication methods available: %s\n",
            sshc->authlist);

      state(conn, SSH_AUTH_PKEY_INIT);
      break;

    case SSH_AUTH_PKEY_INIT:
      /*
       * Check the supported auth types in the order I feel is most secure
       * with the requested type of authentication
       */
      sshc->authed = FALSE;

      if((data->set.ssh_auth_types & CURLSSH_AUTH_PUBLICKEY) &&
         (strstr(sshc->authlist, "publickey") != NULL)) {
        char *home;

        sshc->rsa_pub = sshc->rsa = NULL;

        /* To ponder about: should really the lib be messing about with the
           HOME environment variable etc? */
        home = curl_getenv("HOME");

        if(data->set.str[STRING_SSH_PUBLIC_KEY])
          sshc->rsa_pub = aprintf("%s", data->set.str[STRING_SSH_PUBLIC_KEY]);
        else if(home)
          sshc->rsa_pub = aprintf("%s/.ssh/id_dsa.pub", home);
        else
          /* as a final resort, try current dir! */
          sshc->rsa_pub = strdup("id_dsa.pub");

        if(sshc->rsa_pub == NULL) {
          Curl_safefree(home);
          home = NULL;
          state(conn, SSH_SESSION_FREE);
          sshc->actualcode = CURLE_OUT_OF_MEMORY;
          break;
        }

        if(data->set.str[STRING_SSH_PRIVATE_KEY])
          sshc->rsa = aprintf("%s", data->set.str[STRING_SSH_PRIVATE_KEY]);
        else if(home)
          sshc->rsa = aprintf("%s/.ssh/id_dsa", home);
        else
          /* as a final resort, try current dir! */
          sshc->rsa = strdup("id_dsa");

        if(sshc->rsa == NULL) {
          Curl_safefree(home);
          home = NULL;
          Curl_safefree(sshc->rsa_pub);
          sshc->rsa_pub = NULL;
          state(conn, SSH_SESSION_FREE);
          sshc->actualcode = CURLE_OUT_OF_MEMORY;
          break;
        }

        sshc->passphrase = data->set.str[STRING_KEY_PASSWD];
        if(!sshc->passphrase)
          sshc->passphrase = "";

        Curl_safefree(home);
        home = NULL;

        infof(data, "Using ssh public key file %s\n", sshc->rsa_pub);
        infof(data, "Using ssh private key file %s\n", sshc->rsa);

        state(conn, SSH_AUTH_PKEY);
      }
      else {
        state(conn, SSH_AUTH_PASS_INIT);
      }
      break;

    case SSH_AUTH_PKEY:
      /* The function below checks if the files exists, no need to stat() here.
       */
      rc = libssh2_userauth_publickey_fromfile_ex(sshc->ssh_session,
                                                  conn->user,
                                                  (unsigned int)
                                                  strlen(conn->user),
                                                  sshc->rsa_pub,
                                                  sshc->rsa, sshc->passphrase);
      if(rc == LIBSSH2_ERROR_EAGAIN) {
        break;
      }

      Curl_safefree(sshc->rsa_pub);
      sshc->rsa_pub = NULL;
      Curl_safefree(sshc->rsa);
      sshc->rsa = NULL;

      if(rc == 0) {
        sshc->authed = TRUE;
        infof(data, "Initialized SSH public key authentication\n");
        state(conn, SSH_AUTH_DONE);
      }
      else {
        char *err_msg;
        (void)libssh2_session_last_error(sshc->ssh_session,
                                         &err_msg, NULL, 0);
        infof(data, "SSH public key authentication failed: %s\n", err_msg);
        state(conn, SSH_AUTH_PASS_INIT);
      }
      break;

    case SSH_AUTH_PASS_INIT:
      if((data->set.ssh_auth_types & CURLSSH_AUTH_PASSWORD) &&
         (strstr(sshc->authlist, "password") != NULL)) {
        state(conn, SSH_AUTH_PASS);
      }
      else {
        state(conn, SSH_AUTH_HOST_INIT);
      }
      break;

    case SSH_AUTH_PASS:
      rc = libssh2_userauth_password_ex(sshc->ssh_session, conn->user,
                                        (unsigned int)strlen(conn->user),
                                        conn->passwd,
                                        (unsigned int)strlen(conn->passwd),
                                        NULL);
      if(rc == LIBSSH2_ERROR_EAGAIN) {
        break;
      }
      else if(rc == 0) {
        sshc->authed = TRUE;
        infof(data, "Initialized password authentication\n");
        state(conn, SSH_AUTH_DONE);
      }
      else {
        state(conn, SSH_AUTH_HOST_INIT);
      }
      break;

    case SSH_AUTH_HOST_INIT:
      if((data->set.ssh_auth_types & CURLSSH_AUTH_HOST) &&
         (strstr(sshc->authlist, "hostbased") != NULL)) {
        state(conn, SSH_AUTH_HOST);
      }
      else {
        state(conn, SSH_AUTH_KEY_INIT);
      }
      break;

    case SSH_AUTH_HOST:
      state(conn, SSH_AUTH_KEY_INIT);
      break;

    case SSH_AUTH_KEY_INIT:
      if((data->set.ssh_auth_types & CURLSSH_AUTH_KEYBOARD)
         && (strstr(sshc->authlist, "keyboard-interactive") != NULL)) {
        state(conn, SSH_AUTH_KEY);
      }
      else {
        state(conn, SSH_AUTH_DONE);
      }
      break;

    case SSH_AUTH_KEY:
      /* Authentication failed. Continue with keyboard-interactive now. */
      rc = libssh2_userauth_keyboard_interactive_ex(sshc->ssh_session,
                                                    conn->user,
                                                    (unsigned int)
                                                    strlen(conn->user),
                                                    &kbd_callback);
      if(rc == LIBSSH2_ERROR_EAGAIN) {
        break;
      }
      else if(rc == 0) {
        sshc->authed = TRUE;
        infof(data, "Initialized keyboard interactive authentication\n");
      }
      state(conn, SSH_AUTH_DONE);
      break;

    case SSH_AUTH_DONE:
      if(!sshc->authed) {
        failf(data, "Authentication failure");
        state(conn, SSH_SESSION_FREE);
        sshc->actualcode = CURLE_LOGIN_DENIED;
        break;
      }

      /*
       * At this point we have an authenticated ssh session.
       */
      infof(data, "Authentication complete\n");

      Curl_pgrsTime(conn->data, TIMER_APPCONNECT); /* SSH is connected */

      conn->sockfd = sock;
      conn->writesockfd = CURL_SOCKET_BAD;

      if(conn->protocol == PROT_SFTP) {
        state(conn, SSH_SFTP_INIT);
        break;
      }
      infof(data, "SSH CONNECT phase done\n");
      state(conn, SSH_STOP);
      break;

    case SSH_SFTP_INIT:
      /*
       * Start the libssh2 sftp session
       */
      sshc->sftp_session = libssh2_sftp_init(sshc->ssh_session);
      if(!sshc->sftp_session) {
        if(libssh2_session_last_errno(sshc->ssh_session) ==
           LIBSSH2_ERROR_EAGAIN) {
          rc = LIBSSH2_ERROR_EAGAIN;
          break;
        }
        else {
          char *err_msg;

          (void)libssh2_session_last_error(sshc->ssh_session,
                                           &err_msg, NULL, 0);
          failf(data, "Failure initializing sftp session: %s", err_msg);
          state(conn, SSH_SESSION_FREE);
          sshc->actualcode = CURLE_FAILED_INIT;
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
      rc = libssh2_sftp_realpath(sshc->sftp_session, ".",
                                 tempHome, PATH_MAX-1);
      if(rc == LIBSSH2_ERROR_EAGAIN) {
        break;
      }
      else if(rc > 0) {
        /* It seems that this string is not always NULL terminated */
        tempHome[rc] = '\0';
        sshc->homedir = strdup(tempHome);
        if(!sshc->homedir) {
          state(conn, SSH_SFTP_CLOSE);
          sshc->actualcode = CURLE_OUT_OF_MEMORY;
          break;
        }
      }
      else {
        /* Return the error type */
        err = (int)(libssh2_sftp_last_error(sshc->sftp_session));
        result = sftp_libssh2_error_to_CURLE(err);
        sshc->actualcode = result?result:CURLE_SSH;
        DEBUGF(infof(data, "error = %d makes libcurl = %d\n",
                     err, (int)result));
        state(conn, SSH_STOP);
        break;
      }
    }
    /* This is the last step in the SFTP connect phase. Do note that while
       we get the homedir here, we get the "workingpath" in the DO action
       since the homedir will remain the same between request but the
       working path will not. */
    DEBUGF(infof(data, "SSH CONNECT phase done\n"));
    state(conn, SSH_STOP);
    break;

    case SSH_SFTP_QUOTE_INIT:

      result = ssh_getworkingpath(conn, sshc->homedir, &sftp_scp->path);
      if(result) {
        sshc->actualcode = result;
        state(conn, SSH_STOP);
        break;
      }

      if(data->set.quote) {
        infof(data, "Sending quote commands\n");
        sshc->quote_item = data->set.quote;
        state(conn, SSH_SFTP_QUOTE);
      }
      else {
        state(conn, SSH_SFTP_TRANS_INIT);
      }
      break;

    case SSH_SFTP_POSTQUOTE_INIT:
      if(data->set.postquote) {
        infof(data, "Sending quote commands\n");
        sshc->quote_item = data->set.postquote;
        state(conn, SSH_SFTP_QUOTE);
      }
      else {
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
      if(curl_strequal("pwd", sshc->quote_item->data)) {
        /* output debug output if that is requested */
        if(data->set.verbose) {
          char tmp[PATH_MAX+1];

          Curl_debug(data, CURLINFO_HEADER_OUT, (char *)"PWD\n", 4, conn);
          snprintf(tmp, PATH_MAX, "257 \"%s\" is current directory.\n",
                   sftp_scp->path);
          Curl_debug(data, CURLINFO_HEADER_IN, tmp, strlen(tmp), conn);
        }
        state(conn, SSH_SFTP_NEXT_QUOTE);
        break;
      }
      else if(sshc->quote_item->data) {
        /*
         * the arguments following the command must be separated from the
         * command with a space so we can check for it unconditionally
         */
        cp = strchr(sshc->quote_item->data, ' ');
        if(cp == NULL) {
          failf(data, "Syntax error in SFTP command. Supply parameter(s)!");
          state(conn, SSH_SFTP_CLOSE);
          sshc->actualcode = CURLE_QUOTE_ERROR;
          break;
        }

        /*
         * also, every command takes at least one argument so we get that
         * first argument right now
         */
        result = get_pathname(&cp, &sshc->quote_path1);
        if(result) {
          if(result == CURLE_OUT_OF_MEMORY)
            failf(data, "Out of memory");
          else
            failf(data, "Syntax error: Bad first parameter");
          state(conn, SSH_SFTP_CLOSE);
          sshc->actualcode = result;
          break;
        }

        /*
         * SFTP is a binary protocol, so we don't send text commands to
         * the server. Instead, we scan for commands for commands used by
         * OpenSSH's sftp program and call the appropriate libssh2
         * functions.
         */
        if(curl_strnequal(sshc->quote_item->data, "chgrp ", 6) ||
           curl_strnequal(sshc->quote_item->data, "chmod ", 6) ||
           curl_strnequal(sshc->quote_item->data, "chown ", 6) ) {
          /* attribute change */

          /* sshc->quote_path1 contains the mode to set */
          /* get the destination */
          result = get_pathname(&cp, &sshc->quote_path2);
          if(result) {
            if(result == CURLE_OUT_OF_MEMORY)
              failf(data, "Out of memory");
            else
              failf(data, "Syntax error in chgrp/chmod/chown: "
                    "Bad second parameter");
            Curl_safefree(sshc->quote_path1);
            sshc->quote_path1 = NULL;
            state(conn, SSH_SFTP_CLOSE);
            sshc->actualcode = result;
            break;
          }
          memset(&sshc->quote_attrs, 0, sizeof(LIBSSH2_SFTP_ATTRIBUTES));
          state(conn, SSH_SFTP_QUOTE_STAT);
          break;
        }
        else if(curl_strnequal(sshc->quote_item->data, "ln ", 3) ||
                curl_strnequal(sshc->quote_item->data, "symlink ", 8)) {
          /* symbolic linking */
          /* sshc->quote_path1 is the source */
          /* get the destination */
          result = get_pathname(&cp, &sshc->quote_path2);
          if(result) {
            if(result == CURLE_OUT_OF_MEMORY)
              failf(data, "Out of memory");
            else
              failf(data,
                    "Syntax error in ln/symlink: Bad second parameter");
            Curl_safefree(sshc->quote_path1);
            sshc->quote_path1 = NULL;
            state(conn, SSH_SFTP_CLOSE);
            sshc->actualcode = result;
            break;
          }
          state(conn, SSH_SFTP_QUOTE_SYMLINK);
          break;
        }
        else if(curl_strnequal(sshc->quote_item->data, "mkdir ", 6)) {
          /* create dir */
          state(conn, SSH_SFTP_QUOTE_MKDIR);
          break;
        }
        else if(curl_strnequal(sshc->quote_item->data, "rename ", 7)) {
          /* rename file */
          /* first param is the source path */
          /* second param is the dest. path */
          result = get_pathname(&cp, &sshc->quote_path2);
          if(result) {
            if(result == CURLE_OUT_OF_MEMORY)
              failf(data, "Out of memory");
            else
              failf(data, "Syntax error in rename: Bad second parameter");
            Curl_safefree(sshc->quote_path1);
            sshc->quote_path1 = NULL;
            state(conn, SSH_SFTP_CLOSE);
            sshc->actualcode = result;
            break;
          }
          state(conn, SSH_SFTP_QUOTE_RENAME);
          break;
        }
        else if(curl_strnequal(sshc->quote_item->data, "rmdir ", 6)) {
          /* delete dir */
          state(conn, SSH_SFTP_QUOTE_RMDIR);
          break;
        }
        else if(curl_strnequal(sshc->quote_item->data, "rm ", 3)) {
          state(conn, SSH_SFTP_QUOTE_UNLINK);
          break;
        }

        failf(data, "Unknown SFTP command");
        Curl_safefree(sshc->quote_path1);
        sshc->quote_path1 = NULL;
        Curl_safefree(sshc->quote_path2);
        sshc->quote_path2 = NULL;
        state(conn, SSH_SFTP_CLOSE);
        sshc->actualcode = CURLE_QUOTE_ERROR;
        break;
      }
    }
    if(!sshc->quote_item) {
      state(conn, SSH_SFTP_TRANS_INIT);
    }
    break;

    case SSH_SFTP_NEXT_QUOTE:
      if(sshc->quote_path1) {
        Curl_safefree(sshc->quote_path1);
        sshc->quote_path1 = NULL;
      }
      if(sshc->quote_path2) {
        Curl_safefree(sshc->quote_path2);
        sshc->quote_path2 = NULL;
      }

      sshc->quote_item = sshc->quote_item->next;

      if(sshc->quote_item) {
        state(conn, SSH_SFTP_QUOTE);
      }
      else {
        if(sshc->nextstate != SSH_NO_STATE) {
          state(conn, sshc->nextstate);
          sshc->nextstate = SSH_NO_STATE;
        }
        else {
          state(conn, SSH_SFTP_TRANS_INIT);
        }
      }
      break;

    case SSH_SFTP_QUOTE_STAT:
      if(!curl_strnequal(sshc->quote_item->data, "chmod", 5)) {
        /* Since chown and chgrp only set owner OR group but libssh2 wants to
         * set them both at once, we need to obtain the current ownership
         * first.  This takes an extra protocol round trip.
         */
        rc = libssh2_sftp_stat_ex(sshc->sftp_session, sshc->quote_path2,
                                  (unsigned int)strlen(sshc->quote_path2),
                                  LIBSSH2_SFTP_STAT,
                                  &sshc->quote_attrs);
        if(rc == LIBSSH2_ERROR_EAGAIN) {
          break;
        }
        else if(rc != 0) { /* get those attributes */
          err = (int)(libssh2_sftp_last_error(sshc->sftp_session));
          Curl_safefree(sshc->quote_path1);
          sshc->quote_path1 = NULL;
          Curl_safefree(sshc->quote_path2);
          sshc->quote_path2 = NULL;
          failf(data, "Attempt to get SFTP stats failed: %s",
                sftp_libssh2_strerror(err));
          state(conn, SSH_SFTP_CLOSE);
          sshc->actualcode = CURLE_QUOTE_ERROR;
          break;
        }
      }

      /* Now set the new attributes... */
      if(curl_strnequal(sshc->quote_item->data, "chgrp", 5)) {
        sshc->quote_attrs.gid = strtoul(sshc->quote_path1, NULL, 10);
        sshc->quote_attrs.flags = LIBSSH2_SFTP_ATTR_UIDGID;
        if(sshc->quote_attrs.gid == 0 && !ISDIGIT(sshc->quote_path1[0])) {
          Curl_safefree(sshc->quote_path1);
          sshc->quote_path1 = NULL;
          Curl_safefree(sshc->quote_path2);
          sshc->quote_path2 = NULL;
          failf(data, "Syntax error: chgrp gid not a number");
          state(conn, SSH_SFTP_CLOSE);
          sshc->actualcode = CURLE_QUOTE_ERROR;
          break;
        }
      }
      else if(curl_strnequal(sshc->quote_item->data, "chmod", 5)) {
        sshc->quote_attrs.permissions = strtoul(sshc->quote_path1, NULL, 8);
        sshc->quote_attrs.flags = LIBSSH2_SFTP_ATTR_PERMISSIONS;
        /* permissions are octal */
        if(sshc->quote_attrs.permissions == 0 &&
           !ISDIGIT(sshc->quote_path1[0])) {
          Curl_safefree(sshc->quote_path1);
          sshc->quote_path1 = NULL;
          Curl_safefree(sshc->quote_path2);
          sshc->quote_path2 = NULL;
          failf(data, "Syntax error: chmod permissions not a number");
          state(conn, SSH_SFTP_CLOSE);
          sshc->actualcode = CURLE_QUOTE_ERROR;
          break;
        }
      }
      else if(curl_strnequal(sshc->quote_item->data, "chown", 5)) {
        sshc->quote_attrs.uid = strtoul(sshc->quote_path1, NULL, 10);
        sshc->quote_attrs.flags = LIBSSH2_SFTP_ATTR_UIDGID;
        if(sshc->quote_attrs.uid == 0 && !ISDIGIT(sshc->quote_path1[0])) {
          Curl_safefree(sshc->quote_path1);
          sshc->quote_path1 = NULL;
          Curl_safefree(sshc->quote_path2);
          sshc->quote_path2 = NULL;
          failf(data, "Syntax error: chown uid not a number");
          state(conn, SSH_SFTP_CLOSE);
          sshc->actualcode = CURLE_QUOTE_ERROR;
          break;
        }
      }

      /* Now send the completed structure... */
      state(conn, SSH_SFTP_QUOTE_SETSTAT);
      break;

    case SSH_SFTP_QUOTE_SETSTAT:
      rc = libssh2_sftp_stat_ex(sshc->sftp_session, sshc->quote_path2,
                                (unsigned int)strlen(sshc->quote_path2),
                                LIBSSH2_SFTP_SETSTAT,
                                &sshc->quote_attrs);
      if(rc == LIBSSH2_ERROR_EAGAIN) {
        break;
      }
      else if(rc != 0) {
        err = (int)(libssh2_sftp_last_error(sshc->sftp_session));
        Curl_safefree(sshc->quote_path1);
        sshc->quote_path1 = NULL;
        Curl_safefree(sshc->quote_path2);
        sshc->quote_path2 = NULL;
        failf(data, "Attempt to set SFTP stats failed: %s",
              sftp_libssh2_strerror(err));
        state(conn, SSH_SFTP_CLOSE);
        sshc->actualcode = CURLE_QUOTE_ERROR;
        break;
      }
      state(conn, SSH_SFTP_NEXT_QUOTE);
      break;

    case SSH_SFTP_QUOTE_SYMLINK:
      rc = libssh2_sftp_symlink_ex(sshc->sftp_session, sshc->quote_path1,
                                   (unsigned int)strlen(sshc->quote_path1),
                                   sshc->quote_path2,
                                   (unsigned int)strlen(sshc->quote_path2),
                                   LIBSSH2_SFTP_SYMLINK);
      if(rc == LIBSSH2_ERROR_EAGAIN) {
        break;
      }
      else if(rc != 0) {
        err = (int)(libssh2_sftp_last_error(sshc->sftp_session));
        Curl_safefree(sshc->quote_path1);
        sshc->quote_path1 = NULL;
        Curl_safefree(sshc->quote_path2);
        sshc->quote_path2 = NULL;
        failf(data, "symlink command failed: %s",
              sftp_libssh2_strerror(err));
        state(conn, SSH_SFTP_CLOSE);
        sshc->actualcode = CURLE_QUOTE_ERROR;
        break;
      }
      state(conn, SSH_SFTP_NEXT_QUOTE);
      break;

    case SSH_SFTP_QUOTE_MKDIR:
      rc = libssh2_sftp_mkdir_ex(sshc->sftp_session, sshc->quote_path1,
                                 (unsigned int)strlen(sshc->quote_path1),
                                 0755);
      if(rc == LIBSSH2_ERROR_EAGAIN) {
        break;
      }
      else if(rc != 0) {
        err = (int)(libssh2_sftp_last_error(sshc->sftp_session));
        Curl_safefree(sshc->quote_path1);
        sshc->quote_path1 = NULL;
        failf(data, "mkdir command failed: %s", sftp_libssh2_strerror(err));
        state(conn, SSH_SFTP_CLOSE);
        sshc->actualcode = CURLE_QUOTE_ERROR;
        break;
      }
      state(conn, SSH_SFTP_NEXT_QUOTE);
      break;

    case SSH_SFTP_QUOTE_RENAME:
      rc = libssh2_sftp_rename_ex(sshc->sftp_session, sshc->quote_path1,
                                  (unsigned int)strlen(sshc->quote_path1),
                                  sshc->quote_path2,
                                  (unsigned int)strlen(sshc->quote_path2),
                                  LIBSSH2_SFTP_RENAME_OVERWRITE |
                                  LIBSSH2_SFTP_RENAME_ATOMIC |
                                  LIBSSH2_SFTP_RENAME_NATIVE);
      if(rc == LIBSSH2_ERROR_EAGAIN) {
        break;
      }
      else if(rc != 0) {
        err = (int)(libssh2_sftp_last_error(sshc->sftp_session));
        Curl_safefree(sshc->quote_path1);
        sshc->quote_path1 = NULL;
        Curl_safefree(sshc->quote_path2);
        sshc->quote_path2 = NULL;
        failf(data, "rename command failed: %s", sftp_libssh2_strerror(err));
        state(conn, SSH_SFTP_CLOSE);
        sshc->actualcode = CURLE_QUOTE_ERROR;
        break;
      }
      state(conn, SSH_SFTP_NEXT_QUOTE);
      break;

    case SSH_SFTP_QUOTE_RMDIR:
      rc = libssh2_sftp_rmdir_ex(sshc->sftp_session, sshc->quote_path1,
                                 (unsigned int)strlen(sshc->quote_path1));
      if(rc == LIBSSH2_ERROR_EAGAIN) {
        break;
      }
      else if(rc != 0) {
        err = (int)(libssh2_sftp_last_error(sshc->sftp_session));
        Curl_safefree(sshc->quote_path1);
        sshc->quote_path1 = NULL;
        failf(data, "rmdir command failed: %s", sftp_libssh2_strerror(err));
        state(conn, SSH_SFTP_CLOSE);
        sshc->actualcode = CURLE_QUOTE_ERROR;
        break;
      }
      state(conn, SSH_SFTP_NEXT_QUOTE);
      break;

    case SSH_SFTP_QUOTE_UNLINK:
      rc = libssh2_sftp_unlink_ex(sshc->sftp_session, sshc->quote_path1,
                                  (unsigned int)strlen(sshc->quote_path1));
      if(rc == LIBSSH2_ERROR_EAGAIN) {
        break;
      }
      else if(rc != 0) {
        err = (int)(libssh2_sftp_last_error(sshc->sftp_session));
        Curl_safefree(sshc->quote_path1);
        sshc->quote_path1 = NULL;
        failf(data, "rm command failed: %s", sftp_libssh2_strerror(err));
        state(conn, SSH_SFTP_CLOSE);
        sshc->actualcode = CURLE_QUOTE_ERROR;
        break;
      }
      state(conn, SSH_SFTP_NEXT_QUOTE);
      break;

    case SSH_SFTP_TRANS_INIT:
      if(data->set.upload)
        state(conn, SSH_SFTP_UPLOAD_INIT);
      else {
        if(data->set.opt_no_body)
          state(conn, SSH_STOP);
        else if(sftp_scp->path[strlen(sftp_scp->path)-1] == '/')
          state(conn, SSH_SFTP_READDIR_INIT);
        else
          state(conn, SSH_SFTP_DOWNLOAD_INIT);
      }
      break;

    case SSH_SFTP_UPLOAD_INIT:
    {
      unsigned long flags;
      /*
       * NOTE!!!  libssh2 requires that the destination path is a full path
       *          that includes the destination file and name OR ends in a "/"
       *          If this is not done the destination file will be named the
       *          same name as the last directory in the path.
       */

      if(data->state.resume_from != 0) {
        LIBSSH2_SFTP_ATTRIBUTES attrs;
        if(data->state.resume_from< 0) {
          rc = libssh2_sftp_stat_ex(sshc->sftp_session, sftp_scp->path,
                                    (unsigned int)strlen(sftp_scp->path),
                                    LIBSSH2_SFTP_STAT, &attrs);
          if(rc == LIBSSH2_ERROR_EAGAIN) {
            break;
          }
          else if(rc) {
            data->state.resume_from = 0;
          }
          else {
            data->state.resume_from = attrs.filesize;
          }
        }
      }

      if(data->set.ftp_append)
        /* Try to open for append, but create if nonexisting */
        flags = LIBSSH2_FXF_WRITE|LIBSSH2_FXF_CREAT|LIBSSH2_FXF_APPEND;
      else if (data->state.resume_from > 0)
        /* If we have restart position then open for append */
        flags = LIBSSH2_FXF_WRITE|LIBSSH2_FXF_APPEND;
      else
        /* Clear file before writing (normal behaviour) */
        flags = LIBSSH2_FXF_WRITE|LIBSSH2_FXF_CREAT|LIBSSH2_FXF_TRUNC;

      sshc->sftp_handle =
        libssh2_sftp_open_ex(sshc->sftp_session, sftp_scp->path,
                             (unsigned int)strlen(sftp_scp->path),
                             flags, data->set.new_file_perms,
                             LIBSSH2_SFTP_OPENFILE);

      if(!sshc->sftp_handle) {
        rc = libssh2_session_last_errno(sshc->ssh_session);

        if(LIBSSH2_ERROR_EAGAIN == rc)
          break;
        else {
          if(LIBSSH2_ERROR_SFTP_PROTOCOL == rc)
            /* only when there was an SFTP protocol error can we extract
               the sftp error! */
            err = (int)(libssh2_sftp_last_error(sshc->sftp_session));
          else
            err = -1; /* not an sftp error at all */

          if(sshc->secondCreateDirs) {
            state(conn, SSH_SFTP_CLOSE);
            sshc->actualcode = err>= LIBSSH2_FX_OK?
              sftp_libssh2_error_to_CURLE(err):CURLE_SSH;
            failf(data, "Creating the dir/file failed: %s",
                  sftp_libssh2_strerror(err));
            break;
          }
          else if(((err == LIBSSH2_FX_NO_SUCH_FILE) ||
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
          sshc->actualcode = err>= LIBSSH2_FX_OK?
            sftp_libssh2_error_to_CURLE(err):CURLE_SSH;
          if(!sshc->actualcode) {
            /* Sometimes, for some reason libssh2_sftp_last_error() returns
               zero even though libssh2_sftp_open() failed previously! We need
               to work around that! */
            sshc->actualcode = CURLE_SSH;
            err=-1;
          }
          failf(data, "Upload failed: %s (%d/%d)",
                err>= LIBSSH2_FX_OK?sftp_libssh2_strerror(err):"ssh error",
                err, rc);
          break;
        }
      }

      /* If we have restart point then we need to seek to the correct
         position. */
      if(data->state.resume_from > 0) {
        /* Let's read off the proper amount of bytes from the input. */
        if(conn->seek_func) {
          seekerr = conn->seek_func(conn->seek_client, data->state.resume_from,
                                    SEEK_SET);
        }

        if(seekerr != CURL_SEEKFUNC_OK){

          if(seekerr != CURL_SEEKFUNC_CANTSEEK) {
            failf(data, "Could not seek stream");
            return CURLE_FTP_COULDNT_USE_REST;
          }
          /* seekerr == CURL_SEEKFUNC_CANTSEEK (can't seek to offset) */
          else {
            curl_off_t passed=0;
            curl_off_t readthisamountnow;
            curl_off_t actuallyread;
            do {
              readthisamountnow = (data->state.resume_from - passed);

              if(readthisamountnow > BUFSIZE)
                readthisamountnow = BUFSIZE;

              actuallyread =
                (curl_off_t) conn->fread_func(data->state.buffer, 1,
                                              (size_t)readthisamountnow,
                                              conn->fread_in);

              passed += actuallyread;
              if((actuallyread <= 0) || (actuallyread > readthisamountnow)) {
                /* this checks for greater-than only to make sure that the
                   CURL_READFUNC_ABORT return code still aborts */
                failf(data, "Failed to read data");
                return CURLE_FTP_COULDNT_USE_REST;
              }
            } while(passed < data->state.resume_from);
          }
        }

        /* now, decrease the size of the read */
        if(data->set.infilesize>0) {
          data->set.infilesize -= data->state.resume_from;
          data->req.size = data->set.infilesize;
          Curl_pgrsSetUploadSize(data, data->set.infilesize);
        }

        SFTP_SEEK(sshc->sftp_handle, data->state.resume_from);
      }
      if(data->set.infilesize>0) {
        data->req.size = data->set.infilesize;
        Curl_pgrsSetUploadSize(data, data->set.infilesize);
      }
      /* upload data */
      result = Curl_setup_transfer(conn, -1, -1, FALSE, NULL,
                                   FIRSTSOCKET, NULL);

      /* not set by Curl_setup_transfer to preserve keepon bits */
      conn->sockfd = conn->writesockfd;

      if(result) {
        state(conn, SSH_SFTP_CLOSE);
        sshc->actualcode = result;
      }
      else {
        /* store this original bitmask setup to use later on if we can't
           figure out a "real" bitmask */
        sshc->orig_waitfor = data->req.keepon;

        state(conn, SSH_STOP);
      }
      break;
    }

    case SSH_SFTP_CREATE_DIRS_INIT:
      if(strlen(sftp_scp->path) > 1) {
        sshc->slash_pos = sftp_scp->path + 1; /* ignore the leading '/' */
        state(conn, SSH_SFTP_CREATE_DIRS);
      }
      else {
        state(conn, SSH_SFTP_UPLOAD_INIT);
      }
      break;

    case SSH_SFTP_CREATE_DIRS:
      if((sshc->slash_pos = strchr(sshc->slash_pos, '/')) != NULL) {
        *sshc->slash_pos = 0;

        infof(data, "Creating directory '%s'\n", sftp_scp->path);
        state(conn, SSH_SFTP_CREATE_DIRS_MKDIR);
        break;
      }
      else {
        state(conn, SSH_SFTP_UPLOAD_INIT);
      }
      break;

    case SSH_SFTP_CREATE_DIRS_MKDIR:
      /* 'mode' - parameter is preliminary - default to 0644 */
      rc = libssh2_sftp_mkdir_ex(sshc->sftp_session, sftp_scp->path,
                                 (unsigned int)strlen(sftp_scp->path),
                                 data->set.new_directory_perms);
      if(rc == LIBSSH2_ERROR_EAGAIN) {
        break;
      }
      *sshc->slash_pos = '/';
      ++sshc->slash_pos;
      if(rc == -1) {
        unsigned int sftp_err = 0;
        /*
         * Abort if failure wasn't that the dir already exists or the
         * permission was denied (creation might succeed further down the
         * path) - retry on unspecific FAILURE also
         */
        sftp_err = (unsigned int)(libssh2_sftp_last_error(sshc->sftp_session));
        if((sftp_err != LIBSSH2_FX_FILE_ALREADY_EXISTS) &&
           (sftp_err != LIBSSH2_FX_FAILURE) &&
           (sftp_err != LIBSSH2_FX_PERMISSION_DENIED)) {
          result = sftp_libssh2_error_to_CURLE(sftp_err);
          state(conn, SSH_SFTP_CLOSE);
          sshc->actualcode = result?result:CURLE_SSH;
          break;
        }
      }
      state(conn, SSH_SFTP_CREATE_DIRS);
      break;

    case SSH_SFTP_READDIR_INIT:
      /*
       * This is a directory that we are trying to get, so produce a directory
       * listing
       */
      sshc->sftp_handle = libssh2_sftp_open_ex(sshc->sftp_session,
                                               sftp_scp->path,
                                               (unsigned int)
                                               strlen(sftp_scp->path),
                                               0, 0, LIBSSH2_SFTP_OPENDIR);
      if(!sshc->sftp_handle) {
        if(libssh2_session_last_errno(sshc->ssh_session) ==
           LIBSSH2_ERROR_EAGAIN) {
          rc = LIBSSH2_ERROR_EAGAIN;
          break;
        }
        else {
          err = (int)(libssh2_sftp_last_error(sshc->sftp_session));
          failf(data, "Could not open directory for reading: %s",
                sftp_libssh2_strerror(err));
          state(conn, SSH_SFTP_CLOSE);
          result = sftp_libssh2_error_to_CURLE(err);
          sshc->actualcode = result?result:CURLE_SSH;
          break;
        }
      }
      if((sshc->readdir_filename = malloc(PATH_MAX+1)) == NULL) {
        state(conn, SSH_SFTP_CLOSE);
        sshc->actualcode = CURLE_OUT_OF_MEMORY;
        break;
      }
      if((sshc->readdir_longentry = malloc(PATH_MAX+1)) == NULL) {
        Curl_safefree(sshc->readdir_filename);
        sshc->readdir_filename = NULL;
        state(conn, SSH_SFTP_CLOSE);
        sshc->actualcode = CURLE_OUT_OF_MEMORY;
        break;
      }
      state(conn, SSH_SFTP_READDIR);
      break;

    case SSH_SFTP_READDIR:
      sshc->readdir_len = libssh2_sftp_readdir_ex(sshc->sftp_handle,
                                                  sshc->readdir_filename,
                                                  PATH_MAX,
                                                  sshc->readdir_longentry,
                                                  PATH_MAX,
                                                  &sshc->readdir_attrs);
      if(sshc->readdir_len == LIBSSH2_ERROR_EAGAIN) {
        rc = LIBSSH2_ERROR_EAGAIN;
        break;
      }
      if(sshc->readdir_len > 0) {
        sshc->readdir_filename[sshc->readdir_len] = '\0';

        if(data->set.ftp_list_only) {
          char *tmpLine;

          tmpLine = aprintf("%s\n", sshc->readdir_filename);
          if(tmpLine == NULL) {
            state(conn, SSH_SFTP_CLOSE);
            sshc->actualcode = CURLE_OUT_OF_MEMORY;
            break;
          }
          result = Curl_client_write(conn, CLIENTWRITE_BODY,
                                     tmpLine, sshc->readdir_len+1);
          Curl_safefree(tmpLine);

          if(result) {
            state(conn, SSH_STOP);
            break;
          }
          /* since this counts what we send to the client, we include the
             newline in this counter */
          data->req.bytecount += sshc->readdir_len+1;

          /* output debug output if that is requested */
          if(data->set.verbose) {
            Curl_debug(data, CURLINFO_DATA_OUT, sshc->readdir_filename,
                       sshc->readdir_len, conn);
          }
        }
        else {
          sshc->readdir_currLen = (int)strlen(sshc->readdir_longentry);
          sshc->readdir_totalLen = 80 + sshc->readdir_currLen;
          sshc->readdir_line = calloc(sshc->readdir_totalLen, 1);
          if(!sshc->readdir_line) {
            Curl_safefree(sshc->readdir_filename);
            sshc->readdir_filename = NULL;
            Curl_safefree(sshc->readdir_longentry);
            sshc->readdir_longentry = NULL;
            state(conn, SSH_SFTP_CLOSE);
            sshc->actualcode = CURLE_OUT_OF_MEMORY;
            break;
          }

          memcpy(sshc->readdir_line, sshc->readdir_longentry,
                 sshc->readdir_currLen);
          if((sshc->readdir_attrs.flags & LIBSSH2_SFTP_ATTR_PERMISSIONS) &&
             ((sshc->readdir_attrs.permissions & LIBSSH2_SFTP_S_IFMT) ==
              LIBSSH2_SFTP_S_IFLNK)) {
            sshc->readdir_linkPath = malloc(PATH_MAX + 1);
            if(sshc->readdir_linkPath == NULL) {
              Curl_safefree(sshc->readdir_filename);
              sshc->readdir_filename = NULL;
              Curl_safefree(sshc->readdir_longentry);
              sshc->readdir_longentry = NULL;
              state(conn, SSH_SFTP_CLOSE);
              sshc->actualcode = CURLE_OUT_OF_MEMORY;
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
      else if(sshc->readdir_len == 0) {
        Curl_safefree(sshc->readdir_filename);
        sshc->readdir_filename = NULL;
        Curl_safefree(sshc->readdir_longentry);
        sshc->readdir_longentry = NULL;
        state(conn, SSH_SFTP_READDIR_DONE);
        break;
      }
      else if(sshc->readdir_len <= 0) {
        err = (int)(libssh2_sftp_last_error(sshc->sftp_session));
        result = sftp_libssh2_error_to_CURLE(err);
        sshc->actualcode = result?result:CURLE_SSH;
        failf(data, "Could not open remote file for reading: %s :: %d",
              sftp_libssh2_strerror(err),
              libssh2_session_last_errno(sshc->ssh_session));
        Curl_safefree(sshc->readdir_filename);
        sshc->readdir_filename = NULL;
        Curl_safefree(sshc->readdir_longentry);
        sshc->readdir_longentry = NULL;
        state(conn, SSH_SFTP_CLOSE);
        break;
      }
      break;

    case SSH_SFTP_READDIR_LINK:
      sshc->readdir_len =
        libssh2_sftp_symlink_ex(sshc->sftp_session,
                                sshc->readdir_linkPath,
                                (unsigned int) strlen(sshc->readdir_linkPath),
                                sshc->readdir_filename,
                                PATH_MAX, LIBSSH2_SFTP_READLINK);
      if(sshc->readdir_len == LIBSSH2_ERROR_EAGAIN) {
        rc = LIBSSH2_ERROR_EAGAIN;
        break;
      }
      Curl_safefree(sshc->readdir_linkPath);
      sshc->readdir_linkPath = NULL;
      sshc->readdir_line = realloc(sshc->readdir_line,
                                   sshc->readdir_totalLen + 4 +
                                   sshc->readdir_len);
      if(!sshc->readdir_line) {
        Curl_safefree(sshc->readdir_filename);
        sshc->readdir_filename = NULL;
        Curl_safefree(sshc->readdir_longentry);
        sshc->readdir_longentry = NULL;
        state(conn, SSH_SFTP_CLOSE);
        sshc->actualcode = CURLE_OUT_OF_MEMORY;
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
                                 sshc->readdir_line,
                                 sshc->readdir_currLen);

      if(result == CURLE_OK) {

        /* output debug output if that is requested */
        if(data->set.verbose) {
          Curl_debug(data, CURLINFO_DATA_OUT, sshc->readdir_line,
                     sshc->readdir_currLen, conn);
        }
        data->req.bytecount += sshc->readdir_currLen;
      }
      Curl_safefree(sshc->readdir_line);
      sshc->readdir_line = NULL;
      if(result) {
        state(conn, SSH_STOP);
      }
      else
        state(conn, SSH_SFTP_READDIR);
      break;

    case SSH_SFTP_READDIR_DONE:
      if(libssh2_sftp_closedir(sshc->sftp_handle) ==
         LIBSSH2_ERROR_EAGAIN) {
        rc = LIBSSH2_ERROR_EAGAIN;
        break;
      }
      sshc->sftp_handle = NULL;
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
      sshc->sftp_handle =
        libssh2_sftp_open_ex(sshc->sftp_session, sftp_scp->path,
                             (unsigned int)strlen(sftp_scp->path),
                             LIBSSH2_FXF_READ, data->set.new_file_perms,
                             LIBSSH2_SFTP_OPENFILE);
      if(!sshc->sftp_handle) {
        if(libssh2_session_last_errno(sshc->ssh_session) ==
           LIBSSH2_ERROR_EAGAIN) {
          rc = LIBSSH2_ERROR_EAGAIN;
          break;
        }
        else {
          err = (int)(libssh2_sftp_last_error(sshc->sftp_session));
          failf(data, "Could not open remote file for reading: %s",
                sftp_libssh2_strerror(err));
          state(conn, SSH_SFTP_CLOSE);
          result = sftp_libssh2_error_to_CURLE(err);
          sshc->actualcode = result?result:CURLE_SSH;
          break;
        }
      }
      state(conn, SSH_SFTP_DOWNLOAD_STAT);
      break;

    case SSH_SFTP_DOWNLOAD_STAT:
    {
      LIBSSH2_SFTP_ATTRIBUTES attrs;

      rc = libssh2_sftp_stat_ex(sshc->sftp_session, sftp_scp->path,
                                (unsigned int)strlen(sftp_scp->path),
                                LIBSSH2_SFTP_STAT, &attrs);
      if(rc == LIBSSH2_ERROR_EAGAIN) {
        break;
      }
      else if(rc) {
        /*
         * libssh2_sftp_open() didn't return an error, so maybe the server
         * just doesn't support stat()
         */
        data->req.size = -1;
        data->req.maxdownload = -1;
      }
      else {
        curl_off_t size;

        size = attrs.filesize;
        if(conn->data->state.use_range) {
          curl_off_t from, to;
          char *ptr;
          char *ptr2;

          from=curlx_strtoofft(conn->data->state.range, &ptr, 0);
          while(ptr && *ptr && (isspace((int)*ptr) || (*ptr=='-')))
            ptr++;
          to=curlx_strtoofft(ptr, &ptr2, 0);
          if((ptr == ptr2) /* no "to" value given */
             || (to >= size)) {
            to = size - 1;
          }
          if(from < 0) {
            /* from is relative to end of file */
            from += size;
          }
          if(from >= size) {
            failf(data, "Offset (%"
                  FORMAT_OFF_T ") was beyond file size (%" FORMAT_OFF_T ")",
                  from, attrs.filesize);
            return CURLE_BAD_DOWNLOAD_RESUME;
          }
          if(from > to) {
            from = to;
            size = 0;
          }
          else {
            size = to - from + 1;
          }

          SFTP_SEEK(conn->proto.sshc.sftp_handle, from);
        }
        data->req.size = size;
        data->req.maxdownload = size;
        Curl_pgrsSetDownloadSize(data, size);
      }

      /* We can resume if we can seek to the resume position */
      if(data->state.resume_from) {
        if(data->state.resume_from< 0) {
          /* We're supposed to download the last abs(from) bytes */
          if((curl_off_t)attrs.filesize < -data->state.resume_from) {
            failf(data, "Offset (%"
                  FORMAT_OFF_T ") was beyond file size (%" FORMAT_OFF_T ")",
                  data->state.resume_from, attrs.filesize);
            return CURLE_BAD_DOWNLOAD_RESUME;
          }
          /* download from where? */
          data->state.resume_from = attrs.filesize - data->state.resume_from;
        }
        else {
          if((curl_off_t)attrs.filesize < data->state.resume_from) {
            failf(data, "Offset (%" FORMAT_OFF_T
                  ") was beyond file size (%" FORMAT_OFF_T ")",
                  data->state.resume_from, attrs.filesize);
            return CURLE_BAD_DOWNLOAD_RESUME;
          }
        }
        /* Does a completed file need to be seeked and started or closed ? */
        /* Now store the number of bytes we are expected to download */
        data->req.size = attrs.filesize - data->state.resume_from;
        data->req.maxdownload = attrs.filesize - data->state.resume_from;
        Curl_pgrsSetDownloadSize(data,
                                 attrs.filesize - data->state.resume_from);
        SFTP_SEEK(sshc->sftp_handle, data->state.resume_from);
      }
    }
    /* Setup the actual download */
    if(data->req.size == 0) {
      /* no data to transfer */
      result = Curl_setup_transfer(conn, -1, -1, FALSE, NULL, -1, NULL);
      infof(data, "File already completely downloaded\n");
      state(conn, SSH_STOP);
      break;
    }
    else {
      result = Curl_setup_transfer(conn, FIRSTSOCKET, data->req.size,
                                   FALSE, NULL, -1, NULL);

      /* not set by Curl_setup_transfer to preserve keepon bits */
      conn->writesockfd = conn->sockfd;

      /* FIXME: here should be explained why we need it to start the
       * download */
      conn->cselect_bits = CURL_CSELECT_IN;
    }
    if(result) {
      state(conn, SSH_SFTP_CLOSE);
      sshc->actualcode = result;
    }
    else {
      state(conn, SSH_STOP);
    }
    break;

    case SSH_SFTP_CLOSE:
      if(sshc->sftp_handle) {
        rc = libssh2_sftp_close(sshc->sftp_handle);
        if(rc == LIBSSH2_ERROR_EAGAIN) {
          break;
        }
        else if(rc < 0) {
          infof(data, "Failed to close libssh2 file\n");
        }
        sshc->sftp_handle = NULL;
      }
      Curl_safefree(sftp_scp->path);
      sftp_scp->path = NULL;

      DEBUGF(infof(data, "SFTP DONE done\n"));
#if 0 /* PREV */
      state(conn, SSH_SFTP_SHUTDOWN);
#endif
      state(conn, SSH_STOP);
      result = sshc->actualcode;
      break;

    case SSH_SFTP_SHUTDOWN:
      /* during times we get here due to a broken transfer and then the
         sftp_handle might not have been taken down so make sure that is done
         before we proceed */

      if(sshc->sftp_handle) {
        rc = libssh2_sftp_close(sshc->sftp_handle);
        if(rc == LIBSSH2_ERROR_EAGAIN) {
          break;
        }
        else if(rc < 0) {
          infof(data, "Failed to close libssh2 file\n");
        }
        sshc->sftp_handle = NULL;
      }
      if(sshc->sftp_session) {
        rc = libssh2_sftp_shutdown(sshc->sftp_session);
        if(rc == LIBSSH2_ERROR_EAGAIN) {
          break;
        }
        else if(rc < 0) {
          infof(data, "Failed to stop libssh2 sftp subsystem\n");
        }
        sshc->sftp_session = NULL;
      }

      Curl_safefree(sshc->homedir);
      sshc->homedir = NULL;

      state(conn, SSH_SESSION_DISCONNECT);
      break;

    case SSH_SCP_TRANS_INIT:
      result = ssh_getworkingpath(conn, sshc->homedir, &sftp_scp->path);
      if(result) {
        sshc->actualcode = result;
        state(conn, SSH_STOP);
        break;
      }

      if(data->set.upload) {
        if(data->set.infilesize < 0) {
          failf(data, "SCP requires a known file size for upload");
          sshc->actualcode = CURLE_UPLOAD_FAILED;
          state(conn, SSH_SCP_CHANNEL_FREE);
          break;
        }
        state(conn, SSH_SCP_UPLOAD_INIT);
      }
      else {
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
      sshc->ssh_channel =
        libssh2_scp_send_ex(sshc->ssh_session, sftp_scp->path,
                            (int)(data->set.new_file_perms),
                            (size_t)data->set.infilesize, 0, 0);
      if(!sshc->ssh_channel) {
        if(libssh2_session_last_errno(sshc->ssh_session) ==
           LIBSSH2_ERROR_EAGAIN) {
          rc = LIBSSH2_ERROR_EAGAIN;
          break;
        }
        else {
          int ssh_err;
          char *err_msg;

          ssh_err = (int)(libssh2_session_last_error(sshc->ssh_session,
                                                     &err_msg, NULL, 0));
          failf(conn->data, "%s", err_msg);
          state(conn, SSH_SCP_CHANNEL_FREE);
          sshc->actualcode = libssh2_session_error_to_CURLE(ssh_err);
          break;
        }
      }

      /* upload data */
      result = Curl_setup_transfer(conn, -1, data->req.size, FALSE, NULL,
                                   FIRSTSOCKET, NULL);

      /* not set by Curl_setup_transfer to preserve keepon bits */
      conn->sockfd = conn->writesockfd;

      if(result) {
        state(conn, SSH_SCP_CHANNEL_FREE);
        sshc->actualcode = result;
      }
      else {
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

      /* clear the struct scp recv will fill in */
      memset(&sb, 0, sizeof(struct stat));

      /* get a fresh new channel from the ssh layer */
      sshc->ssh_channel = libssh2_scp_recv(sshc->ssh_session,
                                           sftp_scp->path, &sb);
      if(!sshc->ssh_channel) {
        if(libssh2_session_last_errno(sshc->ssh_session) ==
           LIBSSH2_ERROR_EAGAIN) {
          rc = LIBSSH2_ERROR_EAGAIN;
          break;
        }
        else {
          int ssh_err;
          char *err_msg;

          ssh_err = (int)(libssh2_session_last_error(sshc->ssh_session,
                                                     &err_msg, NULL, 0));
          failf(conn->data, "%s", err_msg);
          state(conn, SSH_SCP_CHANNEL_FREE);
          sshc->actualcode = libssh2_session_error_to_CURLE(ssh_err);
          break;
        }
      }

      /* download data */
      bytecount = (curl_off_t)sb.st_size;
      data->req.maxdownload =  (curl_off_t)sb.st_size;
      result = Curl_setup_transfer(conn, FIRSTSOCKET,
                                   bytecount, FALSE, NULL, -1, NULL);

      /* not set by Curl_setup_transfer to preserve keepon bits */
      conn->writesockfd = conn->sockfd;

      /* FIXME: here should be explained why we need it to start the
       * download */
      conn->cselect_bits = CURL_CSELECT_IN;

      if(result) {
        state(conn, SSH_SCP_CHANNEL_FREE);
        sshc->actualcode = result;
      }
      else
        state(conn, SSH_STOP);
    }
    break;

    case SSH_SCP_DONE:
      if(data->set.upload)
        state(conn, SSH_SCP_SEND_EOF);
      else
        state(conn, SSH_SCP_CHANNEL_FREE);
      break;

    case SSH_SCP_SEND_EOF:
      if(sshc->ssh_channel) {
        rc = libssh2_channel_send_eof(sshc->ssh_channel);
        if(rc == LIBSSH2_ERROR_EAGAIN) {
          break;
        }
        else if(rc) {
          infof(data, "Failed to send libssh2 channel EOF\n");
        }
      }
      state(conn, SSH_SCP_WAIT_EOF);
      break;

    case SSH_SCP_WAIT_EOF:
      if(sshc->ssh_channel) {
        rc = libssh2_channel_wait_eof(sshc->ssh_channel);
        if(rc == LIBSSH2_ERROR_EAGAIN) {
          break;
        }
        else if(rc) {
          infof(data, "Failed to get channel EOF: %d\n", rc);
        }
      }
      state(conn, SSH_SCP_WAIT_CLOSE);
      break;

    case SSH_SCP_WAIT_CLOSE:
      if(sshc->ssh_channel) {
        rc = libssh2_channel_wait_closed(sshc->ssh_channel);
        if(rc == LIBSSH2_ERROR_EAGAIN) {
          break;
        }
        else if(rc) {
          infof(data, "Channel failed to close: %d\n", rc);
        }
      }
      state(conn, SSH_SCP_CHANNEL_FREE);
      break;

    case SSH_SCP_CHANNEL_FREE:
      if(sshc->ssh_channel) {
        rc = libssh2_channel_free(sshc->ssh_channel);
        if(rc == LIBSSH2_ERROR_EAGAIN) {
          break;
        }
        else if(rc < 0) {
          infof(data, "Failed to free libssh2 scp subsystem\n");
        }
        sshc->ssh_channel = NULL;
      }
      DEBUGF(infof(data, "SCP DONE phase complete\n"));
#if 0 /* PREV */
      state(conn, SSH_SESSION_DISCONNECT);
#endif
      state(conn, SSH_STOP);
      result = sshc->actualcode;
      break;

    case SSH_SESSION_DISCONNECT:
      /* during weird times when we've been prematurely aborted, the channel
         is still alive when we reach this state and we MUST kill the channel
         properly first */
      if(sshc->ssh_channel) {
        rc = libssh2_channel_free(sshc->ssh_channel);
        if(rc == LIBSSH2_ERROR_EAGAIN) {
          break;
        }
        else if(rc < 0) {
          infof(data, "Failed to free libssh2 scp subsystem\n");
        }
        sshc->ssh_channel = NULL;
      }

      if(sshc->ssh_session) {
        rc = libssh2_session_disconnect(sshc->ssh_session, "Shutdown");
        if(rc == LIBSSH2_ERROR_EAGAIN) {
          break;
        }
        else if(rc < 0) {
          infof(data, "Failed to disconnect libssh2 session\n");
        }
      }

      Curl_safefree(sshc->homedir);
      sshc->homedir = NULL;

      state(conn, SSH_SESSION_FREE);
      break;

    case SSH_SESSION_FREE:
#ifdef HAVE_LIBSSH2_KNOWNHOST_API
      if(sshc->kh) {
        libssh2_knownhost_free(sshc->kh);
        sshc->kh = NULL;
      }
#endif

      if(sshc->ssh_session) {
        rc = libssh2_session_free(sshc->ssh_session);
        if(rc == LIBSSH2_ERROR_EAGAIN) {
          break;
        }
        else if(rc < 0) {
          infof(data, "Failed to free libssh2 session\n");
        }
        sshc->ssh_session = NULL;
      }
      conn->bits.close = TRUE;
      sshc->nextstate = SSH_NO_STATE;
      state(conn, SSH_STOP);
      result = sshc->actualcode;
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

  if(rc == LIBSSH2_ERROR_EAGAIN) {
    /* we would block, we need to wait for the socket to be ready (in the
       right direction too)! */
    *block = TRUE;
  }

  return result;
}

/* called by the multi interface to figure out what socket(s) to wait for and
   for what actions in the DO_DONE, PERFORM and WAITPERFORM states */
static int ssh_perform_getsock(const struct connectdata *conn,
                               curl_socket_t *sock, /* points to numsocks
                                                       number of sockets */
                               int numsocks)
{
#ifdef HAVE_LIBSSH2_SESSION_BLOCK_DIRECTION
  int bitmap = GETSOCK_BLANK;
  (void)numsocks;

  sock[0] = conn->sock[FIRSTSOCKET];

  if(conn->waitfor & KEEP_RECV)
    bitmap |= GETSOCK_READSOCK(FIRSTSOCKET);

  if(conn->waitfor & KEEP_SEND)
    bitmap |= GETSOCK_WRITESOCK(FIRSTSOCKET);

  return bitmap;
#else
  /* if we don't know the direction we can use the generic *_getsock()
     function even for the protocol_connect and doing states */
  return Curl_single_getsock(conn, sock, numsocks);
#endif
}

/* Generic function called by the multi interface to figure out what socket(s)
   to wait for and for what actions during the DOING and PROTOCONNECT states*/
static int ssh_getsock(struct connectdata *conn,
                       curl_socket_t *sock, /* points to numsocks number
                                               of sockets */
                       int numsocks)
{
#ifndef HAVE_LIBSSH2_SESSION_BLOCK_DIRECTION
  (void)conn;
  (void)sock;
  (void)numsocks;
  /* if we don't know any direction we can just play along as we used to and
     not provide any sensible info */
  return GETSOCK_BLANK;
#else
  /* if we know the direction we can use the generic *_getsock() function even
     for the protocol_connect and doing states */
  return ssh_perform_getsock(conn, sock, numsocks);
#endif
}

#ifdef HAVE_LIBSSH2_SESSION_BLOCK_DIRECTION
/*
 * When one of the libssh2 functions has returned LIBSSH2_ERROR_EAGAIN this
 * function is used to figure out in what direction and stores this info so
 * that the multi interface can take advantage of it. Make sure to call this
 * function in all cases so that when it _doesn't_ return EAGAIN we can
 * restore the default wait bits.
 */
static void ssh_block2waitfor(struct connectdata *conn, bool block)
{
  struct ssh_conn *sshc = &conn->proto.sshc;
  int dir;
  if(!block)
    conn->waitfor = 0;
  else if((dir = libssh2_session_block_directions(sshc->ssh_session))) {
    /* translate the libssh2 define bits into our own bit defines */
    conn->waitfor = ((dir&LIBSSH2_SESSION_BLOCK_INBOUND)?KEEP_RECV:0) |
      ((dir&LIBSSH2_SESSION_BLOCK_OUTBOUND)?KEEP_SEND:0);
  }
  else
    /* It didn't block or libssh2 didn't reveal in which direction, put back
       the original set */
    conn->waitfor = sshc->orig_waitfor;
}
#else
  /* no libssh2 directional support so we simply don't know */
#define ssh_block2waitfor(x,y)
#endif

/* called repeatedly until done from multi.c */
static CURLcode ssh_multi_statemach(struct connectdata *conn, bool *done)
{
  struct ssh_conn *sshc = &conn->proto.sshc;
  CURLcode result = CURLE_OK;
  bool block; /* we store the status and use that to provide a ssh_getsock()
                 implementation */

  result = ssh_statemach_act(conn, &block);
  *done = (bool)(sshc->state == SSH_STOP);
  ssh_block2waitfor(conn, block);

  return result;
}

static CURLcode ssh_easy_statemach(struct connectdata *conn)
{
  struct ssh_conn *sshc = &conn->proto.sshc;
  CURLcode result = CURLE_OK;

  while((sshc->state != SSH_STOP) && !result) {
    bool block;
    result = ssh_statemach_act(conn, &block);

#ifdef HAVE_LIBSSH2_SESSION_BLOCK_DIRECTION
    if((CURLE_OK == result) && block) {
      int dir = libssh2_session_block_directions(sshc->ssh_session);
      curl_socket_t sock = conn->sock[FIRSTSOCKET];
      curl_socket_t fd_read = CURL_SOCKET_BAD;
      curl_socket_t fd_write = CURL_SOCKET_BAD;
      if (LIBSSH2_SESSION_BLOCK_INBOUND & dir) {
        fd_read = sock;
      }
      if (LIBSSH2_SESSION_BLOCK_OUTBOUND & dir) {
        fd_write = sock;
      }
      /* wait for the socket to become ready */
      Curl_socket_ready(fd_read, fd_write, 1000); /* ignore result */
    }
#endif

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
  struct ssh_conn *sshc = &conn->proto.sshc;

  sshc->actualcode = CURLE_OK; /* reset error code */
  sshc->secondCreateDirs =0;   /* reset the create dir attempt state
                                  variable */

  if(data->state.proto.ssh)
    return CURLE_OK;

  ssh = calloc(1, sizeof(struct SSHPROTO));
  if(!ssh)
    return CURLE_OUT_OF_MEMORY;

  data->state.proto.ssh = ssh;

  return CURLE_OK;
}

/*
 * Curl_ssh_connect() gets called from Curl_protocol_connect() to allow us to
 * do protocol-specific actions at connect-time.
 */
static CURLcode ssh_connect(struct connectdata *conn, bool *done)
{
#ifdef CURL_LIBSSH2_DEBUG
  curl_socket_t sock;
#endif
  struct ssh_conn *ssh;
  CURLcode result;
  struct SessionHandle *data = conn->data;

  /* We default to persistent connections. We set this already in this connect
     function to make the re-use checks properly be able to check this bit. */
  conn->bits.close = FALSE;

  /* If there already is a protocol-specific struct allocated for this
     sessionhandle, deal with it */
  Curl_reset_reqproto(conn);

  result = ssh_init(conn);
  if(result)
    return result;

  ssh = &conn->proto.sshc;

#ifdef CURL_LIBSSH2_DEBUG
  if(conn->user) {
    infof(data, "User: %s\n", conn->user);
  }
  if(conn->passwd) {
    infof(data, "Password: %s\n", conn->passwd);
  }
  sock = conn->sock[FIRSTSOCKET];
#endif /* CURL_LIBSSH2_DEBUG */

  ssh->ssh_session = libssh2_session_init_ex(libssh2_malloc, libssh2_free,
                                             libssh2_realloc, conn);
  if(ssh->ssh_session == NULL) {
    failf(data, "Failure initialising ssh session");
    return CURLE_FAILED_INIT;
  }

#ifdef HAVE_LIBSSH2_KNOWNHOST_API
  if(data->set.str[STRING_SSH_KNOWNHOSTS]) {
    int rc;
    ssh->kh = libssh2_knownhost_init(ssh->ssh_session);
    if(!ssh->kh) {
      /* eeek. TODO: free the ssh_session! */
      return CURLE_FAILED_INIT;
    }

    /* read all known hosts from there */
    rc = libssh2_knownhost_readfile(ssh->kh,
                                    data->set.str[STRING_SSH_KNOWNHOSTS],
                                    LIBSSH2_KNOWNHOST_FILE_OPENSSH);
    if(rc) {
      infof(data, "Failed to read known hosts from %s\n",
            data->set.str[STRING_SSH_KNOWNHOSTS]);
    }
  }
#endif /* HAVE_LIBSSH2_KNOWNHOST_API */

#ifdef CURL_LIBSSH2_DEBUG
  libssh2_trace(ssh->ssh_session, ~0);
  infof(data, "SSH socket: %d\n", (int)sock);
#endif /* CURL_LIBSSH2_DEBUG */

  state(conn, SSH_S_STARTUP);

  if(data->state.used_interface == Curl_if_multi)
    result = ssh_multi_statemach(conn, done);
  else {
    result = ssh_easy_statemach(conn);
    if(!result)
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
  if(conn->data->state.used_interface == Curl_if_multi) {
    result = ssh_multi_statemach(conn, dophase_done);
  }
  else {
    result = ssh_easy_statemach(conn);
    *dophase_done = TRUE; /* with the easy interface we are done here */
  }
  *connected = conn->bits.tcpconnect;

  if(*dophase_done) {
    DEBUGF(infof(conn->data, "DO phase is complete\n"));
  }

  return result;
}

/* called from multi.c while DOing */
static CURLcode scp_doing(struct connectdata *conn,
                               bool *dophase_done)
{
  CURLcode result;
  result = ssh_multi_statemach(conn, dophase_done);

  if(*dophase_done) {
    DEBUGF(infof(conn->data, "DO phase is complete\n"));
  }
  return result;
}

/*
 * The DO function is generic for both protocols. There was previously two
 * separate ones but this way means less duplicated code.
 */

static CURLcode ssh_do(struct connectdata *conn, bool *done)
{
  CURLcode res;
  bool connected = 0;
  struct SessionHandle *data = conn->data;

  *done = FALSE; /* default to false */

  /*
    Since connections can be re-used between SessionHandles, this might be a
    connection already existing but on a fresh SessionHandle struct so we must
    make sure we have a good 'struct SSHPROTO' to play with. For new
    connections, the struct SSHPROTO is allocated and setup in the
    ssh_connect() function.
  */
  Curl_reset_reqproto(conn);
  res = ssh_init(conn);
  if(res)
    return res;

  data->req.size = -1; /* make sure this is unknown at this point */

  Curl_pgrsSetUploadCounter(data, 0);
  Curl_pgrsSetDownloadCounter(data, 0);
  Curl_pgrsSetUploadSize(data, 0);
  Curl_pgrsSetDownloadSize(data, 0);

  if(conn->protocol & PROT_SCP)
    res = scp_perform(conn, &connected,  done);
  else
    res = sftp_perform(conn, &connected,  done);

  return res;
}

/* BLOCKING, but the function is using the state machine so the only reason
   this is still blocking is that the multi interface code has no support for
   disconnecting operations that takes a while */
static CURLcode scp_disconnect(struct connectdata *conn)
{
  CURLcode result = CURLE_OK;
  struct ssh_conn *ssh = &conn->proto.sshc;

  Curl_safefree(conn->data->state.proto.ssh);
  conn->data->state.proto.ssh = NULL;

  if(ssh->ssh_session) {
    /* only if there's a session still around to use! */

    state(conn, SSH_SESSION_DISCONNECT);

    result = ssh_easy_statemach(conn);
  }

  return result;
}

/* generic done function for both SCP and SFTP called from their specific
   done functions */
static CURLcode ssh_done(struct connectdata *conn, CURLcode status)
{
  CURLcode result = CURLE_OK;
  struct SSHPROTO *sftp_scp = conn->data->state.proto.ssh;

  if(status == CURLE_OK) {
    /* run the state-machine

       TODO: when the multi interface is used, this _really_ should be using
       the ssh_multi_statemach function but we have no general support for
       non-blocking DONE operations, not in the multi state machine and with
       Curl_done() invokes on several places in the code!
    */
    result = ssh_easy_statemach(conn);
  }
  else
    result = status;

  Curl_safefree(sftp_scp->path);
  sftp_scp->path = NULL;
  Curl_pgrsDone(conn);

  conn->data->req.keepon = 0; /* clear all bits */
  return result;
}


static CURLcode scp_done(struct connectdata *conn, CURLcode status,
                         bool premature)
{
  (void)premature; /* not used */

  if(status == CURLE_OK)
    state(conn, SSH_SCP_DONE);

  return ssh_done(conn, status);

}

/* return number of received (decrypted) bytes */
ssize_t Curl_scp_send(struct connectdata *conn, int sockindex,
                      const void *mem, size_t len)
{
  ssize_t nwrite;
  (void)sockindex; /* we only support SCP on the fixed known primary socket */

  /* libssh2_channel_write() returns int! */
  nwrite = (ssize_t)
    libssh2_channel_write(conn->proto.sshc.ssh_channel, mem, len);

  ssh_block2waitfor(conn, (nwrite == LIBSSH2_ERROR_EAGAIN)?TRUE:FALSE);

  if(nwrite == LIBSSH2_ERROR_EAGAIN)
    return 0;

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

  /* libssh2_channel_read() returns int */
  nread = (ssize_t)
    libssh2_channel_read(conn->proto.sshc.ssh_channel, mem, len);

  ssh_block2waitfor(conn, (nread == LIBSSH2_ERROR_EAGAIN)?TRUE:FALSE);

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
  if(conn->data->state.used_interface == Curl_if_multi) {
    result = ssh_multi_statemach(conn, dophase_done);
  }
  else {
    result = ssh_easy_statemach(conn);
    *dophase_done = TRUE; /* with the easy interface we are done here */
  }
  *connected = conn->bits.tcpconnect;

  if(*dophase_done) {
    DEBUGF(infof(conn->data, "DO phase is complete\n"));
  }

  return result;
}

/* called from multi.c while DOing */
static CURLcode sftp_doing(struct connectdata *conn,
                           bool *dophase_done)
{
  CURLcode result;
  result = ssh_multi_statemach(conn, dophase_done);

  if(*dophase_done) {
    DEBUGF(infof(conn->data, "DO phase is complete\n"));
  }
  return result;
}

/* BLOCKING, but the function is using the state machine so the only reason
   this is still blocking is that the multi interface code has no support for
   disconnecting operations that takes a while */
static CURLcode sftp_disconnect(struct connectdata *conn)
{
  CURLcode result = CURLE_OK;

  DEBUGF(infof(conn->data, "SSH DISCONNECT starts now\n"));

  Curl_safefree(conn->data->state.proto.ssh);
  conn->data->state.proto.ssh = NULL;

  if(conn->proto.sshc.ssh_session) {
    /* only if there's a session still around to use! */
    state(conn, SSH_SFTP_SHUTDOWN);
    result = ssh_easy_statemach(conn);
  }

  DEBUGF(infof(conn->data, "SSH DISCONNECT is done\n"));

  return result;

}

static CURLcode sftp_done(struct connectdata *conn, CURLcode status,
                               bool premature)
{
  struct ssh_conn *sshc = &conn->proto.sshc;

  if(status == CURLE_OK) {
    /* Before we shut down, see if there are any post-quote commands to
       send: */
    if(!status && !premature && conn->data->set.postquote) {
      sshc->nextstate = SSH_SFTP_CLOSE;
      state(conn, SSH_SFTP_POSTQUOTE_INIT);
    }
    else
      state(conn, SSH_SFTP_CLOSE);
  }
  return ssh_done(conn, status);
}

/* return number of sent bytes */
ssize_t Curl_sftp_send(struct connectdata *conn, int sockindex,
                       const void *mem, size_t len)
{
  ssize_t nwrite;   /* libssh2_sftp_write() used to return size_t in 0.14
                       but is changed to ssize_t in 0.15. These days we don't
                       support libssh2 0.15*/
  (void)sockindex;

  nwrite = libssh2_sftp_write(conn->proto.sshc.sftp_handle, mem, len);

  ssh_block2waitfor(conn, (nwrite == LIBSSH2_ERROR_EAGAIN)?TRUE:FALSE);

  if(nwrite == LIBSSH2_ERROR_EAGAIN)
    return 0;

  return nwrite;
}

/*
 * Return number of received (decrypted) bytes
 */
ssize_t Curl_sftp_recv(struct connectdata *conn, int sockindex,
                       char *mem, size_t len)
{
  ssize_t nread;
  (void)sockindex;

  nread = libssh2_sftp_read(conn->proto.sshc.sftp_handle, mem, len);

  ssh_block2waitfor(conn, (nread == LIBSSH2_ERROR_EAGAIN)?TRUE:FALSE);

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
static CURLcode
get_pathname(const char **cpp, char **path)
{
  const char *cp = *cpp, *end;
  char quot;
  unsigned int i, j;
  static const char WHITESPACE[] = " \t\r\n";

  cp += strspn(cp, WHITESPACE);
  if(!*cp) {
    *cpp = cp;
    *path = NULL;
    return CURLE_QUOTE_ERROR;
  }

  *path = malloc(strlen(cp) + 1);
  if(*path == NULL)
    return CURLE_OUT_OF_MEMORY;

  /* Check for quoted filenames */
  if(*cp == '\"' || *cp == '\'') {
    quot = *cp++;

    /* Search for terminating quote, unescape some chars */
    for (i = j = 0; i <= strlen(cp); i++) {
      if(cp[i] == quot) {  /* Found quote */
        i++;
        (*path)[j] = '\0';
        break;
      }
      if(cp[i] == '\0') {  /* End of string */
        /*error("Unterminated quote");*/
        goto fail;
      }
      if(cp[i] == '\\') {  /* Escaped characters */
        i++;
        if(cp[i] != '\'' && cp[i] != '\"' &&
            cp[i] != '\\') {
          /*error("Bad escaped character '\\%c'",
              cp[i]);*/
          goto fail;
        }
      }
      (*path)[j++] = cp[i];
    }

    if(j == 0) {
      /*error("Empty quotes");*/
      goto fail;
    }
    *cpp = cp + i + strspn(cp + i, WHITESPACE);
  }
  else {
    /* Read to end of filename */
    end = strpbrk(cp, WHITESPACE);
    if(end == NULL)
      end = strchr(cp, '\0');
    *cpp = end + strspn(end, WHITESPACE);

    memcpy(*path, cp, end - cp);
    (*path)[end - cp] = '\0';
  }
  return CURLE_OK;

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
