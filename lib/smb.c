/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
 * Copyright (C) Bill Nagel <wnagel@tycoint.com>, Exacq Technologies
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

#include "curl_setup.h"

#if !defined(CURL_DISABLE_SMB) && defined(USE_CURL_NTLM_CORE)

#include "smb.h"
#include "urldata.h"
#include "url.h"
#include "sendf.h"
#include "multiif.h"
#include "cfilters.h"
#include "connect.h"
#include "progress.h"
#include "transfer.h"
#include "vtls/vtls.h"
#include "curl_ntlm_core.h"
#include "escape.h"
#include "curl_endian.h"

/* The last 3 #include files should be in this order */
#include "curl_printf.h"
#include "curl_memory.h"
#include "memdebug.h"


/* meta key for storing protocol meta at easy handle */
#define CURL_META_SMB_EASY   "meta:proto:smb:easy"
/* meta key for storing protocol meta at connection */
#define CURL_META_SMB_CONN   "meta:proto:smb:conn"

enum smb_conn_state {
  SMB_NOT_CONNECTED = 0,
  SMB_CONNECTING,
  SMB_NEGOTIATE,
  SMB_SETUP,
  SMB_CONNECTED
};

/* SMB connection data, kept at connection */
struct smb_conn {
  enum smb_conn_state state;
  char *user;
  char *domain;
  char *share;
  unsigned char challenge[8];
  unsigned int session_key;
  unsigned short uid;
  char *recv_buf;
  char *send_buf;
  size_t upload_size;
  size_t send_size;
  size_t sent;
  size_t got;
};

/* SMB request state */
enum smb_req_state {
  SMB_REQUESTING,
  SMB_TREE_CONNECT,
  SMB_OPEN,
  SMB_DOWNLOAD,
  SMB_UPLOAD,
  SMB_CLOSE,
  SMB_TREE_DISCONNECT,
  SMB_DONE
};

/* SMB request data, kept at easy handle */
struct smb_request {
  enum smb_req_state state;
  char *path;
  unsigned short tid; /* Even if we connect to the same tree as another */
  unsigned short fid; /* request, the tid will be different */
  CURLcode result;
};

/*
 * Definitions for SMB protocol data structures
 */
#if defined(_MSC_VER) || defined(__ILEC400__)
#  define PACK
#  pragma pack(push)
#  pragma pack(1)
#elif defined(__GNUC__)
#  define PACK __attribute__((packed))
#else
#  define PACK
#endif

#define SMB_COM_CLOSE                 0x04
#define SMB_COM_READ_ANDX             0x2e
#define SMB_COM_WRITE_ANDX            0x2f
#define SMB_COM_TREE_DISCONNECT       0x71
#define SMB_COM_NEGOTIATE             0x72
#define SMB_COM_SETUP_ANDX            0x73
#define SMB_COM_TREE_CONNECT_ANDX     0x75
#define SMB_COM_NT_CREATE_ANDX        0xa2
#define SMB_COM_NO_ANDX_COMMAND       0xff

#define SMB_WC_CLOSE                  0x03
#define SMB_WC_READ_ANDX              0x0c
#define SMB_WC_WRITE_ANDX             0x0e
#define SMB_WC_SETUP_ANDX             0x0d
#define SMB_WC_TREE_CONNECT_ANDX      0x04
#define SMB_WC_NT_CREATE_ANDX         0x18

#define SMB_FLAGS_CANONICAL_PATHNAMES 0x10
#define SMB_FLAGS_CASELESS_PATHNAMES  0x08
/* #define SMB_FLAGS2_UNICODE_STRINGS    0x8000 */
#define SMB_FLAGS2_IS_LONG_NAME       0x0040
#define SMB_FLAGS2_KNOWS_LONG_NAME    0x0001

#define SMB_CAP_LARGE_FILES           0x08
#define SMB_GENERIC_WRITE             0x40000000
#define SMB_GENERIC_READ              0x80000000
#define SMB_FILE_SHARE_ALL            0x07
#define SMB_FILE_OPEN                 0x01
#define SMB_FILE_OVERWRITE_IF         0x05

#define SMB_ERR_NOACCESS              0x00050001

struct smb_header {
  unsigned char nbt_type;
  unsigned char nbt_flags;
  unsigned short nbt_length;
  unsigned char magic[4];
  unsigned char command;
  unsigned int status;
  unsigned char flags;
  unsigned short flags2;
  unsigned short pid_high;
  unsigned char signature[8];
  unsigned short pad;
  unsigned short tid;
  unsigned short pid;
  unsigned short uid;
  unsigned short mid;
} PACK;

struct smb_negotiate_response {
  struct smb_header h;
  unsigned char word_count;
  unsigned short dialect_index;
  unsigned char security_mode;
  unsigned short max_mpx_count;
  unsigned short max_number_vcs;
  unsigned int max_buffer_size;
  unsigned int max_raw_size;
  unsigned int session_key;
  unsigned int capabilities;
  unsigned int system_time_low;
  unsigned int system_time_high;
  unsigned short server_time_zone;
  unsigned char encryption_key_length;
  unsigned short byte_count;
  char bytes[1];
} PACK;

struct andx {
  unsigned char command;
  unsigned char pad;
  unsigned short offset;
} PACK;

struct smb_setup {
  unsigned char word_count;
  struct andx andx;
  unsigned short max_buffer_size;
  unsigned short max_mpx_count;
  unsigned short vc_number;
  unsigned int session_key;
  unsigned short lengths[2];
  unsigned int pad;
  unsigned int capabilities;
  unsigned short byte_count;
  char bytes[1024];
} PACK;

struct smb_tree_connect {
  unsigned char word_count;
  struct andx andx;
  unsigned short flags;
  unsigned short pw_len;
  unsigned short byte_count;
  char bytes[1024];
} PACK;

struct smb_nt_create {
  unsigned char word_count;
  struct andx andx;
  unsigned char pad;
  unsigned short name_length;
  unsigned int flags;
  unsigned int root_fid;
  unsigned int access;
  curl_off_t allocation_size;
  unsigned int ext_file_attributes;
  unsigned int share_access;
  unsigned int create_disposition;
  unsigned int create_options;
  unsigned int impersonation_level;
  unsigned char security_flags;
  unsigned short byte_count;
  char bytes[1024];
} PACK;

struct smb_nt_create_response {
  struct smb_header h;
  unsigned char word_count;
  struct andx andx;
  unsigned char op_lock_level;
  unsigned short fid;
  unsigned int create_disposition;

  curl_off_t create_time;
  curl_off_t last_access_time;
  curl_off_t last_write_time;
  curl_off_t last_change_time;
  unsigned int ext_file_attributes;
  curl_off_t allocation_size;
  curl_off_t end_of_file;
} PACK;

struct smb_read {
  unsigned char word_count;
  struct andx andx;
  unsigned short fid;
  unsigned int offset;
  unsigned short max_bytes;
  unsigned short min_bytes;
  unsigned int timeout;
  unsigned short remaining;
  unsigned int offset_high;
  unsigned short byte_count;
} PACK;

struct smb_write {
  struct smb_header h;
  unsigned char word_count;
  struct andx andx;
  unsigned short fid;
  unsigned int offset;
  unsigned int timeout;
  unsigned short write_mode;
  unsigned short remaining;
  unsigned short pad;
  unsigned short data_length;
  unsigned short data_offset;
  unsigned int offset_high;
  unsigned short byte_count;
  unsigned char pad2;
} PACK;

struct smb_close {
  unsigned char word_count;
  unsigned short fid;
  unsigned int last_mtime;
  unsigned short byte_count;
} PACK;

struct smb_tree_disconnect {
  unsigned char word_count;
  unsigned short byte_count;
} PACK;

#if defined(_MSC_VER) || defined(__ILEC400__)
#  pragma pack(pop)
#endif

/* Local API functions */
static CURLcode smb_setup_connection(struct Curl_easy *data,
                                     struct connectdata *conn);
static CURLcode smb_connect(struct Curl_easy *data, bool *done);
static CURLcode smb_connection_state(struct Curl_easy *data, bool *done);
static CURLcode smb_do(struct Curl_easy *data, bool *done);
static CURLcode smb_request_state(struct Curl_easy *data, bool *done);
static int smb_getsock(struct Curl_easy *data, struct connectdata *conn,
                       curl_socket_t *socks);
static CURLcode smb_parse_url_path(struct Curl_easy *data,
                                   struct smb_conn *smbc,
                                   struct smb_request *req);

/*
 * SMB handler interface
 */
const struct Curl_handler Curl_handler_smb = {
  "smb",                                /* scheme */
  smb_setup_connection,                 /* setup_connection */
  smb_do,                               /* do_it */
  ZERO_NULL,                            /* done */
  ZERO_NULL,                            /* do_more */
  smb_connect,                          /* connect_it */
  smb_connection_state,                 /* connecting */
  smb_request_state,                    /* doing */
  smb_getsock,                          /* proto_getsock */
  smb_getsock,                          /* doing_getsock */
  ZERO_NULL,                            /* domore_getsock */
  ZERO_NULL,                            /* perform_getsock */
  ZERO_NULL,                            /* disconnect */
  ZERO_NULL,                            /* write_resp */
  ZERO_NULL,                            /* write_resp_hd */
  ZERO_NULL,                            /* connection_check */
  ZERO_NULL,                            /* attach connection */
  ZERO_NULL,                            /* follow */
  PORT_SMB,                             /* defport */
  CURLPROTO_SMB,                        /* protocol */
  CURLPROTO_SMB,                        /* family */
  PROTOPT_NONE                          /* flags */
};

#ifdef USE_SSL
/*
 * SMBS handler interface
 */
const struct Curl_handler Curl_handler_smbs = {
  "smbs",                               /* scheme */
  smb_setup_connection,                 /* setup_connection */
  smb_do,                               /* do_it */
  ZERO_NULL,                            /* done */
  ZERO_NULL,                            /* do_more */
  smb_connect,                          /* connect_it */
  smb_connection_state,                 /* connecting */
  smb_request_state,                    /* doing */
  smb_getsock,                          /* proto_getsock */
  smb_getsock,                          /* doing_getsock */
  ZERO_NULL,                            /* domore_getsock */
  ZERO_NULL,                            /* perform_getsock */
  ZERO_NULL,                            /* disconnect */
  ZERO_NULL,                            /* write_resp */
  ZERO_NULL,                            /* write_resp_hd */
  ZERO_NULL,                            /* connection_check */
  ZERO_NULL,                            /* attach connection */
  ZERO_NULL,                            /* follow */
  PORT_SMBS,                            /* defport */
  CURLPROTO_SMBS,                       /* protocol */
  CURLPROTO_SMB,                        /* family */
  PROTOPT_SSL                           /* flags */
};
#endif

#define MAX_PAYLOAD_SIZE  0x8000
#define MAX_MESSAGE_SIZE  (MAX_PAYLOAD_SIZE + 0x1000)
#define CLIENTNAME        "curl"
#define SERVICENAME       "?????"

/* SMB is mostly little endian */
#if (defined(__BYTE_ORDER__) && __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__) || \
  defined(__OS400__)
static unsigned short smb_swap16(unsigned short x)
{
  return (unsigned short) ((x << 8) | ((x >> 8) & 0xff));
}

static unsigned int smb_swap32(unsigned int x)
{
  return (x << 24) | ((x << 8) & 0xff0000) | ((x >> 8) & 0xff00) |
    ((x >> 24) & 0xff);
}

static curl_off_t smb_swap64(curl_off_t x)
{
  return ((curl_off_t) smb_swap32((unsigned int) x) << 32) |
    smb_swap32((unsigned int) (x >> 32));
}

#else
#  define smb_swap16(x) (x)
#  define smb_swap32(x) (x)
#  define smb_swap64(x) (x)
#endif

static void conn_state(struct Curl_easy *data, struct smb_conn *smbc,
                       enum smb_conn_state newstate)
{
#if defined(DEBUGBUILD) && !defined(CURL_DISABLE_VERBOSE_STRINGS)
  /* For debug purposes */
  static const char * const names[] = {
    "SMB_NOT_CONNECTED",
    "SMB_CONNECTING",
    "SMB_NEGOTIATE",
    "SMB_SETUP",
    "SMB_CONNECTED",
    /* LAST */
  };

  if(smbc->state != newstate)
    infof(data, "SMB conn %p state change from %s to %s",
          (void *)smbc, names[smbc->state], names[newstate]);
#endif
  (void)data;
  smbc->state = newstate;
}

static void request_state(struct Curl_easy *data,
                          enum smb_req_state newstate)
{
  struct smb_request *req = Curl_meta_get(data, CURL_META_SMB_EASY);
  if(req) {
#if defined(DEBUGBUILD) && !defined(CURL_DISABLE_VERBOSE_STRINGS)
    /* For debug purposes */
    static const char * const names[] = {
      "SMB_REQUESTING",
      "SMB_TREE_CONNECT",
      "SMB_OPEN",
      "SMB_DOWNLOAD",
      "SMB_UPLOAD",
      "SMB_CLOSE",
      "SMB_TREE_DISCONNECT",
      "SMB_DONE",
      /* LAST */
    };

    if(req->state != newstate)
      infof(data, "SMB request %p state change from %s to %s",
            (void *)req, names[req->state], names[newstate]);
#endif

    req->state = newstate;
  }
}

static void smb_easy_dtor(void *key, size_t klen, void *entry)
{
  struct smb_request *req = entry;
  (void)key;
  (void)klen;
  /* `req->path` points to somewhere in `struct smb_conn` which is
   * kept at the connection meta. If the connection is destroyed first,
   * req->path points to free'd memory. */
  free(req);
}

static void smb_conn_dtor(void *key, size_t klen, void *entry)
{
  struct smb_conn *smbc = entry;
  (void)key;
  (void)klen;
  Curl_safefree(smbc->share);
  Curl_safefree(smbc->domain);
  Curl_safefree(smbc->recv_buf);
  Curl_safefree(smbc->send_buf);
  free(smbc);
}

/* this should setup things in the connection, not in the easy
   handle */
static CURLcode smb_setup_connection(struct Curl_easy *data,
                                     struct connectdata *conn)
{
  struct smb_conn *smbc;
  struct smb_request *req;

  /* Initialize the connection state */
  smbc = calloc(1, sizeof(*smbc));
  if(!smbc ||
     Curl_conn_meta_set(conn, CURL_META_SMB_CONN, smbc, smb_conn_dtor))
    return CURLE_OUT_OF_MEMORY;

  /* Initialize the request state */
  req = calloc(1, sizeof(*req));
  if(!req ||
     Curl_meta_set(data, CURL_META_SMB_EASY, req, smb_easy_dtor))
    return CURLE_OUT_OF_MEMORY;

  /* Parse the URL path */
  return smb_parse_url_path(data, smbc, req);
}

static CURLcode smb_connect(struct Curl_easy *data, bool *done)
{
  struct connectdata *conn = data->conn;
  struct smb_conn *smbc = Curl_conn_meta_get(conn, CURL_META_SMB_CONN);
  char *slash;

  (void) done;
  if(!smbc)
    return CURLE_FAILED_INIT;

  /* Check we have a username and password to authenticate with */
  if(!data->state.aptr.user)
    return CURLE_LOGIN_DENIED;

  /* Initialize the connection state */
  smbc->state = SMB_CONNECTING;
  smbc->recv_buf = malloc(MAX_MESSAGE_SIZE);
  if(!smbc->recv_buf)
    return CURLE_OUT_OF_MEMORY;
  smbc->send_buf = malloc(MAX_MESSAGE_SIZE);
  if(!smbc->send_buf)
    return CURLE_OUT_OF_MEMORY;

  /* Multiple requests are allowed with this connection */
  connkeep(conn, "SMB default");

  /* Parse the username, domain, and password */
  slash = strchr(conn->user, '/');
  if(!slash)
    slash = strchr(conn->user, '\\');

  if(slash) {
    smbc->user = slash + 1;
    smbc->domain = strdup(conn->user);
    if(!smbc->domain)
      return CURLE_OUT_OF_MEMORY;
    smbc->domain[slash - conn->user] = 0;
  }
  else {
    smbc->user = conn->user;
    smbc->domain = strdup(conn->host.name);
    if(!smbc->domain)
      return CURLE_OUT_OF_MEMORY;
  }

  return CURLE_OK;
}

static CURLcode smb_recv_message(struct Curl_easy *data,
                                 struct smb_conn *smbc,
                                 void **msg)
{
  char *buf = smbc->recv_buf;
  ssize_t bytes_read;
  size_t nbt_size;
  size_t msg_size;
  size_t len = MAX_MESSAGE_SIZE - smbc->got;
  CURLcode result;

  result = Curl_xfer_recv(data, buf + smbc->got, len, &bytes_read);
  if(result)
    return result;

  if(!bytes_read)
    return CURLE_OK;

  smbc->got += bytes_read;

  /* Check for a 32-bit nbt header */
  if(smbc->got < sizeof(unsigned int))
    return CURLE_OK;

  nbt_size = Curl_read16_be((const unsigned char *)
                            (buf + sizeof(unsigned short))) +
    sizeof(unsigned int);
  if(smbc->got < nbt_size)
    return CURLE_OK;

  msg_size = sizeof(struct smb_header);
  if(nbt_size >= msg_size + 1) {
    /* Add the word count */
    msg_size += 1 + ((unsigned char) buf[msg_size]) * sizeof(unsigned short);
    if(nbt_size >= msg_size + sizeof(unsigned short)) {
      /* Add the byte count */
      msg_size += sizeof(unsigned short) +
        Curl_read16_le((const unsigned char *)&buf[msg_size]);
      if(nbt_size < msg_size)
        return CURLE_READ_ERROR;
    }
  }

  *msg = buf;

  return CURLE_OK;
}

static void smb_pop_message(struct smb_conn *smbc)
{
  smbc->got = 0;
}

static void smb_format_message(struct smb_conn *smbc,
                               struct smb_request *req,
                               struct smb_header *h,
                               unsigned char cmd, size_t len)
{
  const unsigned int pid = 0xbad71d; /* made up */

  memset(h, 0, sizeof(*h));
  h->nbt_length = htons((unsigned short) (sizeof(*h) - sizeof(unsigned int) +
                                          len));
  memcpy((char *)h->magic, "\xffSMB", 4);
  h->command = cmd;
  h->flags = SMB_FLAGS_CANONICAL_PATHNAMES | SMB_FLAGS_CASELESS_PATHNAMES;
  h->flags2 = smb_swap16(SMB_FLAGS2_IS_LONG_NAME | SMB_FLAGS2_KNOWS_LONG_NAME);
  h->uid = smb_swap16(smbc->uid);
  h->tid = smb_swap16(req->tid);
  h->pid_high = smb_swap16((unsigned short)(pid >> 16));
  h->pid = smb_swap16((unsigned short) pid);
}

static CURLcode smb_send(struct Curl_easy *data, struct smb_conn *smbc,
                         size_t len, size_t upload_size)
{
  size_t bytes_written;
  CURLcode result;

  result = Curl_xfer_send(data, smbc->send_buf, len, FALSE, &bytes_written);
  if(result)
    return result;

  if(bytes_written != len) {
    smbc->send_size = len;
    smbc->sent = bytes_written;
  }

  smbc->upload_size = upload_size;

  return CURLE_OK;
}

static CURLcode smb_flush(struct Curl_easy *data, struct smb_conn *smbc)
{
  size_t bytes_written;
  size_t len = smbc->send_size - smbc->sent;
  CURLcode result;

  if(!smbc->send_size)
    return CURLE_OK;

  result = Curl_xfer_send(data, smbc->send_buf + smbc->sent, len, FALSE,
                          &bytes_written);
  if(result)
    return result;

  if(bytes_written != len)
    smbc->sent += bytes_written;
  else
    smbc->send_size = 0;

  return CURLE_OK;
}

static CURLcode smb_send_message(struct Curl_easy *data,
                                 struct smb_conn *smbc,
                                 struct smb_request *req,
                                 unsigned char cmd,
                                 const void *msg, size_t msg_len)
{
  smb_format_message(smbc, req, (struct smb_header *)smbc->send_buf,
                     cmd, msg_len);
  DEBUGASSERT((sizeof(struct smb_header) + msg_len) <= MAX_MESSAGE_SIZE);
  memcpy(smbc->send_buf + sizeof(struct smb_header), msg, msg_len);

  return smb_send(data, smbc, sizeof(struct smb_header) + msg_len, 0);
}

static CURLcode smb_send_negotiate(struct Curl_easy *data,
                                   struct smb_conn *smbc,
                                   struct smb_request *req)
{
  const char *msg = "\x00\x0c\x00\x02NT LM 0.12";

  return smb_send_message(data, smbc, req, SMB_COM_NEGOTIATE, msg, 15);
}

static CURLcode smb_send_setup(struct Curl_easy *data)
{
  struct connectdata *conn = data->conn;
  struct smb_conn *smbc = Curl_conn_meta_get(conn, CURL_META_SMB_CONN);
  struct smb_request *req = Curl_meta_get(data, CURL_META_SMB_EASY);
  struct smb_setup msg;
  char *p = msg.bytes;
  unsigned char lm_hash[21];
  unsigned char lm[24];
  unsigned char nt_hash[21];
  unsigned char nt[24];
  size_t byte_count;

  if(!smbc || !req)
    return CURLE_FAILED_INIT;

  byte_count = sizeof(lm) + sizeof(nt) +
    strlen(smbc->user) + strlen(smbc->domain) +
    strlen(CURL_OS) + strlen(CLIENTNAME) + 4; /* 4 null chars */
  if(byte_count > sizeof(msg.bytes))
    return CURLE_FILESIZE_EXCEEDED;

  Curl_ntlm_core_mk_lm_hash(conn->passwd, lm_hash);
  Curl_ntlm_core_lm_resp(lm_hash, smbc->challenge, lm);
  Curl_ntlm_core_mk_nt_hash(conn->passwd, nt_hash);
  Curl_ntlm_core_lm_resp(nt_hash, smbc->challenge, nt);

  memset(&msg, 0, sizeof(msg) - sizeof(msg.bytes));
  msg.word_count = SMB_WC_SETUP_ANDX;
  msg.andx.command = SMB_COM_NO_ANDX_COMMAND;
  msg.max_buffer_size = smb_swap16(MAX_MESSAGE_SIZE);
  msg.max_mpx_count = smb_swap16(1);
  msg.vc_number = smb_swap16(1);
  msg.session_key = smb_swap32(smbc->session_key);
  msg.capabilities = smb_swap32(SMB_CAP_LARGE_FILES);
  msg.lengths[0] = smb_swap16(sizeof(lm));
  msg.lengths[1] = smb_swap16(sizeof(nt));
  memcpy(p, lm, sizeof(lm));
  p += sizeof(lm);
  memcpy(p, nt, sizeof(nt));
  p += sizeof(nt);
  p += msnprintf(p, byte_count - sizeof(nt) - sizeof(lm),
                 "%s%c"  /* user */
                 "%s%c"  /* domain */
                 "%s%c"  /* OS */
                 "%s", /* client name */
                 smbc->user, 0, smbc->domain, 0, CURL_OS, 0, CLIENTNAME);
  p++; /* count the final null-termination */
  DEBUGASSERT(byte_count == (size_t)(p - msg.bytes));
  msg.byte_count = smb_swap16((unsigned short)byte_count);

  return smb_send_message(data, smbc, req, SMB_COM_SETUP_ANDX, &msg,
                          sizeof(msg) - sizeof(msg.bytes) + byte_count);
}

static CURLcode smb_send_tree_connect(struct Curl_easy *data,
                                      struct smb_conn *smbc,
                                      struct smb_request *req)
{
  struct smb_tree_connect msg;
  struct connectdata *conn = data->conn;
  char *p = msg.bytes;
  const size_t byte_count = strlen(conn->host.name) + strlen(smbc->share) +
    strlen(SERVICENAME) + 5; /* 2 nulls and 3 backslashes */

  if(byte_count > sizeof(msg.bytes))
    return CURLE_FILESIZE_EXCEEDED;

  memset(&msg, 0, sizeof(msg) - sizeof(msg.bytes));
  msg.word_count = SMB_WC_TREE_CONNECT_ANDX;
  msg.andx.command = SMB_COM_NO_ANDX_COMMAND;
  msg.pw_len = 0;

  p += msnprintf(p, byte_count,
                 "\\\\%s\\"  /* hostname */
                 "%s%c"      /* share */
                 "%s",       /* service */
                 conn->host.name, smbc->share, 0, SERVICENAME);
  p++; /* count the final null-termination */
  DEBUGASSERT(byte_count == (size_t)(p - msg.bytes));
  msg.byte_count = smb_swap16((unsigned short)byte_count);

  return smb_send_message(data, smbc, req, SMB_COM_TREE_CONNECT_ANDX, &msg,
                          sizeof(msg) - sizeof(msg.bytes) + byte_count);
}

static CURLcode smb_send_open(struct Curl_easy *data,
                              struct smb_conn *smbc,
                              struct smb_request *req)
{
  struct smb_nt_create msg;
  const size_t byte_count = strlen(req->path) + 1;

  if(byte_count > sizeof(msg.bytes))
    return CURLE_FILESIZE_EXCEEDED;

  memset(&msg, 0, sizeof(msg) - sizeof(msg.bytes));
  msg.word_count = SMB_WC_NT_CREATE_ANDX;
  msg.andx.command = SMB_COM_NO_ANDX_COMMAND;
  msg.name_length = smb_swap16((unsigned short)(byte_count - 1));
  msg.share_access = smb_swap32(SMB_FILE_SHARE_ALL);
  if(data->state.upload) {
    msg.access = smb_swap32(SMB_GENERIC_READ | SMB_GENERIC_WRITE);
    msg.create_disposition = smb_swap32(SMB_FILE_OVERWRITE_IF);
  }
  else {
    msg.access = smb_swap32(SMB_GENERIC_READ);
    msg.create_disposition = smb_swap32(SMB_FILE_OPEN);
  }
  msg.byte_count = smb_swap16((unsigned short) byte_count);
  strcpy(msg.bytes, req->path);

  return smb_send_message(data, smbc, req, SMB_COM_NT_CREATE_ANDX, &msg,
                          sizeof(msg) - sizeof(msg.bytes) + byte_count);
}

static CURLcode smb_send_close(struct Curl_easy *data,
                               struct smb_conn *smbc,
                               struct smb_request *req)
{
  struct smb_close msg;

  memset(&msg, 0, sizeof(msg));
  msg.word_count = SMB_WC_CLOSE;
  msg.fid = smb_swap16(req->fid);

  return smb_send_message(data, smbc, req, SMB_COM_CLOSE, &msg, sizeof(msg));
}

static CURLcode smb_send_tree_disconnect(struct Curl_easy *data,
                                         struct smb_conn *smbc,
                                         struct smb_request *req)
{
  struct smb_tree_disconnect msg;
  memset(&msg, 0, sizeof(msg));
  return smb_send_message(data, smbc, req, SMB_COM_TREE_DISCONNECT,
                          &msg, sizeof(msg));
}

static CURLcode smb_send_read(struct Curl_easy *data,
                              struct smb_conn *smbc,
                              struct smb_request *req)
{
  curl_off_t offset = data->req.offset;
  struct smb_read msg;

  memset(&msg, 0, sizeof(msg));
  msg.word_count = SMB_WC_READ_ANDX;
  msg.andx.command = SMB_COM_NO_ANDX_COMMAND;
  msg.fid = smb_swap16(req->fid);
  msg.offset = smb_swap32((unsigned int) offset);
  msg.offset_high = smb_swap32((unsigned int) (offset >> 32));
  msg.min_bytes = smb_swap16(MAX_PAYLOAD_SIZE);
  msg.max_bytes = smb_swap16(MAX_PAYLOAD_SIZE);

  return smb_send_message(data, smbc, req, SMB_COM_READ_ANDX,
                          &msg, sizeof(msg));
}

static CURLcode smb_send_write(struct Curl_easy *data,
                               struct smb_conn *smbc,
                               struct smb_request *req)
{
  struct smb_write *msg;
  curl_off_t offset = data->req.offset;
  curl_off_t upload_size = data->req.size - data->req.bytecount;

  msg = (struct smb_write *)smbc->send_buf;
  if(upload_size >= MAX_PAYLOAD_SIZE - 1) /* There is one byte of padding */
    upload_size = MAX_PAYLOAD_SIZE - 1;

  memset(msg, 0, sizeof(*msg));
  msg->word_count = SMB_WC_WRITE_ANDX;
  msg->andx.command = SMB_COM_NO_ANDX_COMMAND;
  msg->fid = smb_swap16(req->fid);
  msg->offset = smb_swap32((unsigned int) offset);
  msg->offset_high = smb_swap32((unsigned int) (offset >> 32));
  msg->data_length = smb_swap16((unsigned short) upload_size);
  msg->data_offset = smb_swap16(sizeof(*msg) - sizeof(unsigned int));
  msg->byte_count = smb_swap16((unsigned short) (upload_size + 1));

  smb_format_message(smbc, req, &msg->h, SMB_COM_WRITE_ANDX,
                     sizeof(*msg) - sizeof(msg->h) + (size_t) upload_size);

  return smb_send(data, smbc, sizeof(*msg), (size_t) upload_size);
}

static CURLcode smb_send_and_recv(struct Curl_easy *data,
                                  struct smb_conn *smbc, void **msg)
{
  CURLcode result;
  *msg = NULL; /* if it returns early */

  /* Check if there is data in the transfer buffer */
  if(!smbc->send_size && smbc->upload_size) {
    size_t nread = smbc->upload_size > (size_t)MAX_MESSAGE_SIZE ?
      (size_t)MAX_MESSAGE_SIZE : smbc->upload_size;
    bool eos;

    result = Curl_client_read(data, smbc->send_buf, nread, &nread, &eos);
    if(result && result != CURLE_AGAIN)
      return result;
    if(!nread)
      return CURLE_OK;

    smbc->upload_size -= nread;
    smbc->send_size = nread;
    smbc->sent = 0;
  }

  /* Check if there is data to send */
  if(smbc->send_size) {
    result = smb_flush(data, smbc);
    if(result)
      return result;
  }

  /* Check if there is still data to be sent */
  if(smbc->send_size || smbc->upload_size)
    return CURLE_AGAIN;

  return smb_recv_message(data, smbc, msg);
}

static CURLcode smb_connection_state(struct Curl_easy *data, bool *done)
{
  struct connectdata *conn = data->conn;
  struct smb_conn *smbc = Curl_conn_meta_get(conn, CURL_META_SMB_CONN);
  struct smb_request *req = Curl_meta_get(data, CURL_META_SMB_EASY);
  struct smb_negotiate_response *nrsp;
  struct smb_header *h;
  CURLcode result;
  void *msg = NULL;

  if(!smbc || !req)
    return CURLE_FAILED_INIT;

  if(smbc->state == SMB_CONNECTING) {
#ifdef USE_SSL
    if(Curl_conn_is_ssl(conn, FIRSTSOCKET)) {
      bool ssl_done = FALSE;
      result = Curl_conn_connect(data, FIRSTSOCKET, FALSE, &ssl_done);
      if(result && result != CURLE_AGAIN)
        return result;
      if(!ssl_done)
        return CURLE_OK;
    }
#endif

    result = smb_send_negotiate(data, smbc, req);
    if(result) {
      connclose(conn, "SMB: failed to send negotiate message");
      return result;
    }

    conn_state(data, smbc, SMB_NEGOTIATE);
  }

  /* Send the previous message and check for a response */
  result = smb_send_and_recv(data, smbc, &msg);
  if(result && result != CURLE_AGAIN) {
    connclose(conn, "SMB: failed to communicate");
    return result;
  }

  if(!msg)
    return CURLE_OK;

  h = msg;

  switch(smbc->state) {
  case SMB_NEGOTIATE:
    if((smbc->got < sizeof(*nrsp) + sizeof(smbc->challenge) - 1) ||
       h->status) {
      connclose(conn, "SMB: negotiation failed");
      return CURLE_COULDNT_CONNECT;
    }
    nrsp = msg;
#if defined(__GNUC__) && __GNUC__ >= 13
#pragma GCC diagnostic push
/* error: 'memcpy' offset [74, 80] from the object at '<unknown>' is out of
   the bounds of referenced subobject 'bytes' with type 'char[1]' */
#pragma GCC diagnostic ignored "-Warray-bounds"
#endif
    memcpy(smbc->challenge, nrsp->bytes, sizeof(smbc->challenge));
#if defined(__GNUC__) && __GNUC__ >= 13
#pragma GCC diagnostic pop
#endif
    smbc->session_key = smb_swap32(nrsp->session_key);
    result = smb_send_setup(data);
    if(result) {
      connclose(conn, "SMB: failed to send setup message");
      return result;
    }
    conn_state(data, smbc, SMB_SETUP);
    break;

  case SMB_SETUP:
    if(h->status) {
      connclose(conn, "SMB: authentication failed");
      return CURLE_LOGIN_DENIED;
    }
    smbc->uid = smb_swap16(h->uid);
    conn_state(data, smbc, SMB_CONNECTED);
    *done = TRUE;
    break;

  default:
    smb_pop_message(smbc);
    return CURLE_OK; /* ignore */
  }

  smb_pop_message(smbc);

  return CURLE_OK;
}

/*
 * Convert a timestamp from the Windows world (100 nsec units from 1 Jan 1601)
 * to POSIX time. Cap the output to fit within a time_t.
 */
static void get_posix_time(time_t *out, curl_off_t timestamp)
{
  if(timestamp >= CURL_OFF_T_C(116444736000000000)) {
    timestamp -= CURL_OFF_T_C(116444736000000000);
    timestamp /= 10000000;
#if SIZEOF_TIME_T < SIZEOF_CURL_OFF_T
    if(timestamp > TIME_T_MAX)
      *out = TIME_T_MAX;
    else if(timestamp < TIME_T_MIN)
      *out = TIME_T_MIN;
    else
#endif
      *out = (time_t) timestamp;
  }
  else
    *out = 0;
}

static CURLcode smb_request_state(struct Curl_easy *data, bool *done)
{
  struct connectdata *conn = data->conn;
  struct smb_conn *smbc = Curl_conn_meta_get(conn, CURL_META_SMB_CONN);
  struct smb_request *req = Curl_meta_get(data, CURL_META_SMB_EASY);
  struct smb_header *h;
  enum smb_req_state next_state = SMB_DONE;
  unsigned short len;
  unsigned short off;
  CURLcode result;
  void *msg = NULL;
  const struct smb_nt_create_response *smb_m;

  if(!smbc || !req)
    return CURLE_FAILED_INIT;

  if(data->state.upload && (data->state.infilesize < 0)) {
    failf(data, "SMB upload needs to know the size up front");
    return CURLE_SEND_ERROR;
  }

  /* Start the request */
  if(req->state == SMB_REQUESTING) {
    result = smb_send_tree_connect(data, smbc, req);
    if(result) {
      connclose(conn, "SMB: failed to send tree connect message");
      return result;
    }

    request_state(data, SMB_TREE_CONNECT);
  }

  /* Send the previous message and check for a response */
  result = smb_send_and_recv(data, smbc, &msg);
  if(result && result != CURLE_AGAIN) {
    connclose(conn, "SMB: failed to communicate");
    return result;
  }

  if(!msg)
    return CURLE_OK;

  h = msg;

  switch(req->state) {
  case SMB_TREE_CONNECT:
    if(h->status) {
      req->result = CURLE_REMOTE_FILE_NOT_FOUND;
      if(h->status == smb_swap32(SMB_ERR_NOACCESS))
        req->result = CURLE_REMOTE_ACCESS_DENIED;
      break;
    }
    req->tid = smb_swap16(h->tid);
    next_state = SMB_OPEN;
    break;

  case SMB_OPEN:
    if(h->status || smbc->got < sizeof(struct smb_nt_create_response)) {
      req->result = CURLE_REMOTE_FILE_NOT_FOUND;
      if(h->status == smb_swap32(SMB_ERR_NOACCESS))
        req->result = CURLE_REMOTE_ACCESS_DENIED;
      next_state = SMB_TREE_DISCONNECT;
      break;
    }
    smb_m = (const struct smb_nt_create_response*) msg;
    req->fid = smb_swap16(smb_m->fid);
    data->req.offset = 0;
    if(data->state.upload) {
      data->req.size = data->state.infilesize;
      Curl_pgrsSetUploadSize(data, data->req.size);
      next_state = SMB_UPLOAD;
    }
    else {
      data->req.size = smb_swap64(smb_m->end_of_file);
      if(data->req.size < 0) {
        req->result = CURLE_WEIRD_SERVER_REPLY;
        next_state = SMB_CLOSE;
      }
      else {
        Curl_pgrsSetDownloadSize(data, data->req.size);
        if(data->set.get_filetime)
          get_posix_time(&data->info.filetime, smb_m->last_change_time);
        next_state = SMB_DOWNLOAD;
      }
    }
    break;

  case SMB_DOWNLOAD:
    if(h->status || smbc->got < sizeof(struct smb_header) + 14) {
      req->result = CURLE_RECV_ERROR;
      next_state = SMB_CLOSE;
      break;
    }
    len = Curl_read16_le(((const unsigned char *) msg) +
                         sizeof(struct smb_header) + 11);
    off = Curl_read16_le(((const unsigned char *) msg) +
                         sizeof(struct smb_header) + 13);
    if(len > 0) {
      if(off + sizeof(unsigned int) + len > smbc->got) {
        failf(data, "Invalid input packet");
        result = CURLE_RECV_ERROR;
      }
      else
        result = Curl_client_write(data, CLIENTWRITE_BODY,
                                   (char *)msg + off + sizeof(unsigned int),
                                   len);
      if(result) {
        req->result = result;
        next_state = SMB_CLOSE;
        break;
      }
    }
    data->req.offset += len;
    next_state = (len < MAX_PAYLOAD_SIZE) ? SMB_CLOSE : SMB_DOWNLOAD;
    break;

  case SMB_UPLOAD:
    if(h->status || smbc->got < sizeof(struct smb_header) + 6) {
      req->result = CURLE_UPLOAD_FAILED;
      next_state = SMB_CLOSE;
      break;
    }
    len = Curl_read16_le(((const unsigned char *) msg) +
                         sizeof(struct smb_header) + 5);
    data->req.bytecount += len;
    data->req.offset += len;
    Curl_pgrsSetUploadCounter(data, data->req.bytecount);
    if(data->req.bytecount >= data->req.size)
      next_state = SMB_CLOSE;
    else
      next_state = SMB_UPLOAD;
    break;

  case SMB_CLOSE:
    /* We do not care if the close failed, proceed to tree disconnect anyway */
    next_state = SMB_TREE_DISCONNECT;
    break;

  case SMB_TREE_DISCONNECT:
    next_state = SMB_DONE;
    break;

  default:
    smb_pop_message(smbc);
    return CURLE_OK; /* ignore */
  }

  smb_pop_message(smbc);

  switch(next_state) {
  case SMB_OPEN:
    result = smb_send_open(data, smbc, req);
    break;

  case SMB_DOWNLOAD:
    result = smb_send_read(data, smbc, req);
    break;

  case SMB_UPLOAD:
    result = smb_send_write(data, smbc, req);
    break;

  case SMB_CLOSE:
    result = smb_send_close(data, smbc, req);
    break;

  case SMB_TREE_DISCONNECT:
    result = smb_send_tree_disconnect(data, smbc, req);
    break;

  case SMB_DONE:
    result = req->result;
    *done = TRUE;
    break;

  default:
    break;
  }

  if(result) {
    connclose(conn, "SMB: failed to send message");
    return result;
  }

  request_state(data, next_state);

  return CURLE_OK;
}

static int smb_getsock(struct Curl_easy *data,
                       struct connectdata *conn, curl_socket_t *socks)
{
  (void)data;
  socks[0] = conn->sock[FIRSTSOCKET];
  return GETSOCK_READSOCK(0) | GETSOCK_WRITESOCK(0);
}

static CURLcode smb_do(struct Curl_easy *data, bool *done)
{
  struct connectdata *conn = data->conn;
  struct smb_conn *smbc = Curl_conn_meta_get(conn, CURL_META_SMB_CONN);

  *done = FALSE;
  if(!smbc)
    return CURLE_FAILED_INIT;
  if(smbc->share)
    return CURLE_OK;
  return CURLE_URL_MALFORMAT;
}

static CURLcode smb_parse_url_path(struct Curl_easy *data,
                                   struct smb_conn *smbc,
                                   struct smb_request *req)
{
  char *path;
  char *slash;
  CURLcode result;

  /* URL decode the path */
  result = Curl_urldecode(data->state.up.path, 0, &path, NULL, REJECT_CTRL);
  if(result)
    return result;

  /* Parse the path for the share */
  smbc->share = strdup((*path == '/' || *path == '\\') ? path + 1 : path);
  free(path);
  if(!smbc->share)
    return CURLE_OUT_OF_MEMORY;

  slash = strchr(smbc->share, '/');
  if(!slash)
    slash = strchr(smbc->share, '\\');

  /* The share must be present */
  if(!slash) {
    Curl_safefree(smbc->share);
    failf(data, "missing share in URL path for SMB");
    return CURLE_URL_MALFORMAT;
  }

  /* Parse the path for the file path converting any forward slashes into
     backslashes */
  *slash++ = 0;
  req->path = slash;

  for(; *slash; slash++) {
    if(*slash == '/')
      *slash = '\\';
  }
  return CURLE_OK;
}

#endif /* CURL_DISABLE_SMB && USE_CURL_NTLM_CORE &&
          SIZEOF_CURL_OFF_T > 4 */
