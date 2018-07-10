/***************************************************************************
 *                      _   _ ____  _
 *  Project         ___| | | |  _ \| |
 *                 / __| | | | |_) | |
 *                | (__| |_| |  _ <| |___
 *                 \___|\___/|_| \_\_____|
 *
 * Copyright (C) 2018, Richard W.M. Jones, <rjones@redhat.com>
 * Copyright (C) 2018, Red Hat Inc.
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

#ifndef CURL_DISABLE_NBD

/* Curl support for the NBD protocol.
 *
 * Only simple uploads and downloads of the whole image are supported.
 * Only servers using the "fixed newstyle" protocol are supported.
 *
 * Some other missing features:
 *
 * - Connect over Unix domain socket.
 *
 * - TLS authentication and encryption.
 *
 * - Detect if upload block is all zeroes and use NBD_CMD_WRITE_ZEROS.
 *
 * - Range requests (upload/download part of the image).
 *
 * - Support for: trim, write zeroes, flush.
 *
 * - Setting FUA flag in requests.
 *
 * - Support for server flags: readonly, rotational.
 *
 * - List export names.
 */

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
#include "connect.h"
#include "progress.h"
#include "sendf.h"
#include "multiif.h"
#include "transfer.h"
#include "escape.h"
#include "nbd.h"
/* The last #include file should be: */
#include "memdebug.h"

/* Maximum we will read from the socket, which is also the size of
 * the internal recv_buf buffer that we allocate per handle.
 */
#define NBD_MAX_MESSAGE_SIZE 8192

/* The maximum size of a request we will make to the server.
 *
 * nbdkit supports up to 64MB per request, but other servers may
 * support less than this so choose a smaller number than the
 * theoretical maximum.
 */
#define NBD_MAX_REQUEST_SIZE (4*1024*1024)

#if defined(_MSC_VER) || defined(__ILEC400__)
#  define PACK
#  pragma pack(push)
#  pragma pack(1)
#elif defined(__GNUC__)
#  define PACK __attribute__((packed))
#else
#  define PACK
#endif

struct handshake {
  char nbdmagic[8];             /* "NBDMAGIC" */
  char version[8];              /* "IHAVEOPT"  */
  unsigned short gflags;        /* global flags */
#define NBD_FLAG_FIXED_NEWSTYLE 1
#define NBD_FLAG_NO_ZEROES      2
} PACK;

struct option {
  char version[8];              /* "IHAVEOPT"  */
  unsigned int option;          /* NBD_OPT_* */
#define NBD_OPT_EXPORT_NAME 1
  unsigned int len;             /* Length of option data. */
  char data[1];                 /* Option data. */
} PACK;

struct export_data {
  curl_off_t size;              /* Size of the export. */
  unsigned short tflags;        /* Transmission flags. */
} PACK;

struct request {
  unsigned char rqmagic[4];     /* 0x25 0x60 0x95 0x13 */
  unsigned short cmdflags;      /* NBD_CMD_FLAG_* */
  unsigned short type;          /* NBD_CMD_* */
#define NBD_CMD_READ  0
#define NBD_CMD_WRITE 1
#define NBD_CMD_DISC  2
  curl_off_t handle;            /* Request handle. */
  curl_off_t offset;            /* Request offset. */
  unsigned int count;           /* Request length. */
} PACK;

struct reply {
  unsigned char rpmagic[4];     /* 0x67 0x44 0x66 0x98 */
  unsigned int error;           /* Error code. */
#define NBD_SUCCESS     0
#define NBD_EPERM       1
#define NBD_EIO         5
#define NBD_ENOMEM     12
#define NBD_EINVAL     22
#define NBD_ENOSPC     28
#define NBD_ESHUTDOWN 108
  curl_off_t handle;            /* Request handle. */
} PACK;

static CURLcode nbd_connect(struct connectdata *conn, bool *done);
static CURLcode nbd_connection_state(struct connectdata *conn, bool *done);
static CURLcode nbd_request_state(struct connectdata *conn, bool *done);
static int nbd_getsock(struct connectdata *conn, curl_socket_t *socks,
                       int numsocks);
static CURLcode nbd_disconnect(struct connectdata *conn,
                               bool dead_connection);

const struct Curl_handler Curl_handler_nbd = {
  "NBD",                                /* scheme */
  ZERO_NULL,                            /* setup_connection */
  ZERO_NULL,                            /* do_it */
  ZERO_NULL,                            /* done */
  ZERO_NULL,                            /* do_more */
  nbd_connect,                          /* connect_it */
  nbd_connection_state,                 /* connecting */
  nbd_request_state,                    /* doing */
  nbd_getsock,                          /* proto_getsock */
  nbd_getsock,                          /* doing_getsock */
  ZERO_NULL,                            /* domore_getsock */
  ZERO_NULL,                            /* perform_getsock */
  nbd_disconnect,                       /* disconnect */
  ZERO_NULL,                            /* readwrite */
  ZERO_NULL,                            /* connection_check */
  PORT_NBD,                             /* defport */
  CURLPROTO_NBD,                        /* protocol */
  PROTOPT_NONE                          /* flags*/
};

/* Use for debugging builds. */
#if defined(DEBUGBUILD) && !defined(CURL_DISABLE_VERBOSE_STRINGS)
static const char *nbdstate_names[] = {
  "STOP",
  "EXPECTING_MAGIC",
  "SENDING_CLIENT_FLAGS",
  "SENDING_EXPORT_NAME",
  "EXPECTING_EXPORT_DATA",
  "EXPECTING_124_ZEROES",
  "CONNECTED",
  "SENDING_REQUEST",
  "EXPECTING_REPLY",
  "DOWNLOADING_DATA",
};
#endif

static void debug_state(struct connectdata *conn, const char *what)
{
#if defined(DEBUGBUILD) && !defined(CURL_DISABLE_VERBOSE_STRINGS)
  struct nbd_conn *nbdc = &conn->proto.nbdc;

  infof(conn->data, "NBD %p %s state is %s\n",
        nbdc, what, nbdstate_names[nbdc->state]);
#endif
}

/* Only use this function for changing the state. */
static void state(struct connectdata *conn, nbdstate newstate)
{
  struct nbd_conn *nbdc = &conn->proto.nbdc;
#if defined(DEBUGBUILD) && !defined(CURL_DISABLE_VERBOSE_STRINGS)
  if(nbdc->state != newstate)
    infof(conn->data, "NBD %p state change from %s to %s\n",
          nbdc, nbdstate_names[nbdc->state], nbdstate_names[newstate]);
#endif
  nbdc->state = newstate;
}

static CURLcode nbd_parse_url(struct connectdata *conn)
{
  CURLcode result;
  struct nbd_conn *nbdc = &conn->proto.nbdc;

  result = Curl_urldecode(conn->data, conn->data->state.path,
                          0, &nbdc->exportname, NULL, TRUE);
  if(result)
    return result;

  return CURLE_OK;
}

/* Create the protocol connection object. */
static CURLcode nbd_connect(struct connectdata *conn, bool *done)
{
  struct nbd_conn *nbdc = &conn->proto.nbdc;
  CURLcode result;
  (void)done;

  /* Initialize the connection structure. */
  memset(nbdc, 0, sizeof(*nbdc));
  state(conn, NBD_EXPECTING_MAGIC);
  nbdc->recv_buf = malloc(NBD_MAX_MESSAGE_SIZE);
  if(!nbdc->recv_buf)
    return CURLE_OUT_OF_MEMORY;

  /* NBD always has the equivalent of keepalive. */
  connkeep(conn, "NBD default");

  /* Parse the exportname from the URL. */
  result = nbd_parse_url(conn);
  if(result)
    return result;

  return CURLE_OK;
}

/* Receive a message of a certain size from the remote end.
 * This is stored in nbdc->recv_buf so it must not be larger
 * than NBD_MAX_MESSAGE_SIZE bytes.
 *
 * Note that the full message has only been read if *msg != NULL
 * after this function returns.
 */
static CURLcode nbd_recv(struct connectdata *conn,
                         size_t msg_size, void **msg)
{
  struct nbd_conn *nbdc = &conn->proto.nbdc;
  CURLcode result;
  char *buf = nbdc->recv_buf;
  size_t len = msg_size - nbdc->received;
  ssize_t bytes_read;

  result = Curl_read(conn, FIRSTSOCKET, buf + nbdc->received, len,
                     &bytes_read);
  if(result)
    return result;
  if(bytes_read == 0)
    return CURLE_OK;

  nbdc->received += bytes_read;

  /* Didn't receive a whole message yet? */
  if(nbdc->received < msg_size)
    return CURLE_AGAIN;

  DEBUGASSERT(nbdc->received == msg_size);

  /* Received whole message, return it. */
  *msg = buf;
  nbdc->received = 0;
  return CURLE_OK;
}

static CURLcode nbd_flush(struct connectdata *conn);

/* Queue up a message to send.
 * If upload_size != 0 then the message is followed by a payload.
 */
static CURLcode nbd_send(struct connectdata *conn,
                         void *msg, ssize_t msg_len,
                         size_t upload_size)
{
  struct nbd_conn *nbdc = &conn->proto.nbdc;

  memcpy(conn->data->state.uploadbuffer + nbdc->send_size, msg, msg_len);
  nbdc->send_size += msg_len;

  nbdc->upload_size = upload_size;

  return nbd_flush(conn);
}

/* Send more of the outgoing message. */
static CURLcode nbd_flush(struct connectdata *conn)
{
  struct nbd_conn *nbdc = &conn->proto.nbdc;
  ssize_t bytes_written;
  ssize_t len;
  CURLcode result;

  /* Follow the message with a payload? */
  if(nbdc->send_size == 0 && nbdc->upload_size > 0) {
    int nread = nbdc->upload_size > UPLOAD_BUFSIZE ? UPLOAD_BUFSIZE :
      (int) nbdc->upload_size;

    conn->data->req.upload_fromhere = conn->data->state.uploadbuffer;
    /* This calls the user callback to fill upload_fromhere with data. */
    result = Curl_fillreadbuffer(conn, nread, &nread);
    if(result && result != CURLE_AGAIN)
      return result;
    if(!nread)
      return CURLE_OK;

    nbdc->upload_size -= nread;
    nbdc->send_size = nread;
    nbdc->sent = 0;
  }

  if(nbdc->send_size > 0) {
    len = nbdc->send_size - nbdc->sent;
    if(len == 0)
      return CURLE_OK;

    result = Curl_write(conn, FIRSTSOCKET,
                        conn->data->state.uploadbuffer + nbdc->sent,
                        len, &bytes_written);
    if(result)
      return result;

    if(bytes_written != len)
      nbdc->sent += bytes_written;
    else
      nbdc->send_size = nbdc->sent = 0;
  }

  return CURLE_OK;
}

/* This is the normal way to receive a message: It first sends any
 * remaining part of the outgoing message, if there is one, then it
 * receives an incoming message.
 */
static CURLcode nbd_send_recv(struct connectdata *conn,
                              size_t msg_size, void **msg)
{
  struct nbd_conn *nbdc = &conn->proto.nbdc;
  CURLcode result;

  if(nbdc->send_size > 0 || nbdc->upload_size > 0) {
    result = nbd_flush(conn);
    if(result)
      return result;
  }

  /* More to send? */
  if(nbdc->send_size > 0 || nbdc->upload_size > 0)
    return CURLE_AGAIN;

  /* Otherwise try to receive. */
  return nbd_recv(conn, msg_size, msg);
}

static CURLcode nbd_recv_magic(struct connectdata *conn)
{
  struct nbd_conn *nbdc = &conn->proto.nbdc;
  struct handshake *handshake = NULL;
  CURLcode result;

  result = nbd_send_recv(conn, sizeof(struct handshake), (void **) &handshake);
  if(result)
    return result;
  if(!handshake)
    return CURLE_OK;

  if(memcmp(handshake->nbdmagic, "NBDMAGIC", 8) != 0 ||
     memcmp(handshake->version, "IHAVEOPT", 8) != 0) {
    Curl_failf(conn->data,
               "not an NBD server supporting the newstyle protocol");
    return CURLE_WEIRD_SERVER_REPLY;
  }

  /* We only support "fixed newstyle".  All modern NBD servers should
   * behave this way so if this fails it indicates some weird/old
   * server.
   */
  nbdc->gflags = ntohs(handshake->gflags);
  if((nbdc->gflags & NBD_FLAG_FIXED_NEWSTYLE) != NBD_FLAG_FIXED_NEWSTYLE) {
    Curl_failf(conn->data,
               "NBD server does not support the fixed newstyle protocol");
    return CURLE_WEIRD_SERVER_REPLY;
  }

  /* Move to the next state. */
  state(conn, NBD_SENDING_CLIENT_FLAGS);

  return CURLE_OK;
}

static CURLcode nbd_send_client_flags(struct connectdata *conn)
{
  struct nbd_conn *nbdc = &conn->proto.nbdc;
  unsigned int flags;
  CURLcode result;

  /* Send back only the global flags that we know about. */
  flags = nbdc->gflags;
  flags &= NBD_FLAG_FIXED_NEWSTYLE|NBD_FLAG_NO_ZEROES;
  flags = htonl(flags);
  result = nbd_send(conn, &flags, 4, 0);

  /* Even though we haven't necessarily sent the data we can still
   * move to the next state.
   */
  state(conn, NBD_SENDING_EXPORT_NAME);

  return result;
}

static CURLcode nbd_send_export_name(struct connectdata *conn)
{
  struct nbd_conn *nbdc = &conn->proto.nbdc;
  CURLcode result;
  struct option *option;
  size_t len = strlen(nbdc->exportname);
  size_t msg_len = sizeof(struct option) + len - 1; /* because of data[1] */

  option = malloc(msg_len);
  if(option == NULL)
    return CURLE_OUT_OF_MEMORY;
  memcpy(option->version, "IHAVEOPT", 8);
  option->option = htonl(NBD_OPT_EXPORT_NAME);
  option->len = htonl((unsigned int)len);
  memcpy(option->data, nbdc->exportname, len);
  result = nbd_send(conn, option, msg_len, 0);
  free(option);

  /* Even though we haven't necessarily sent the data we can still
   * move to the next state.
   */
  state(conn, NBD_EXPECTING_EXPORT_DATA);

  return result;
}

static CURLcode nbd_recv_export_data(struct connectdata *conn)
{
  struct nbd_conn *nbdc = &conn->proto.nbdc;
  struct export_data *data = NULL;
  const bool uploading = conn->data->set.upload;
  CURLcode result;

  result = nbd_send_recv(conn, sizeof(struct export_data), (void **) &data);
  if(result)
    return result;
  if(!data)
    return CURLE_OK;

  nbdc->size = be64toh(data->size);
  nbdc->tflags = ntohs(data->tflags);

  conn->data->req.size = conn->data->req.maxdownload = nbdc->size;
  if(uploading)
    Curl_pgrsSetUploadSize(conn->data, nbdc->size);
  else
    Curl_pgrsSetDownloadSize(conn->data, nbdc->size);

  /* Move to the next state. */
  if(!(nbdc->gflags & NBD_FLAG_NO_ZEROES))
    state(conn, NBD_EXPECTING_124_ZEROES);
  else
    state(conn, NBD_CONNECTED);

  return CURLE_OK;
}

/* Some old NBD servers send this. */
static CURLcode nbd_recv_124_zeroes(struct connectdata *conn)
{
  char *ignore = NULL;
  CURLcode result;

  result = nbd_send_recv(conn, 124, (void **) &ignore);
  if(result)
    return result;
  if(!ignore)
    return CURLE_OK;

  state(conn, NBD_CONNECTED);

  return CURLE_OK;
}

/* The state machine which handshakes with the NBD server. */
static CURLcode nbd_connection_state(struct connectdata *conn, bool *done)
{
  struct nbd_conn *nbdc = &conn->proto.nbdc;
  CURLcode result;

  debug_state(conn, "connecting");

  switch(nbdc->state) {
  case NBD_EXPECTING_MAGIC:
    result = nbd_recv_magic(conn);
    break;

  case NBD_SENDING_CLIENT_FLAGS:
    result = nbd_send_client_flags(conn);
    break;

  case NBD_SENDING_EXPORT_NAME:
    result = nbd_send_export_name(conn);
    break;

  case NBD_EXPECTING_EXPORT_DATA:
    result = nbd_recv_export_data(conn);
    break;

  case NBD_EXPECTING_124_ZEROES:
    result = nbd_recv_124_zeroes(conn);
    break;

  case NBD_CONNECTED:
    *done = TRUE;
    result = CURLE_OK;
    break;

  case NBD_STOP:
    *done = TRUE;
    result = CURLE_COULDNT_CONNECT;
    break;

  default:
    Curl_failf(conn->data,
               "internal error: bad state connecting to server: %d",
               nbdc->state);
    result = CURLE_COULDNT_CONNECT;
  }

  if(result == CURLE_AGAIN)
    return CURLE_OK;
  return result;
}

static CURLcode nbd_send_request(struct connectdata *conn)
{
  struct nbd_conn *nbdc = &conn->proto.nbdc;
  struct request rq;
  const unsigned char rqmagic[] = { 0x25, 0x60, 0x95, 0x13 };
  const bool uploading = conn->data->set.upload;
  const curl_off_t offset = conn->data->req.bytecount;
  size_t upload_size = 0;
  curl_off_t len;
  CURLcode result;

  /* Remaining length ... */
  len = conn->data->req.size - conn->data->req.bytecount;
  /* ... but we can only request up to NBD_MAX_REQUEST_SIZE each time. */
  if(len > NBD_MAX_REQUEST_SIZE)
    len = NBD_MAX_REQUEST_SIZE;
  conn->data->req.bytecount += len;
  conn->data->req.offset += len;

  if(uploading) {
    upload_size = len;
    Curl_pgrsSetUploadCounter(conn->data, conn->data->req.bytecount);
  }
  else {
    nbdc->download_size = len;
    Curl_pgrsSetDownloadCounter(conn->data, conn->data->req.bytecount);
  }

  memcpy(&rq.rqmagic, rqmagic, 4);
  rq.cmdflags = 0;
  if(uploading)
    rq.type = htons(NBD_CMD_WRITE);
  else
    rq.type = htons(NBD_CMD_READ);
  rq.handle = 0;
  rq.offset = htobe64(offset);
  rq.count = htonl((unsigned)len);
  result = nbd_send(conn, &rq, sizeof(rq), upload_size);

  state(conn, NBD_EXPECTING_REPLY);

  return result;
}

static int nbd_error_to_curl_error(struct connectdata *conn,
                                   bool uploading, int nbd_error)
{
  switch(nbd_error) {
  case NBD_SUCCESS:
    return CURLE_OK;

  case NBD_EPERM:
    Curl_failf(conn->data, "NBD error: EPERM: Permission denied");
    return CURLE_REMOTE_ACCESS_DENIED;
  case NBD_ENOMEM:
    Curl_failf(conn->data, "NBD error: ENOMEM: Cannot allocate memory");
    return CURLE_OUT_OF_MEMORY;
  case NBD_ENOSPC:
    Curl_failf(conn->data, "NBD error: ENOSPC: No space left on device");
    return CURLE_REMOTE_DISK_FULL;

  case NBD_ESHUTDOWN:           /* XXX Find better Curl equivalents. */
    Curl_failf(conn->data, "NBD error: ESHUTDOWN: "
               "Cannot send after transport endpoint shutdown");
    goto error;
  case NBD_EINVAL:
    Curl_failf(conn->data, "NBD error: EINVAL: Invalid argument");
    goto error;
  case NBD_EIO:
    Curl_failf(conn->data, "NBD error: EIO: Input/output error");
    goto error;
  default:
    Curl_failf(conn->data, "NBD error: error %d", nbd_error);
  error:
    if(uploading)
      return CURLE_WRITE_ERROR;
    else
      return CURLE_READ_ERROR;
  }
}

static CURLcode nbd_recv_reply(struct connectdata *conn)
{
  struct reply *rp = NULL;
  const unsigned char rpmagic[] = { 0x67, 0x44, 0x66, 0x98 };
  const bool uploading = conn->data->set.upload;
  CURLcode result;

  result = nbd_send_recv(conn, sizeof(struct reply), (void **) &rp);
  if(result)
    return result;
  if(!rp)
    return CURLE_OK;

  if(memcmp(rp->rpmagic, rpmagic, 4) != 0) {
    Curl_failf(conn->data, "incorrect reply magic number");
    return CURLE_WEIRD_SERVER_REPLY;
  }
  rp->error = ntohl(rp->error);
  if(rp->error != 0)
    return nbd_error_to_curl_error(conn, uploading, rp->error);

  if(uploading)
    state(conn, NBD_CONNECTED);
  else
    state(conn, NBD_DOWNLOADING_DATA);

  return CURLE_OK;
}

static CURLcode nbd_recv_data(struct connectdata *conn)
{
  struct nbd_conn *nbdc = &conn->proto.nbdc;
  char *data = NULL;
  size_t download_size;
  CURLcode result;

  download_size = nbdc->download_size;
  /* We're reusing nbdc->recv_buf, so we cannot read more than this. */
  if(download_size > NBD_MAX_MESSAGE_SIZE)
    download_size = NBD_MAX_MESSAGE_SIZE;

  /* Anything left to download? */
  if(download_size > 0) {
    result = nbd_send_recv(conn, download_size, (void **) &data);
    if(result)
      return result;
    if(!data)
      return CURLE_OK;

    /* Give it to the user's WRITEFUNCTION. */
    result = Curl_client_write(conn, CLIENTWRITE_BODY, data, download_size);
    if(result) {
      state(conn, NBD_STOP);
      return result;
    }
    nbdc->download_size -= download_size;
  }

  if(download_size == 0)
    state(conn, NBD_CONNECTED);

  return CURLE_OK;
}

/* The state machine which handles a single request. */
static CURLcode nbd_request_state(struct connectdata *conn, bool *done)
{
  struct nbd_conn *nbdc = &conn->proto.nbdc;
  CURLcode result;
  const bool uploading = conn->data->set.upload;

  /* If we're in the CONNECTED state and we haven't finished
   * up-/downloading the data, send another request.
   */
  if(nbdc->state == NBD_CONNECTED &&
     conn->data->req.size - conn->data->req.bytecount > 0)
    state(conn, NBD_SENDING_REQUEST);

  debug_state(conn, "requesting");

  switch(nbdc->state) {
  case NBD_SENDING_REQUEST:
    result = nbd_send_request(conn);
    break;

  case NBD_EXPECTING_REPLY:
    result = nbd_recv_reply(conn);
    break;

  case NBD_DOWNLOADING_DATA:
    result = nbd_recv_data(conn);
    break;

  case NBD_CONNECTED:           /* Back to the idle state. */
    *done = TRUE;
    result = CURLE_OK;
    break;

  case NBD_STOP:
    *done = TRUE;
    goto error;

  default:
    Curl_failf(conn->data, "internal error: bad state: %d", nbdc->state);
  error:
    if(uploading)
      result = CURLE_WRITE_ERROR;
    else
      result = CURLE_READ_ERROR;
  }

  if(result == CURLE_AGAIN)
    return CURLE_OK;
  return result;
}

static int nbd_getsock(struct connectdata *conn, curl_socket_t *socks,
                       int numsocks)
{
  struct nbd_conn *nbdc = &conn->proto.nbdc;

  if(!numsocks)
    return GETSOCK_BLANK;

  socks[0] = conn->sock[FIRSTSOCKET];

  if(nbdc->send_size > 0 || nbdc->upload_size > 0)
    return GETSOCK_WRITESOCK(0);
  else
    return GETSOCK_READSOCK(0);
}

static CURLcode nbd_disconnect(struct connectdata *conn,
                                bool dead_connection)
{
  struct nbd_conn *nbdc = &conn->proto.nbdc;
  (void)dead_connection;

  Curl_safefree(nbdc->exportname);
  Curl_safefree(nbdc->recv_buf);

  return CURLE_OK;
}

#endif  /* !CURL_DISABLE_NBD */
