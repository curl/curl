/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) 1998 - 2016, Daniel Stenberg, <daniel@haxx.se>, et al.
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

#ifndef CURL_DISABLE_TFTP

#ifdef HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif
#ifdef HAVE_NETDB_H
#include <netdb.h>
#endif
#ifdef HAVE_ARPA_INET_H
#include <arpa/inet.h>
#endif
#ifdef HAVE_NET_IF_H
#include <net/if.h>
#endif
#ifdef HAVE_SYS_IOCTL_H
#include <sys/ioctl.h>
#endif

#ifdef HAVE_SYS_PARAM_H
#include <sys/param.h>
#endif

#include "urldata.h"
#include <curl/curl.h>
#include "transfer.h"
#include "sendf.h"
#include "tftp.h"
#include "progress.h"
#include "connect.h"
#include "strerror.h"
#include "sockaddr.h" /* required for Curl_sockaddr_storage */
#include "multiif.h"
#include "url.h"
#include "rawstr.h"
#include "speedcheck.h"
#include "select.h"

/* The last 3 #include files should be in this order */
#include "curl_printf.h"
#include "curl_memory.h"
#include "memdebug.h"

/* RFC2348 allows the block size to be negotiated */
#define TFTP_BLKSIZE_DEFAULT 512
#define TFTP_BLKSIZE_MIN 8
#define TFTP_BLKSIZE_MAX 65464
#define TFTP_OPTION_BLKSIZE "blksize"

/* from RFC2349: */
#define TFTP_OPTION_TSIZE    "tsize"
#define TFTP_OPTION_INTERVAL "timeout"

typedef enum {
  TFTP_MODE_NETASCII=0,
  TFTP_MODE_OCTET
} tftp_mode_t;

typedef enum {
  TFTP_STATE_START=0,
  TFTP_STATE_RX,
  TFTP_STATE_TX,
  TFTP_STATE_FIN
} tftp_state_t;

typedef enum {
  TFTP_EVENT_NONE = -1,
  TFTP_EVENT_INIT = 0,
  TFTP_EVENT_RRQ = 1,
  TFTP_EVENT_WRQ = 2,
  TFTP_EVENT_DATA = 3,
  TFTP_EVENT_ACK = 4,
  TFTP_EVENT_ERROR = 5,
  TFTP_EVENT_OACK = 6,
  TFTP_EVENT_TIMEOUT
} tftp_event_t;

typedef enum {
  TFTP_ERR_UNDEF=0,
  TFTP_ERR_NOTFOUND,
  TFTP_ERR_PERM,
  TFTP_ERR_DISKFULL,
  TFTP_ERR_ILLEGAL,
  TFTP_ERR_UNKNOWNID,
  TFTP_ERR_EXISTS,
  TFTP_ERR_NOSUCHUSER,  /* This will never be triggered by this code */

  /* The remaining error codes are internal to curl */
  TFTP_ERR_NONE = -100,
  TFTP_ERR_TIMEOUT,
  TFTP_ERR_NORESPONSE
} tftp_error_t;

typedef struct tftp_packet {
  unsigned char *data;
} tftp_packet_t;

typedef struct tftp_state_data {
  tftp_state_t    state;
  tftp_mode_t     mode;
  tftp_error_t    error;
  tftp_event_t    event;
  struct connectdata      *conn;
  curl_socket_t   sockfd;
  int             retries;
  int             retry_time;
  int             retry_max;
  time_t          start_time;
  time_t          max_time;
  time_t          rx_time;
  unsigned short  block;
  struct Curl_sockaddr_storage   local_addr;
  struct Curl_sockaddr_storage   remote_addr;
  curl_socklen_t  remote_addrlen;
  int             rbytes;
  int             sbytes;
  int             blksize;
  int             requested_blksize;
  tftp_packet_t   rpacket;
  tftp_packet_t   spacket;
} tftp_state_data_t;


/* Forward declarations */
static CURLcode tftp_rx(tftp_state_data_t *state, tftp_event_t event);
static CURLcode tftp_tx(tftp_state_data_t *state, tftp_event_t event);
static CURLcode tftp_connect(struct connectdata *conn, bool *done);
static CURLcode tftp_disconnect(struct connectdata *conn,
                                bool dead_connection);
static CURLcode tftp_do(struct connectdata *conn, bool *done);
static CURLcode tftp_done(struct connectdata *conn,
                          CURLcode, bool premature);
static CURLcode tftp_setup_connection(struct connectdata * conn);
static CURLcode tftp_multi_statemach(struct connectdata *conn, bool *done);
static CURLcode tftp_doing(struct connectdata *conn, bool *dophase_done);
static int tftp_getsock(struct connectdata *conn, curl_socket_t *socks,
                        int numsocks);
static CURLcode tftp_translate_code(tftp_error_t error);


/*
 * TFTP protocol handler.
 */

const struct Curl_handler Curl_handler_tftp = {
  "TFTP",                               /* scheme */
  tftp_setup_connection,                /* setup_connection */
  tftp_do,                              /* do_it */
  tftp_done,                            /* done */
  ZERO_NULL,                            /* do_more */
  tftp_connect,                         /* connect_it */
  tftp_multi_statemach,                 /* connecting */
  tftp_doing,                           /* doing */
  tftp_getsock,                         /* proto_getsock */
  tftp_getsock,                         /* doing_getsock */
  ZERO_NULL,                            /* domore_getsock */
  ZERO_NULL,                            /* perform_getsock */
  tftp_disconnect,                      /* disconnect */
  ZERO_NULL,                            /* readwrite */
  PORT_TFTP,                            /* defport */
  CURLPROTO_TFTP,                       /* protocol */
  PROTOPT_NONE | PROTOPT_NOURLQUERY     /* flags */
};

/**********************************************************
 *
 * tftp_set_timeouts -
 *
 * Set timeouts based on state machine state.
 * Use user provided connect timeouts until DATA or ACK
 * packet is received, then use user-provided transfer timeouts
 *
 *
 **********************************************************/
static CURLcode tftp_set_timeouts(tftp_state_data_t *state)
{
  time_t maxtime, timeout;
  long timeout_ms;
  bool start = (state->state == TFTP_STATE_START) ? TRUE : FALSE;

  time(&state->start_time);

  /* Compute drop-dead time */
  timeout_ms = Curl_timeleft(state->conn->data, NULL, start);

  if(timeout_ms < 0) {
    /* time-out, bail out, go home */
    failf(state->conn->data, "Connection time-out");
    return CURLE_OPERATION_TIMEDOUT;
  }

  if(start) {

    maxtime = (time_t)(timeout_ms + 500) / 1000;
    state->max_time = state->start_time+maxtime;

    /* Set per-block timeout to total */
    timeout = maxtime;

    /* Average restart after 5 seconds */
    state->retry_max = (int)timeout/5;

    if(state->retry_max < 1)
      /* avoid division by zero below */
      state->retry_max = 1;

    /* Compute the re-start interval to suit the timeout */
    state->retry_time = (int)timeout/state->retry_max;
    if(state->retry_time<1)
      state->retry_time=1;

  }
  else {
    if(timeout_ms > 0)
      maxtime = (time_t)(timeout_ms + 500) / 1000;
    else
      maxtime = 3600;

    state->max_time = state->start_time+maxtime;

    /* Set per-block timeout to total */
    timeout = maxtime;

    /* Average reposting an ACK after 5 seconds */
    state->retry_max = (int)timeout/5;
  }
  /* But bound the total number */
  if(state->retry_max<3)
    state->retry_max=3;

  if(state->retry_max>50)
    state->retry_max=50;

  /* Compute the re-ACK interval to suit the timeout */
  state->retry_time = (int)(timeout/state->retry_max);
  if(state->retry_time<1)
    state->retry_time=1;

  infof(state->conn->data,
        "set timeouts for state %d; Total %ld, retry %d maxtry %d\n",
        (int)state->state, (long)(state->max_time-state->start_time),
        state->retry_time, state->retry_max);

  /* init RX time */
  time(&state->rx_time);

  return CURLE_OK;
}

/**********************************************************
 *
 * tftp_set_send_first
 *
 * Event handler for the START state
 *
 **********************************************************/

static void setpacketevent(tftp_packet_t *packet, unsigned short num)
{
  packet->data[0] = (unsigned char)(num >> 8);
  packet->data[1] = (unsigned char)(num & 0xff);
}


static void setpacketblock(tftp_packet_t *packet, unsigned short num)
{
  packet->data[2] = (unsigned char)(num >> 8);
  packet->data[3] = (unsigned char)(num & 0xff);
}

static unsigned short getrpacketevent(const tftp_packet_t *packet)
{
  return (unsigned short)((packet->data[0] << 8) | packet->data[1]);
}

static unsigned short getrpacketblock(const tftp_packet_t *packet)
{
  return (unsigned short)((packet->data[2] << 8) | packet->data[3]);
}

static size_t Curl_strnlen(const char *string, size_t maxlen)
{
  const char *end = memchr (string, '\0', maxlen);
  return end ? (size_t) (end - string) : maxlen;
}

static const char *tftp_option_get(const char *buf, size_t len,
                                   const char **option, const char **value)
{
  size_t loc;

  loc = Curl_strnlen(buf, len);
  loc++; /* NULL term */

  if(loc >= len)
    return NULL;
  *option = buf;

  loc += Curl_strnlen(buf+loc, len-loc);
  loc++; /* NULL term */

  if(loc > len)
    return NULL;
  *value = &buf[strlen(*option) + 1];

  return &buf[loc];
}

static CURLcode tftp_parse_option_ack(tftp_state_data_t *state,
                                      const char *ptr, int len)
{
  const char *tmp = ptr;
  struct SessionHandle *data = state->conn->data;

  /* if OACK doesn't contain blksize option, the default (512) must be used */
  state->blksize = TFTP_BLKSIZE_DEFAULT;

  while(tmp < ptr + len) {
    const char *option, *value;

    tmp = tftp_option_get(tmp, ptr + len - tmp, &option, &value);
    if(tmp == NULL) {
      failf(data, "Malformed ACK packet, rejecting");
      return CURLE_TFTP_ILLEGAL;
    }

    infof(data, "got option=(%s) value=(%s)\n", option, value);

    if(checkprefix(option, TFTP_OPTION_BLKSIZE)) {
      long blksize;

      blksize = strtol(value, NULL, 10);

      if(!blksize) {
        failf(data, "invalid blocksize value in OACK packet");
        return CURLE_TFTP_ILLEGAL;
      }
      else if(blksize > TFTP_BLKSIZE_MAX) {
        failf(data, "%s (%d)", "blksize is larger than max supported",
              TFTP_BLKSIZE_MAX);
        return CURLE_TFTP_ILLEGAL;
      }
      else if(blksize < TFTP_BLKSIZE_MIN) {
        failf(data, "%s (%d)", "blksize is smaller than min supported",
              TFTP_BLKSIZE_MIN);
        return CURLE_TFTP_ILLEGAL;
      }
      else if(blksize > state->requested_blksize) {
        /* could realloc pkt buffers here, but the spec doesn't call out
         * support for the server requesting a bigger blksize than the client
         * requests */
        failf(data, "%s (%ld)",
              "server requested blksize larger than allocated", blksize);
        return CURLE_TFTP_ILLEGAL;
      }

      state->blksize = (int)blksize;
      infof(data, "%s (%d) %s (%d)\n", "blksize parsed from OACK",
            state->blksize, "requested", state->requested_blksize);
    }
    else if(checkprefix(option, TFTP_OPTION_TSIZE)) {
      long tsize = 0;

      tsize = strtol(value, NULL, 10);
      infof(data, "%s (%ld)\n", "tsize parsed from OACK", tsize);

      /* tsize should be ignored on upload: Who cares about the size of the
         remote file? */
      if(!data->set.upload) {
        if(!tsize) {
          failf(data, "invalid tsize -:%s:- value in OACK packet", value);
          return CURLE_TFTP_ILLEGAL;
        }
        Curl_pgrsSetDownloadSize(data, tsize);
      }
    }
  }

  return CURLE_OK;
}

static size_t tftp_option_add(tftp_state_data_t *state, size_t csize,
                              char *buf, const char *option)
{
  if(( strlen(option) + csize + 1) > (size_t)state->blksize)
    return 0;
  strcpy(buf, option);
  return strlen(option) + 1;
}

static CURLcode tftp_connect_for_tx(tftp_state_data_t *state,
                                    tftp_event_t event)
{
  CURLcode result;
#ifndef CURL_DISABLE_VERBOSE_STRINGS
  struct SessionHandle *data = state->conn->data;

  infof(data, "%s\n", "Connected for transmit");
#endif
  state->state = TFTP_STATE_TX;
  result = tftp_set_timeouts(state);
  if(result)
    return result;
  return tftp_tx(state, event);
}

static CURLcode tftp_connect_for_rx(tftp_state_data_t *state,
                                    tftp_event_t event)
{
  CURLcode result;
#ifndef CURL_DISABLE_VERBOSE_STRINGS
  struct SessionHandle *data = state->conn->data;

  infof(data, "%s\n", "Connected for receive");
#endif
  state->state = TFTP_STATE_RX;
  result = tftp_set_timeouts(state);
  if(result)
    return result;
  return tftp_rx(state, event);
}

static CURLcode tftp_send_first(tftp_state_data_t *state, tftp_event_t event)
{
  size_t sbytes;
  ssize_t senddata;
  const char *mode = "octet";
  char *filename;
  char buf[64];
  struct SessionHandle *data = state->conn->data;
  CURLcode result = CURLE_OK;

  /* Set ascii mode if -B flag was used */
  if(data->set.prefer_ascii)
    mode = "netascii";

  switch(event) {

  case TFTP_EVENT_INIT:    /* Send the first packet out */
  case TFTP_EVENT_TIMEOUT: /* Resend the first packet out */
    /* Increment the retry counter, quit if over the limit */
    state->retries++;
    if(state->retries>state->retry_max) {
      state->error = TFTP_ERR_NORESPONSE;
      state->state = TFTP_STATE_FIN;
      return result;
    }

    if(data->set.upload) {
      /* If we are uploading, send an WRQ */
      setpacketevent(&state->spacket, TFTP_EVENT_WRQ);
      state->conn->data->req.upload_fromhere =
        (char *)state->spacket.data+4;
      if(data->state.infilesize != -1)
        Curl_pgrsSetUploadSize(data, data->state.infilesize);
    }
    else {
      /* If we are downloading, send an RRQ */
      setpacketevent(&state->spacket, TFTP_EVENT_RRQ);
    }
    /* As RFC3617 describes the separator slash is not actually part of the
       file name so we skip the always-present first letter of the path
       string. */
    filename = curl_easy_unescape(data, &state->conn->data->state.path[1], 0,
                                  NULL);
    if(!filename)
      return CURLE_OUT_OF_MEMORY;

    snprintf((char *)state->spacket.data+2,
             state->blksize,
             "%s%c%s%c", filename, '\0',  mode, '\0');
    sbytes = 4 + strlen(filename) + strlen(mode);

    /* optional addition of TFTP options */
    if(!data->set.tftp_no_options) {
      /* add tsize option */
      if(data->set.upload && (data->state.infilesize != -1))
        snprintf(buf, sizeof(buf), "%" CURL_FORMAT_CURL_OFF_T,
                 data->state.infilesize);
      else
        strcpy(buf, "0"); /* the destination is large enough */

      sbytes += tftp_option_add(state, sbytes,
                                (char *)state->spacket.data+sbytes,
                                TFTP_OPTION_TSIZE);
      sbytes += tftp_option_add(state, sbytes,
                                (char *)state->spacket.data+sbytes, buf);
      /* add blksize option */
      snprintf(buf, sizeof(buf), "%d", state->requested_blksize);
      sbytes += tftp_option_add(state, sbytes,
                                (char *)state->spacket.data+sbytes,
                                TFTP_OPTION_BLKSIZE);
      sbytes += tftp_option_add(state, sbytes,
                                (char *)state->spacket.data+sbytes, buf);

      /* add timeout option */
      snprintf(buf, sizeof(buf), "%d", state->retry_time);
      sbytes += tftp_option_add(state, sbytes,
                                (char *)state->spacket.data+sbytes,
                                TFTP_OPTION_INTERVAL);
      sbytes += tftp_option_add(state, sbytes,
                                (char *)state->spacket.data+sbytes, buf);
    }

    /* the typecase for the 3rd argument is mostly for systems that do
       not have a size_t argument, like older unixes that want an 'int' */
    senddata = sendto(state->sockfd, (void *)state->spacket.data,
                      (SEND_TYPE_ARG3)sbytes, 0,
                      state->conn->ip_addr->ai_addr,
                      state->conn->ip_addr->ai_addrlen);
    if(senddata != (ssize_t)sbytes) {
      failf(data, "%s", Curl_strerror(state->conn, SOCKERRNO));
    }
    free(filename);
    break;

  case TFTP_EVENT_OACK:
    if(data->set.upload) {
      result = tftp_connect_for_tx(state, event);
    }
    else {
      result = tftp_connect_for_rx(state, event);
    }
    break;

  case TFTP_EVENT_ACK: /* Connected for transmit */
    result = tftp_connect_for_tx(state, event);
    break;

  case TFTP_EVENT_DATA: /* Connected for receive */
    result = tftp_connect_for_rx(state, event);
    break;

  case TFTP_EVENT_ERROR:
    state->state = TFTP_STATE_FIN;
    break;

  default:
    failf(state->conn->data, "tftp_send_first: internal error");
    break;
  }

  return result;
}

/* the next blocknum is x + 1 but it needs to wrap at an unsigned 16bit
   boundary */
#define NEXT_BLOCKNUM(x) (((x)+1)&0xffff)

/**********************************************************
 *
 * tftp_rx
 *
 * Event handler for the RX state
 *
 **********************************************************/
static CURLcode tftp_rx(tftp_state_data_t *state, tftp_event_t event)
{
  ssize_t sbytes;
  int rblock;
  struct SessionHandle *data = state->conn->data;

  switch(event) {

  case TFTP_EVENT_DATA:
    /* Is this the block we expect? */
    rblock = getrpacketblock(&state->rpacket);
    if(NEXT_BLOCKNUM(state->block) == rblock) {
      /* This is the expected block.  Reset counters and ACK it. */
      state->retries = 0;
    }
    else if(state->block == rblock) {
      /* This is the last recently received block again. Log it and ACK it
         again. */
      infof(data, "Received last DATA packet block %d again.\n", rblock);
    }
    else {
      /* totally unexpected, just log it */
      infof(data,
            "Received unexpected DATA packet block %d, expecting block %d\n",
            rblock, NEXT_BLOCKNUM(state->block));
      break;
    }

    /* ACK this block. */
    state->block = (unsigned short)rblock;
    setpacketevent(&state->spacket, TFTP_EVENT_ACK);
    setpacketblock(&state->spacket, state->block);
    sbytes = sendto(state->sockfd, (void *)state->spacket.data,
                    4, SEND_4TH_ARG,
                    (struct sockaddr *)&state->remote_addr,
                    state->remote_addrlen);
    if(sbytes < 0) {
      failf(data, "%s", Curl_strerror(state->conn, SOCKERRNO));
      return CURLE_SEND_ERROR;
    }

    /* Check if completed (That is, a less than full packet is received) */
    if(state->rbytes < (ssize_t)state->blksize+4) {
      state->state = TFTP_STATE_FIN;
    }
    else {
      state->state = TFTP_STATE_RX;
    }
    time(&state->rx_time);
    break;

  case TFTP_EVENT_OACK:
    /* ACK option acknowledgement so we can move on to data */
    state->block = 0;
    state->retries = 0;
    setpacketevent(&state->spacket, TFTP_EVENT_ACK);
    setpacketblock(&state->spacket, state->block);
    sbytes = sendto(state->sockfd, (void *)state->spacket.data,
                    4, SEND_4TH_ARG,
                    (struct sockaddr *)&state->remote_addr,
                    state->remote_addrlen);
    if(sbytes < 0) {
      failf(data, "%s", Curl_strerror(state->conn, SOCKERRNO));
      return CURLE_SEND_ERROR;
    }

    /* we're ready to RX data */
    state->state = TFTP_STATE_RX;
    time(&state->rx_time);
    break;

  case TFTP_EVENT_TIMEOUT:
    /* Increment the retry count and fail if over the limit */
    state->retries++;
    infof(data,
          "Timeout waiting for block %d ACK.  Retries = %d\n",
          NEXT_BLOCKNUM(state->block), state->retries);
    if(state->retries > state->retry_max) {
      state->error = TFTP_ERR_TIMEOUT;
      state->state = TFTP_STATE_FIN;
    }
    else {
      /* Resend the previous ACK */
      sbytes = sendto(state->sockfd, (void *)state->spacket.data,
                      4, SEND_4TH_ARG,
                      (struct sockaddr *)&state->remote_addr,
                      state->remote_addrlen);
      if(sbytes<0) {
        failf(data, "%s", Curl_strerror(state->conn, SOCKERRNO));
        return CURLE_SEND_ERROR;
      }
    }
    break;

  case TFTP_EVENT_ERROR:
    setpacketevent(&state->spacket, TFTP_EVENT_ERROR);
    setpacketblock(&state->spacket, state->block);
    (void)sendto(state->sockfd, (void *)state->spacket.data,
                 4, SEND_4TH_ARG,
                 (struct sockaddr *)&state->remote_addr,
                 state->remote_addrlen);
    /* don't bother with the return code, but if the socket is still up we
     * should be a good TFTP client and let the server know we're done */
    state->state = TFTP_STATE_FIN;
    break;

  default:
    failf(data, "%s", "tftp_rx: internal error");
    return CURLE_TFTP_ILLEGAL; /* not really the perfect return code for
                                  this */
  }
  return CURLE_OK;
}

/**********************************************************
 *
 * tftp_tx
 *
 * Event handler for the TX state
 *
 **********************************************************/
static CURLcode tftp_tx(tftp_state_data_t *state, tftp_event_t event)
{
  struct SessionHandle *data = state->conn->data;
  ssize_t sbytes;
  int rblock;
  CURLcode result = CURLE_OK;
  struct SingleRequest *k = &data->req;

  switch(event) {

  case TFTP_EVENT_ACK:
  case TFTP_EVENT_OACK:
    if(event == TFTP_EVENT_ACK) {
      /* Ack the packet */
      rblock = getrpacketblock(&state->rpacket);

      if(rblock != state->block &&
         /* There's a bug in tftpd-hpa that causes it to send us an ack for
          * 65535 when the block number wraps to 0. So when we're expecting
          * 0, also accept 65535. See
          * http://syslinux.zytor.com/archives/2010-September/015253.html
          * */
         !(state->block == 0 && rblock == 65535)) {
        /* This isn't the expected block.  Log it and up the retry counter */
        infof(data, "Received ACK for block %d, expecting %d\n",
              rblock, state->block);
        state->retries++;
        /* Bail out if over the maximum */
        if(state->retries>state->retry_max) {
          failf(data, "tftp_tx: giving up waiting for block %d ack",
                state->block);
          result = CURLE_SEND_ERROR;
        }
        else {
          /* Re-send the data packet */
          sbytes = sendto(state->sockfd, (void *)state->spacket.data,
                          4+state->sbytes, SEND_4TH_ARG,
                          (struct sockaddr *)&state->remote_addr,
                          state->remote_addrlen);
          /* Check all sbytes were sent */
          if(sbytes<0) {
            failf(data, "%s", Curl_strerror(state->conn, SOCKERRNO));
            result = CURLE_SEND_ERROR;
          }
        }

        return result;
      }
      /* This is the expected packet.  Reset the counters and send the next
         block */
      time(&state->rx_time);
      state->block++;
    }
    else
      state->block = 1; /* first data block is 1 when using OACK */

    state->retries = 0;
    setpacketevent(&state->spacket, TFTP_EVENT_DATA);
    setpacketblock(&state->spacket, state->block);
    if(state->block > 1 && state->sbytes < (int)state->blksize) {
      state->state = TFTP_STATE_FIN;
      return CURLE_OK;
    }

    result = Curl_fillreadbuffer(state->conn, state->blksize, &state->sbytes);
    if(result)
      return result;

    sbytes = sendto(state->sockfd, (void *) state->spacket.data,
                    4 + state->sbytes, SEND_4TH_ARG,
                    (struct sockaddr *)&state->remote_addr,
                    state->remote_addrlen);
    /* Check all sbytes were sent */
    if(sbytes<0) {
      failf(data, "%s", Curl_strerror(state->conn, SOCKERRNO));
      return CURLE_SEND_ERROR;
    }
    /* Update the progress meter */
    k->writebytecount += state->sbytes;
    Curl_pgrsSetUploadCounter(data, k->writebytecount);
    break;

  case TFTP_EVENT_TIMEOUT:
    /* Increment the retry counter and log the timeout */
    state->retries++;
    infof(data, "Timeout waiting for block %d ACK. "
          " Retries = %d\n", NEXT_BLOCKNUM(state->block), state->retries);
    /* Decide if we've had enough */
    if(state->retries > state->retry_max) {
      state->error = TFTP_ERR_TIMEOUT;
      state->state = TFTP_STATE_FIN;
    }
    else {
      /* Re-send the data packet */
      sbytes = sendto(state->sockfd, (void *)state->spacket.data,
                      4+state->sbytes, SEND_4TH_ARG,
                      (struct sockaddr *)&state->remote_addr,
                      state->remote_addrlen);
      /* Check all sbytes were sent */
      if(sbytes<0) {
        failf(data, "%s", Curl_strerror(state->conn, SOCKERRNO));
        return CURLE_SEND_ERROR;
      }
      /* since this was a re-send, we remain at the still byte position */
      Curl_pgrsSetUploadCounter(data, k->writebytecount);
    }
    break;

  case TFTP_EVENT_ERROR:
    state->state = TFTP_STATE_FIN;
    setpacketevent(&state->spacket, TFTP_EVENT_ERROR);
    setpacketblock(&state->spacket, state->block);
    (void)sendto(state->sockfd, (void *)state->spacket.data, 4, SEND_4TH_ARG,
                 (struct sockaddr *)&state->remote_addr,
                 state->remote_addrlen);
    /* don't bother with the return code, but if the socket is still up we
     * should be a good TFTP client and let the server know we're done */
    state->state = TFTP_STATE_FIN;
    break;

  default:
    failf(data, "tftp_tx: internal error, event: %i", (int)(event));
    break;
  }

  return result;
}

/**********************************************************
 *
 * tftp_translate_code
 *
 * Translate internal error codes to CURL error codes
 *
 **********************************************************/
static CURLcode tftp_translate_code(tftp_error_t error)
{
  CURLcode result = CURLE_OK;

  if(error != TFTP_ERR_NONE) {
    switch(error) {
    case TFTP_ERR_NOTFOUND:
      result = CURLE_TFTP_NOTFOUND;
      break;
    case TFTP_ERR_PERM:
      result = CURLE_TFTP_PERM;
      break;
    case TFTP_ERR_DISKFULL:
      result = CURLE_REMOTE_DISK_FULL;
      break;
    case TFTP_ERR_UNDEF:
    case TFTP_ERR_ILLEGAL:
      result = CURLE_TFTP_ILLEGAL;
      break;
    case TFTP_ERR_UNKNOWNID:
      result = CURLE_TFTP_UNKNOWNID;
      break;
    case TFTP_ERR_EXISTS:
      result = CURLE_REMOTE_FILE_EXISTS;
      break;
    case TFTP_ERR_NOSUCHUSER:
      result = CURLE_TFTP_NOSUCHUSER;
      break;
    case TFTP_ERR_TIMEOUT:
      result = CURLE_OPERATION_TIMEDOUT;
      break;
    case TFTP_ERR_NORESPONSE:
      result = CURLE_COULDNT_CONNECT;
      break;
    default:
      result = CURLE_ABORTED_BY_CALLBACK;
      break;
    }
  }
  else
    result = CURLE_OK;

  return result;
}

/**********************************************************
 *
 * tftp_state_machine
 *
 * The tftp state machine event dispatcher
 *
 **********************************************************/
static CURLcode tftp_state_machine(tftp_state_data_t *state,
                                   tftp_event_t event)
{
  CURLcode result = CURLE_OK;
  struct SessionHandle *data = state->conn->data;

  switch(state->state) {
  case TFTP_STATE_START:
    DEBUGF(infof(data, "TFTP_STATE_START\n"));
    result = tftp_send_first(state, event);
    break;
  case TFTP_STATE_RX:
    DEBUGF(infof(data, "TFTP_STATE_RX\n"));
    result = tftp_rx(state, event);
    break;
  case TFTP_STATE_TX:
    DEBUGF(infof(data, "TFTP_STATE_TX\n"));
    result = tftp_tx(state, event);
    break;
  case TFTP_STATE_FIN:
    infof(data, "%s\n", "TFTP finished");
    break;
  default:
    DEBUGF(infof(data, "STATE: %d\n", state->state));
    failf(data, "%s", "Internal state machine error");
    result = CURLE_TFTP_ILLEGAL;
    break;
  }

  return result;
}

/**********************************************************
 *
 * tftp_disconnect
 *
 * The disconnect callback
 *
 **********************************************************/
static CURLcode tftp_disconnect(struct connectdata *conn, bool dead_connection)
{
  tftp_state_data_t *state = conn->proto.tftpc;
  (void) dead_connection;

  /* done, free dynamically allocated pkt buffers */
  if(state) {
    Curl_safefree(state->rpacket.data);
    Curl_safefree(state->spacket.data);
    free(state);
  }

  return CURLE_OK;
}

/**********************************************************
 *
 * tftp_connect
 *
 * The connect callback
 *
 **********************************************************/
static CURLcode tftp_connect(struct connectdata *conn, bool *done)
{
  tftp_state_data_t *state;
  int blksize, rc;

  blksize = TFTP_BLKSIZE_DEFAULT;

  state = conn->proto.tftpc = calloc(1, sizeof(tftp_state_data_t));
  if(!state)
    return CURLE_OUT_OF_MEMORY;

  /* alloc pkt buffers based on specified blksize */
  if(conn->data->set.tftp_blksize) {
    blksize = (int)conn->data->set.tftp_blksize;
    if(blksize > TFTP_BLKSIZE_MAX || blksize < TFTP_BLKSIZE_MIN)
      return CURLE_TFTP_ILLEGAL;
  }

  if(!state->rpacket.data) {
    state->rpacket.data = calloc(1, blksize + 2 + 2);

    if(!state->rpacket.data)
      return CURLE_OUT_OF_MEMORY;
  }

  if(!state->spacket.data) {
    state->spacket.data = calloc(1, blksize + 2 + 2);

    if(!state->spacket.data)
      return CURLE_OUT_OF_MEMORY;
  }

  /* we don't keep TFTP connections up basically because there's none or very
   * little gain for UDP */
  connclose(conn, "TFTP");

  state->conn = conn;
  state->sockfd = state->conn->sock[FIRSTSOCKET];
  state->state = TFTP_STATE_START;
  state->error = TFTP_ERR_NONE;
  state->blksize = TFTP_BLKSIZE_DEFAULT;
  state->requested_blksize = blksize;

  ((struct sockaddr *)&state->local_addr)->sa_family =
    (unsigned short)(conn->ip_addr->ai_family);

  tftp_set_timeouts(state);

  if(!conn->bits.bound) {
    /* If not already bound, bind to any interface, random UDP port. If it is
     * reused or a custom local port was desired, this has already been done!
     *
     * We once used the size of the local_addr struct as the third argument
     * for bind() to better work with IPv6 or whatever size the struct could
     * have, but we learned that at least Tru64, AIX and IRIX *requires* the
     * size of that argument to match the exact size of a 'sockaddr_in' struct
     * when running IPv4-only.
     *
     * Therefore we use the size from the address we connected to, which we
     * assume uses the same IP version and thus hopefully this works for both
     * IPv4 and IPv6...
     */
    rc = bind(state->sockfd, (struct sockaddr *)&state->local_addr,
              conn->ip_addr->ai_addrlen);
    if(rc) {
      failf(conn->data, "bind() failed; %s",
            Curl_strerror(conn, SOCKERRNO));
      return CURLE_COULDNT_CONNECT;
    }
    conn->bits.bound = TRUE;
  }

  Curl_pgrsStartNow(conn->data);

  *done = TRUE;

  return CURLE_OK;
}

/**********************************************************
 *
 * tftp_done
 *
 * The done callback
 *
 **********************************************************/
static CURLcode tftp_done(struct connectdata *conn, CURLcode status,
                          bool premature)
{
  CURLcode result = CURLE_OK;
  tftp_state_data_t *state = (tftp_state_data_t *)conn->proto.tftpc;

  (void)status; /* unused */
  (void)premature; /* not used */

  if(Curl_pgrsDone(conn))
    return CURLE_ABORTED_BY_CALLBACK;

  /* If we have encountered an error */
  if(state)
    result = tftp_translate_code(state->error);

  return result;
}

/**********************************************************
 *
 * tftp_getsock
 *
 * The getsock callback
 *
 **********************************************************/
static int tftp_getsock(struct connectdata *conn, curl_socket_t *socks,
                        int numsocks)
{
  if(!numsocks)
    return GETSOCK_BLANK;

  socks[0] = conn->sock[FIRSTSOCKET];

  return GETSOCK_READSOCK(0);
}

/**********************************************************
 *
 * tftp_receive_packet
 *
 * Called once select fires and data is ready on the socket
 *
 **********************************************************/
static CURLcode tftp_receive_packet(struct connectdata *conn)
{
  struct Curl_sockaddr_storage fromaddr;
  curl_socklen_t        fromlen;
  CURLcode              result = CURLE_OK;
  struct SessionHandle  *data = conn->data;
  tftp_state_data_t     *state = (tftp_state_data_t *)conn->proto.tftpc;
  struct SingleRequest  *k = &data->req;

  /* Receive the packet */
  fromlen = sizeof(fromaddr);
  state->rbytes = (int)recvfrom(state->sockfd,
                                (void *)state->rpacket.data,
                                state->blksize+4,
                                0,
                                (struct sockaddr *)&fromaddr,
                                &fromlen);
  if(state->remote_addrlen==0) {
    memcpy(&state->remote_addr, &fromaddr, fromlen);
    state->remote_addrlen = fromlen;
  }

  /* Sanity check packet length */
  if(state->rbytes < 4) {
    failf(data, "Received too short packet");
    /* Not a timeout, but how best to handle it? */
    state->event = TFTP_EVENT_TIMEOUT;
  }
  else {
    /* The event is given by the TFTP packet time */
    state->event = (tftp_event_t)getrpacketevent(&state->rpacket);

    switch(state->event) {
    case TFTP_EVENT_DATA:
      /* Don't pass to the client empty or retransmitted packets */
      if(state->rbytes > 4 &&
         (NEXT_BLOCKNUM(state->block) == getrpacketblock(&state->rpacket))) {
        result = Curl_client_write(conn, CLIENTWRITE_BODY,
                                   (char *)state->rpacket.data+4,
                                   state->rbytes-4);
        if(result) {
          tftp_state_machine(state, TFTP_EVENT_ERROR);
          return result;
        }
        k->bytecount += state->rbytes-4;
        Curl_pgrsSetDownloadCounter(data, (curl_off_t) k->bytecount);
      }
      break;
    case TFTP_EVENT_ERROR:
      state->error = (tftp_error_t)getrpacketblock(&state->rpacket);
      infof(data, "%s\n", (const char *)state->rpacket.data+4);
      break;
    case TFTP_EVENT_ACK:
      break;
    case TFTP_EVENT_OACK:
      result = tftp_parse_option_ack(state,
                                     (const char *)state->rpacket.data+2,
                                     state->rbytes-2);
      if(result)
        return result;
      break;
    case TFTP_EVENT_RRQ:
    case TFTP_EVENT_WRQ:
    default:
      failf(data, "%s", "Internal error: Unexpected packet");
      break;
    }

    /* Update the progress meter */
    if(Curl_pgrsUpdate(conn)) {
      tftp_state_machine(state, TFTP_EVENT_ERROR);
      return CURLE_ABORTED_BY_CALLBACK;
    }
  }
  return result;
}

/**********************************************************
 *
 * tftp_state_timeout
 *
 * Check if timeouts have been reached
 *
 **********************************************************/
static long tftp_state_timeout(struct connectdata *conn, tftp_event_t *event)
{
  time_t                current;
  tftp_state_data_t     *state = (tftp_state_data_t *)conn->proto.tftpc;

  if(event)
    *event = TFTP_EVENT_NONE;

  time(&current);
  if(current > state->max_time) {
    DEBUGF(infof(conn->data, "timeout: %ld > %ld\n",
                 (long)current, (long)state->max_time));
    state->error = TFTP_ERR_TIMEOUT;
    state->state = TFTP_STATE_FIN;
    return 0;
  }
  else if(current > state->rx_time+state->retry_time) {
    if(event)
      *event = TFTP_EVENT_TIMEOUT;
    time(&state->rx_time); /* update even though we received nothing */
  }

  /* there's a typecast below here since 'time_t' may in fact be larger than
     'long', but we estimate that a 'long' will still be able to hold number
     of seconds even if "only" 32 bit */
  return (long)(state->max_time - current);
}

/**********************************************************
 *
 * tftp_multi_statemach
 *
 * Handle single RX socket event and return
 *
 **********************************************************/
static CURLcode tftp_multi_statemach(struct connectdata *conn, bool *done)
{
  int                   rc;
  tftp_event_t          event;
  CURLcode              result = CURLE_OK;
  struct SessionHandle  *data = conn->data;
  tftp_state_data_t     *state = (tftp_state_data_t *)conn->proto.tftpc;
  long                  timeout_ms = tftp_state_timeout(conn, &event);

  *done = FALSE;

  if(timeout_ms <= 0) {
    failf(data, "TFTP response timeout");
    return CURLE_OPERATION_TIMEDOUT;
  }
  else if(event != TFTP_EVENT_NONE) {
    result = tftp_state_machine(state, event);
    if(result)
      return result;
    *done = (state->state == TFTP_STATE_FIN) ? TRUE : FALSE;
    if(*done)
      /* Tell curl we're done */
      Curl_setup_transfer(conn, -1, -1, FALSE, NULL, -1, NULL);
  }
  else {
    /* no timeouts to handle, check our socket */
    rc = Curl_socket_ready(state->sockfd, CURL_SOCKET_BAD, 0);

    if(rc == -1) {
      /* bail out */
      int error = SOCKERRNO;
      failf(data, "%s", Curl_strerror(conn, error));
      state->event = TFTP_EVENT_ERROR;
    }
    else if(rc != 0) {
      result = tftp_receive_packet(conn);
      if(result)
        return result;
      result = tftp_state_machine(state, state->event);
      if(result)
        return result;
      *done = (state->state == TFTP_STATE_FIN) ? TRUE : FALSE;
      if(*done)
        /* Tell curl we're done */
        Curl_setup_transfer(conn, -1, -1, FALSE, NULL, -1, NULL);
    }
    /* if rc == 0, then select() timed out */
  }

  return result;
}

/**********************************************************
 *
 * tftp_doing
 *
 * Called from multi.c while DOing
 *
 **********************************************************/
static CURLcode tftp_doing(struct connectdata *conn, bool *dophase_done)
{
  CURLcode result;
  result = tftp_multi_statemach(conn, dophase_done);

  if(*dophase_done) {
    DEBUGF(infof(conn->data, "DO phase is complete\n"));
  }
  else if(!result) {
    /* The multi code doesn't have this logic for the DOING state so we
       provide it for TFTP since it may do the entire transfer in this
       state. */
    if(Curl_pgrsUpdate(conn))
      result = CURLE_ABORTED_BY_CALLBACK;
    else
      result = Curl_speedcheck(conn->data, Curl_tvnow());
  }
  return result;
}

/**********************************************************
 *
 * tftp_peform
 *
 * Entry point for transfer from tftp_do, sarts state mach
 *
 **********************************************************/
static CURLcode tftp_perform(struct connectdata *conn, bool *dophase_done)
{
  CURLcode              result = CURLE_OK;
  tftp_state_data_t     *state = (tftp_state_data_t *)conn->proto.tftpc;

  *dophase_done = FALSE;

  result = tftp_state_machine(state, TFTP_EVENT_INIT);

  if((state->state == TFTP_STATE_FIN) || result)
    return result;

  tftp_multi_statemach(conn, dophase_done);

  if(*dophase_done)
    DEBUGF(infof(conn->data, "DO phase is complete\n"));

  return result;
}


/**********************************************************
 *
 * tftp_do
 *
 * The do callback
 *
 * This callback initiates the TFTP transfer
 *
 **********************************************************/

static CURLcode tftp_do(struct connectdata *conn, bool *done)
{
  tftp_state_data_t *state;
  CURLcode result;

  *done = FALSE;

  if(!conn->proto.tftpc) {
    result = tftp_connect(conn, done);
    if(result)
      return result;
  }

  state = (tftp_state_data_t *)conn->proto.tftpc;
  if(!state)
    return CURLE_BAD_CALLING_ORDER;

  result = tftp_perform(conn, done);

  /* If tftp_perform() returned an error, use that for return code. If it
     was OK, see if tftp_translate_code() has an error. */
  if(!result)
    /* If we have encountered an internal tftp error, translate it. */
    result = tftp_translate_code(state->error);

  return result;
}

static CURLcode tftp_setup_connection(struct connectdata * conn)
{
  struct SessionHandle *data = conn->data;
  char * type;
  char command;

  conn->socktype = SOCK_DGRAM;   /* UDP datagram based */

  /* TFTP URLs support an extension like ";mode=<typecode>" that
   * we'll try to get now! */
  type = strstr(data->state.path, ";mode=");

  if(!type)
    type = strstr(conn->host.rawalloc, ";mode=");

  if(type) {
    *type = 0;                   /* it was in the middle of the hostname */
    command = Curl_raw_toupper(type[6]);

    switch (command) {
    case 'A': /* ASCII mode */
    case 'N': /* NETASCII mode */
      data->set.prefer_ascii = TRUE;
      break;

    case 'O': /* octet mode */
    case 'I': /* binary mode */
    default:
      /* switch off ASCII */
      data->set.prefer_ascii = FALSE;
      break;
    }
  }

  return CURLE_OK;
}
#endif
