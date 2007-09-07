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

#include "setup.h"

#ifndef CURL_DISABLE_TFTP
/* -- WIN32 approved -- */
#include <stdio.h>
#include <string.h>
#include <stdarg.h>
#include <stdlib.h>
#include <ctype.h>

#if defined(WIN32)
#include <time.h>
#include <io.h>
#else
#ifdef HAVE_SYS_SOCKET_H
#include <sys/socket.h>
#endif
#include <netinet/in.h>
#ifdef HAVE_SYS_TIME_H
#include <sys/time.h>
#endif
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#include <netdb.h>
#ifdef HAVE_ARPA_INET_H
#include <arpa/inet.h>
#endif
#ifdef HAVE_NET_IF_H
#include <net/if.h>
#endif
#include <sys/ioctl.h>
#include <signal.h>

#ifdef HAVE_SYS_PARAM_H
#include <sys/param.h>
#endif

#endif /* WIN32 */

#include "urldata.h"
#include <curl/curl.h>
#include "transfer.h"
#include "sendf.h"
#include "tftp.h"
#include "progress.h"
#include "connect.h"
#include "strerror.h"
#include "sockaddr.h" /* required for Curl_sockaddr_storage */
#include "url.h"

#define _MPRINTF_REPLACE /* use our functions only */
#include <curl/mprintf.h>

#include "memory.h"
#include "select.h"

/* The last #include file should be: */
#include "memdebug.h"

/* RFC2348 allows the block size to be negotiated, but we don't support that */
#define TFTP_BLOCKSIZE 512

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
  TFTP_EVENT_INIT=0,
  TFTP_EVENT_RRQ = 1,
  TFTP_EVENT_WRQ = 2,
  TFTP_EVENT_DATA = 3,
  TFTP_EVENT_ACK = 4,
  TFTP_EVENT_ERROR = 5,
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
  TFTP_ERR_NOSUCHUSER,	/* This will never be triggered by this code */

  /* The remaining error codes are internal to curl */
  TFTP_ERR_NONE = -100,
  TFTP_ERR_TIMEOUT,
  TFTP_ERR_NORESPONSE
} tftp_error_t;

typedef struct tftp_packet {
  unsigned char data[2 + 2 + TFTP_BLOCKSIZE];
} tftp_packet_t;

typedef struct tftp_state_data {
  tftp_state_t    state;
  tftp_mode_t     mode;
  tftp_error_t    error;
  struct connectdata      *conn;
  curl_socket_t   sockfd;
  int             retries;
  int             retry_time;
  int             retry_max;
  time_t          start_time;
  time_t          max_time;
  unsigned short  block;
  struct Curl_sockaddr_storage   local_addr;
  struct Curl_sockaddr_storage   remote_addr;
  socklen_t       remote_addrlen;
  int             rbytes;
  int             sbytes;
  tftp_packet_t   rpacket;
  tftp_packet_t   spacket;
} tftp_state_data_t;


/* Forward declarations */
static CURLcode tftp_rx(tftp_state_data_t *state, tftp_event_t event) ;
static CURLcode tftp_tx(tftp_state_data_t *state, tftp_event_t event) ;

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
static void tftp_set_timeouts(tftp_state_data_t *state)
{

  struct SessionHandle *data = state->conn->data;
  time_t maxtime, timeout;

  time(&state->start_time);
  if(state->state == TFTP_STATE_START) {
    /* Compute drop-dead time */
    maxtime = (time_t)(data->set.connecttimeout/1000L?
                       data->set.connecttimeout/1000L:30);
    state->max_time = state->start_time+maxtime;

    /* Set per-block timeout to total */
    timeout = maxtime ;

    /* Average restart after 5 seconds */
    state->retry_max = timeout/5;

    if(state->retry_max < 1)
      /* avoid division by zero below */
      state->retry_max = 1;

    /* Compute the re-start interval to suit the timeout */
    state->retry_time = timeout/state->retry_max;
    if(state->retry_time<1)
      state->retry_time=1;

  }
  else {

    /* Compute drop-dead time */
    maxtime = (time_t)(data->set.timeout/1000L?
                       data->set.timeout/1000L:3600);
    state->max_time = state->start_time+maxtime;

    /* Set per-block timeout to 10% of total */
    timeout = maxtime/10 ;

    /* Average reposting an ACK after 15 seconds */
    state->retry_max = timeout/15;
  }
  /* But bound the total number  */
  if(state->retry_max<3)
    state->retry_max=3;

  if(state->retry_max>50)
    state->retry_max=50;

  /* Compute the re-ACK interval to suit the timeout */
  state->retry_time = timeout/state->retry_max;
  if(state->retry_time<1)
    state->retry_time=1;

  infof(data, "set timeouts for state %d; Total %d, retry %d maxtry %d\n",
        state->state, (state->max_time-state->start_time),
        state->retry_time, state->retry_max);
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

static CURLcode tftp_send_first(tftp_state_data_t *state, tftp_event_t event)
{
  int sbytes;
  const char *mode = "octet";
  char *filename;
  struct SessionHandle *data = state->conn->data;
  CURLcode res = CURLE_OK;

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
      return res;
    }

    if(data->set.upload) {
      /* If we are uploading, send an WRQ */
      setpacketevent(&state->spacket, TFTP_EVENT_WRQ);
      state->conn->data->reqdata.upload_fromhere = (char *)&state->spacket.data[4];
      if(data->set.infilesize != -1)
        Curl_pgrsSetUploadSize(data, data->set.infilesize);
    }
    else {
      /* If we are downloading, send an RRQ */
      setpacketevent(&state->spacket, TFTP_EVENT_RRQ);
    }
    /* As RFC3617 describes the separator slash is not actually part of the
    file name so we skip the always-present first letter of the path string. */
    filename = curl_easy_unescape(data, &state->conn->data->reqdata.path[1], 0,
                                  NULL);
    if (!filename)
      return CURLE_OUT_OF_MEMORY;

    snprintf((char *)&state->spacket.data[2],
             TFTP_BLOCKSIZE,
             "%s%c%s%c", filename, '\0',  mode, '\0');
    sbytes = 4 + (int)strlen(filename) + (int)strlen(mode);
    sbytes = sendto(state->sockfd, (void *)&state->spacket,
                    sbytes, 0,
                    state->conn->ip_addr->ai_addr,
                    state->conn->ip_addr->ai_addrlen);
    if(sbytes < 0) {
      failf(data, "%s\n", Curl_strerror(state->conn, SOCKERRNO));
    }
    Curl_safefree(filename);
    break;

  case TFTP_EVENT_ACK: /* Connected for transmit */
    infof(data, "%s\n", "Connected for transmit");
    state->state = TFTP_STATE_TX;
    tftp_set_timeouts(state);
    return tftp_tx(state, event);

  case TFTP_EVENT_DATA: /* connected for receive */
    infof(data, "%s\n", "Connected for receive");
    state->state = TFTP_STATE_RX;
    tftp_set_timeouts(state);
    return tftp_rx(state, event);

  case TFTP_EVENT_ERROR:
    state->state = TFTP_STATE_FIN;
    break;

  default:
    failf(state->conn->data, "tftp_send_first: internal error\n");
    break;
  }
  return res;
}

/**********************************************************
 *
 * tftp_rx
 *
 * Event handler for the RX state
 *
 **********************************************************/
static CURLcode tftp_rx(tftp_state_data_t *state, tftp_event_t event)
{
  int sbytes;
  int rblock;
  struct SessionHandle *data = state->conn->data;

  switch(event) {

  case TFTP_EVENT_DATA:

    /* Is this the block we expect? */
    rblock = getrpacketblock(&state->rpacket);
    if ((state->block+1) != rblock) {
      /* No, log it, up the retry count and fail if over the limit */
      infof(data,
            "Received unexpected DATA packet block %d\n", rblock);
      state->retries++;
      if (state->retries>state->retry_max) {
        failf(data, "tftp_rx: giving up waiting for block %d\n",
              state->block+1);
        return CURLE_TFTP_ILLEGAL;
      }
    }
    /* This is the expected block.  Reset counters and ACK it. */
    state->block = (unsigned short)rblock;
    state->retries = 0;
    setpacketevent(&state->spacket, TFTP_EVENT_ACK);
    setpacketblock(&state->spacket, state->block);
    sbytes = sendto(state->sockfd, (void *)state->spacket.data,
                    4, SEND_4TH_ARG,
                    (struct sockaddr *)&state->remote_addr,
                    state->remote_addrlen);
    if(sbytes < 0) {
      failf(data, "%s\n", Curl_strerror(state->conn, SOCKERRNO));
      return CURLE_SEND_ERROR;
    }

    /* Check if completed (That is, a less than full packet is received) */
    if (state->rbytes < (int)sizeof(state->spacket)){
      state->state = TFTP_STATE_FIN;
    }
    else {
      state->state = TFTP_STATE_RX;
    }
    break;

  case TFTP_EVENT_TIMEOUT:
    /* Increment the retry count and fail if over the limit */
    state->retries++;
    infof(data,
          "Timeout waiting for block %d ACK.  Retries = %d\n", state->retries);
    if(state->retries > state->retry_max) {
      state->error = TFTP_ERR_TIMEOUT;
      state->state = TFTP_STATE_FIN;
    }
    else {
      /* Resend the previous ACK */
      sbytes = sendto(state->sockfd, (void *)&state->spacket,
                      4, SEND_4TH_ARG,
                      (struct sockaddr *)&state->remote_addr,
                      state->remote_addrlen);
      /* Check all sbytes were sent */
      if(sbytes<0) {
        failf(data, "%s\n", Curl_strerror(state->conn, SOCKERRNO));
        return CURLE_SEND_ERROR;
      }
    }
    break;

  case TFTP_EVENT_ERROR:
    state->state = TFTP_STATE_FIN;
    break;

  default:
    failf(data, "%s\n", "tftp_rx: internal error");
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
  int sbytes;
  int rblock;
  CURLcode res = CURLE_OK;
  struct Curl_transfer_keeper *k = &data->reqdata.keep;

  switch(event) {

  case TFTP_EVENT_ACK:
    /* Ack the packet */
    rblock = getrpacketblock(&state->rpacket);

    if(rblock != state->block) {
      /* This isn't the expected block.  Log it and up the retry counter */
      infof(data, "Received ACK for block %d, expecting %d\n",
            rblock, state->block);
      state->retries++;
      /* Bail out if over the maximum */
      if(state->retries>state->retry_max) {
        failf(data, "tftp_tx: giving up waiting for block %d ack",
              state->block);
        res = CURLE_SEND_ERROR;
      }
      else {
        /* Re-send the data packet */
        sbytes = sendto(state->sockfd, (void *)&state->spacket,
                        4+state->sbytes, SEND_4TH_ARG,
                        (struct sockaddr *)&state->remote_addr,
                        state->remote_addrlen);
        /* Check all sbytes were sent */
        if(sbytes<0) {
          failf(data, "%s\n", Curl_strerror(state->conn, SOCKERRNO));
          res = CURLE_SEND_ERROR;
        }
      }
      return res;
    }
    /* This is the expected packet.  Reset the counters and send the next
       block */
    state->block++;
    state->retries = 0;
    setpacketevent(&state->spacket, TFTP_EVENT_DATA);
    setpacketblock(&state->spacket, state->block);
    if(state->block > 1 && state->sbytes < TFTP_BLOCKSIZE) {
      state->state = TFTP_STATE_FIN;
      return CURLE_OK;
    }
    res = Curl_fillreadbuffer(state->conn, TFTP_BLOCKSIZE, &state->sbytes);
    if(res)
      return res;
    sbytes = sendto(state->sockfd, (void *)state->spacket.data,
                    4+state->sbytes, SEND_4TH_ARG,
                    (struct sockaddr *)&state->remote_addr,
                    state->remote_addrlen);
    /* Check all sbytes were sent */
    if(sbytes<0) {
      failf(data, "%s\n", Curl_strerror(state->conn, SOCKERRNO));
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
          " Retries = %d\n", state->retries);
    /* Decide if we've had enough */
    if(state->retries > state->retry_max) {
      state->error = TFTP_ERR_TIMEOUT;
      state->state = TFTP_STATE_FIN;
    }
    else {
      /* Re-send the data packet */
      sbytes = sendto(state->sockfd, (void *)&state->spacket,
                      4+state->sbytes, SEND_4TH_ARG,
                      (struct sockaddr *)&state->remote_addr,
                      state->remote_addrlen);
      /* Check all sbytes were sent */
      if(sbytes<0) {
        failf(data, "%s\n", Curl_strerror(state->conn, SOCKERRNO));
        return CURLE_SEND_ERROR;
      }
      /* since this was a re-send, we remain at the still byte position */
      Curl_pgrsSetUploadCounter(data, k->writebytecount);
    }
    break;

  case TFTP_EVENT_ERROR:
    state->state = TFTP_STATE_FIN;
    break;

  default:
    failf(data, "%s\n", "tftp_tx: internal error");
    break;
  }

  return res;
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
  CURLcode res = CURLE_OK;
  struct SessionHandle *data = state->conn->data;
  switch(state->state) {
  case TFTP_STATE_START:
    DEBUGF(infof(data, "TFTP_STATE_START\n"));
    res = tftp_send_first(state, event);
    break;
  case TFTP_STATE_RX:
    DEBUGF(infof(data, "TFTP_STATE_RX\n"));
    res = tftp_rx(state, event);
    break;
  case TFTP_STATE_TX:
    DEBUGF(infof(data, "TFTP_STATE_TX\n"));
    res = tftp_tx(state, event);
    break;
  case TFTP_STATE_FIN:
    infof(data, "%s\n", "TFTP finished");
    break;
  default:
    DEBUGF(infof(data, "STATE: %d\n", state->state));
    failf(data, "%s\n", "Internal state machine error");
    res = CURLE_TFTP_ILLEGAL;
    break;
  }
  return res;
}


/**********************************************************
 *
 * Curl_tftp_connect
 *
 * The connect callback
 *
 **********************************************************/
CURLcode Curl_tftp_connect(struct connectdata *conn, bool *done)
{
  CURLcode code;
  tftp_state_data_t     *state;
  int rc;

  state = conn->data->reqdata.proto.tftp = calloc(sizeof(tftp_state_data_t),
                                                  1);
  if(!state)
    return CURLE_OUT_OF_MEMORY;

  conn->bits.close = FALSE; /* keep it open if possible */

  state->conn = conn;
  state->sockfd = state->conn->sock[FIRSTSOCKET];
  state->state = TFTP_STATE_START;
  state->error = TFTP_ERR_NONE;

  ((struct sockaddr *)&state->local_addr)->sa_family =
    (unsigned short)(conn->ip_addr->ai_family);

  tftp_set_timeouts(state);

  if(!conn->bits.reuse) {
    /* If not reused, bind to any interface, random UDP port. If it is reused,
     * this has already been done!
     *
     * We once used the size of the local_addr struct as the third argument for
     * bind() to better work with IPv6 or whatever size the struct could have,
     * but we learned that at least Tru64, AIX and IRIX *requires* the size of
     * that argument to match the exact size of a 'sockaddr_in' struct when
     * running IPv4-only.
     *
     * Therefore we use the size from the address we connected to, which we
     * assume uses the same IP version and thus hopefully this works for both
     * IPv4 and IPv6...
     */
    rc = bind(state->sockfd, (struct sockaddr *)&state->local_addr,
              conn->ip_addr->ai_addrlen);
    if(rc) {
      failf(conn->data, "bind() failed; %s\n",
            Curl_strerror(conn, SOCKERRNO));
      return CURLE_COULDNT_CONNECT;
    }
  }

  Curl_pgrsStartNow(conn->data);

  *done = TRUE;
  code = CURLE_OK;
  return(code);
}

/**********************************************************
 *
 * Curl_tftp_done
 *
 * The done callback
 *
 **********************************************************/
CURLcode Curl_tftp_done(struct connectdata *conn, CURLcode status,
                        bool premature)
{
  (void)status; /* unused */
  (void)premature; /* not used */

#if 0
  free(conn->data->reqdata.proto.tftp);
  conn->data->reqdata.proto.tftp = NULL;
#endif
  Curl_pgrsDone(conn);

  return CURLE_OK;
}


/**********************************************************
 *
 * Curl_tftp
 *
 * The do callback
 *
 * This callback handles the entire TFTP transfer
 *
 **********************************************************/

CURLcode Curl_tftp(struct connectdata *conn, bool *done)
{
  struct SessionHandle  *data = conn->data;
  tftp_state_data_t     *state =
    (tftp_state_data_t *) conn->data->reqdata.proto.tftp;
  tftp_event_t          event;
  CURLcode              code;
  int                   rc;
  struct Curl_sockaddr_storage fromaddr;
  socklen_t             fromlen;
  int                   check_time = 0;
  struct Curl_transfer_keeper *k = &data->reqdata.keep;

  *done = TRUE;

  /*
    Since connections can be re-used between SessionHandles, this might be a
    connection already existing but on a fresh SessionHandle struct so we must
    make sure we have a good 'struct TFTP' to play with. For new connections,
    the struct TFTP is allocated and setup in the Curl_tftp_connect() function.
  */
  if(!state) {
    code = Curl_tftp_connect(conn, done);
    if(code)
      return code;
    state = (tftp_state_data_t *)conn->data->reqdata.proto.tftp;
  }

  code = Curl_readwrite_init(conn);
  if(code)
    return code;

  /* Run the TFTP State Machine */
  for(code=tftp_state_machine(state, TFTP_EVENT_INIT);
      (state->state != TFTP_STATE_FIN) && (code == CURLE_OK);
      code=tftp_state_machine(state, event) ) {

    /* Wait until ready to read or timeout occurs */
    rc=Curl_socket_ready(state->sockfd, CURL_SOCKET_BAD,
                         state->retry_time * 1000);

    if(rc == -1) {
      /* bail out */
      int error = SOCKERRNO;
      failf(data, "%s\n", Curl_strerror(conn, error));
      event = TFTP_EVENT_ERROR;
    }
    else if (rc==0) {
      /* A timeout occured */
      event = TFTP_EVENT_TIMEOUT;

      /* Force a look at transfer timeouts */
      check_time = 0;

    }
    else {

      /* Receive the packet */
      fromlen=sizeof(fromaddr);
      state->rbytes = recvfrom(state->sockfd,
                               (void *)&state->rpacket, sizeof(state->rpacket),
                               0, (struct sockaddr *)&fromaddr, &fromlen);
      if(state->remote_addrlen==0) {
        memcpy(&state->remote_addr, &fromaddr, fromlen);
        state->remote_addrlen = fromlen;
      }

      /* Sanity check packet length */
      if (state->rbytes < 4) {
        failf(conn->data, "Received too short packet\n");
        /* Not a timeout, but how best to handle it? */
        event = TFTP_EVENT_TIMEOUT;
      }
      else {

        /* The event is given by the TFTP packet time */
        event = (tftp_event_t)getrpacketevent(&state->rpacket);

        switch(event) {
        case TFTP_EVENT_DATA:
          /* Don't pass to the client empty or retransmitted packets */
          if (state->rbytes > 4 &&
              ((state->block+1) == getrpacketblock(&state->rpacket))) {
            code = Curl_client_write(conn, CLIENTWRITE_BODY,
                                     (char *)&state->rpacket.data[4],
                                     state->rbytes-4);
            if(code)
              return code;
            k->bytecount += state->rbytes-4;
            Curl_pgrsSetDownloadCounter(data, (curl_off_t) k->bytecount);
          }
          break;
        case TFTP_EVENT_ERROR:
          state->error = (tftp_error_t)getrpacketblock(&state->rpacket);
          infof(conn->data, "%s\n", (char *)&state->rpacket.data[4]);
          break;
        case TFTP_EVENT_ACK:
          break;
        case TFTP_EVENT_RRQ:
        case TFTP_EVENT_WRQ:
        default:
          failf(conn->data, "%s\n", "Internal error: Unexpected packet");
          break;
        }

        /* Update the progress meter */
        if(Curl_pgrsUpdate(conn))
          return CURLE_ABORTED_BY_CALLBACK;
      }
    }

    /* Check for transfer timeout every 10 blocks, or after timeout */
    if(check_time%10==0) {
      time_t current;
      time(&current);
      if(current>state->max_time) {
        DEBUGF(infof(data, "timeout: %d > %d\n",
                     current, state->max_time));
        state->error = TFTP_ERR_TIMEOUT;
        state->state = TFTP_STATE_FIN;
      }
    }

  }
  if(code)
    return code;

  /* Tell curl we're done */
  code = Curl_setup_transfer(conn, -1, -1, FALSE, NULL, -1, NULL);
  if(code)
    return code;

  /* If we have encountered an error */
  if(state->error != TFTP_ERR_NONE) {

    /* Translate internal error codes to curl error codes */
    switch(state->error) {
    case TFTP_ERR_NOTFOUND:
      code = CURLE_TFTP_NOTFOUND;
      break;
    case TFTP_ERR_PERM:
      code = CURLE_TFTP_PERM;
      break;
    case TFTP_ERR_DISKFULL:
      code = CURLE_REMOTE_DISK_FULL;
      break;
    case TFTP_ERR_UNDEF:
    case TFTP_ERR_ILLEGAL:
      code = CURLE_TFTP_ILLEGAL;
      break;
    case TFTP_ERR_UNKNOWNID:
      code = CURLE_TFTP_UNKNOWNID;
      break;
    case TFTP_ERR_EXISTS:
      code = CURLE_REMOTE_FILE_EXISTS;
      break;
    case TFTP_ERR_NOSUCHUSER:
      code = CURLE_TFTP_NOSUCHUSER;
      break;
    case TFTP_ERR_TIMEOUT:
      code = CURLE_OPERATION_TIMEDOUT;
      break;
    case TFTP_ERR_NORESPONSE:
      code = CURLE_COULDNT_CONNECT;
      break;
    default:
      code= CURLE_ABORTED_BY_CALLBACK;
      break;
    }
  }
  else
    code = CURLE_OK;
  return code;
}
#endif
