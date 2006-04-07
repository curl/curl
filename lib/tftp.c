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

#include "setup.h"

#ifndef CURL_DISABLE_TFTP
/* -- WIN32 approved -- */
#include <stdio.h>
#include <string.h>
#include <stdarg.h>
#include <stdlib.h>
#include <ctype.h>
#ifdef HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif
#ifdef HAVE_SYS_STAT_H
#include <sys/stat.h>
#endif
#include <errno.h>

#if defined(WIN32)
#include <time.h>
#include <io.h>
#else
#ifdef HAVE_SYS_SOCKET_H
#include <sys/socket.h>
#endif
#include <netinet/in.h>
#include <sys/time.h>
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

#define _MPRINTF_REPLACE /* use our functions only */
#include <curl/mprintf.h>

#include "memory.h"
#include "select.h"

/* The last #include file should be: */
#include "memdebug.h"

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
  TFTP_ERR_NOSUCHUSER,
  TFTP_ERR_TIMEOUT,
  TFTP_ERR_NORESPONSE
} tftp_error_t;

typedef struct tftp_packet {
  unsigned short  event;
  union {
    struct {
      unsigned char   data[512];
    } request;
    struct {
      unsigned short  block;
      unsigned char   data[512];
    } data;
    struct {
      unsigned short  block;
    } ack;
    struct {
      unsigned short  code;
      unsigned char   data[512];
    } error;
  } u;
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
  socklen_t       local_addrlen;
  struct Curl_sockaddr_storage   remote_addr;
  socklen_t       remote_addrlen;
  int             rbytes;
  int             sbytes;
  tftp_packet_t   rpacket;
  tftp_packet_t   spacket;
} tftp_state_data_t;


/* Forward declarations */
static void tftp_rx(tftp_state_data_t *state, tftp_event_t event) ;
static void tftp_tx(tftp_state_data_t *state, tftp_event_t event) ;
void tftp_set_timeouts(tftp_state_data_t *state) ;

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
void tftp_set_timeouts(tftp_state_data_t *state)
{

  struct SessionHandle *data = state->conn->data;
  time_t maxtime, timeout;

  time(&state->start_time);
  if(state->state == TFTP_STATE_START) {
    /* Compute drop-dead time */
    maxtime = (time_t)(data->set.connecttimeout?data->set.connecttimeout:30);
    state->max_time = state->start_time+maxtime;

    /* Set per-block timeout to total */
    timeout = maxtime ;

    /* Average restart after 5 seconds */
    state->retry_max = timeout/5;

    /* Compute the re-start interval to suit the timeout */
    state->retry_time = timeout/state->retry_max;
    if(state->retry_time<1) state->retry_time=1;

  }
  else {

    /* Compute drop-dead time */
    maxtime = (time_t)(data->set.timeout?data->set.timeout:3600);
    state->max_time = state->start_time+maxtime;

    /* Set per-block timeout to 10% of total */
    timeout = maxtime/10 ;

    /* Average reposting an ACK after 15 seconds */
    state->retry_max = timeout/15;
  }
  /* But bound the total number  */
  if(state->retry_max<3) state->retry_max=3;
  if(state->retry_max>50) state->retry_max=50;

  /* Compute the re-ACK interval to suit the timeout */
  state->retry_time = timeout/state->retry_max;
  if(state->retry_time<1) state->retry_time=1;

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

static void tftp_send_first(tftp_state_data_t *state, tftp_event_t event)
{
  int sbytes;
  const char *mode = "octet";
  char *filename = state->conn->path;
  struct SessionHandle *data = state->conn->data;

  /* Set ascii mode if -B flag was used */
  if(data->set.ftp_ascii)
    mode = "netascii";

  switch(event) {

  case TFTP_EVENT_INIT:    /* Send the first packet out */
  case TFTP_EVENT_TIMEOUT: /* Resend the first packet out */
    /* Increment the retry counter, quit if over the limit */
    state->retries++;
    if(state->retries>state->retry_max) {
      state->error = TFTP_ERR_NORESPONSE;
      state->state = TFTP_STATE_FIN;
      return;
    }

    if(data->set.upload) {
      /* If we are uploading, send an WRQ */
      state->spacket.event = htons(TFTP_EVENT_WRQ);
      filename = curl_easy_unescape(data, filename, 0, NULL);
      state->conn->upload_fromhere = (char *)state->spacket.u.data.data;
      if(data->set.infilesize != -1)
        Curl_pgrsSetUploadSize(data, data->set.infilesize);
    }
    else {
      /* If we are downloading, send an RRQ */
      state->spacket.event = htons(TFTP_EVENT_RRQ);
    }
    snprintf((char *)state->spacket.u.request.data,
             sizeof(state->spacket.u.request.data),
             "%s%c%s%c", filename, '\0',  mode, '\0');
    sbytes = 4 + (int)strlen(filename) + (int)strlen(mode);
    sbytes = sendto(state->sockfd, (void *)&state->spacket,
                    sbytes, 0,
                    state->conn->ip_addr->ai_addr,
                    state->conn->ip_addr->ai_addrlen);
    if(sbytes < 0) {
      failf(data, "%s\n", strerror(errno));
    }
    break;

  case TFTP_EVENT_ACK: /* Connected for transmit */
    infof(data, "%s\n", "Connected for transmit");
    state->state = TFTP_STATE_TX;
    tftp_set_timeouts(state);
    tftp_tx(state, event);
    break;

  case TFTP_EVENT_DATA: /* connected for receive */
    infof(data, "%s\n", "Connected for receive");
    state->state = TFTP_STATE_RX;
    tftp_set_timeouts(state);
    tftp_rx(state, event);
    break;

  case TFTP_EVENT_ERROR:
    state->state = TFTP_STATE_FIN;
    break;

  default:
    failf(state->conn->data, "tftp_send_first: internal error\n");
    break;
  }
}

/**********************************************************
 *
 * tftp_rx
 *
 * Event handler for the RX state
 *
 **********************************************************/
static void tftp_rx(tftp_state_data_t *state, tftp_event_t event)
{
  int sbytes;
  int rblock;
  struct SessionHandle *data = state->conn->data;

  switch(event) {

  case TFTP_EVENT_DATA:

    /* Is this the block we expect? */
    rblock = ntohs(state->rpacket.u.data.block);
    if ((state->block+1) != rblock) {
      /* No, log it, up the retry count and fail if over the limit */
      infof(data,
            "Received unexpected DATA packet block %d\n", rblock);
      state->retries++;
      if (state->retries>state->retry_max) {
        failf(data, "tftp_rx: giving up waiting for block %d\n",
              state->block+1);
        return;
      }
    }
    /* This is the expected block.  Reset counters and ACK it. */
    state->block = rblock;
    state->retries = 0;
    state->spacket.event = htons(TFTP_EVENT_ACK);
    state->spacket.u.ack.block = htons(state->block);
    sbytes = sendto(state->sockfd, (void *)&state->spacket,
                    4, SEND_4TH_ARG,
                    (struct sockaddr *)&state->remote_addr,
                    state->remote_addrlen);
    if(sbytes < 0) {
      failf(data, "%s\n", strerror(errno));
    }

    /* Check if completed (That is, a less than full packet is recieved) */
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
    } else {
      /* Resend the previous ACK */
      sbytes = sendto(state->sockfd, (void *)&state->spacket,
                      4, SEND_4TH_ARG,
                      (struct sockaddr *)&state->remote_addr,
                      state->remote_addrlen);
      /* Check all sbytes were sent */
      if(sbytes<0) {
        failf(data, "%s\n", strerror(errno));
      }
    }
    break;

  case TFTP_EVENT_ERROR:
    state->state = TFTP_STATE_FIN;
    break;

  default:
    failf(data, "%s\n", "tftp_rx: internal error");
    break;
  }
  Curl_pgrsSetDownloadCounter(data,
                              (curl_off_t) state->block*512);
}

/**********************************************************
 *
 * tftp_tx
 *
 * Event handler for the TX state
 *
 **********************************************************/
static void tftp_tx(tftp_state_data_t *state, tftp_event_t event)
{
  struct SessionHandle *data = state->conn->data;
  int sbytes;
  int rblock;

  switch(event) {

  case TFTP_EVENT_ACK:
    /* Ack the packet */
    rblock = ntohs(state->rpacket.u.data.block);

    if(rblock != state->block) {
      /* This isn't the expected block.  Log it and up the retry counter */
      infof(data, "Received ACK for block %d, expecting %d\n",
            rblock, state->block);
      state->retries++;
      /* Bail out if over the maximum */
      if(state->retries>state->retry_max) {
        failf(data, "%s\n",
              "tftp_tx: giving up waiting for block %d ack",
              state->block);
      }
      return;
    }
    /* This is the expected packet.  Reset the counters and send the next
       block */
    state->block++;
    state->retries = 0;
    state->spacket.event = htons(TFTP_EVENT_DATA);
    state->spacket.u.ack.block = htons(state->block);
    if(state->block > 1 && state->sbytes < 512) {
      state->state = TFTP_STATE_FIN;
      return;
    }
    Curl_fillreadbuffer(state->conn, 512, &state->sbytes);
    sbytes = sendto(state->sockfd, (void *)&state->spacket,
                    4+state->sbytes, SEND_4TH_ARG,
                    (struct sockaddr *)&state->remote_addr,
                    state->remote_addrlen);
    /* Check all sbytes were sent */
    if(sbytes<0) {
      failf(data, "%s\n", strerror(errno));
    }
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
    } else {
      /* Re-send the data packet */
      sbytes = sendto(state->sockfd, (void *)&state->spacket,
                      4+state->sbytes, SEND_4TH_ARG,
                      (struct sockaddr *)&state->remote_addr,
                      state->remote_addrlen);
      /* Check all sbytes were sent */
      if(sbytes<0) {
        failf(data, "%s\n", strerror(errno));
      }
    }
    break;

  case TFTP_EVENT_ERROR:
    state->state = TFTP_STATE_FIN;
    break;

  default:
    failf(data, "%s\n", "tftp_tx: internal error");
    break;
  }

  /* Update the progress meter */
  Curl_pgrsSetUploadCounter(data, (curl_off_t) state->block*512);
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
  struct SessionHandle *data = state->conn->data;
  switch(state->state) {
  case TFTP_STATE_START:
    DEBUGF(infof(data, "TFTP_STATE_START\n"));
    tftp_send_first(state, event);
    break;
  case TFTP_STATE_RX:
    DEBUGF(infof(data, "TFTP_STATE_RX\n"));
    tftp_rx(state, event);
    break;
  case TFTP_STATE_TX:
    DEBUGF(infof(data, "TFTP_STATE_TX\n"));
    tftp_tx(state, event);
    break;
  case TFTP_STATE_FIN:
    infof(data, "%s\n", "TFTP finished");
    break;
  default:
    DEBUGF(infof(data, "STATE: %d\n", state->state));
    failf(data, "%s\n", "Internal state machine error");
    break;
  }
  return CURLE_OK;
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

  /*
   * The TFTP code is not portable because it sends C structs directly over
   * the wire.  Since C gives compiler writers a wide latitude in padding and
   * aligning structs, this fails on many architectures (e.g. ARM).
   *
   * The only portable way to fix this is to copy each struct item into a
   * flat buffer and send the flat buffer instead of the struct.  The
   * alternative, trying to get the compiler to eliminate padding bytes
   * within the struct, is a nightmare to maintain (each compiler does it
   * differently), and is still not guaranteed to work because some
   * architectures can't handle the resulting alignment.
   *
   * This check can be removed once the code has been fixed.
   */
  if(sizeof(struct tftp_packet) != 516) {
    failf(conn->data, "tftp not supported on this architecture");
    return CURLE_FAILED_INIT;
  }

  if((state = conn->proto.tftp = calloc(sizeof(tftp_state_data_t), 1))==NULL) {
    return CURLE_OUT_OF_MEMORY;
  }

  state->conn = conn;
  state->sockfd = state->conn->sock[FIRSTSOCKET];
  state->state = TFTP_STATE_START;

#ifdef WIN32
  /* AF_UNSPEC == 0 (from above calloc) doesn't work on Winsock */

  /* NOTE: this blatantly assumes IPv4. This should be fixed! */
  ((struct sockaddr_in*)&state->local_addr)->sin_family =
    conn->ip_addr->ai_family;
#endif

  tftp_set_timeouts(state);

  /* Bind to any interface, random UDP port.
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
          Curl_strerror(conn,Curl_ourerrno()));
    return CURLE_COULDNT_CONNECT;
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
CURLcode Curl_tftp_done(struct connectdata *conn, CURLcode status)
{
  (void)status; /* unused */

  free(conn->proto.tftp);
  conn->proto.tftp = NULL;
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
  tftp_state_data_t     *state = (tftp_state_data_t *)(conn->proto.tftp);
  tftp_event_t          event;
  CURLcode              code;
  int                   rc;
  struct Curl_sockaddr_storage fromaddr;
  socklen_t             fromlen;
  int                   check_time = 0;

  (void)done; /* prevent compiler warning */

  /* Run the TFTP State Machine */
  for(tftp_state_machine(state, TFTP_EVENT_INIT);
      state->state != TFTP_STATE_FIN;
      tftp_state_machine(state, event) ) {

    /* Wait until ready to read or timeout occurs */
    rc=Curl_select(state->sockfd, CURL_SOCKET_BAD, state->retry_time * 1000);

    if(rc == -1) {
      /* bail out */
      int error = Curl_ourerrno();
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
      if (state->rbytes < 4)
      {
        failf(conn->data, "Received too short packet\n");
        /* Not a timeout, but how best to handle it? */
        event = TFTP_EVENT_TIMEOUT;
      } else {

	/* The event is given by the TFTP packet time */
	event = (tftp_event_t)ntohs(state->rpacket.event);

	switch(event) {
	case TFTP_EVENT_DATA:
	  if (state->rbytes > 4)
	    Curl_client_write(data, CLIENTWRITE_BODY,
			  (char *)state->rpacket.u.data.data, state->rbytes-4);
	  break;
	case TFTP_EVENT_ERROR:
	  state->error = (tftp_error_t)ntohs(state->rpacket.u.error.code);
	  infof(conn->data, "%s\n", (char *)state->rpacket.u.error.data);
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
	Curl_pgrsUpdate(conn);

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

  /* Tell curl we're done */
  Curl_Transfer(conn, -1, -1, FALSE, NULL, -1, NULL);

  /* If we have encountered an error */
  if(state->error) {

    /* Translate internal error codes to curl error codes */
    switch(state->error) {
    case TFTP_ERR_NOTFOUND:
      code = CURLE_TFTP_NOTFOUND;
      break;
    case TFTP_ERR_PERM:
      code = CURLE_TFTP_PERM;
      break;
    case TFTP_ERR_DISKFULL:
      code = CURLE_TFTP_DISKFULL;
      break;
    case TFTP_ERR_ILLEGAL:
      code = CURLE_TFTP_ILLEGAL;
      break;
    case TFTP_ERR_UNKNOWNID:
      code = CURLE_TFTP_UNKNOWNID;
      break;
    case TFTP_ERR_EXISTS:
      code = CURLE_TFTP_EXISTS;
      break;
    case TFTP_ERR_NOSUCHUSER:
      code = CURLE_TFTP_NOSUCHUSER;
      break;
    case TFTP_ERR_TIMEOUT:
      code = CURLE_OPERATION_TIMEOUTED;
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
