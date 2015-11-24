/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) 1998 - 2015, Daniel Stenberg, <daniel@haxx.se>, et al.
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

#include "curl_setup.h"

#ifndef CURL_DISABLE_TELNET

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
#include "telnet.h"
#include "connect.h"
#include "progress.h"
#include "curl_printf.h"

#define  TELOPTS
#define  TELCMDS

#include "arpa_telnet.h"
#include "select.h"
#include "strequal.h"
#include "rawstr.h"
#include "warnless.h"

/* The last #include files should be: */
#include "curl_memory.h"
#include "memdebug.h"

#define SUBBUFSIZE 512

#define CURL_SB_CLEAR(x)  x->subpointer = x->subbuffer
#define CURL_SB_TERM(x)                                 \
  do {                                                  \
    x->subend = x->subpointer;                          \
    CURL_SB_CLEAR(x);                                   \
  } WHILE_FALSE
#define CURL_SB_ACCUM(x,c)                                   \
  do {                                                       \
    if(x->subpointer < (x->subbuffer+sizeof x->subbuffer))   \
      *x->subpointer++ = (c);                                \
  } WHILE_FALSE

#define  CURL_SB_GET(x) ((*x->subpointer++)&0xff)
#define  CURL_SB_PEEK(x)   ((*x->subpointer)&0xff)
#define  CURL_SB_EOF(x) (x->subpointer >= x->subend)
#define  CURL_SB_LEN(x) (x->subend - x->subpointer)

#ifdef CURL_DISABLE_VERBOSE_STRINGS
#define printoption(a,b,c,d)  Curl_nop_stmt
#endif

#ifdef USE_WINSOCK
typedef FARPROC WSOCK2_FUNC;
static CURLcode check_wsock2 ( struct SessionHandle *data );
#endif

static
CURLcode telrcv(struct connectdata *,
                const unsigned char *inbuf, /* Data received from socket */
                ssize_t count);             /* Number of bytes received */

#ifndef CURL_DISABLE_VERBOSE_STRINGS
static void printoption(struct SessionHandle *data,
                        const char *direction,
                        int cmd, int option);
#endif

static void negotiate(struct connectdata *);
static void send_negotiation(struct connectdata *, int cmd, int option);
static void set_local_option(struct connectdata *, int cmd, int option);
static void set_remote_option(struct connectdata *, int cmd, int option);

static void printsub(struct SessionHandle *data,
                     int direction, unsigned char *pointer,
                     size_t length);
static void suboption(struct connectdata *);
static void sendsuboption(struct connectdata *conn, int option);

static CURLcode telnet_do(struct connectdata *conn, bool *done);
static CURLcode telnet_done(struct connectdata *conn,
                                 CURLcode, bool premature);
static CURLcode send_telnet_data(struct connectdata *conn,
                                 char *buffer, ssize_t nread);

/* For negotiation compliant to RFC 1143 */
#define CURL_NO          0
#define CURL_YES         1
#define CURL_WANTYES     2
#define CURL_WANTNO      3

#define CURL_EMPTY       0
#define CURL_OPPOSITE    1

/*
 * Telnet receiver states for fsm
 */
typedef enum
{
   CURL_TS_DATA = 0,
   CURL_TS_IAC,
   CURL_TS_WILL,
   CURL_TS_WONT,
   CURL_TS_DO,
   CURL_TS_DONT,
   CURL_TS_CR,
   CURL_TS_SB,   /* sub-option collection */
   CURL_TS_SE   /* looking for sub-option end */
} TelnetReceive;

struct TELNET {
  int please_negotiate;
  int already_negotiated;
  int us[256];
  int usq[256];
  int us_preferred[256];
  int him[256];
  int himq[256];
  int him_preferred[256];
  int subnegotiation[256];
  char subopt_ttype[32];             /* Set with suboption TTYPE */
  char subopt_xdisploc[128];         /* Set with suboption XDISPLOC */
  unsigned short subopt_wsx;         /* Set with suboption NAWS */
  unsigned short subopt_wsy;         /* Set with suboption NAWS */
  struct curl_slist *telnet_vars;    /* Environment variables */

  /* suboptions */
  unsigned char subbuffer[SUBBUFSIZE];
  unsigned char *subpointer, *subend;      /* buffer for sub-options */

  TelnetReceive telrcv_state;
};


/*
 * TELNET protocol handler.
 */

const struct Curl_handler Curl_handler_telnet = {
  "TELNET",                             /* scheme */
  ZERO_NULL,                            /* setup_connection */
  telnet_do,                            /* do_it */
  telnet_done,                          /* done */
  ZERO_NULL,                            /* do_more */
  ZERO_NULL,                            /* connect_it */
  ZERO_NULL,                            /* connecting */
  ZERO_NULL,                            /* doing */
  ZERO_NULL,                            /* proto_getsock */
  ZERO_NULL,                            /* doing_getsock */
  ZERO_NULL,                            /* domore_getsock */
  ZERO_NULL,                            /* perform_getsock */
  ZERO_NULL,                            /* disconnect */
  ZERO_NULL,                            /* readwrite */
  PORT_TELNET,                          /* defport */
  CURLPROTO_TELNET,                     /* protocol */
  PROTOPT_NONE | PROTOPT_NOURLQUERY     /* flags */
};


#ifdef USE_WINSOCK
static CURLcode
check_wsock2 ( struct SessionHandle *data )
{
  int err;
  WORD wVersionRequested;
  WSADATA wsaData;

  DEBUGASSERT(data);

  /* telnet requires at least WinSock 2.0 so ask for it. */
  wVersionRequested = MAKEWORD(2, 0);

  err = WSAStartup(wVersionRequested, &wsaData);

  /* We must've called this once already, so this call */
  /* should always succeed.  But, just in case... */
  if(err != 0) {
    failf(data,"WSAStartup failed (%d)",err);
    return CURLE_FAILED_INIT;
  }

  /* We have to have a WSACleanup call for every successful */
  /* WSAStartup call. */
  WSACleanup();

  /* Check that our version is supported */
  if(LOBYTE(wsaData.wVersion) != LOBYTE(wVersionRequested) ||
      HIBYTE(wsaData.wVersion) != HIBYTE(wVersionRequested)) {
      /* Our version isn't supported */
    failf(data, "insufficient winsock version to support "
          "telnet");
    return CURLE_FAILED_INIT;
  }

  /* Our version is supported */
  return CURLE_OK;
}
#endif

static
CURLcode init_telnet(struct connectdata *conn)
{
  struct TELNET *tn;

  tn = calloc(1, sizeof(struct TELNET));
  if(!tn)
    return CURLE_OUT_OF_MEMORY;

  conn->data->req.protop = tn; /* make us known */

  tn->telrcv_state = CURL_TS_DATA;

  /* Init suboptions */
  CURL_SB_CLEAR(tn);

  /* Set the options we want by default */
  tn->us_preferred[CURL_TELOPT_SGA] = CURL_YES;
  tn->him_preferred[CURL_TELOPT_SGA] = CURL_YES;

  /* To be compliant with previous releases of libcurl
     we enable this option by default. This behaviour
         can be changed thanks to the "BINARY" option in
         CURLOPT_TELNETOPTIONS
  */
  tn->us_preferred[CURL_TELOPT_BINARY] = CURL_YES;
  tn->him_preferred[CURL_TELOPT_BINARY] = CURL_YES;

  /* We must allow the server to echo what we sent
         but it is not necessary to request the server
         to do so (it might forces the server to close
         the connection). Hence, we ignore ECHO in the
         negotiate function
  */
  tn->him_preferred[CURL_TELOPT_ECHO] = CURL_YES;

  /* Set the subnegotiation fields to send information
    just after negotiation passed (do/will)

     Default values are (0,0) initialized by calloc.
     According to the RFC1013 it is valid:
     A value equal to zero is acceptable for the width (or height),
         and means that no character width (or height) is being sent.
         In this case, the width (or height) that will be assumed by the
         Telnet server is operating system specific (it will probably be
         based upon the terminal type information that may have been sent
         using the TERMINAL TYPE Telnet option). */
  tn->subnegotiation[CURL_TELOPT_NAWS] = CURL_YES;
  return CURLE_OK;
}

static void negotiate(struct connectdata *conn)
{
  int i;
  struct TELNET *tn = (struct TELNET *) conn->data->req.protop;

  for(i = 0;i < CURL_NTELOPTS;i++) {
    if(i==CURL_TELOPT_ECHO)
      continue;

    if(tn->us_preferred[i] == CURL_YES)
      set_local_option(conn, i, CURL_YES);

    if(tn->him_preferred[i] == CURL_YES)
      set_remote_option(conn, i, CURL_YES);
  }
}

#ifndef CURL_DISABLE_VERBOSE_STRINGS
static void printoption(struct SessionHandle *data,
                        const char *direction, int cmd, int option)
{
  const char *fmt;
  const char *opt;

  if(data->set.verbose) {
    if(cmd == CURL_IAC) {
      if(CURL_TELCMD_OK(option))
        infof(data, "%s IAC %s\n", direction, CURL_TELCMD(option));
      else
        infof(data, "%s IAC %d\n", direction, option);
    }
    else {
      fmt = (cmd == CURL_WILL) ? "WILL" : (cmd == CURL_WONT) ? "WONT" :
        (cmd == CURL_DO) ? "DO" : (cmd == CURL_DONT) ? "DONT" : 0;
      if(fmt) {
        if(CURL_TELOPT_OK(option))
          opt = CURL_TELOPT(option);
        else if(option == CURL_TELOPT_EXOPL)
          opt = "EXOPL";
        else
          opt = NULL;

        if(opt)
          infof(data, "%s %s %s\n", direction, fmt, opt);
        else
          infof(data, "%s %s %d\n", direction, fmt, option);
      }
      else
        infof(data, "%s %d %d\n", direction, cmd, option);
    }
  }
}
#endif

static void send_negotiation(struct connectdata *conn, int cmd, int option)
{
   unsigned char buf[3];
   ssize_t bytes_written;
   int err;
   struct SessionHandle *data = conn->data;

   buf[0] = CURL_IAC;
   buf[1] = (unsigned char)cmd;
   buf[2] = (unsigned char)option;

   bytes_written = swrite(conn->sock[FIRSTSOCKET], buf, 3);
   if(bytes_written < 0) {
     err = SOCKERRNO;
     failf(data,"Sending data failed (%d)",err);
   }

   printoption(conn->data, "SENT", cmd, option);
}

static
void set_remote_option(struct connectdata *conn, int option, int newstate)
{
  struct TELNET *tn = (struct TELNET *)conn->data->req.protop;
  if(newstate == CURL_YES) {
    switch(tn->him[option]) {
    case CURL_NO:
      tn->him[option] = CURL_WANTYES;
      send_negotiation(conn, CURL_DO, option);
      break;

    case CURL_YES:
      /* Already enabled */
      break;

    case CURL_WANTNO:
      switch(tn->himq[option]) {
      case CURL_EMPTY:
        /* Already negotiating for CURL_YES, queue the request */
        tn->himq[option] = CURL_OPPOSITE;
        break;
      case CURL_OPPOSITE:
        /* Error: already queued an enable request */
        break;
      }
      break;

    case CURL_WANTYES:
      switch(tn->himq[option]) {
      case CURL_EMPTY:
        /* Error: already negotiating for enable */
        break;
      case CURL_OPPOSITE:
        tn->himq[option] = CURL_EMPTY;
        break;
      }
      break;
    }
  }
  else { /* NO */
    switch(tn->him[option]) {
    case CURL_NO:
      /* Already disabled */
      break;

    case CURL_YES:
      tn->him[option] = CURL_WANTNO;
      send_negotiation(conn, CURL_DONT, option);
      break;

    case CURL_WANTNO:
      switch(tn->himq[option]) {
      case CURL_EMPTY:
        /* Already negotiating for NO */
        break;
      case CURL_OPPOSITE:
        tn->himq[option] = CURL_EMPTY;
        break;
      }
      break;

    case CURL_WANTYES:
      switch(tn->himq[option]) {
      case CURL_EMPTY:
        tn->himq[option] = CURL_OPPOSITE;
        break;
      case CURL_OPPOSITE:
        break;
      }
      break;
    }
  }
}

static
void rec_will(struct connectdata *conn, int option)
{
  struct TELNET *tn = (struct TELNET *)conn->data->req.protop;
  switch(tn->him[option]) {
  case CURL_NO:
    if(tn->him_preferred[option] == CURL_YES) {
      tn->him[option] = CURL_YES;
      send_negotiation(conn, CURL_DO, option);
    }
    else
      send_negotiation(conn, CURL_DONT, option);

    break;

  case CURL_YES:
    /* Already enabled */
    break;

  case CURL_WANTNO:
    switch(tn->himq[option]) {
    case CURL_EMPTY:
      /* Error: DONT answered by WILL */
      tn->him[option] = CURL_NO;
      break;
    case CURL_OPPOSITE:
      /* Error: DONT answered by WILL */
      tn->him[option] = CURL_YES;
      tn->himq[option] = CURL_EMPTY;
      break;
    }
    break;

  case CURL_WANTYES:
    switch(tn->himq[option]) {
    case CURL_EMPTY:
      tn->him[option] = CURL_YES;
      break;
    case CURL_OPPOSITE:
      tn->him[option] = CURL_WANTNO;
      tn->himq[option] = CURL_EMPTY;
      send_negotiation(conn, CURL_DONT, option);
      break;
    }
    break;
  }
}

static
void rec_wont(struct connectdata *conn, int option)
{
  struct TELNET *tn = (struct TELNET *)conn->data->req.protop;
  switch(tn->him[option]) {
  case CURL_NO:
    /* Already disabled */
    break;

  case CURL_YES:
    tn->him[option] = CURL_NO;
    send_negotiation(conn, CURL_DONT, option);
    break;

  case CURL_WANTNO:
    switch(tn->himq[option]) {
    case CURL_EMPTY:
      tn->him[option] = CURL_NO;
      break;

    case CURL_OPPOSITE:
      tn->him[option] = CURL_WANTYES;
      tn->himq[option] = CURL_EMPTY;
      send_negotiation(conn, CURL_DO, option);
      break;
    }
    break;

  case CURL_WANTYES:
    switch(tn->himq[option]) {
    case CURL_EMPTY:
      tn->him[option] = CURL_NO;
      break;
    case CURL_OPPOSITE:
      tn->him[option] = CURL_NO;
      tn->himq[option] = CURL_EMPTY;
      break;
    }
    break;
  }
}

static void
set_local_option(struct connectdata *conn, int option, int newstate)
{
  struct TELNET *tn = (struct TELNET *)conn->data->req.protop;
  if(newstate == CURL_YES) {
    switch(tn->us[option]) {
    case CURL_NO:
      tn->us[option] = CURL_WANTYES;
      send_negotiation(conn, CURL_WILL, option);
      break;

    case CURL_YES:
      /* Already enabled */
      break;

    case CURL_WANTNO:
      switch(tn->usq[option]) {
      case CURL_EMPTY:
        /* Already negotiating for CURL_YES, queue the request */
        tn->usq[option] = CURL_OPPOSITE;
        break;
      case CURL_OPPOSITE:
        /* Error: already queued an enable request */
        break;
      }
      break;

    case CURL_WANTYES:
      switch(tn->usq[option]) {
      case CURL_EMPTY:
        /* Error: already negotiating for enable */
        break;
      case CURL_OPPOSITE:
        tn->usq[option] = CURL_EMPTY;
        break;
      }
      break;
    }
  }
  else { /* NO */
    switch(tn->us[option]) {
    case CURL_NO:
      /* Already disabled */
      break;

    case CURL_YES:
      tn->us[option] = CURL_WANTNO;
      send_negotiation(conn, CURL_WONT, option);
      break;

    case CURL_WANTNO:
      switch(tn->usq[option]) {
      case CURL_EMPTY:
        /* Already negotiating for NO */
        break;
      case CURL_OPPOSITE:
        tn->usq[option] = CURL_EMPTY;
        break;
      }
      break;

    case CURL_WANTYES:
      switch(tn->usq[option]) {
      case CURL_EMPTY:
        tn->usq[option] = CURL_OPPOSITE;
        break;
      case CURL_OPPOSITE:
        break;
      }
      break;
    }
  }
}

static
void rec_do(struct connectdata *conn, int option)
{
  struct TELNET *tn = (struct TELNET *)conn->data->req.protop;
  switch(tn->us[option]) {
  case CURL_NO:
    if(tn->us_preferred[option] == CURL_YES) {
      tn->us[option] = CURL_YES;
      send_negotiation(conn, CURL_WILL, option);
      if(tn->subnegotiation[option] == CURL_YES)
        /* transmission of data option */
        sendsuboption(conn, option);
    }
    else if(tn->subnegotiation[option] == CURL_YES) {
      /* send information to achieve this option*/
      tn->us[option] = CURL_YES;
      send_negotiation(conn, CURL_WILL, option);
      sendsuboption(conn, option);
    }
    else
      send_negotiation(conn, CURL_WONT, option);
    break;

  case CURL_YES:
    /* Already enabled */
    break;

  case CURL_WANTNO:
    switch(tn->usq[option]) {
    case CURL_EMPTY:
      /* Error: DONT answered by WILL */
      tn->us[option] = CURL_NO;
      break;
    case CURL_OPPOSITE:
      /* Error: DONT answered by WILL */
      tn->us[option] = CURL_YES;
      tn->usq[option] = CURL_EMPTY;
      break;
    }
    break;

  case CURL_WANTYES:
    switch(tn->usq[option]) {
    case CURL_EMPTY:
      tn->us[option] = CURL_YES;
      if(tn->subnegotiation[option] == CURL_YES) {
        /* transmission of data option */
        sendsuboption(conn, option);
      }
      break;
    case CURL_OPPOSITE:
      tn->us[option] = CURL_WANTNO;
      tn->himq[option] = CURL_EMPTY;
      send_negotiation(conn, CURL_WONT, option);
      break;
    }
    break;
  }
}

static
void rec_dont(struct connectdata *conn, int option)
{
  struct TELNET *tn = (struct TELNET *)conn->data->req.protop;
  switch(tn->us[option]) {
  case CURL_NO:
    /* Already disabled */
    break;

  case CURL_YES:
    tn->us[option] = CURL_NO;
    send_negotiation(conn, CURL_WONT, option);
    break;

  case CURL_WANTNO:
    switch(tn->usq[option]) {
    case CURL_EMPTY:
      tn->us[option] = CURL_NO;
      break;

    case CURL_OPPOSITE:
      tn->us[option] = CURL_WANTYES;
      tn->usq[option] = CURL_EMPTY;
      send_negotiation(conn, CURL_WILL, option);
      break;
    }
    break;

  case CURL_WANTYES:
    switch(tn->usq[option]) {
    case CURL_EMPTY:
      tn->us[option] = CURL_NO;
      break;
    case CURL_OPPOSITE:
      tn->us[option] = CURL_NO;
      tn->usq[option] = CURL_EMPTY;
      break;
    }
    break;
  }
}


static void printsub(struct SessionHandle *data,
                     int direction,             /* '<' or '>' */
                     unsigned char *pointer,    /* where suboption data is */
                     size_t length)             /* length of suboption data */
{
  unsigned int i = 0;

  if(data->set.verbose) {
    if(direction) {
      infof(data, "%s IAC SB ", (direction == '<')? "RCVD":"SENT");
      if(length >= 3) {
        int j;

        i = pointer[length-2];
        j = pointer[length-1];

        if(i != CURL_IAC || j != CURL_SE) {
          infof(data, "(terminated by ");
          if(CURL_TELOPT_OK(i))
            infof(data, "%s ", CURL_TELOPT(i));
          else if(CURL_TELCMD_OK(i))
            infof(data, "%s ", CURL_TELCMD(i));
          else
            infof(data, "%u ", i);
          if(CURL_TELOPT_OK(j))
            infof(data, "%s", CURL_TELOPT(j));
          else if(CURL_TELCMD_OK(j))
            infof(data, "%s", CURL_TELCMD(j));
          else
            infof(data, "%d", j);
          infof(data, ", not IAC SE!) ");
        }
      }
      length -= 2;
    }
    if(length < 1) {
      infof(data, "(Empty suboption?)");
      return;
    }

    if(CURL_TELOPT_OK(pointer[0])) {
      switch(pointer[0]) {
      case CURL_TELOPT_TTYPE:
      case CURL_TELOPT_XDISPLOC:
      case CURL_TELOPT_NEW_ENVIRON:
      case CURL_TELOPT_NAWS:
        infof(data, "%s", CURL_TELOPT(pointer[0]));
        break;
      default:
        infof(data, "%s (unsupported)", CURL_TELOPT(pointer[0]));
        break;
      }
    }
    else
      infof(data, "%d (unknown)", pointer[i]);

    switch(pointer[0]) {
    case CURL_TELOPT_NAWS:
      if(length > 4)
        infof(data, "Width: %hu ; Height: %hu", (pointer[1]<<8) | pointer[2],
              (pointer[3]<<8) | pointer[4]);
      break;
    default:
      switch(pointer[1]) {
      case CURL_TELQUAL_IS:
        infof(data, " IS");
        break;
      case CURL_TELQUAL_SEND:
        infof(data, " SEND");
        break;
      case CURL_TELQUAL_INFO:
        infof(data, " INFO/REPLY");
        break;
      case CURL_TELQUAL_NAME:
        infof(data, " NAME");
        break;
      }

      switch(pointer[0]) {
      case CURL_TELOPT_TTYPE:
      case CURL_TELOPT_XDISPLOC:
        pointer[length] = 0;
        infof(data, " \"%s\"", &pointer[2]);
        break;
      case CURL_TELOPT_NEW_ENVIRON:
        if(pointer[1] == CURL_TELQUAL_IS) {
          infof(data, " ");
          for(i = 3;i < length;i++) {
            switch(pointer[i]) {
            case CURL_NEW_ENV_VAR:
              infof(data, ", ");
              break;
            case CURL_NEW_ENV_VALUE:
              infof(data, " = ");
              break;
            default:
              infof(data, "%c", pointer[i]);
              break;
            }
          }
        }
        break;
      default:
        for(i = 2; i < length; i++)
          infof(data, " %.2x", pointer[i]);
        break;
      }
    }
    if(direction)
      infof(data, "\n");
  }
}

static CURLcode check_telnet_options(struct connectdata *conn)
{
  struct curl_slist *head;
  struct curl_slist *beg;
  char option_keyword[128] = "";
  char option_arg[256] = "";
  struct SessionHandle *data = conn->data;
  struct TELNET *tn = (struct TELNET *)conn->data->req.protop;
  CURLcode result = CURLE_OK;
  int binary_option;

  /* Add the user name as an environment variable if it
     was given on the command line */
  if(conn->bits.user_passwd) {
    snprintf(option_arg, sizeof(option_arg), "USER,%s", conn->user);
    beg = curl_slist_append(tn->telnet_vars, option_arg);
    if(!beg) {
      curl_slist_free_all(tn->telnet_vars);
      tn->telnet_vars = NULL;
      return CURLE_OUT_OF_MEMORY;
    }
    tn->telnet_vars = beg;
    tn->us_preferred[CURL_TELOPT_NEW_ENVIRON] = CURL_YES;
  }

  for(head = data->set.telnet_options; head; head=head->next) {
    if(sscanf(head->data, "%127[^= ]%*[ =]%255s",
              option_keyword, option_arg) == 2) {

      /* Terminal type */
      if(Curl_raw_equal(option_keyword, "TTYPE")) {
        strncpy(tn->subopt_ttype, option_arg, 31);
        tn->subopt_ttype[31] = 0; /* String termination */
        tn->us_preferred[CURL_TELOPT_TTYPE] = CURL_YES;
        continue;
      }

      /* Display variable */
      if(Curl_raw_equal(option_keyword, "XDISPLOC")) {
        strncpy(tn->subopt_xdisploc, option_arg, 127);
        tn->subopt_xdisploc[127] = 0; /* String termination */
        tn->us_preferred[CURL_TELOPT_XDISPLOC] = CURL_YES;
        continue;
      }

      /* Environment variable */
      if(Curl_raw_equal(option_keyword, "NEW_ENV")) {
        beg = curl_slist_append(tn->telnet_vars, option_arg);
        if(!beg) {
          result = CURLE_OUT_OF_MEMORY;
          break;
        }
        tn->telnet_vars = beg;
        tn->us_preferred[CURL_TELOPT_NEW_ENVIRON] = CURL_YES;
        continue;
      }

          /* Window Size */
      if(Curl_raw_equal(option_keyword, "WS")) {
        if(sscanf(option_arg, "%hu%*[xX]%hu",
                  &tn->subopt_wsx, &tn->subopt_wsy) == 2)
          tn->us_preferred[CURL_TELOPT_NAWS] = CURL_YES;
        else {
          failf(data, "Syntax error in telnet option: %s", head->data);
          result = CURLE_TELNET_OPTION_SYNTAX;
          break;
        }
        continue;
      }

      /* To take care or not of the 8th bit in data exchange */
      if(Curl_raw_equal(option_keyword, "BINARY")) {
        binary_option=atoi(option_arg);
        if(binary_option!=1) {
          tn->us_preferred[CURL_TELOPT_BINARY] = CURL_NO;
          tn->him_preferred[CURL_TELOPT_BINARY] = CURL_NO;
        }
        continue;
      }

      failf(data, "Unknown telnet option %s", head->data);
      result = CURLE_UNKNOWN_TELNET_OPTION;
      break;
    }
    else {
      failf(data, "Syntax error in telnet option: %s", head->data);
      result = CURLE_TELNET_OPTION_SYNTAX;
      break;
    }
  }

  if(result) {
    curl_slist_free_all(tn->telnet_vars);
    tn->telnet_vars = NULL;
  }

  return result;
}

/*
 * suboption()
 *
 * Look at the sub-option buffer, and try to be helpful to the other
 * side.
 */

static void suboption(struct connectdata *conn)
{
  struct curl_slist *v;
  unsigned char temp[2048];
  ssize_t bytes_written;
  size_t len;
  size_t tmplen;
  int err;
  char varname[128] = "";
  char varval[128] = "";
  struct SessionHandle *data = conn->data;
  struct TELNET *tn = (struct TELNET *)data->req.protop;

  printsub(data, '<', (unsigned char *)tn->subbuffer, CURL_SB_LEN(tn)+2);
  switch (CURL_SB_GET(tn)) {
    case CURL_TELOPT_TTYPE:
      len = strlen(tn->subopt_ttype) + 4 + 2;
      snprintf((char *)temp, sizeof(temp),
               "%c%c%c%c%s%c%c", CURL_IAC, CURL_SB, CURL_TELOPT_TTYPE,
               CURL_TELQUAL_IS, tn->subopt_ttype, CURL_IAC, CURL_SE);
      bytes_written = swrite(conn->sock[FIRSTSOCKET], temp, len);
      if(bytes_written < 0) {
        err = SOCKERRNO;
        failf(data,"Sending data failed (%d)",err);
      }
      printsub(data, '>', &temp[2], len-2);
      break;
    case CURL_TELOPT_XDISPLOC:
      len = strlen(tn->subopt_xdisploc) + 4 + 2;
      snprintf((char *)temp, sizeof(temp),
               "%c%c%c%c%s%c%c", CURL_IAC, CURL_SB, CURL_TELOPT_XDISPLOC,
               CURL_TELQUAL_IS, tn->subopt_xdisploc, CURL_IAC, CURL_SE);
      bytes_written = swrite(conn->sock[FIRSTSOCKET], temp, len);
      if(bytes_written < 0) {
        err = SOCKERRNO;
        failf(data,"Sending data failed (%d)",err);
      }
      printsub(data, '>', &temp[2], len-2);
      break;
    case CURL_TELOPT_NEW_ENVIRON:
      snprintf((char *)temp, sizeof(temp),
               "%c%c%c%c", CURL_IAC, CURL_SB, CURL_TELOPT_NEW_ENVIRON,
               CURL_TELQUAL_IS);
      len = 4;

      for(v = tn->telnet_vars;v;v = v->next) {
        tmplen = (strlen(v->data) + 1);
        /* Add the variable only if it fits */
        if(len + tmplen < (int)sizeof(temp)-6) {
          if(sscanf(v->data, "%127[^,],%127s", varname, varval)) {
            snprintf((char *)&temp[len], sizeof(temp) - len,
                     "%c%s%c%s", CURL_NEW_ENV_VAR, varname,
                     CURL_NEW_ENV_VALUE, varval);
            len += tmplen;
          }
        }
      }
      snprintf((char *)&temp[len], sizeof(temp) - len,
               "%c%c", CURL_IAC, CURL_SE);
      len += 2;
      bytes_written = swrite(conn->sock[FIRSTSOCKET], temp, len);
      if(bytes_written < 0) {
        err = SOCKERRNO;
        failf(data,"Sending data failed (%d)",err);
      }
      printsub(data, '>', &temp[2], len-2);
      break;
  }
  return;
}


/*
 * sendsuboption()
 *
 * Send suboption information to the server side.
 */

static void sendsuboption(struct connectdata *conn, int option)
{
  ssize_t bytes_written;
  int err;
  unsigned short x, y;
  unsigned char*uc1, *uc2;

  struct SessionHandle *data = conn->data;
  struct TELNET *tn = (struct TELNET *)data->req.protop;

  switch (option) {
  case CURL_TELOPT_NAWS:
    /* We prepare data to be sent */
    CURL_SB_CLEAR(tn);
    CURL_SB_ACCUM(tn, CURL_IAC);
    CURL_SB_ACCUM(tn, CURL_SB);
    CURL_SB_ACCUM(tn, CURL_TELOPT_NAWS);
    /* We must deal either with litte or big endien processors */
    /* Window size must be sent according to the 'network order' */
    x=htons(tn->subopt_wsx);
    y=htons(tn->subopt_wsy);
    uc1 = (unsigned char*)&x;
    uc2 = (unsigned char*)&y;
    CURL_SB_ACCUM(tn, uc1[0]);
    CURL_SB_ACCUM(tn, uc1[1]);
    CURL_SB_ACCUM(tn, uc2[0]);
    CURL_SB_ACCUM(tn, uc2[1]);

    CURL_SB_ACCUM(tn, CURL_IAC);
    CURL_SB_ACCUM(tn, CURL_SE);
    CURL_SB_TERM(tn);
    /* data suboption is now ready */

    printsub(data, '>', (unsigned char *)tn->subbuffer+2,
             CURL_SB_LEN(tn)-2);

    /* we send the header of the suboption... */
    bytes_written = swrite(conn->sock[FIRSTSOCKET], tn->subbuffer, 3);
    if(bytes_written < 0) {
      err = SOCKERRNO;
      failf(data, "Sending data failed (%d)", err);
    }
    /* ... then the window size with the send_telnet_data() function
       to deal with 0xFF cases ... */
    send_telnet_data(conn, (char *)tn->subbuffer+3, 4);
    /* ... and the footer */
    bytes_written = swrite(conn->sock[FIRSTSOCKET], tn->subbuffer+7, 2);
    if(bytes_written < 0) {
      err = SOCKERRNO;
      failf(data, "Sending data failed (%d)", err);
    }
    break;
  }
}


static
CURLcode telrcv(struct connectdata *conn,
                const unsigned char *inbuf, /* Data received from socket */
                ssize_t count)              /* Number of bytes received */
{
  unsigned char c;
  CURLcode result;
  int in = 0;
  int startwrite=-1;
  struct SessionHandle *data = conn->data;
  struct TELNET *tn = (struct TELNET *)data->req.protop;

#define startskipping()                                       \
  if(startwrite >= 0) {                                       \
    result = Curl_client_write(conn,                          \
                               CLIENTWRITE_BODY,              \
                               (char *)&inbuf[startwrite],    \
                               in-startwrite);                \
    if(result)                                                \
      return result;                                          \
  }                                                           \
  startwrite = -1

#define writebyte() \
    if(startwrite < 0) \
      startwrite = in

#define bufferflush() startskipping()

  while(count--) {
    c = inbuf[in];

    switch (tn->telrcv_state) {
    case CURL_TS_CR:
      tn->telrcv_state = CURL_TS_DATA;
      if(c == '\0') {
        startskipping();
        break;   /* Ignore \0 after CR */
      }
      writebyte();
      break;

    case CURL_TS_DATA:
      if(c == CURL_IAC) {
        tn->telrcv_state = CURL_TS_IAC;
        startskipping();
        break;
      }
      else if(c == '\r')
        tn->telrcv_state = CURL_TS_CR;
      writebyte();
      break;

    case CURL_TS_IAC:
    process_iac:
      DEBUGASSERT(startwrite < 0);
      switch (c) {
      case CURL_WILL:
        tn->telrcv_state = CURL_TS_WILL;
        break;
      case CURL_WONT:
        tn->telrcv_state = CURL_TS_WONT;
        break;
      case CURL_DO:
        tn->telrcv_state = CURL_TS_DO;
        break;
      case CURL_DONT:
        tn->telrcv_state = CURL_TS_DONT;
        break;
      case CURL_SB:
        CURL_SB_CLEAR(tn);
        tn->telrcv_state = CURL_TS_SB;
        break;
      case CURL_IAC:
        tn->telrcv_state = CURL_TS_DATA;
        writebyte();
        break;
      case CURL_DM:
      case CURL_NOP:
      case CURL_GA:
      default:
        tn->telrcv_state = CURL_TS_DATA;
        printoption(data, "RCVD", CURL_IAC, c);
        break;
      }
      break;

      case CURL_TS_WILL:
        printoption(data, "RCVD", CURL_WILL, c);
        tn->please_negotiate = 1;
        rec_will(conn, c);
        tn->telrcv_state = CURL_TS_DATA;
        break;

      case CURL_TS_WONT:
        printoption(data, "RCVD", CURL_WONT, c);
        tn->please_negotiate = 1;
        rec_wont(conn, c);
        tn->telrcv_state = CURL_TS_DATA;
        break;

      case CURL_TS_DO:
        printoption(data, "RCVD", CURL_DO, c);
        tn->please_negotiate = 1;
        rec_do(conn, c);
        tn->telrcv_state = CURL_TS_DATA;
        break;

      case CURL_TS_DONT:
        printoption(data, "RCVD", CURL_DONT, c);
        tn->please_negotiate = 1;
        rec_dont(conn, c);
        tn->telrcv_state = CURL_TS_DATA;
        break;

      case CURL_TS_SB:
        if(c == CURL_IAC)
          tn->telrcv_state = CURL_TS_SE;
        else
          CURL_SB_ACCUM(tn, c);
        break;

      case CURL_TS_SE:
        if(c != CURL_SE) {
          if(c != CURL_IAC) {
            /*
             * This is an error.  We only expect to get "IAC IAC" or "IAC SE".
             * Several things may have happened.  An IAC was not doubled, the
             * IAC SE was left off, or another option got inserted into the
             * suboption are all possibilities.  If we assume that the IAC was
             * not doubled, and really the IAC SE was left off, we could get
             * into an infinate loop here.  So, instead, we terminate the
             * suboption, and process the partial suboption if we can.
             */
            CURL_SB_ACCUM(tn, CURL_IAC);
            CURL_SB_ACCUM(tn, c);
            tn->subpointer -= 2;
            CURL_SB_TERM(tn);

            printoption(data, "In SUBOPTION processing, RCVD", CURL_IAC, c);
            suboption(conn);   /* handle sub-option */
            tn->telrcv_state = CURL_TS_IAC;
            goto process_iac;
          }
          CURL_SB_ACCUM(tn, c);
          tn->telrcv_state = CURL_TS_SB;
        }
        else
        {
          CURL_SB_ACCUM(tn, CURL_IAC);
          CURL_SB_ACCUM(tn, CURL_SE);
          tn->subpointer -= 2;
          CURL_SB_TERM(tn);
          suboption(conn);   /* handle sub-option */
          tn->telrcv_state = CURL_TS_DATA;
        }
        break;
    }
    ++in;
  }
  bufferflush();
  return CURLE_OK;
}

/* Escape and send a telnet data block */
/* TODO: write large chunks of data instead of one byte at a time */
static CURLcode send_telnet_data(struct connectdata *conn,
                                 char *buffer, ssize_t nread)
{
  unsigned char outbuf[2];
  ssize_t bytes_written, total_written;
  int out_count;
  CURLcode result = CURLE_OK;

  while(!result && nread--) {
    outbuf[0] = *buffer++;
    out_count = 1;
    if(outbuf[0] == CURL_IAC)
      outbuf[out_count++] = CURL_IAC;

    total_written = 0;
    do {
      /* Make sure socket is writable to avoid EWOULDBLOCK condition */
      struct pollfd pfd[1];
      pfd[0].fd = conn->sock[FIRSTSOCKET];
      pfd[0].events = POLLOUT;
      switch (Curl_poll(pfd, 1, -1)) {
        case -1:                    /* error, abort writing */
        case 0:                     /* timeout (will never happen) */
          result = CURLE_SEND_ERROR;
          break;
        default:                    /* write! */
          bytes_written = 0;
          result = Curl_write(conn, conn->sock[FIRSTSOCKET],
                              outbuf+total_written, out_count-total_written,
                              &bytes_written);
          total_written += bytes_written;
          break;
      }
      /* handle partial write */
    } while(!result && total_written < out_count);
  }
  return result;
}

static CURLcode telnet_done(struct connectdata *conn,
                                 CURLcode status, bool premature)
{
  struct TELNET *tn = (struct TELNET *)conn->data->req.protop;
  (void)status; /* unused */
  (void)premature; /* not used */

  if(!tn)
    return CURLE_OK;

  curl_slist_free_all(tn->telnet_vars);
  tn->telnet_vars = NULL;

  Curl_safefree(conn->data->req.protop);

  return CURLE_OK;
}

static CURLcode telnet_do(struct connectdata *conn, bool *done)
{
  CURLcode result;
  struct SessionHandle *data = conn->data;
  curl_socket_t sockfd = conn->sock[FIRSTSOCKET];
#ifdef USE_WINSOCK
  HMODULE wsock2;
  WSOCK2_FUNC close_event_func;
  WSOCK2_FUNC create_event_func;
  WSOCK2_FUNC event_select_func;
  WSOCK2_FUNC enum_netevents_func;
  WSAEVENT event_handle;
  WSANETWORKEVENTS events;
  HANDLE stdin_handle;
  HANDLE objs[2];
  DWORD  obj_count;
  DWORD  wait_timeout;
  DWORD waitret;
  DWORD readfile_read;
  int err;
#else
  int interval_ms;
  struct pollfd pfd[2];
  int poll_cnt;
  curl_off_t total_dl = 0;
  curl_off_t total_ul = 0;
#endif
  ssize_t nread;
  struct timeval now;
  bool keepon = TRUE;
  char *buf = data->state.buffer;
  struct TELNET *tn;

  *done = TRUE; /* unconditionally */

  result = init_telnet(conn);
  if(result)
    return result;

  tn = (struct TELNET *)data->req.protop;

  result = check_telnet_options(conn);
  if(result)
    return result;

#ifdef USE_WINSOCK
  /*
  ** This functionality only works with WinSock >= 2.0.  So,
  ** make sure have it.
  */
  result = check_wsock2(data);
  if(result)
    return result;

  /* OK, so we have WinSock 2.0.  We need to dynamically */
  /* load ws2_32.dll and get the function pointers we need. */
  wsock2 = LoadLibrary(TEXT("WS2_32.DLL"));
  if(wsock2 == NULL) {
    failf(data, "failed to load WS2_32.DLL (%d)", ERRNO);
    return CURLE_FAILED_INIT;
  }

  /* Grab a pointer to WSACreateEvent */
  create_event_func = GetProcAddress(wsock2, "WSACreateEvent");
  if(create_event_func == NULL) {
    failf(data, "failed to find WSACreateEvent function (%d)", ERRNO);
    FreeLibrary(wsock2);
    return CURLE_FAILED_INIT;
  }

  /* And WSACloseEvent */
  close_event_func = GetProcAddress(wsock2, "WSACloseEvent");
  if(close_event_func == NULL) {
    failf(data, "failed to find WSACloseEvent function (%d)", ERRNO);
    FreeLibrary(wsock2);
    return CURLE_FAILED_INIT;
  }

  /* And WSAEventSelect */
  event_select_func = GetProcAddress(wsock2, "WSAEventSelect");
  if(event_select_func == NULL) {
    failf(data, "failed to find WSAEventSelect function (%d)", ERRNO);
    FreeLibrary(wsock2);
    return CURLE_FAILED_INIT;
  }

  /* And WSAEnumNetworkEvents */
  enum_netevents_func = GetProcAddress(wsock2, "WSAEnumNetworkEvents");
  if(enum_netevents_func == NULL) {
    failf(data, "failed to find WSAEnumNetworkEvents function (%d)", ERRNO);
    FreeLibrary(wsock2);
    return CURLE_FAILED_INIT;
  }

  /* We want to wait for both stdin and the socket. Since
  ** the select() function in winsock only works on sockets
  ** we have to use the WaitForMultipleObjects() call.
  */

  /* First, create a sockets event object */
  event_handle = (WSAEVENT)create_event_func();
  if(event_handle == WSA_INVALID_EVENT) {
    failf(data, "WSACreateEvent failed (%d)", SOCKERRNO);
    FreeLibrary(wsock2);
    return CURLE_FAILED_INIT;
  }

  /* Tell winsock what events we want to listen to */
  if(event_select_func(sockfd, event_handle, FD_READ|FD_CLOSE) ==
     SOCKET_ERROR) {
    close_event_func(event_handle);
    FreeLibrary(wsock2);
    return CURLE_OK;
  }

  /* The get the Windows file handle for stdin */
  stdin_handle = GetStdHandle(STD_INPUT_HANDLE);

  /* Create the list of objects to wait for */
  objs[0] = event_handle;
  objs[1] = stdin_handle;

  /* If stdin_handle is a pipe, use PeekNamedPipe() method to check it,
     else use the old WaitForMultipleObjects() way */
  if(GetFileType(stdin_handle) == FILE_TYPE_PIPE ||
     data->set.is_fread_set) {
    /* Don't wait for stdin_handle, just wait for event_handle */
    obj_count = 1;
    /* Check stdin_handle per 100 milliseconds */
    wait_timeout = 100;
  }
  else {
    obj_count = 2;
    wait_timeout = 1000;
  }

  /* Keep on listening and act on events */
  while(keepon) {
    waitret = WaitForMultipleObjects(obj_count, objs, FALSE, wait_timeout);
    switch(waitret) {
    case WAIT_TIMEOUT:
    {
      for(;;) {
        if(data->set.is_fread_set) {
          /* read from user-supplied method */
          result = (int)data->state.fread_func(buf, 1, BUFSIZE - 1,
                                               data->state.in);
          if(result == CURL_READFUNC_ABORT) {
            keepon = FALSE;
            result = CURLE_READ_ERROR;
            break;
          }

          if(result == CURL_READFUNC_PAUSE)
            break;

          if(result == 0)                        /* no bytes */
            break;

          readfile_read = result; /* fall thru with number of bytes read */
        }
        else {
          /* read from stdin */
          if(!PeekNamedPipe(stdin_handle, NULL, 0, NULL,
                            &readfile_read, NULL)) {
            keepon = FALSE;
            result = CURLE_READ_ERROR;
            break;
          }

          if(!readfile_read)
            break;

          if(!ReadFile(stdin_handle, buf, sizeof(data->state.buffer),
                       &readfile_read, NULL)) {
            keepon = FALSE;
            result = CURLE_READ_ERROR;
            break;
          }
        }

        result = send_telnet_data(conn, buf, readfile_read);
        if(result) {
          keepon = FALSE;
          break;
        }
      }
    }
    break;

    case WAIT_OBJECT_0 + 1:
    {
      if(!ReadFile(stdin_handle, buf, sizeof(data->state.buffer),
                   &readfile_read, NULL)) {
        keepon = FALSE;
        result = CURLE_READ_ERROR;
        break;
      }

      result = send_telnet_data(conn, buf, readfile_read);
      if(result) {
        keepon = FALSE;
        break;
      }
    }
    break;

    case WAIT_OBJECT_0:

      events.lNetworkEvents = 0;
      if(SOCKET_ERROR == enum_netevents_func(sockfd, event_handle, &events)) {
        if((err = SOCKERRNO) != EINPROGRESS) {
          infof(data, "WSAEnumNetworkEvents failed (%d)", err);
          keepon = FALSE;
          result = CURLE_READ_ERROR;
        }
        break;
      }
      if(events.lNetworkEvents & FD_READ) {
        /* read data from network */
        result = Curl_read(conn, sockfd, buf, BUFSIZE - 1, &nread);
        /* read would've blocked. Loop again */
        if(result == CURLE_AGAIN)
          break;
        /* returned not-zero, this an error */
        else if(result) {
          keepon = FALSE;
          break;
        }
        /* returned zero but actually received 0 or less here,
           the server closed the connection and we bail out */
        else if(nread <= 0) {
          keepon = FALSE;
          break;
        }

        result = telrcv(conn, (unsigned char *) buf, nread);
        if(result) {
          keepon = FALSE;
          break;
        }

        /* Negotiate if the peer has started negotiating,
           otherwise don't. We don't want to speak telnet with
           non-telnet servers, like POP or SMTP. */
        if(tn->please_negotiate && !tn->already_negotiated) {
          negotiate(conn);
          tn->already_negotiated = 1;
        }
      }
      if(events.lNetworkEvents & FD_CLOSE) {
        keepon = FALSE;
      }
      break;

    }

    if(data->set.timeout) {
      now = Curl_tvnow();
      if(Curl_tvdiff(now, conn->created) >= data->set.timeout) {
        failf(data, "Time-out");
        result = CURLE_OPERATION_TIMEDOUT;
        keepon = FALSE;
      }
    }
  }

  /* We called WSACreateEvent, so call WSACloseEvent */
  if(!close_event_func(event_handle)) {
    infof(data, "WSACloseEvent failed (%d)", SOCKERRNO);
  }

  /* "Forget" pointers into the library we're about to free */
  create_event_func = NULL;
  close_event_func = NULL;
  event_select_func = NULL;
  enum_netevents_func = NULL;

  /* We called LoadLibrary, so call FreeLibrary */
  if(!FreeLibrary(wsock2))
    infof(data, "FreeLibrary(wsock2) failed (%d)", ERRNO);
#else
  pfd[0].fd = sockfd;
  pfd[0].events = POLLIN;

  if(data->set.is_fread_set) {
    poll_cnt = 1;
    interval_ms = 100; /* poll user-supplied read function */
  }
  else {
    /* really using fread, so infile is a FILE* */
    pfd[1].fd = fileno((FILE *)data->state.in);
    pfd[1].events = POLLIN;
    poll_cnt = 2;
    interval_ms = 1 * 1000;
  }

  while(keepon) {
    switch (Curl_poll(pfd, poll_cnt, interval_ms)) {
    case -1:                    /* error, stop reading */
      keepon = FALSE;
      continue;
    case 0:                     /* timeout */
      pfd[0].revents = 0;
      pfd[1].revents = 0;
      /* fall through */
    default:                    /* read! */
      if(pfd[0].revents & POLLIN) {
        /* read data from network */
        result = Curl_read(conn, sockfd, buf, BUFSIZE - 1, &nread);
        /* read would've blocked. Loop again */
        if(result == CURLE_AGAIN)
          break;
        /* returned not-zero, this an error */
        else if(result) {
          keepon = FALSE;
          break;
        }
        /* returned zero but actually received 0 or less here,
           the server closed the connection and we bail out */
        else if(nread <= 0) {
          keepon = FALSE;
          break;
        }

        total_dl += nread;
        Curl_pgrsSetDownloadCounter(data, total_dl);
        result = telrcv(conn, (unsigned char *)buf, nread);
        if(result) {
          keepon = FALSE;
          break;
        }

        /* Negotiate if the peer has started negotiating,
           otherwise don't. We don't want to speak telnet with
           non-telnet servers, like POP or SMTP. */
        if(tn->please_negotiate && !tn->already_negotiated) {
          negotiate(conn);
          tn->already_negotiated = 1;
        }
      }

      nread = 0;
      if(poll_cnt == 2) {
        if(pfd[1].revents & POLLIN) { /* read from in file */
          nread = read(pfd[1].fd, buf, BUFSIZE - 1);
        }
      }
      else {
        /* read from user-supplied method */
        nread = (int)data->state.fread_func(buf, 1, BUFSIZE - 1,
                                            data->state.in);
        if(nread == CURL_READFUNC_ABORT) {
          keepon = FALSE;
          break;
        }
        if(nread == CURL_READFUNC_PAUSE)
          break;
      }

      if(nread > 0) {
        result = send_telnet_data(conn, buf, nread);
        if(result) {
          keepon = FALSE;
          break;
        }
        total_ul += nread;
        Curl_pgrsSetUploadCounter(data, total_ul);
      }
      else if(nread < 0)
        keepon = FALSE;

      break;
    } /* poll switch statement */

    if(data->set.timeout) {
      now = Curl_tvnow();
      if(Curl_tvdiff(now, conn->created) >= data->set.timeout) {
        failf(data, "Time-out");
        result = CURLE_OPERATION_TIMEDOUT;
        keepon = FALSE;
      }
    }

    if(Curl_pgrsUpdate(conn)) {
      result = CURLE_ABORTED_BY_CALLBACK;
      break;
    }
  }
#endif
  /* mark this as "no further transfer wanted" */
  Curl_setup_transfer(conn, -1, -1, FALSE, NULL, -1, NULL);

  return result;
}
#endif
