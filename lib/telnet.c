/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
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
 * SPDX-License-Identifier: fetch
 *
 ***************************************************************************/

#include "fetch_setup.h"

#ifndef FETCH_DISABLE_TELNET

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
#include <fetch/fetch.h>
#include "transfer.h"
#include "sendf.h"
#include "telnet.h"
#include "connect.h"
#include "progress.h"
#include "system_win32.h"
#include "arpa_telnet.h"
#include "select.h"
#include "strcase.h"
#include "warnless.h"

/* The last 3 #include files should be in this order */
#include "fetch_printf.h"
#include "fetch_memory.h"
#include "memdebug.h"

#define SUBBUFSIZE 512

#define FETCH_SB_CLEAR(x) x->subpointer = x->subbuffer
#define FETCH_SB_TERM(x)       \
  do                           \
  {                            \
    x->subend = x->subpointer; \
    FETCH_SB_CLEAR(x);         \
  } while (0)
#define FETCH_SB_ACCUM(x, c)                                   \
  do                                                           \
  {                                                            \
    if (x->subpointer < (x->subbuffer + sizeof(x->subbuffer))) \
      *x->subpointer++ = (c);                                  \
  } while (0)

#define FETCH_SB_GET(x) ((*x->subpointer++) & 0xff)
#define FETCH_SB_LEN(x) (x->subend - x->subpointer)

/* For posterity:
#define  FETCH_SB_PEEK(x) ((*x->subpointer)&0xff)
#define  FETCH_SB_EOF(x) (x->subpointer >= x->subend) */

#ifdef FETCH_DISABLE_VERBOSE_STRINGS
#define printoption(a, b, c, d) Curl_nop_stmt
#endif

static FETCHcode telrcv(struct Curl_easy *data,
                        const unsigned char *inbuf, /* Data received from socket */
                        ssize_t count);             /* Number of bytes received */

#ifndef FETCH_DISABLE_VERBOSE_STRINGS
static void printoption(struct Curl_easy *data,
                        const char *direction,
                        int cmd, int option);
#endif

static void negotiate(struct Curl_easy *data);
static void send_negotiation(struct Curl_easy *data, int cmd, int option);
static void set_local_option(struct Curl_easy *data,
                             int option, int newstate);
static void set_remote_option(struct Curl_easy *data,
                              int option, int newstate);

static void printsub(struct Curl_easy *data,
                     int direction, unsigned char *pointer,
                     size_t length);
static void suboption(struct Curl_easy *data);
static void sendsuboption(struct Curl_easy *data, int option);

static FETCHcode telnet_do(struct Curl_easy *data, bool *done);
static FETCHcode telnet_done(struct Curl_easy *data,
                             FETCHcode, bool premature);
static FETCHcode send_telnet_data(struct Curl_easy *data,
                                  char *buffer, ssize_t nread);

/* For negotiation compliant to RFC 1143 */
#define FETCH_NO 0
#define FETCH_YES 1
#define FETCH_WANTYES 2
#define FETCH_WANTNO 3

#define FETCH_EMPTY 0
#define FETCH_OPPOSITE 1

/*
 * Telnet receiver states for fsm
 */
typedef enum
{
  FETCH_TS_DATA = 0,
  FETCH_TS_IAC,
  FETCH_TS_WILL,
  FETCH_TS_WONT,
  FETCH_TS_DO,
  FETCH_TS_DONT,
  FETCH_TS_CR,
  FETCH_TS_SB, /* sub-option collection */
  FETCH_TS_SE  /* looking for sub-option end */
} TelnetReceive;

struct TELNET
{
  int please_negotiate;
  int already_negotiated;
  int us[256];
  int usq[256];
  int us_preferred[256];
  int him[256];
  int himq[256];
  int him_preferred[256];
  int subnegotiation[256];
  char *subopt_ttype;        /* Set with suboption TTYPE */
  char *subopt_xdisploc;     /* Set with suboption XDISPLOC */
  unsigned short subopt_wsx; /* Set with suboption NAWS */
  unsigned short subopt_wsy; /* Set with suboption NAWS */
  TelnetReceive telrcv_state;
  struct fetch_slist *telnet_vars; /* Environment variables */
  struct dynbuf out;               /* output buffer */

  /* suboptions */
  unsigned char subbuffer[SUBBUFSIZE];
  unsigned char *subpointer, *subend; /* buffer for sub-options */
};

/*
 * TELNET protocol handler.
 */

const struct Curl_handler Curl_handler_telnet = {
    "telnet",                         /* scheme */
    ZERO_NULL,                        /* setup_connection */
    telnet_do,                        /* do_it */
    telnet_done,                      /* done */
    ZERO_NULL,                        /* do_more */
    ZERO_NULL,                        /* connect_it */
    ZERO_NULL,                        /* connecting */
    ZERO_NULL,                        /* doing */
    ZERO_NULL,                        /* proto_getsock */
    ZERO_NULL,                        /* doing_getsock */
    ZERO_NULL,                        /* domore_getsock */
    ZERO_NULL,                        /* perform_getsock */
    ZERO_NULL,                        /* disconnect */
    ZERO_NULL,                        /* write_resp */
    ZERO_NULL,                        /* write_resp_hd */
    ZERO_NULL,                        /* connection_check */
    ZERO_NULL,                        /* attach connection */
    ZERO_NULL,                        /* follow */
    PORT_TELNET,                      /* defport */
    FETCHPROTO_TELNET,                /* protocol */
    FETCHPROTO_TELNET,                /* family */
    PROTOPT_NONE | PROTOPT_NOURLQUERY /* flags */
};

static FETCHcode init_telnet(struct Curl_easy *data)
{
  struct TELNET *tn;

  tn = calloc(1, sizeof(struct TELNET));
  if (!tn)
    return FETCHE_OUT_OF_MEMORY;

  Curl_dyn_init(&tn->out, 0xffff);
  data->req.p.telnet = tn; /* make us known */

  tn->telrcv_state = FETCH_TS_DATA;

  /* Init suboptions */
  FETCH_SB_CLEAR(tn);

  /* Set the options we want by default */
  tn->us_preferred[FETCH_TELOPT_SGA] = FETCH_YES;
  tn->him_preferred[FETCH_TELOPT_SGA] = FETCH_YES;

  /* To be compliant with previous releases of libfetch
     we enable this option by default. This behavior
         can be changed thanks to the "BINARY" option in
         FETCHOPT_TELNETOPTIONS
  */
  tn->us_preferred[FETCH_TELOPT_BINARY] = FETCH_YES;
  tn->him_preferred[FETCH_TELOPT_BINARY] = FETCH_YES;

  /* We must allow the server to echo what we sent
         but it is not necessary to request the server
         to do so (it might forces the server to close
         the connection). Hence, we ignore ECHO in the
         negotiate function
  */
  tn->him_preferred[FETCH_TELOPT_ECHO] = FETCH_YES;

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
  tn->subnegotiation[FETCH_TELOPT_NAWS] = FETCH_YES;
  return FETCHE_OK;
}

static void negotiate(struct Curl_easy *data)
{
  int i;
  struct TELNET *tn = data->req.p.telnet;

  for (i = 0; i < FETCH_NTELOPTS; i++)
  {
    if (i == FETCH_TELOPT_ECHO)
      continue;

    if (tn->us_preferred[i] == FETCH_YES)
      set_local_option(data, i, FETCH_YES);

    if (tn->him_preferred[i] == FETCH_YES)
      set_remote_option(data, i, FETCH_YES);
  }
}

#ifndef FETCH_DISABLE_VERBOSE_STRINGS
static void printoption(struct Curl_easy *data,
                        const char *direction, int cmd, int option)
{
  if (data->set.verbose)
  {
    if (cmd == FETCH_IAC)
    {
      if (FETCH_TELCMD_OK(option))
        infof(data, "%s IAC %s", direction, FETCH_TELCMD(option));
      else
        infof(data, "%s IAC %d", direction, option);
    }
    else
    {
      const char *fmt = (cmd == FETCH_WILL) ? "WILL" : (cmd == FETCH_WONT) ? "WONT"
                                                   : (cmd == FETCH_DO)     ? "DO"
                                                   : (cmd == FETCH_DONT)   ? "DONT"
                                                                           : 0;
      if (fmt)
      {
        const char *opt;
        if (FETCH_TELOPT_OK(option))
          opt = FETCH_TELOPT(option);
        else if (option == FETCH_TELOPT_EXOPL)
          opt = "EXOPL";
        else
          opt = NULL;

        if (opt)
          infof(data, "%s %s %s", direction, fmt, opt);
        else
          infof(data, "%s %s %d", direction, fmt, option);
      }
      else
        infof(data, "%s %d %d", direction, cmd, option);
    }
  }
}
#endif

static void send_negotiation(struct Curl_easy *data, int cmd, int option)
{
  unsigned char buf[3];
  ssize_t bytes_written;
  struct connectdata *conn = data->conn;

  buf[0] = FETCH_IAC;
  buf[1] = (unsigned char)cmd;
  buf[2] = (unsigned char)option;

  bytes_written = swrite(conn->sock[FIRSTSOCKET], buf, 3);
  if (bytes_written < 0)
  {
    int err = SOCKERRNO;
    failf(data, "Sending data failed (%d)", err);
  }

  printoption(data, "SENT", cmd, option);
}

static void set_remote_option(struct Curl_easy *data, int option, int newstate)
{
  struct TELNET *tn = data->req.p.telnet;
  if (newstate == FETCH_YES)
  {
    switch (tn->him[option])
    {
    case FETCH_NO:
      tn->him[option] = FETCH_WANTYES;
      send_negotiation(data, FETCH_DO, option);
      break;

    case FETCH_YES:
      /* Already enabled */
      break;

    case FETCH_WANTNO:
      switch (tn->himq[option])
      {
      case FETCH_EMPTY:
        /* Already negotiating for FETCH_YES, queue the request */
        tn->himq[option] = FETCH_OPPOSITE;
        break;
      case FETCH_OPPOSITE:
        /* Error: already queued an enable request */
        break;
      }
      break;

    case FETCH_WANTYES:
      switch (tn->himq[option])
      {
      case FETCH_EMPTY:
        /* Error: already negotiating for enable */
        break;
      case FETCH_OPPOSITE:
        tn->himq[option] = FETCH_EMPTY;
        break;
      }
      break;
    }
  }
  else
  { /* NO */
    switch (tn->him[option])
    {
    case FETCH_NO:
      /* Already disabled */
      break;

    case FETCH_YES:
      tn->him[option] = FETCH_WANTNO;
      send_negotiation(data, FETCH_DONT, option);
      break;

    case FETCH_WANTNO:
      switch (tn->himq[option])
      {
      case FETCH_EMPTY:
        /* Already negotiating for NO */
        break;
      case FETCH_OPPOSITE:
        tn->himq[option] = FETCH_EMPTY;
        break;
      }
      break;

    case FETCH_WANTYES:
      switch (tn->himq[option])
      {
      case FETCH_EMPTY:
        tn->himq[option] = FETCH_OPPOSITE;
        break;
      case FETCH_OPPOSITE:
        break;
      }
      break;
    }
  }
}

static void rec_will(struct Curl_easy *data, int option)
{
  struct TELNET *tn = data->req.p.telnet;
  switch (tn->him[option])
  {
  case FETCH_NO:
    if (tn->him_preferred[option] == FETCH_YES)
    {
      tn->him[option] = FETCH_YES;
      send_negotiation(data, FETCH_DO, option);
    }
    else
      send_negotiation(data, FETCH_DONT, option);

    break;

  case FETCH_YES:
    /* Already enabled */
    break;

  case FETCH_WANTNO:
    switch (tn->himq[option])
    {
    case FETCH_EMPTY:
      /* Error: DONT answered by WILL */
      tn->him[option] = FETCH_NO;
      break;
    case FETCH_OPPOSITE:
      /* Error: DONT answered by WILL */
      tn->him[option] = FETCH_YES;
      tn->himq[option] = FETCH_EMPTY;
      break;
    }
    break;

  case FETCH_WANTYES:
    switch (tn->himq[option])
    {
    case FETCH_EMPTY:
      tn->him[option] = FETCH_YES;
      break;
    case FETCH_OPPOSITE:
      tn->him[option] = FETCH_WANTNO;
      tn->himq[option] = FETCH_EMPTY;
      send_negotiation(data, FETCH_DONT, option);
      break;
    }
    break;
  }
}

static void rec_wont(struct Curl_easy *data, int option)
{
  struct TELNET *tn = data->req.p.telnet;
  switch (tn->him[option])
  {
  case FETCH_NO:
    /* Already disabled */
    break;

  case FETCH_YES:
    tn->him[option] = FETCH_NO;
    send_negotiation(data, FETCH_DONT, option);
    break;

  case FETCH_WANTNO:
    switch (tn->himq[option])
    {
    case FETCH_EMPTY:
      tn->him[option] = FETCH_NO;
      break;

    case FETCH_OPPOSITE:
      tn->him[option] = FETCH_WANTYES;
      tn->himq[option] = FETCH_EMPTY;
      send_negotiation(data, FETCH_DO, option);
      break;
    }
    break;

  case FETCH_WANTYES:
    switch (tn->himq[option])
    {
    case FETCH_EMPTY:
      tn->him[option] = FETCH_NO;
      break;
    case FETCH_OPPOSITE:
      tn->him[option] = FETCH_NO;
      tn->himq[option] = FETCH_EMPTY;
      break;
    }
    break;
  }
}

static void
set_local_option(struct Curl_easy *data, int option, int newstate)
{
  struct TELNET *tn = data->req.p.telnet;
  if (newstate == FETCH_YES)
  {
    switch (tn->us[option])
    {
    case FETCH_NO:
      tn->us[option] = FETCH_WANTYES;
      send_negotiation(data, FETCH_WILL, option);
      break;

    case FETCH_YES:
      /* Already enabled */
      break;

    case FETCH_WANTNO:
      switch (tn->usq[option])
      {
      case FETCH_EMPTY:
        /* Already negotiating for FETCH_YES, queue the request */
        tn->usq[option] = FETCH_OPPOSITE;
        break;
      case FETCH_OPPOSITE:
        /* Error: already queued an enable request */
        break;
      }
      break;

    case FETCH_WANTYES:
      switch (tn->usq[option])
      {
      case FETCH_EMPTY:
        /* Error: already negotiating for enable */
        break;
      case FETCH_OPPOSITE:
        tn->usq[option] = FETCH_EMPTY;
        break;
      }
      break;
    }
  }
  else
  { /* NO */
    switch (tn->us[option])
    {
    case FETCH_NO:
      /* Already disabled */
      break;

    case FETCH_YES:
      tn->us[option] = FETCH_WANTNO;
      send_negotiation(data, FETCH_WONT, option);
      break;

    case FETCH_WANTNO:
      switch (tn->usq[option])
      {
      case FETCH_EMPTY:
        /* Already negotiating for NO */
        break;
      case FETCH_OPPOSITE:
        tn->usq[option] = FETCH_EMPTY;
        break;
      }
      break;

    case FETCH_WANTYES:
      switch (tn->usq[option])
      {
      case FETCH_EMPTY:
        tn->usq[option] = FETCH_OPPOSITE;
        break;
      case FETCH_OPPOSITE:
        break;
      }
      break;
    }
  }
}

static void rec_do(struct Curl_easy *data, int option)
{
  struct TELNET *tn = data->req.p.telnet;
  switch (tn->us[option])
  {
  case FETCH_NO:
    if (tn->us_preferred[option] == FETCH_YES)
    {
      tn->us[option] = FETCH_YES;
      send_negotiation(data, FETCH_WILL, option);
      if (tn->subnegotiation[option] == FETCH_YES)
        /* transmission of data option */
        sendsuboption(data, option);
    }
    else if (tn->subnegotiation[option] == FETCH_YES)
    {
      /* send information to achieve this option */
      tn->us[option] = FETCH_YES;
      send_negotiation(data, FETCH_WILL, option);
      sendsuboption(data, option);
    }
    else
      send_negotiation(data, FETCH_WONT, option);
    break;

  case FETCH_YES:
    /* Already enabled */
    break;

  case FETCH_WANTNO:
    switch (tn->usq[option])
    {
    case FETCH_EMPTY:
      /* Error: DONT answered by WILL */
      tn->us[option] = FETCH_NO;
      break;
    case FETCH_OPPOSITE:
      /* Error: DONT answered by WILL */
      tn->us[option] = FETCH_YES;
      tn->usq[option] = FETCH_EMPTY;
      break;
    }
    break;

  case FETCH_WANTYES:
    switch (tn->usq[option])
    {
    case FETCH_EMPTY:
      tn->us[option] = FETCH_YES;
      if (tn->subnegotiation[option] == FETCH_YES)
      {
        /* transmission of data option */
        sendsuboption(data, option);
      }
      break;
    case FETCH_OPPOSITE:
      tn->us[option] = FETCH_WANTNO;
      tn->himq[option] = FETCH_EMPTY;
      send_negotiation(data, FETCH_WONT, option);
      break;
    }
    break;
  }
}

static void rec_dont(struct Curl_easy *data, int option)
{
  struct TELNET *tn = data->req.p.telnet;
  switch (tn->us[option])
  {
  case FETCH_NO:
    /* Already disabled */
    break;

  case FETCH_YES:
    tn->us[option] = FETCH_NO;
    send_negotiation(data, FETCH_WONT, option);
    break;

  case FETCH_WANTNO:
    switch (tn->usq[option])
    {
    case FETCH_EMPTY:
      tn->us[option] = FETCH_NO;
      break;

    case FETCH_OPPOSITE:
      tn->us[option] = FETCH_WANTYES;
      tn->usq[option] = FETCH_EMPTY;
      send_negotiation(data, FETCH_WILL, option);
      break;
    }
    break;

  case FETCH_WANTYES:
    switch (tn->usq[option])
    {
    case FETCH_EMPTY:
      tn->us[option] = FETCH_NO;
      break;
    case FETCH_OPPOSITE:
      tn->us[option] = FETCH_NO;
      tn->usq[option] = FETCH_EMPTY;
      break;
    }
    break;
  }
}

static void printsub(struct Curl_easy *data,
                     int direction,          /* '<' or '>' */
                     unsigned char *pointer, /* where suboption data is */
                     size_t length)          /* length of suboption data */
{
  if (data->set.verbose)
  {
    unsigned int i = 0;
    if (direction)
    {
      infof(data, "%s IAC SB ", (direction == '<') ? "RCVD" : "SENT");
      if (length >= 3)
      {
        int j;

        i = pointer[length - 2];
        j = pointer[length - 1];

        if (i != FETCH_IAC || j != FETCH_SE)
        {
          infof(data, "(terminated by ");
          if (FETCH_TELOPT_OK(i))
            infof(data, "%s ", FETCH_TELOPT(i));
          else if (FETCH_TELCMD_OK(i))
            infof(data, "%s ", FETCH_TELCMD(i));
          else
            infof(data, "%u ", i);
          if (FETCH_TELOPT_OK(j))
            infof(data, "%s", FETCH_TELOPT(j));
          else if (FETCH_TELCMD_OK(j))
            infof(data, "%s", FETCH_TELCMD(j));
          else
            infof(data, "%d", j);
          infof(data, ", not IAC SE) ");
        }
      }
      if (length >= 2)
        length -= 2;
      else /* bad input */
        return;
    }
    if (length < 1)
    {
      infof(data, "(Empty suboption?)");
      return;
    }

    if (FETCH_TELOPT_OK(pointer[0]))
    {
      switch (pointer[0])
      {
      case FETCH_TELOPT_TTYPE:
      case FETCH_TELOPT_XDISPLOC:
      case FETCH_TELOPT_NEW_ENVIRON:
      case FETCH_TELOPT_NAWS:
        infof(data, "%s", FETCH_TELOPT(pointer[0]));
        break;
      default:
        infof(data, "%s (unsupported)", FETCH_TELOPT(pointer[0]));
        break;
      }
    }
    else
      infof(data, "%d (unknown)", pointer[i]);

    switch (pointer[0])
    {
    case FETCH_TELOPT_NAWS:
      if (length > 4)
        infof(data, "Width: %d ; Height: %d", (pointer[1] << 8) | pointer[2],
              (pointer[3] << 8) | pointer[4]);
      break;
    default:
      switch (pointer[1])
      {
      case FETCH_TELQUAL_IS:
        infof(data, " IS");
        break;
      case FETCH_TELQUAL_SEND:
        infof(data, " SEND");
        break;
      case FETCH_TELQUAL_INFO:
        infof(data, " INFO/REPLY");
        break;
      case FETCH_TELQUAL_NAME:
        infof(data, " NAME");
        break;
      }

      switch (pointer[0])
      {
      case FETCH_TELOPT_TTYPE:
      case FETCH_TELOPT_XDISPLOC:
        pointer[length] = 0;
        infof(data, " \"%s\"", &pointer[2]);
        break;
      case FETCH_TELOPT_NEW_ENVIRON:
        if (pointer[1] == FETCH_TELQUAL_IS)
        {
          infof(data, " ");
          for (i = 3; i < length; i++)
          {
            switch (pointer[i])
            {
            case FETCH_NEW_ENV_VAR:
              infof(data, ", ");
              break;
            case FETCH_NEW_ENV_VALUE:
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
        for (i = 2; i < length; i++)
          infof(data, " %.2x", pointer[i]);
        break;
      }
    }
  }
}

#ifdef _MSC_VER
#pragma warning(push)
#pragma warning(disable : 4706) /* assignment within conditional expression */
#endif
static bool str_is_nonascii(const char *str)
{
  char c;
  while ((c = *str++))
    if (c & 0x80)
      return TRUE;

  return FALSE;
}
#ifdef _MSC_VER
#pragma warning(pop)
#endif

static FETCHcode check_telnet_options(struct Curl_easy *data)
{
  struct fetch_slist *head;
  struct fetch_slist *beg;
  struct TELNET *tn = data->req.p.telnet;
  FETCHcode result = FETCHE_OK;

  /* Add the username as an environment variable if it
     was given on the command line */
  if (data->state.aptr.user)
  {
    char buffer[256];
    if (str_is_nonascii(data->conn->user))
    {
      DEBUGF(infof(data, "set a non ASCII username in telnet"));
      return FETCHE_BAD_FUNCTION_ARGUMENT;
    }
    msnprintf(buffer, sizeof(buffer), "USER,%s", data->conn->user);
    beg = fetch_slist_append(tn->telnet_vars, buffer);
    if (!beg)
    {
      fetch_slist_free_all(tn->telnet_vars);
      tn->telnet_vars = NULL;
      return FETCHE_OUT_OF_MEMORY;
    }
    tn->telnet_vars = beg;
    tn->us_preferred[FETCH_TELOPT_NEW_ENVIRON] = FETCH_YES;
  }

  for (head = data->set.telnet_options; head && !result; head = head->next)
  {
    size_t olen;
    char *option = head->data;
    char *arg;
    char *sep = strchr(option, '=');
    if (sep)
    {
      olen = sep - option;
      arg = ++sep;
      if (str_is_nonascii(arg))
        continue;
      switch (olen)
      {
      case 5:
        /* Terminal type */
        if (strncasecompare(option, "TTYPE", 5))
        {
          tn->subopt_ttype = arg;
          tn->us_preferred[FETCH_TELOPT_TTYPE] = FETCH_YES;
          break;
        }
        result = FETCHE_UNKNOWN_OPTION;
        break;

      case 8:
        /* Display variable */
        if (strncasecompare(option, "XDISPLOC", 8))
        {
          tn->subopt_xdisploc = arg;
          tn->us_preferred[FETCH_TELOPT_XDISPLOC] = FETCH_YES;
          break;
        }
        result = FETCHE_UNKNOWN_OPTION;
        break;

      case 7:
        /* Environment variable */
        if (strncasecompare(option, "NEW_ENV", 7))
        {
          beg = fetch_slist_append(tn->telnet_vars, arg);
          if (!beg)
          {
            result = FETCHE_OUT_OF_MEMORY;
            break;
          }
          tn->telnet_vars = beg;
          tn->us_preferred[FETCH_TELOPT_NEW_ENVIRON] = FETCH_YES;
        }
        else
          result = FETCHE_UNKNOWN_OPTION;
        break;

      case 2:
        /* Window Size */
        if (strncasecompare(option, "WS", 2))
        {
          char *p;
          unsigned long x = strtoul(arg, &p, 10);
          unsigned long y = 0;
          if (x && (x <= 0xffff) && Curl_raw_tolower(*p) == 'x')
          {
            p++;
            y = strtoul(p, NULL, 10);
            if (y && (y <= 0xffff))
            {
              tn->subopt_wsx = (unsigned short)x;
              tn->subopt_wsy = (unsigned short)y;
              tn->us_preferred[FETCH_TELOPT_NAWS] = FETCH_YES;
            }
          }
          if (!y)
          {
            failf(data, "Syntax error in telnet option: %s", head->data);
            result = FETCHE_SETOPT_OPTION_SYNTAX;
          }
        }
        else
          result = FETCHE_UNKNOWN_OPTION;
        break;

      case 6:
        /* To take care or not of the 8th bit in data exchange */
        if (strncasecompare(option, "BINARY", 6))
        {
          int binary_option = atoi(arg);
          if (binary_option != 1)
          {
            tn->us_preferred[FETCH_TELOPT_BINARY] = FETCH_NO;
            tn->him_preferred[FETCH_TELOPT_BINARY] = FETCH_NO;
          }
        }
        else
          result = FETCHE_UNKNOWN_OPTION;
        break;
      default:
        failf(data, "Unknown telnet option %s", head->data);
        result = FETCHE_UNKNOWN_OPTION;
        break;
      }
    }
    else
    {
      failf(data, "Syntax error in telnet option: %s", head->data);
      result = FETCHE_SETOPT_OPTION_SYNTAX;
    }
  }

  if (result)
  {
    fetch_slist_free_all(tn->telnet_vars);
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

static void suboption(struct Curl_easy *data)
{
  struct fetch_slist *v;
  unsigned char temp[2048];
  ssize_t bytes_written;
  size_t len;
  int err;
  struct TELNET *tn = data->req.p.telnet;
  struct connectdata *conn = data->conn;

  printsub(data, '<', (unsigned char *)tn->subbuffer, FETCH_SB_LEN(tn) + 2);
  switch (FETCH_SB_GET(tn))
  {
  case FETCH_TELOPT_TTYPE:
    len = strlen(tn->subopt_ttype) + 4 + 2;
    msnprintf((char *)temp, sizeof(temp),
              "%c%c%c%c%s%c%c", FETCH_IAC, FETCH_SB, FETCH_TELOPT_TTYPE,
              FETCH_TELQUAL_IS, tn->subopt_ttype, FETCH_IAC, FETCH_SE);
    bytes_written = swrite(conn->sock[FIRSTSOCKET], temp, len);
    if (bytes_written < 0)
    {
      err = SOCKERRNO;
      failf(data, "Sending data failed (%d)", err);
    }
    printsub(data, '>', &temp[2], len - 2);
    break;
  case FETCH_TELOPT_XDISPLOC:
    len = strlen(tn->subopt_xdisploc) + 4 + 2;
    msnprintf((char *)temp, sizeof(temp),
              "%c%c%c%c%s%c%c", FETCH_IAC, FETCH_SB, FETCH_TELOPT_XDISPLOC,
              FETCH_TELQUAL_IS, tn->subopt_xdisploc, FETCH_IAC, FETCH_SE);
    bytes_written = swrite(conn->sock[FIRSTSOCKET], temp, len);
    if (bytes_written < 0)
    {
      err = SOCKERRNO;
      failf(data, "Sending data failed (%d)", err);
    }
    printsub(data, '>', &temp[2], len - 2);
    break;
  case FETCH_TELOPT_NEW_ENVIRON:
    msnprintf((char *)temp, sizeof(temp),
              "%c%c%c%c", FETCH_IAC, FETCH_SB, FETCH_TELOPT_NEW_ENVIRON,
              FETCH_TELQUAL_IS);
    len = 4;

    for (v = tn->telnet_vars; v; v = v->next)
    {
      size_t tmplen = (strlen(v->data) + 1);
      /* Add the variable if it fits */
      if (len + tmplen < (int)sizeof(temp) - 6)
      {
        char *s = strchr(v->data, ',');
        if (!s)
          len += msnprintf((char *)&temp[len], sizeof(temp) - len,
                           "%c%s", FETCH_NEW_ENV_VAR, v->data);
        else
        {
          size_t vlen = s - v->data;
          len += msnprintf((char *)&temp[len], sizeof(temp) - len,
                           "%c%.*s%c%s", FETCH_NEW_ENV_VAR,
                           (int)vlen, v->data, FETCH_NEW_ENV_VALUE, ++s);
        }
      }
    }
    msnprintf((char *)&temp[len], sizeof(temp) - len,
              "%c%c", FETCH_IAC, FETCH_SE);
    len += 2;
    bytes_written = swrite(conn->sock[FIRSTSOCKET], temp, len);
    if (bytes_written < 0)
    {
      err = SOCKERRNO;
      failf(data, "Sending data failed (%d)", err);
    }
    printsub(data, '>', &temp[2], len - 2);
    break;
  }
  return;
}

/*
 * sendsuboption()
 *
 * Send suboption information to the server side.
 */

static void sendsuboption(struct Curl_easy *data, int option)
{
  ssize_t bytes_written;
  int err;
  unsigned short x, y;
  unsigned char *uc1, *uc2;
  struct TELNET *tn = data->req.p.telnet;
  struct connectdata *conn = data->conn;

  switch (option)
  {
  case FETCH_TELOPT_NAWS:
    /* We prepare data to be sent */
    FETCH_SB_CLEAR(tn);
    FETCH_SB_ACCUM(tn, FETCH_IAC);
    FETCH_SB_ACCUM(tn, FETCH_SB);
    FETCH_SB_ACCUM(tn, FETCH_TELOPT_NAWS);
    /* We must deal either with little or big endian processors */
    /* Window size must be sent according to the 'network order' */
    x = htons(tn->subopt_wsx);
    y = htons(tn->subopt_wsy);
    uc1 = (unsigned char *)&x;
    uc2 = (unsigned char *)&y;
    FETCH_SB_ACCUM(tn, uc1[0]);
    FETCH_SB_ACCUM(tn, uc1[1]);
    FETCH_SB_ACCUM(tn, uc2[0]);
    FETCH_SB_ACCUM(tn, uc2[1]);

    FETCH_SB_ACCUM(tn, FETCH_IAC);
    FETCH_SB_ACCUM(tn, FETCH_SE);
    FETCH_SB_TERM(tn);
    /* data suboption is now ready */

    printsub(data, '>', (unsigned char *)tn->subbuffer + 2,
             FETCH_SB_LEN(tn) - 2);

    /* we send the header of the suboption... */
    bytes_written = swrite(conn->sock[FIRSTSOCKET], tn->subbuffer, 3);
    if (bytes_written < 0)
    {
      err = SOCKERRNO;
      failf(data, "Sending data failed (%d)", err);
    }
    /* ... then the window size with the send_telnet_data() function
       to deal with 0xFF cases ... */
    send_telnet_data(data, (char *)tn->subbuffer + 3, 4);
    /* ... and the footer */
    bytes_written = swrite(conn->sock[FIRSTSOCKET], tn->subbuffer + 7, 2);
    if (bytes_written < 0)
    {
      err = SOCKERRNO;
      failf(data, "Sending data failed (%d)", err);
    }
    break;
  }
}

static FETCHcode telrcv(struct Curl_easy *data,
                        const unsigned char *inbuf, /* Data received from socket */
                        ssize_t count)              /* Number of bytes received */
{
  unsigned char c;
  FETCHcode result;
  int in = 0;
  int startwrite = -1;
  struct TELNET *tn = data->req.p.telnet;

#define startskipping()                                    \
  if (startwrite >= 0)                                     \
  {                                                        \
    result = Curl_client_write(data,                       \
                               CLIENTWRITE_BODY,           \
                               (char *)&inbuf[startwrite], \
                               in - startwrite);           \
    if (result)                                            \
      return result;                                       \
  }                                                        \
  startwrite = -1

#define writebyte()   \
  if (startwrite < 0) \
  startwrite = in

#define bufferflush() startskipping()

  while (count--)
  {
    c = inbuf[in];

    switch (tn->telrcv_state)
    {
    case FETCH_TS_CR:
      tn->telrcv_state = FETCH_TS_DATA;
      if (c == '\0')
      {
        startskipping();
        break; /* Ignore \0 after CR */
      }
      writebyte();
      break;

    case FETCH_TS_DATA:
      if (c == FETCH_IAC)
      {
        tn->telrcv_state = FETCH_TS_IAC;
        startskipping();
        break;
      }
      else if (c == '\r')
        tn->telrcv_state = FETCH_TS_CR;
      writebyte();
      break;

    case FETCH_TS_IAC:
    process_iac:
      DEBUGASSERT(startwrite < 0);
      switch (c)
      {
      case FETCH_WILL:
        tn->telrcv_state = FETCH_TS_WILL;
        break;
      case FETCH_WONT:
        tn->telrcv_state = FETCH_TS_WONT;
        break;
      case FETCH_DO:
        tn->telrcv_state = FETCH_TS_DO;
        break;
      case FETCH_DONT:
        tn->telrcv_state = FETCH_TS_DONT;
        break;
      case FETCH_SB:
        FETCH_SB_CLEAR(tn);
        tn->telrcv_state = FETCH_TS_SB;
        break;
      case FETCH_IAC:
        tn->telrcv_state = FETCH_TS_DATA;
        writebyte();
        break;
      case FETCH_DM:
      case FETCH_NOP:
      case FETCH_GA:
      default:
        tn->telrcv_state = FETCH_TS_DATA;
        printoption(data, "RCVD", FETCH_IAC, c);
        break;
      }
      break;

    case FETCH_TS_WILL:
      printoption(data, "RCVD", FETCH_WILL, c);
      tn->please_negotiate = 1;
      rec_will(data, c);
      tn->telrcv_state = FETCH_TS_DATA;
      break;

    case FETCH_TS_WONT:
      printoption(data, "RCVD", FETCH_WONT, c);
      tn->please_negotiate = 1;
      rec_wont(data, c);
      tn->telrcv_state = FETCH_TS_DATA;
      break;

    case FETCH_TS_DO:
      printoption(data, "RCVD", FETCH_DO, c);
      tn->please_negotiate = 1;
      rec_do(data, c);
      tn->telrcv_state = FETCH_TS_DATA;
      break;

    case FETCH_TS_DONT:
      printoption(data, "RCVD", FETCH_DONT, c);
      tn->please_negotiate = 1;
      rec_dont(data, c);
      tn->telrcv_state = FETCH_TS_DATA;
      break;

    case FETCH_TS_SB:
      if (c == FETCH_IAC)
        tn->telrcv_state = FETCH_TS_SE;
      else
        FETCH_SB_ACCUM(tn, c);
      break;

    case FETCH_TS_SE:
      if (c != FETCH_SE)
      {
        if (c != FETCH_IAC)
        {
          /*
           * This is an error. We only expect to get "IAC IAC" or "IAC SE".
           * Several things may have happened. An IAC was not doubled, the
           * IAC SE was left off, or another option got inserted into the
           * suboption are all possibilities. If we assume that the IAC was
           * not doubled, and really the IAC SE was left off, we could get
           * into an infinite loop here. So, instead, we terminate the
           * suboption, and process the partial suboption if we can.
           */
          FETCH_SB_ACCUM(tn, FETCH_IAC);
          FETCH_SB_ACCUM(tn, c);
          tn->subpointer -= 2;
          FETCH_SB_TERM(tn);

          printoption(data, "In SUBOPTION processing, RCVD", FETCH_IAC, c);
          suboption(data); /* handle sub-option */
          tn->telrcv_state = FETCH_TS_IAC;
          goto process_iac;
        }
        FETCH_SB_ACCUM(tn, c);
        tn->telrcv_state = FETCH_TS_SB;
      }
      else
      {
        FETCH_SB_ACCUM(tn, FETCH_IAC);
        FETCH_SB_ACCUM(tn, FETCH_SE);
        tn->subpointer -= 2;
        FETCH_SB_TERM(tn);
        suboption(data); /* handle sub-option */
        tn->telrcv_state = FETCH_TS_DATA;
      }
      break;
    }
    ++in;
  }
  bufferflush();
  return FETCHE_OK;
}

/* Escape and send a telnet data block */
static FETCHcode send_telnet_data(struct Curl_easy *data,
                                  char *buffer, ssize_t nread)
{
  size_t i, outlen;
  unsigned char *outbuf;
  FETCHcode result = FETCHE_OK;
  size_t bytes_written;
  size_t total_written = 0;
  struct connectdata *conn = data->conn;
  struct TELNET *tn = data->req.p.telnet;

  DEBUGASSERT(tn);
  DEBUGASSERT(nread > 0);
  if (nread < 0)
    return FETCHE_TOO_LARGE;

  if (memchr(buffer, FETCH_IAC, nread))
  {
    /* only use the escape buffer when necessary */
    Curl_dyn_reset(&tn->out);

    for (i = 0; i < (size_t)nread && !result; i++)
    {
      result = Curl_dyn_addn(&tn->out, &buffer[i], 1);
      if (!result && ((unsigned char)buffer[i] == FETCH_IAC))
        /* IAC is FF in hex */
        result = Curl_dyn_addn(&tn->out, "\xff", 1);
    }

    outlen = Curl_dyn_len(&tn->out);
    outbuf = Curl_dyn_uptr(&tn->out);
  }
  else
  {
    outlen = (size_t)nread;
    outbuf = (unsigned char *)buffer;
  }
  while (!result && total_written < outlen)
  {
    /* Make sure socket is writable to avoid EWOULDBLOCK condition */
    struct pollfd pfd[1];
    pfd[0].fd = conn->sock[FIRSTSOCKET];
    pfd[0].events = POLLOUT;
    switch (Curl_poll(pfd, 1, -1))
    {
    case -1: /* error, abort writing */
    case 0:  /* timeout (will never happen) */
      result = FETCHE_SEND_ERROR;
      break;
    default: /* write! */
      bytes_written = 0;
      result = Curl_xfer_send(data, outbuf + total_written,
                              outlen - total_written, FALSE, &bytes_written);
      total_written += bytes_written;
      break;
    }
  }

  return result;
}

static FETCHcode telnet_done(struct Curl_easy *data,
                             FETCHcode status, bool premature)
{
  struct TELNET *tn = data->req.p.telnet;
  (void)status;    /* unused */
  (void)premature; /* not used */

  if (!tn)
    return FETCHE_OK;

  fetch_slist_free_all(tn->telnet_vars);
  tn->telnet_vars = NULL;
  Curl_dyn_free(&tn->out);
  return FETCHE_OK;
}

static FETCHcode telnet_do(struct Curl_easy *data, bool *done)
{
  FETCHcode result;
  struct connectdata *conn = data->conn;
  fetch_socket_t sockfd = conn->sock[FIRSTSOCKET];
#ifdef USE_WINSOCK
  WSAEVENT event_handle;
  WSANETWORKEVENTS events;
  HANDLE stdin_handle;
  HANDLE objs[2];
  DWORD obj_count;
  DWORD wait_timeout;
  DWORD readfile_read;
  int err;
#else
  timediff_t interval_ms;
  struct pollfd pfd[2];
  int poll_cnt;
  fetch_off_t total_dl = 0;
  fetch_off_t total_ul = 0;
#endif
  ssize_t nread;
  struct fetchtime now;
  bool keepon = TRUE;
  char buffer[4 * 1024];
  struct TELNET *tn;

  *done = TRUE; /* unconditionally */

  result = init_telnet(data);
  if (result)
    return result;

  tn = data->req.p.telnet;

  result = check_telnet_options(data);
  if (result)
    return result;

#ifdef USE_WINSOCK
  /* We want to wait for both stdin and the socket. Since
  ** the select() function in Winsock only works on sockets
  ** we have to use the WaitForMultipleObjects() call.
  */

  /* First, create a sockets event object */
  event_handle = WSACreateEvent();
  if (event_handle == WSA_INVALID_EVENT)
  {
    failf(data, "WSACreateEvent failed (%d)", SOCKERRNO);
    return FETCHE_FAILED_INIT;
  }

  /* Tell Winsock what events we want to listen to */
  if (WSAEventSelect(sockfd, event_handle, FD_READ | FD_CLOSE) == SOCKET_ERROR)
  {
    WSACloseEvent(event_handle);
    return FETCHE_OK;
  }

  /* The get the Windows file handle for stdin */
  stdin_handle = GetStdHandle(STD_INPUT_HANDLE);

  /* Create the list of objects to wait for */
  objs[0] = event_handle;
  objs[1] = stdin_handle;

  /* If stdin_handle is a pipe, use PeekNamedPipe() method to check it,
     else use the old WaitForMultipleObjects() way */
  if (GetFileType(stdin_handle) == FILE_TYPE_PIPE ||
      data->set.is_fread_set)
  {
    /* Do not wait for stdin_handle, just wait for event_handle */
    obj_count = 1;
    /* Check stdin_handle per 100 milliseconds */
    wait_timeout = 100;
  }
  else
  {
    obj_count = 2;
    wait_timeout = 1000;
  }

  /* Keep on listening and act on events */
  while (keepon)
  {
    const DWORD buf_size = (DWORD)sizeof(buffer);
    DWORD waitret = WaitForMultipleObjects(obj_count, objs,
                                           FALSE, wait_timeout);
    switch (waitret)
    {

    case WAIT_TIMEOUT:
    {
      for (;;)
      {
        if (data->set.is_fread_set)
        {
          size_t n;
          /* read from user-supplied method */
          n = data->state.fread_func(buffer, 1, buf_size, data->state.in);
          if (n == FETCH_READFUNC_ABORT)
          {
            keepon = FALSE;
            result = FETCHE_READ_ERROR;
            break;
          }

          if (n == FETCH_READFUNC_PAUSE)
            break;

          if (n == 0) /* no bytes */
            break;

          /* fall through with number of bytes read */
          readfile_read = (DWORD)n;
        }
        else
        {
          /* read from stdin */
          if (!PeekNamedPipe(stdin_handle, NULL, 0, NULL,
                             &readfile_read, NULL))
          {
            keepon = FALSE;
            result = FETCHE_READ_ERROR;
            break;
          }

          if (!readfile_read)
            break;

          if (!ReadFile(stdin_handle, buffer, buf_size,
                        &readfile_read, NULL))
          {
            keepon = FALSE;
            result = FETCHE_READ_ERROR;
            break;
          }
        }

        result = send_telnet_data(data, buffer, readfile_read);
        if (result)
        {
          keepon = FALSE;
          break;
        }
      }
    }
    break;

    case WAIT_OBJECT_0 + 1:
    {
      if (!ReadFile(stdin_handle, buffer, buf_size,
                    &readfile_read, NULL))
      {
        keepon = FALSE;
        result = FETCHE_READ_ERROR;
        break;
      }

      result = send_telnet_data(data, buffer, readfile_read);
      if (result)
      {
        keepon = FALSE;
        break;
      }
    }
    break;

    case WAIT_OBJECT_0:
    {
      events.lNetworkEvents = 0;
      if (WSAEnumNetworkEvents(sockfd, event_handle, &events) == SOCKET_ERROR)
      {
        err = SOCKERRNO;
        if (err != EINPROGRESS)
        {
          infof(data, "WSAEnumNetworkEvents failed (%d)", err);
          keepon = FALSE;
          result = FETCHE_READ_ERROR;
        }
        break;
      }
      if (events.lNetworkEvents & FD_READ)
      {
        /* read data from network */
        result = Curl_xfer_recv(data, buffer, sizeof(buffer), &nread);
        /* read would have blocked. Loop again */
        if (result == FETCHE_AGAIN)
          break;
        /* returned not-zero, this an error */
        else if (result)
        {
          keepon = FALSE;
          break;
        }
        /* returned zero but actually received 0 or less here,
           the server closed the connection and we bail out */
        else if (nread <= 0)
        {
          keepon = FALSE;
          break;
        }

        result = telrcv(data, (unsigned char *)buffer, nread);
        if (result)
        {
          keepon = FALSE;
          break;
        }

        /* Negotiate if the peer has started negotiating,
           otherwise do not. We do not want to speak telnet with
           non-telnet servers, like POP or SMTP. */
        if (tn->please_negotiate && !tn->already_negotiated)
        {
          negotiate(data);
          tn->already_negotiated = 1;
        }
      }
      if (events.lNetworkEvents & FD_CLOSE)
      {
        keepon = FALSE;
      }
    }
    break;
    }

    if (data->set.timeout)
    {
      now = Curl_now();
      if (Curl_timediff(now, conn->created) >= data->set.timeout)
      {
        failf(data, "Time-out");
        result = FETCHE_OPERATION_TIMEDOUT;
        keepon = FALSE;
      }
    }
  }

  /* We called WSACreateEvent, so call WSACloseEvent */
  if (!WSACloseEvent(event_handle))
  {
    infof(data, "WSACloseEvent failed (%d)", SOCKERRNO);
  }
#else
  pfd[0].fd = sockfd;
  pfd[0].events = POLLIN;

  if (data->set.is_fread_set)
  {
    poll_cnt = 1;
    interval_ms = 100; /* poll user-supplied read function */
  }
  else
  {
    /* really using fread, so infile is a FILE* */
    pfd[1].fd = fileno((FILE *)data->state.in);
    pfd[1].events = POLLIN;
    poll_cnt = 2;
    interval_ms = 1 * 1000;
    if (pfd[1].fd < 0)
    {
      failf(data, "cannot read input");
      result = FETCHE_RECV_ERROR;
      keepon = FALSE;
    }
  }

  while (keepon)
  {
    DEBUGF(infof(data, "telnet_do, poll %d fds", poll_cnt));
    switch (Curl_poll(pfd, (unsigned int)poll_cnt, interval_ms))
    {
    case -1: /* error, stop reading */
      keepon = FALSE;
      continue;
    case 0: /* timeout */
      pfd[0].revents = 0;
      pfd[1].revents = 0;
      FALLTHROUGH();
    default: /* read! */
      if (pfd[0].revents & POLLIN)
      {
        /* read data from network */
        result = Curl_xfer_recv(data, buffer, sizeof(buffer), &nread);
        /* read would have blocked. Loop again */
        if (result == FETCHE_AGAIN)
          break;
        /* returned not-zero, this an error */
        if (result)
        {
          keepon = FALSE;
          /* TODO: in test 1452, macOS sees a ECONNRESET sometimes?
           * Is this the telnet test server not shutting down the socket
           * in a clean way? Seems to be timing related, happens more
           * on slow debug build */
          if (data->state.os_errno == ECONNRESET)
          {
            DEBUGF(infof(data, "telnet_do, unexpected ECONNRESET on recv"));
          }
          break;
        }
        /* returned zero but actually received 0 or less here,
           the server closed the connection and we bail out */
        else if (nread <= 0)
        {
          keepon = FALSE;
          break;
        }

        total_dl += nread;
        result = Curl_pgrsSetDownloadCounter(data, total_dl);
        if (!result)
          result = telrcv(data, (unsigned char *)buffer, nread);
        if (result)
        {
          keepon = FALSE;
          break;
        }

        /* Negotiate if the peer has started negotiating,
           otherwise do not. We do not want to speak telnet with
           non-telnet servers, like POP or SMTP. */
        if (tn->please_negotiate && !tn->already_negotiated)
        {
          negotiate(data);
          tn->already_negotiated = 1;
        }
      }

      nread = 0;
      if (poll_cnt == 2)
      {
        if (pfd[1].revents & POLLIN)
        { /* read from in file */
          nread = read(pfd[1].fd, buffer, sizeof(buffer));
        }
      }
      else
      {
        /* read from user-supplied method */
        nread = (int)data->state.fread_func(buffer, 1, sizeof(buffer),
                                            data->state.in);
        if (nread == FETCH_READFUNC_ABORT)
        {
          keepon = FALSE;
          break;
        }
        if (nread == FETCH_READFUNC_PAUSE)
          break;
      }

      if (nread > 0)
      {
        result = send_telnet_data(data, buffer, nread);
        if (result)
        {
          keepon = FALSE;
          break;
        }
        total_ul += nread;
        Curl_pgrsSetUploadCounter(data, total_ul);
      }
      else if (nread < 0)
        keepon = FALSE;

      break;
    } /* poll switch statement */

    if (data->set.timeout)
    {
      now = Curl_now();
      if (Curl_timediff(now, conn->created) >= data->set.timeout)
      {
        failf(data, "Time-out");
        result = FETCHE_OPERATION_TIMEDOUT;
        keepon = FALSE;
      }
    }

    if (Curl_pgrsUpdate(data))
    {
      result = FETCHE_ABORTED_BY_CALLBACK;
      break;
    }
  }
#endif
  /* mark this as "no further transfer wanted" */
  Curl_xfer_setup_nop(data);

  return result;
}
#endif
