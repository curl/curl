/***************************************************************************
 *                                  _   _ ____  _     
 *  Project                     ___| | | |  _ \| |    
 *                             / __| | | | |_) | |    
 *                            | (__| |_| |  _ <| |___ 
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) 1998 - 2002, Daniel Stenberg, <daniel@haxx.se>, et al.
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

#ifndef CURL_DISABLE_TELNET
/* -- WIN32 approved -- */
#include <stdio.h>
#include <string.h>
#include <stdarg.h>
#include <stdlib.h>
#include <ctype.h>
#include <sys/types.h>
#include <sys/stat.h>

#include <errno.h>

#if defined(WIN32) && !defined(__GNUC__) || defined(__MINGW32__)
#include <winsock2.h>
#include <time.h>
#include <io.h>
#else
#ifdef HAVE_SYS_SOCKET_H
#include <sys/socket.h>
#endif
#include <netinet/in.h>
#include <sys/time.h>
#include <sys/resource.h>
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

#ifdef HAVE_SYS_SELECT_H
#include <sys/select.h>
#endif


#endif

#include "urldata.h"
#include <curl/curl.h>
#include "transfer.h"
#include "sendf.h"

#define _MPRINTF_REPLACE /* use our functions only */
#include <curl/mprintf.h>

#define  TELOPTS
#define  TELCMDS

#include "arpa_telnet.h"

/* The last #include file should be: */
#ifdef MALLOCDEBUG
#include "memdebug.h"
#endif

#define SUBBUFSIZE 512

#define  SB_CLEAR(x)  x->subpointer = x->subbuffer;
#define  SB_TERM(x)   { x->subend = x->subpointer; SB_CLEAR(x); }
#define  SB_ACCUM(x,c) if (x->subpointer < (x->subbuffer+sizeof x->subbuffer)) { \
            *x->subpointer++ = (c); \
         }

#define  SB_GET(x) ((*x->subpointer++)&0xff)
#define  SB_PEEK(x)   ((*x->subpointer)&0xff)
#define  SB_EOF(x) (x->subpointer >= x->subend)
#define  SB_LEN(x) (x->subend - x->subpointer)

static
void telrcv(struct connectdata *,
	    unsigned char *inbuf,	/* Data received from socket */
	    int count);			/* Number of bytes received */

static void printoption(struct SessionHandle *data,
			const char *direction,
			int cmd, int option);

static void negotiate(struct connectdata *);
static void send_negotiation(struct connectdata *, int cmd, int option);
static void set_local_option(struct connectdata *, int cmd, int option);
static void set_remote_option(struct connectdata *, int cmd, int option);

static void printsub(struct SessionHandle *data,
		     int direction, unsigned char *pointer, int length);
static void suboption(struct connectdata *);

/* For negotiation compliant to RFC 1143 */
#define NO	0
#define YES 	1
#define WANTYES	2
#define WANTNO	3

#define EMPTY	 0
#define OPPOSITE 1

/*
 * Telnet receiver states for fsm
 */
typedef enum
{
   TS_DATA = 0,
   TS_IAC,
   TS_WILL,
   TS_WONT,
   TS_DO,
   TS_DONT,
   TS_CR,
   TS_SB,   /* sub-option collection */
   TS_SE   /* looking for sub-option end */
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
  char subopt_ttype[32];             /* Set with suboption TTYPE */
  char subopt_xdisploc[128];          /* Set with suboption XDISPLOC */
  struct curl_slist *telnet_vars; /* Environment variables */

  /* suboptions */
  char subbuffer[SUBBUFSIZE];
  char *subpointer, *subend;      /* buffer for sub-options */
  
  TelnetReceive telrcv_state;
};

static
CURLcode init_telnet(struct connectdata *conn)
{
  struct TELNET *tn;

  tn = (struct TELNET *)malloc(sizeof(struct TELNET));
  if(!tn)
    return CURLE_OUT_OF_MEMORY;
  
  conn->proto.telnet = (void *)tn; /* make us known */

  memset(tn, 0, sizeof(struct TELNET));

  tn->telrcv_state = TS_DATA;

  /* Init suboptions */
  SB_CLEAR(tn);

  /* Set all options to NO */
#if 0
  /* NO is zero => default fill pattern */
  memset(tn->us, NO, 256);
  memset(tn->usq, NO, 256);
  memset(tn->us_preferred, NO, 256);
  memset(tn->him, NO, 256);
  memset(tn->himq, NO, 256);
  memset(tn->him_preferred, NO, 256);
#endif
  /* Set the options we want by default */
  tn->us_preferred[TELOPT_BINARY] = YES;
  tn->us_preferred[TELOPT_SGA] = YES;
  tn->him_preferred[TELOPT_BINARY] = YES;
  tn->him_preferred[TELOPT_SGA] = YES;

  return CURLE_OK;
}

static void negotiate(struct connectdata *conn)
{
  int i;
  struct TELNET *tn = (struct TELNET *)conn->proto.telnet;
   
  for(i = 0;i < NTELOPTS;i++)
  {
    if(tn->us_preferred[i] == YES)
      set_local_option(conn, i, YES);
      
    if(tn->him_preferred[i] == YES)
      set_remote_option(conn, i, YES);
  }
}

static void printoption(struct SessionHandle *data,
			const char *direction, int cmd, int option)
{
  const char *fmt;
  const char *opt;
   
  if (data->set.verbose)
  {
    if (cmd == IAC)
    {
      if (TELCMD_OK(option))
        Curl_infof(data, "%s IAC %s\n", direction, TELCMD(option));
      else
        Curl_infof(data, "%s IAC %d\n", direction, option);
    }
    else
    {
      fmt = (cmd == WILL) ? "WILL" : (cmd == WONT) ? "WONT" :
        (cmd == DO) ? "DO" : (cmd == DONT) ? "DONT" : 0;
      if (fmt)
      {
        if (TELOPT_OK(option))
          opt = TELOPT(option);
        else if (option == TELOPT_EXOPL)
          opt = "EXOPL";
        else
          opt = NULL;

        if(opt)
          Curl_infof(data, "%s %s %s\n", direction, fmt, opt);
        else
          Curl_infof(data, "%s %s %d\n", direction, fmt, option);
      }
      else
        Curl_infof(data, "%s %d %d\n", direction, cmd, option);
    }
  }
}

static void send_negotiation(struct connectdata *conn, int cmd, int option)
{
   unsigned char buf[3];

   buf[0] = IAC;
   buf[1] = cmd;
   buf[2] = option;
   
   swrite(conn->firstsocket, buf, 3);
   
   printoption(conn->data, "SENT", cmd, option);
}

static
void set_remote_option(struct connectdata *conn, int option, int newstate)
{
  struct TELNET *tn = (struct TELNET *)conn->proto.telnet;
  if(newstate == YES)
  {
    switch(tn->him[option])
    {
      case NO:
        tn->him[option] = WANTYES;
        send_negotiation(conn, DO, option);
        break;
	 
      case YES:
        /* Already enabled */
        break;
	 
      case WANTNO:
        switch(tn->himq[option])
        {
          case EMPTY:
            /* Already negotiating for YES, queue the request */
            tn->himq[option] = OPPOSITE;
            break;
          case OPPOSITE:
            /* Error: already queued an enable request */
            break;
        }
        break;
	 
      case WANTYES:
        switch(tn->himq[option])
        {
          case EMPTY:
            /* Error: already negotiating for enable */
            break;
          case OPPOSITE:
            tn->himq[option] = EMPTY;
            break;
        }
        break;
    }
  }
  else /* NO */
  {
    switch(tn->him[option])
    {
      case NO:
        /* Already disabled */
        break;
	 
      case YES:
        tn->him[option] = WANTNO;
        send_negotiation(conn, DONT, option);
        break;
	 
      case WANTNO:
        switch(tn->himq[option])
        {
          case EMPTY:
            /* Already negotiating for NO */
            break;
          case OPPOSITE:
            tn->himq[option] = EMPTY;
            break;
        }
        break;
	 
      case WANTYES:
        switch(tn->himq[option])
        {
          case EMPTY:
            tn->himq[option] = OPPOSITE;
            break;
          case OPPOSITE:
            break;
        }
        break;
    }
  }
}

static
void rec_will(struct connectdata *conn, int option)
{
  struct TELNET *tn = (struct TELNET *)conn->proto.telnet;
  switch(tn->him[option])
  {
    case NO:
      if(tn->him_preferred[option] == YES)
      {
        tn->him[option] = YES;
        send_negotiation(conn, DO, option);
      }
      else
      {
        send_negotiation(conn, DONT, option);
      }
      break;
	 
    case YES:
      /* Already enabled */
      break;
	 
    case WANTNO:
      switch(tn->himq[option])
      {
        case EMPTY:
          /* Error: DONT answered by WILL */
          tn->him[option] = NO;
          break;
        case OPPOSITE:
          /* Error: DONT answered by WILL */
          tn->him[option] = YES;
          tn->himq[option] = EMPTY;
          break;
      }
      break;
	 
    case WANTYES:
      switch(tn->himq[option])
      {
        case EMPTY:
          tn->him[option] = YES;
          break;
        case OPPOSITE:
          tn->him[option] = WANTNO;
          tn->himq[option] = EMPTY;
          send_negotiation(conn, DONT, option);
          break;
      }
      break;
  }
}
   
static
void rec_wont(struct connectdata *conn, int option)
{
  struct TELNET *tn = (struct TELNET *)conn->proto.telnet;
  switch(tn->him[option])
  {
    case NO:
      /* Already disabled */
      break;
	 
    case YES:
      tn->him[option] = NO;
      send_negotiation(conn, DONT, option);
      break;
	 
    case WANTNO:
      switch(tn->himq[option])
      {
        case EMPTY:
          tn->him[option] = NO;
          break;
	 
        case OPPOSITE:
          tn->him[option] = WANTYES;
          tn->himq[option] = EMPTY;
          send_negotiation(conn, DO, option);
          break;
      }
      break;
	 
    case WANTYES:
      switch(tn->himq[option])
      {
        case EMPTY:
          tn->him[option] = NO;
          break;
        case OPPOSITE:
          tn->him[option] = NO;
          tn->himq[option] = EMPTY;
          break;
      }
      break;
  }
}
   
void set_local_option(struct connectdata *conn, int option, int newstate)
{
  struct TELNET *tn = (struct TELNET *)conn->proto.telnet;
  if(newstate == YES)
  {
    switch(tn->us[option])
    {
      case NO:
        tn->us[option] = WANTYES;
        send_negotiation(conn, WILL, option);
        break;
	 
      case YES:
        /* Already enabled */
        break;
	 
      case WANTNO:
        switch(tn->usq[option])
        {
          case EMPTY:
            /* Already negotiating for YES, queue the request */
            tn->usq[option] = OPPOSITE;
            break;
          case OPPOSITE:
            /* Error: already queued an enable request */
            break;
        }
        break;
	 
      case WANTYES:
        switch(tn->usq[option])
        {
          case EMPTY:
            /* Error: already negotiating for enable */
            break;
          case OPPOSITE:
            tn->usq[option] = EMPTY;
            break;
        }
        break;
    }
  }
  else /* NO */
  {
    switch(tn->us[option])
    {
      case NO:
        /* Already disabled */
        break;
	 
      case YES:
        tn->us[option] = WANTNO;
        send_negotiation(conn, WONT, option);
        break;
	 
      case WANTNO:
        switch(tn->usq[option])
        {
          case EMPTY:
            /* Already negotiating for NO */
            break;
          case OPPOSITE:
            tn->usq[option] = EMPTY;
            break;
        }
        break;
	 
      case WANTYES:
        switch(tn->usq[option])
        {
          case EMPTY:
            tn->usq[option] = OPPOSITE;
            break;
          case OPPOSITE:
            break;
        }
        break;
    }
  }
}

static
void rec_do(struct connectdata *conn, int option)
{
  struct TELNET *tn = (struct TELNET *)conn->proto.telnet;
  switch(tn->us[option])
  {
    case NO:
      if(tn->us_preferred[option] == YES)
      {
        tn->us[option] = YES;
        send_negotiation(conn, WILL, option);
      }
      else
      {
        send_negotiation(conn, WONT, option);
      }
      break;
	 
    case YES:
      /* Already enabled */
      break;
	 
    case WANTNO:
      switch(tn->usq[option])
      {
        case EMPTY:
          /* Error: DONT answered by WILL */
          tn->us[option] = NO;
          break;
        case OPPOSITE:
          /* Error: DONT answered by WILL */
          tn->us[option] = YES;
          tn->usq[option] = EMPTY;
          break;
      }
      break;
	 
    case WANTYES:
      switch(tn->usq[option])
      {
        case EMPTY:
          tn->us[option] = YES;
          break;
        case OPPOSITE:
          tn->us[option] = WANTNO;
          tn->himq[option] = EMPTY;
          send_negotiation(conn, WONT, option);
          break;
      }
      break;
  }
}

static   
void rec_dont(struct connectdata *conn, int option)
{
  struct TELNET *tn = (struct TELNET *)conn->proto.telnet;
  switch(tn->us[option])
  {
    case NO:
      /* Already disabled */
      break;
	 
    case YES:
      tn->us[option] = NO;
      send_negotiation(conn, WONT, option);
      break;
	 
    case WANTNO:
      switch(tn->usq[option])
      {
        case EMPTY:
          tn->us[option] = NO;
          break;
	 
        case OPPOSITE:
          tn->us[option] = WANTYES;
          tn->usq[option] = EMPTY;
          send_negotiation(conn, WILL, option);
          break;
      }
      break;
	 
    case WANTYES:
      switch(tn->usq[option])
      {
        case EMPTY:
          tn->us[option] = NO;
          break;
        case OPPOSITE:
          tn->us[option] = NO;
          tn->usq[option] = EMPTY;
          break;
      }
      break;
  }
}


static void printsub(struct SessionHandle *data,
		     int direction,		/* '<' or '>' */
		     unsigned char *pointer,	/* where suboption data is */
		     int length)		/* length of suboption data */
{
  int i = 0;

  if (data->set.verbose)
  {
    if (direction)
    {
      Curl_infof(data, "%s IAC SB ", (direction == '<')? "RCVD":"SENT");
      if (length >= 3)
      {
        int j;

        i = pointer[length-2];
        j = pointer[length-1];

        if (i != IAC || j != SE)
        {
          Curl_infof(data, "(terminated by ");
          if (TELOPT_OK(i))
            Curl_infof(data, "%s ", TELOPT(i));
          else if (TELCMD_OK(i))
            Curl_infof(data, "%s ", TELCMD(i));
          else
            Curl_infof(data, "%d ", i);
          if (TELOPT_OK(j))
            Curl_infof(data, "%s", TELOPT(j));
          else if (TELCMD_OK(j))
            Curl_infof(data, "%s", TELCMD(j));
          else
            Curl_infof(data, "%d", j);
          Curl_infof(data, ", not IAC SE!) ");
        }
      }
      length -= 2;
    }
    if (length < 1)
    {
      Curl_infof(data, "(Empty suboption?)");
      return;
    }

    if (TELOPT_OK(pointer[0])) {
      switch(pointer[0]) {
        case TELOPT_TTYPE:
        case TELOPT_XDISPLOC:
        case TELOPT_NEW_ENVIRON:
          Curl_infof(data, "%s", TELOPT(pointer[0]));
          break;
        default:
          Curl_infof(data, "%s (unsupported)", TELOPT(pointer[0]));
          break;
      }
    }
    else
      Curl_infof(data, "%d (unknown)", pointer[i]);

    switch(pointer[1]) {
      case TELQUAL_IS:
        Curl_infof(data, " IS");
        break;
      case TELQUAL_SEND:
        Curl_infof(data, " SEND");
        break;
      case TELQUAL_INFO:
        Curl_infof(data, " INFO/REPLY");
        break;
      case TELQUAL_NAME:
        Curl_infof(data, " NAME");
        break;
    }
      
    switch(pointer[0]) {
      case TELOPT_TTYPE:
      case TELOPT_XDISPLOC:
        pointer[length] = 0;
        Curl_infof(data, " \"%s\"", &pointer[2]);
        break;
      case TELOPT_NEW_ENVIRON:
        if(pointer[1] == TELQUAL_IS) {
          Curl_infof(data, " ");
          for(i = 3;i < length;i++) {
            switch(pointer[i]) {
              case NEW_ENV_VAR:
                Curl_infof(data, ", ");
                break;
              case NEW_ENV_VALUE:
                Curl_infof(data, " = ");
                break;
              default:
                Curl_infof(data, "%c", pointer[i]);
                break;
            }
          }
        }
        break;
      default:
        for (i = 2; i < length; i++)
          Curl_infof(data, " %.2x", pointer[i]);
        break;
    }
      
    if (direction)
    {
      Curl_infof(data, "\n");
    }
  }
}

static int check_telnet_options(struct connectdata *conn)
{
  struct curl_slist *head;
  char option_keyword[128];
  char option_arg[256];
  char *buf;
  struct SessionHandle *data = conn->data;
  struct TELNET *tn = (struct TELNET *)conn->proto.telnet;

  /* Add the user name as an environment variable if it
     was given on the command line */
  if(conn->bits.user_passwd)
  {
    char *buf = malloc(256);
    sprintf(buf, "USER,%s", data->state.user);
    tn->telnet_vars = curl_slist_append(tn->telnet_vars, buf);

    tn->us_preferred[TELOPT_NEW_ENVIRON] = YES;
  }

  for(head = data->set.telnet_options; head; head=head->next) {
    if(sscanf(head->data, "%127[^= ]%*[ =]%255s",
              option_keyword, option_arg) == 2) {

      /* Terminal type */
      if(strequal(option_keyword, "TTYPE")) {
        strncpy(tn->subopt_ttype, option_arg, 31);
        tn->subopt_ttype[31] = 0; /* String termination */
        tn->us_preferred[TELOPT_TTYPE] = YES;
        continue;
      }

      /* Display variable */
      if(strequal(option_keyword, "XDISPLOC")) {
        strncpy(tn->subopt_xdisploc, option_arg, 127);
        tn->subopt_xdisploc[127] = 0; /* String termination */
        tn->us_preferred[TELOPT_XDISPLOC] = YES;
        continue;
      }

      /* Environment variable */
      if(strequal(option_keyword, "NEW_ENV")) {
        buf = strdup(option_arg);
        if(!buf)
          return CURLE_OUT_OF_MEMORY;
        tn->telnet_vars = curl_slist_append(tn->telnet_vars, buf);
        tn->us_preferred[TELOPT_NEW_ENVIRON] = YES;
        continue;
      }

      failf(data, "Unknown telnet option %s", head->data);
      return CURLE_UNKNOWN_TELNET_OPTION;
    } else {
      failf(data, "Syntax error in telnet option: %s", head->data);
      return CURLE_TELNET_OPTION_SYNTAX;
    }
  }

  return CURLE_OK;
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
  unsigned char subchar;
  unsigned char temp[2048];
  int len;
  int tmplen;
  char varname[128];
  char varval[128];
  struct SessionHandle *data = conn->data;
  struct TELNET *tn = (struct TELNET *)conn->proto.telnet;

  printsub(data, '<', (unsigned char *)tn->subbuffer, SB_LEN(tn)+2);
  switch (subchar = SB_GET(tn)) {
    case TELOPT_TTYPE:
      len = strlen(tn->subopt_ttype) + 4 + 2;
      snprintf((char *)temp, sizeof(temp),
               "%c%c%c%c%s%c%c", IAC, SB, TELOPT_TTYPE,
               TELQUAL_IS, tn->subopt_ttype, IAC, SE);
      swrite(conn->firstsocket, temp, len);
      printsub(data, '>', &temp[2], len-2);
      break;
    case TELOPT_XDISPLOC:
      len = strlen(tn->subopt_xdisploc) + 4 + 2;
      snprintf((char *)temp, sizeof(temp),
               "%c%c%c%c%s%c%c", IAC, SB, TELOPT_XDISPLOC,
               TELQUAL_IS, tn->subopt_xdisploc, IAC, SE);
      swrite(conn->firstsocket, temp, len);
      printsub(data, '>', &temp[2], len-2);
      break;
    case TELOPT_NEW_ENVIRON:
      snprintf((char *)temp, sizeof(temp),
               "%c%c%c%c", IAC, SB, TELOPT_NEW_ENVIRON, TELQUAL_IS);
      len = 4;

      for(v = tn->telnet_vars;v;v = v->next) {
        tmplen = (strlen(v->data) + 1);
        /* Add the variable only if it fits */
        if(len + tmplen < (int)sizeof(temp)-6) {
          sscanf(v->data, "%127[^,],%s", varname, varval);
          snprintf((char *)&temp[len], sizeof(temp) - len,
                   "%c%s%c%s", NEW_ENV_VAR, varname,
                   NEW_ENV_VALUE, varval);
          len += tmplen;
        }
      }
      snprintf((char *)&temp[len], sizeof(temp) - len,
               "%c%c", IAC, SE);
      len += 2;
      swrite(conn->firstsocket, temp, len);
      printsub(data, '>', &temp[2], len-2);
      break;
  }
  return;
}

static
void telrcv(struct connectdata *conn,
            unsigned char *inbuf,	/* Data received from socket */
            int count)			/* Number of bytes received */
{
  unsigned char c;
  int index = 0;
  struct SessionHandle *data = conn->data;
  struct TELNET *tn = (struct TELNET *)conn->proto.telnet;

  while(count--)
  {
    c = inbuf[index++];

    switch (tn->telrcv_state)
    {
      case TS_CR:
        tn->telrcv_state = TS_DATA;
        if (c == '\0')
        {
          break;   /* Ignore \0 after CR */
        }

        Curl_client_write(data, CLIENTWRITE_BODY, (char *)&c, 1);
        continue;

      case TS_DATA:
        if (c == IAC)
        {
          tn->telrcv_state = TS_IAC;
          break;
        }
        else if(c == '\r')
        {
          tn->telrcv_state = TS_CR;
        }

        Curl_client_write(data, CLIENTWRITE_BODY, (char *)&c, 1);
        continue;

      case TS_IAC:
      process_iac:
      switch (c)
      {
        case WILL:
          tn->telrcv_state = TS_WILL;
          continue;
        case WONT:
          tn->telrcv_state = TS_WONT;
          continue;
        case DO:
          tn->telrcv_state = TS_DO;
          continue;
        case DONT:
          tn->telrcv_state = TS_DONT;
          continue;
        case SB:
          SB_CLEAR(tn);
          tn->telrcv_state = TS_SB;
          continue;
        case IAC:
          Curl_client_write(data, CLIENTWRITE_BODY, (char *)&c, 1);
          break;
        case DM:
        case NOP:
        case GA:
        default:
          printoption(data, "RCVD", IAC, c);
          break;
      }
      tn->telrcv_state = TS_DATA;
      continue;

      case TS_WILL:
        printoption(data, "RCVD", WILL, c);
        tn->please_negotiate = 1;
        rec_will(conn, c);
        tn->telrcv_state = TS_DATA;
        continue;
      
      case TS_WONT:
        printoption(data, "RCVD", WONT, c);
        tn->please_negotiate = 1;
        rec_wont(conn, c);
        tn->telrcv_state = TS_DATA;
        continue;
      
      case TS_DO:
        printoption(data, "RCVD", DO, c);
        tn->please_negotiate = 1;
        rec_do(conn, c);
        tn->telrcv_state = TS_DATA;
        continue;
      
      case TS_DONT:
        printoption(data, "RCVD", DONT, c);
        tn->please_negotiate = 1;
        rec_dont(conn, c);
        tn->telrcv_state = TS_DATA;
        continue;

      case TS_SB:
        if (c == IAC)
        {
          tn->telrcv_state = TS_SE;
        }
        else
        {
          SB_ACCUM(tn,c);
        }
        continue;

      case TS_SE:
        if (c != SE)
        {
          if (c != IAC)
          {
            /*
             * This is an error.  We only expect to get
             * "IAC IAC" or "IAC SE".  Several things may
             * have happend.  An IAC was not doubled, the
             * IAC SE was left off, or another option got
             * inserted into the suboption are all possibilities.
             * If we assume that the IAC was not doubled,
             * and really the IAC SE was left off, we could
             * get into an infinate loop here.  So, instead,
             * we terminate the suboption, and process the
             * partial suboption if we can.
             */
            SB_ACCUM(tn, (unsigned char)IAC);
            SB_ACCUM(tn, c);
            tn->subpointer -= 2;
            SB_TERM(tn);
	    
            printoption(data, "In SUBOPTION processing, RCVD", IAC, c);
            suboption(conn);   /* handle sub-option */
            tn->telrcv_state = TS_IAC;
            goto process_iac;
          }
          SB_ACCUM(tn,c);
          tn->telrcv_state = TS_SB;
        }
        else
        {
          SB_ACCUM(tn, (unsigned char)IAC);
          SB_ACCUM(tn, (unsigned char)SE);
          tn->subpointer -= 2;
          SB_TERM(tn);
          suboption(conn);   /* handle sub-option */
          tn->telrcv_state = TS_DATA;
        }
        break;
    }
  }
}

CURLcode Curl_telnet_done(struct connectdata *conn)
{
  struct TELNET *tn = (struct TELNET *)conn->proto.telnet;
  curl_slist_free_all(tn->telnet_vars);

  free(conn->proto.telnet);
  conn->proto.telnet = NULL;

  return CURLE_OK;
}

CURLcode Curl_telnet(struct connectdata *conn)
{
  CURLcode code;
  struct SessionHandle *data = conn->data;
  int sockfd = conn->firstsocket;
#ifdef WIN32
  WSAEVENT event_handle;
  WSANETWORKEVENTS events;
  HANDLE stdin_handle;
  HANDLE objs[2];
  DWORD waitret;
#else
  fd_set readfd;
  fd_set keepfd;
#endif
  bool keepon = TRUE;
  char *buf = data->state.buffer;
  ssize_t nread;
  struct TELNET *tn;
  struct timeval now;           /* current time */

  code = init_telnet(conn);
  if(code)
    return code;

  tn = (struct TELNET *)conn->proto.telnet;

  code = check_telnet_options(conn);
  if(code)
    return code;

#ifdef WIN32
  /* We want to wait for both stdin and the socket. Since
  ** the select() function in winsock only works on sockets
  ** we have to use the WaitForMultipleObjects() call.
  */

  /* First, create a sockets event object */
  event_handle = WSACreateEvent();

  /* The get the Windows file handle for stdin */
  stdin_handle = GetStdHandle(STD_INPUT_HANDLE);

  /* Create the list of objects to wait for */
  objs[0] = stdin_handle;
  objs[1] = event_handle;

  /* Tell winsock what events we want to listen to */
  if(WSAEventSelect(sockfd, event_handle, FD_READ|FD_CLOSE) == SOCKET_ERROR) {
    return 0;
  }

  /* Keep on listening and act on events */
  while(keepon) {
    waitret = WaitForMultipleObjects(2, objs, FALSE, INFINITE);
    switch(waitret - WAIT_OBJECT_0)
    {
      case 0:
      {
        unsigned char outbuf[2];
        int out_count = 0;
        ssize_t bytes_written;
        char *buffer = buf;
              
        if(!ReadFile(stdin_handle, buf, 255, &nread, NULL)) {
          keepon = FALSE;
          break;
        }
        
        while(nread--) {
          outbuf[0] = *buffer++;
          out_count = 1;
          if(outbuf[0] == IAC)
            outbuf[out_count++] = IAC;
          
          Curl_write(conn, conn->firstsocket, outbuf,
                     out_count, &bytes_written);
        }
      }
      break;
      
      case 1:
        if(WSAEnumNetworkEvents(sockfd, event_handle, &events)
           != SOCKET_ERROR)
        {
          if(events.lNetworkEvents & FD_READ)
          {
            /* This reallu OUGHT to check its return code. */
            Curl_read(conn, sockfd, buf, BUFSIZE - 1, &nread);
            
            telrcv(conn, (unsigned char *)buf, nread);
            
            fflush(stdout);
            
            /* Negotiate if the peer has started negotiating,
               otherwise don't. We don't want to speak telnet with
               non-telnet servers, like POP or SMTP. */
            if(tn->please_negotiate && !tn->already_negotiated) {
              negotiate(conn);
              tn->already_negotiated = 1;
            }
          }
          
          if(events.lNetworkEvents & FD_CLOSE)
          {
            keepon = FALSE;
          }
        }
        break;
    }
  }
#else
  FD_ZERO (&readfd);		/* clear it */
  FD_SET (sockfd, &readfd);
  FD_SET (0, &readfd);

  keepfd = readfd;

  while (keepon) {
    struct timeval interval;

    readfd = keepfd;		/* set this every lap in the loop */
    interval.tv_sec = 1;
    interval.tv_usec = 0;

    switch (select (sockfd + 1, &readfd, NULL, NULL, &interval)) {
    case -1:			/* error, stop reading */
      keepon = FALSE;
      continue;
    case 0:			/* timeout */
      break;
    default:			/* read! */
      if(FD_ISSET(0, &readfd)) { /* read from stdin */
        unsigned char outbuf[2];
        int out_count = 0;
        ssize_t bytes_written;
        char *buffer = buf;
        
        nread = read(0, buf, 255);

        while(nread--) {
          outbuf[0] = *buffer++;
          out_count = 1;
          if(outbuf[0] == IAC)
            outbuf[out_count++] = IAC;
      
          Curl_write(conn, conn->firstsocket, outbuf,
                     out_count, &bytes_written);
        }
      }

      if(FD_ISSET(sockfd, &readfd)) {
        /* This OUGHT to check the return code... */
        Curl_read(conn, sockfd, buf, BUFSIZE - 1, &nread);

        /* if we receive 0 or less here, the server closed the connection and
           we bail out from this! */
        if (nread <= 0) {
          keepon = FALSE;
          break;
        }

        telrcv(conn, (unsigned char *)buf, nread);

        /* Negotiate if the peer has started negotiating,
           otherwise don't. We don't want to speak telnet with
           non-telnet servers, like POP or SMTP. */
        if(tn->please_negotiate && !tn->already_negotiated) {
          negotiate(conn);
          tn->already_negotiated = 1;
        }
      }
    }
    if(data->set.timeout) {
      now = Curl_tvnow();
      if(Curl_tvdiff(now, conn->created)/1000 >= data->set.timeout) {
        failf(data, "Time-out");
        code = CURLE_OPERATION_TIMEOUTED;
        keepon = FALSE;
      }
    }
  }
#endif
  /* mark this as "no further transfer wanted" */
  Curl_Transfer(conn, -1, -1, FALSE, NULL, -1, NULL);

  return code;
}

/*
 * local variables:
 * eval: (load-file "../curl-mode.el")
 * end:
 * vim600: fdm=marker
 * vim: et sw=2 ts=2 sts=2 tw=78
 */
#endif
