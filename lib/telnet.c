/*****************************************************************************
 *                                  _   _ ____  _     
 *  Project                     ___| | | |  _ \| |    
 *                             / __| | | | |_) | |    
 *                            | (__| |_| |  _ <| |___ 
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) 2000, Daniel Stenberg, <daniel@haxx.se>, et al.
 *
 * In order to be useful for every potential user, curl and libcurl are
 * dual-licensed under the MPL and the MIT/X-derivate licenses.
 *
 * You may opt to use, copy, modify, merge, publish, distribute and/or sell
 * copies of the Software, and permit persons to whom the Software is
 * furnished to do so, under the terms of the MPL or the MIT/X-derivate
 * licenses. You may pick one of these licenses.
 *
 * This software is distributed on an "AS IS" basis, WITHOUT WARRANTY OF ANY
 * KIND, either express or implied.
 *
 * $Id$
 *****************************************************************************/

#include "setup.h"

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
#include <winsock.h>
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

#define SUBBUFSIZE 512

#define  SB_CLEAR()  subpointer = subbuffer;
#define  SB_TERM()   { subend = subpointer; SB_CLEAR(); }
#define  SB_ACCUM(c) if (subpointer < (subbuffer+sizeof subbuffer)) { \
            *subpointer++ = (c); \
         }

#define  SB_GET() ((*subpointer++)&0xff)
#define  SB_PEEK()   ((*subpointer)&0xff)
#define  SB_EOF() (subpointer >= subend)
#define  SB_LEN() (subend - subpointer)

static
void telrcv(struct connectdata *,
	    unsigned char *inbuf,	/* Data received from socket */
	    int count);			/* Number of bytes received */

static void printoption(struct UrlData *data,
			const char *direction,
			int cmd, int option);

static void negotiate(struct connectdata *);
static void send_negotiation(struct connectdata *, int cmd, int option);
static void set_local_option(struct connectdata *, int cmd, int option);
static void set_remote_option(struct connectdata *, int cmd, int option);

static void printsub(struct UrlData *data,
		     int direction, unsigned char *pointer, int length);
static void suboption(struct connectdata *);

/* suboptions */
static char subbuffer[SUBBUFSIZE];
static char *subpointer, *subend;    /* buffer for sub-options */

/*
 * Telnet receiver states for fsm
 */
static enum
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
} telrcv_state;

/* For negotiation compliant to RFC 1143 */
#define NO	0
#define YES 	1
#define WANTYES	2
#define WANTNO	3

#define EMPTY	 0
#define OPPOSITE 1

static int please_negotiate = 0;
static int already_negotiated = 0;
static int us[256]; 
static int usq[256]; 
static int us_preferred[256]; 
static int him[256]; 
static int himq[256]; 
static int him_preferred[256]; 

static char *subopt_ttype = NULL; /* Set with suboption TTYPE */
static char *subopt_xdisploc = NULL; /* Set with suboption XDISPLOC */
static struct curl_slist *telnet_vars = NULL; /* Environment variables */

static
void init_telnet(struct connectdata *conn)
{
  telrcv_state = TS_DATA;

  /* Init suboptions */
  SB_CLEAR();

  /* Set all options to NO */
  memset(us, NO, 256);
  memset(usq, NO, 256);
  memset(us_preferred, NO, 256);
  memset(him, NO, 256);
  memset(himq, NO, 256);
  memset(him_preferred, NO, 256);

  /* Set the options we want by default */
  us_preferred[TELOPT_BINARY] = YES;
  us_preferred[TELOPT_SGA] = YES;
  him_preferred[TELOPT_BINARY] = YES;
  him_preferred[TELOPT_SGA] = YES;
}

static void negotiate(struct connectdata *conn)
{
  int i;
   
  for(i = 0;i < NTELOPTS;i++)
  {
    if(us_preferred[i] == YES)
      set_local_option(conn, i, YES);
      
    if(him_preferred[i] == YES)
      set_remote_option(conn, i, YES);
  }
}

static void printoption(struct UrlData *data,
			const char *direction, int cmd, int option)
{
  char *fmt;
  char *opt;
   
  if (data->bits.verbose)
  {
    if (cmd == IAC)
    {
      if (TELCMD_OK(option))
        printf("%s IAC %s\n", direction, TELCMD(option));
      else
        printf("%s IAC %d\n", direction, option);
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
          printf("%s %s %s\n", direction, fmt, opt);
        else
          printf("%s %s %d\n", direction, fmt, option);
      }
      else
        printf("%s %d %d\n", direction, cmd, option);
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
  if(newstate == YES)
  {
    switch(him[option])
    {
      case NO:
        him[option] = WANTYES;
        send_negotiation(conn, DO, option);
        break;
	 
      case YES:
        /* Already enabled */
        break;
	 
      case WANTNO:
        switch(himq[option])
        {
          case EMPTY:
            /* Already negotiating for YES, queue the request */
            himq[option] = OPPOSITE;
            break;
          case OPPOSITE:
            /* Error: already queued an enable request */
            break;
        }
        break;
	 
      case WANTYES:
        switch(himq[option])
        {
          case EMPTY:
            /* Error: already negotiating for enable */
            break;
          case OPPOSITE:
            himq[option] = EMPTY;
            break;
        }
        break;
    }
  }
  else /* NO */
  {
    switch(him[option])
    {
      case NO:
        /* Already disabled */
        break;
	 
      case YES:
        him[option] = WANTNO;
        send_negotiation(conn, DONT, option);
        break;
	 
      case WANTNO:
        switch(himq[option])
        {
          case EMPTY:
            /* Already negotiating for NO */
            break;
          case OPPOSITE:
            himq[option] = EMPTY;
            break;
        }
        break;
	 
      case WANTYES:
        switch(himq[option])
        {
          case EMPTY:
            himq[option] = OPPOSITE;
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
  switch(him[option])
  {
    case NO:
      if(him_preferred[option] == YES)
      {
        him[option] = YES;
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
      switch(himq[option])
      {
        case EMPTY:
          /* Error: DONT answered by WILL */
          him[option] = NO;
          break;
        case OPPOSITE:
          /* Error: DONT answered by WILL */
          him[option] = YES;
          himq[option] = EMPTY;
          break;
      }
      break;
	 
    case WANTYES:
      switch(himq[option])
      {
        case EMPTY:
          him[option] = YES;
          break;
        case OPPOSITE:
          him[option] = WANTNO;
          himq[option] = EMPTY;
          send_negotiation(conn, DONT, option);
          break;
      }
      break;
  }
}
   
static
void rec_wont(struct connectdata *conn, int option)
{
  switch(him[option])
  {
    case NO:
      /* Already disabled */
      break;
	 
    case YES:
      him[option] = NO;
      send_negotiation(conn, DONT, option);
      break;
	 
    case WANTNO:
      switch(himq[option])
      {
        case EMPTY:
          him[option] = NO;
          break;
	 
        case OPPOSITE:
          him[option] = WANTYES;
          himq[option] = EMPTY;
          send_negotiation(conn, DO, option);
          break;
      }
      break;
	 
    case WANTYES:
      switch(himq[option])
      {
        case EMPTY:
          him[option] = NO;
          break;
        case OPPOSITE:
          him[option] = NO;
          himq[option] = EMPTY;
          break;
      }
      break;
  }
}
   
void set_local_option(struct connectdata *conn, int option, int newstate)
{
  if(newstate == YES)
  {
    switch(us[option])
    {
      case NO:
        us[option] = WANTYES;
        send_negotiation(conn, WILL, option);
        break;
	 
      case YES:
        /* Already enabled */
        break;
	 
      case WANTNO:
        switch(usq[option])
        {
          case EMPTY:
            /* Already negotiating for YES, queue the request */
            usq[option] = OPPOSITE;
            break;
          case OPPOSITE:
            /* Error: already queued an enable request */
            break;
        }
        break;
	 
      case WANTYES:
        switch(usq[option])
        {
          case EMPTY:
            /* Error: already negotiating for enable */
            break;
          case OPPOSITE:
            usq[option] = EMPTY;
            break;
        }
        break;
    }
  }
  else /* NO */
  {
    switch(us[option])
    {
      case NO:
        /* Already disabled */
        break;
	 
      case YES:
        us[option] = WANTNO;
        send_negotiation(conn, WONT, option);
        break;
	 
      case WANTNO:
        switch(usq[option])
        {
          case EMPTY:
            /* Already negotiating for NO */
            break;
          case OPPOSITE:
            usq[option] = EMPTY;
            break;
        }
        break;
	 
      case WANTYES:
        switch(usq[option])
        {
          case EMPTY:
            usq[option] = OPPOSITE;
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
  switch(us[option])
  {
    case NO:
      if(us_preferred[option] == YES)
      {
        us[option] = YES;
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
      switch(usq[option])
      {
        case EMPTY:
          /* Error: DONT answered by WILL */
          us[option] = NO;
          break;
        case OPPOSITE:
          /* Error: DONT answered by WILL */
          us[option] = YES;
          usq[option] = EMPTY;
          break;
      }
      break;
	 
    case WANTYES:
      switch(usq[option])
      {
        case EMPTY:
          us[option] = YES;
          break;
        case OPPOSITE:
          us[option] = WANTNO;
          himq[option] = EMPTY;
          send_negotiation(conn, WONT, option);
          break;
      }
      break;
  }
}

static   
void rec_dont(struct connectdata *conn, int option)
{
  switch(us[option])
  {
    case NO:
      /* Already disabled */
      break;
	 
    case YES:
      us[option] = NO;
      send_negotiation(conn, WONT, option);
      break;
	 
    case WANTNO:
      switch(usq[option])
      {
        case EMPTY:
          us[option] = NO;
          break;
	 
        case OPPOSITE:
          us[option] = WANTYES;
          usq[option] = EMPTY;
          send_negotiation(conn, WILL, option);
          break;
      }
      break;
	 
    case WANTYES:
      switch(usq[option])
      {
        case EMPTY:
          us[option] = NO;
          break;
        case OPPOSITE:
          us[option] = NO;
          usq[option] = EMPTY;
          break;
      }
      break;
  }
}


static void printsub(struct UrlData *data,
		     int direction,		/* '<' or '>' */
		     unsigned char *pointer,	/* where suboption data is */
		     int length)		/* length of suboption data */
{
  int i = 0;

  if (data->bits.verbose)
  {
    if (direction)
    {
      printf("%s IAC SB ", (direction == '<')? "RCVD":"SENT");
      if (length >= 3)
      {
        int j;

        i = pointer[length-2];
        j = pointer[length-1];

        if (i != IAC || j != SE)
        {
          printf("(terminated by ");
          if (TELOPT_OK(i))
            printf("%s ", TELOPT(i));
          else if (TELCMD_OK(i))
            printf("%s ", TELCMD(i));
          else
            printf("%d ", i);
          if (TELOPT_OK(j))
            printf("%s", TELOPT(j));
          else if (TELCMD_OK(j))
            printf("%s", TELCMD(j));
          else
            printf("%d", j);
          printf(", not IAC SE!) ");
        }
      }
      length -= 2;
    }
    if (length < 1)
    {
      printf("(Empty suboption?)");
      return;
    }

    if (TELOPT_OK(pointer[0])) {
      switch(pointer[0]) {
        case TELOPT_TTYPE:
        case TELOPT_XDISPLOC:
        case TELOPT_NEW_ENVIRON:
          printf("%s", TELOPT(pointer[0]));
          break;
        default:
          printf("%s (unsupported)", TELOPT(pointer[0]));
          break;
      }
    }
    else
      printf("%d (unknown)", pointer[i]);

    switch(pointer[1]) {
      case TELQUAL_IS:
        printf(" IS");
        break;
      case TELQUAL_SEND:
        printf(" SEND");
        break;
      case TELQUAL_INFO:
        printf(" INFO/REPLY");
        break;
      case TELQUAL_NAME:
        printf(" NAME");
        break;
    }
      
    switch(pointer[0]) {
      case TELOPT_TTYPE:
      case TELOPT_XDISPLOC:
        pointer[length] = 0;
        printf(" \"%s\"", &pointer[2]);
        break;
      case TELOPT_NEW_ENVIRON:
        if(pointer[1] == TELQUAL_IS) {
          printf(" ");
          for(i = 3;i < length;i++) {
            switch(pointer[i]) {
              case NEW_ENV_VAR:
                printf(", ");
                break;
              case NEW_ENV_VALUE:
                printf(" = ");
                break;
              default:
                printf("%c", pointer[i]);
                break;
            }
          }
        }
        break;
      default:
        for (i = 2; i < length; i++)
          printf(" %.2x", pointer[i]);
        break;
    }
      
    if (direction)
    {
      printf("\n");
    }
  }
}

static int check_telnet_options(struct connectdata *conn)
{
  struct curl_slist *head;
  char option_keyword[128];
  char option_arg[256];
  char *buf;
  struct UrlData *data = conn->data;

  /* Add the user name as an environment variable if it
     was given on the command line */
  if(data->bits.user_passwd)
  {
    char *buf = malloc(256);
    sprintf(buf, "USER,%s", data->user);
    telnet_vars = curl_slist_append(telnet_vars, buf);

    us_preferred[TELOPT_NEW_ENVIRON] = YES;
  }

  for(head = data->telnet_options; head; head=head->next) {
    if(sscanf(head->data, "%127[^= ]%*[ =]%255s",
              option_keyword, option_arg) == 2) {

      /* Terminal type */
      if(strequal(option_keyword, "TTYPE")) {
        subopt_ttype = option_arg;
        us_preferred[TELOPT_TTYPE] = YES;
        continue;
      }

      /* Display variable */
      if(strequal(option_keyword, "XDISPLOC")) {
        subopt_xdisploc = option_arg;
        us_preferred[TELOPT_XDISPLOC] = YES;
        continue;
      }

      /* Environment variable */
      if(strequal(option_keyword, "NEW_ENV")) {
        buf = strdup(option_arg);
        if(!buf)
          return CURLE_OUT_OF_MEMORY;
        telnet_vars = curl_slist_append(telnet_vars, buf);
        us_preferred[TELOPT_NEW_ENVIRON] = YES;
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
 * No suboptions are supported yet.
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
  struct UrlData *data = conn->data;

  printsub(data, '<', (unsigned char *)subbuffer, SB_LEN()+2);
  switch (subchar = SB_GET()) {
    case TELOPT_TTYPE:
      len = strlen(subopt_ttype) + 4 + 2;
      snprintf((char *)temp, sizeof(temp),
               "%c%c%c%c%s%c%c", IAC, SB, TELOPT_TTYPE,
               TELQUAL_IS, subopt_ttype, IAC, SE);
      swrite(conn->firstsocket, temp, len);
      printsub(data, '>', &temp[2], len-2);
      break;
    case TELOPT_XDISPLOC:
      len = strlen(subopt_xdisploc) + 4 + 2;
      snprintf((char *)temp, sizeof(temp),
               "%c%c%c%c%s%c%c", IAC, SB, TELOPT_XDISPLOC,
               TELQUAL_IS, subopt_xdisploc, IAC, SE);
      swrite(conn->firstsocket, temp, len);
      printsub(data, '>', &temp[2], len-2);
      break;
    case TELOPT_NEW_ENVIRON:
      snprintf((char *)temp, sizeof(temp),
               "%c%c%c%c", IAC, SB, TELOPT_NEW_ENVIRON, TELQUAL_IS);
      len = 4;

      for(v = telnet_vars;v;v = v->next) {
        tmplen = (strlen(v->data) + 1);
        /* Add the variable only if it fits */
        if(len + tmplen < sizeof(temp)-6) {
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
  struct UrlData *data = conn->data;

  while(count--)
  {
    c = inbuf[index++];

    switch (telrcv_state)
    {
      case TS_CR:
        telrcv_state = TS_DATA;
        if (c == '\0')
        {
          break;   /* Ignore \0 after CR */
        }

        Curl_client_write(data, CLIENTWRITE_BODY, (char *)&c, 1);
        continue;

      case TS_DATA:
        if (c == IAC)
        {
          telrcv_state = TS_IAC;
          break;
        }
        else if(c == '\r')
        {
          telrcv_state = TS_CR;
        }

        Curl_client_write(data, CLIENTWRITE_BODY, (char *)&c, 1);
        continue;

      case TS_IAC:
      process_iac:
      switch (c)
      {
        case WILL:
          telrcv_state = TS_WILL;
          continue;
        case WONT:
          telrcv_state = TS_WONT;
          continue;
        case DO:
          telrcv_state = TS_DO;
          continue;
        case DONT:
          telrcv_state = TS_DONT;
          continue;
        case SB:
          SB_CLEAR();
          telrcv_state = TS_SB;
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
      telrcv_state = TS_DATA;
      continue;

      case TS_WILL:
        printoption(data, "RCVD", WILL, c);
        please_negotiate = 1;
        rec_will(conn, c);
        telrcv_state = TS_DATA;
        continue;
      
      case TS_WONT:
        printoption(data, "RCVD", WONT, c);
        please_negotiate = 1;
        rec_wont(conn, c);
        telrcv_state = TS_DATA;
        continue;
      
      case TS_DO:
        printoption(data, "RCVD", DO, c);
        please_negotiate = 1;
        rec_do(conn, c);
        telrcv_state = TS_DATA;
        continue;
      
      case TS_DONT:
        printoption(data, "RCVD", DONT, c);
        please_negotiate = 1;
        rec_dont(conn, c);
        telrcv_state = TS_DATA;
        continue;

      case TS_SB:
        if (c == IAC)
        {
          telrcv_state = TS_SE;
        }
        else
        {
          SB_ACCUM(c);
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
            SB_ACCUM((unsigned char)IAC);
            SB_ACCUM(c);
            subpointer -= 2;
            SB_TERM();
	    
            printoption(data, "In SUBOPTION processing, RCVD", IAC, c);
            suboption(conn);   /* handle sub-option */
            telrcv_state = TS_IAC;
            goto process_iac;
          }
          SB_ACCUM(c);
          telrcv_state = TS_SB;
        }
        else
        {
          SB_ACCUM((unsigned char)IAC);
          SB_ACCUM((unsigned char)SE);
          subpointer -= 2;
          SB_TERM();
          suboption(conn);   /* handle sub-option */
          telrcv_state = TS_DATA;
        }
        break;
    }
  }
}

CURLcode Curl_telnet_done(struct connectdata *conn)
{
  curl_slist_free_all(telnet_vars);
  return CURLE_OK;
}

CURLcode Curl_telnet(struct connectdata *conn)
{
  CURLcode code;
  struct UrlData *data = conn->data;
  int sockfd = conn->firstsocket;
  fd_set readfd;
  fd_set keepfd;

  bool keepon = TRUE;
  char *buf = data->buffer;
  ssize_t nread;

  init_telnet(conn);
   
  code = check_telnet_options(conn);
  if(code)
    return code;
  
  FD_ZERO (&readfd);		/* clear it */
  FD_SET (sockfd, &readfd);
  FD_SET (1, &readfd);

  keepfd = readfd;

  while (keepon) {
    readfd = keepfd;		/* set this every lap in the loop */

    switch (select (sockfd + 1, &readfd, NULL, NULL, NULL)) {
    case -1:			/* error, stop reading */
      keepon = FALSE;
      continue;
    case 0:			/* timeout */
      break;
    default:			/* read! */
      if(FD_ISSET(1, &readfd)) { /* read from stdin */
        unsigned char outbuf[2];
        int out_count = 0;
        size_t bytes_written;
        char *buffer = buf;
        
        nread = read(1, buf, 255);

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
        if(please_negotiate && !already_negotiated) {
          negotiate(conn);
          already_negotiated = 1;
        }
      }
    }
  }
  /* mark this as "no further transfer wanted" */
  return Curl_Transfer(conn, -1, -1, FALSE, NULL, -1, NULL);
}
