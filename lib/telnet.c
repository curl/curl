/*****************************************************************************
 *                                  _   _ ____  _     
 *  Project                     ___| | | |  _ \| |    
 *                             / __| | | | |_) | |    
 *                            | (__| |_| |  _ <| |___ 
 *                             \___|\___/|_| \_\_____|
 *
 *  The contents of this file are subject to the Mozilla Public License
 *  Version 1.0 (the "License"); you may not use this file except in
 *  compliance with the License. You may obtain a copy of the License at
 *  http://www.mozilla.org/MPL/
 *
 *  Software distributed under the License is distributed on an "AS IS"
 *  basis, WITHOUT WARRANTY OF ANY KIND, either express or implied. See the
 *  License for the specific language governing rights and limitations
 *  under the License.
 *
 *  The Original Code is Curl.
 *
 *  The Initial Developer of the Original Code is Daniel Stenberg.
 *
 *  Portions created by the Initial Developer are Copyright (C) 1998.
 *  All Rights Reserved.
 *
 * ------------------------------------------------------------
 * Main author:
 * - Daniel Stenberg <Daniel.Stenberg@haxx.nu>
 *
 * 	http://curl.haxx.nu
 *
 * $Source$
 * $Revision$
 * $Date$
 * $Author$
 * $State$
 * $Locker$
 *
 * ------------------------------------------------------------
 *
 * This implementation of the TELNET protocol is written by
 * Linus Nielsen <Linus.Nielsen@haxx.nu>,
 * with some code snippets stolen from the BSD Telnet client.
 *
 * The negotiation is performed according to RFC 1143 (D. Bernstein,
 * "The Q Method of Implementing TELNET Option Negotiation")
 *
 ****************************************************************************/

/* -- WIN32 approved -- */
#include <stdio.h>
#include <string.h>
#include <stdarg.h>
#include <stdlib.h>
#include <ctype.h>
#include <sys/types.h>
#include <sys/stat.h>

#include <errno.h>

#include "setup.h"

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
#include "download.h"
#include "sendf.h"
#include "formdata.h"
#include "progress.h"

#define _MPRINTF_REPLACE /* use our functions only */
#include <curl/mprintf.h>

#define  TELOPTS
#define  TELCMDS
#define  SLC_NAMES

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

void telwrite(struct UrlData *data,
	      unsigned char *buffer,	/* Data to write */
	      int count);		/* Number of bytes to write */

void telrcv(struct UrlData *data,
	    unsigned char *inbuf,	/* Data received from socket */
	    int count);			/* Number of bytes received */

static void printoption(struct UrlData *data,
			const char *direction,
			int cmd, int option);

static void negotiate(struct UrlData *data);
static void send_negotiation(struct UrlData *data, int cmd, int option);
static void set_local_option(struct UrlData *data, int cmd, int option);
static void set_remote_option(struct UrlData *data, int cmd, int option);

static void printsub(struct UrlData *data,
		     int direction, unsigned char *pointer, int length);
static void suboption(struct UrlData *data);

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

static int us[256]; 
static int usq[256]; 
static int us_preferred[256]; 
static int him[256]; 
static int himq[256]; 
static int him_preferred[256]; 

void init_telnet(struct UrlData *data)
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

   /* Set the options we want */
   us_preferred[TELOPT_BINARY] = YES;
   us_preferred[TELOPT_SGA] = YES;
   him_preferred[TELOPT_BINARY] = YES;
   him_preferred[TELOPT_SGA] = YES;

   /* Start negotiating */
   negotiate(data);
}

static void negotiate(struct UrlData *data)
{
   int i;
   
   for(i = 0;i < NTELOPTS;i++)
   {
      if(us_preferred[i] == YES)
	 set_local_option(data, i, YES);
      
      if(him_preferred[i] == YES)
	 set_remote_option(data, i, YES);
   }
}

static void printoption(struct UrlData *data,
			const char *direction, int cmd, int option)
{
   char *fmt;
   char *opt;
   
   if (data->conf & CONF_VERBOSE)
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

static void send_negotiation(struct UrlData *data, int cmd, int option)
{
   unsigned char buf[3];

   buf[0] = IAC;
   buf[1] = cmd;
   buf[2] = option;
   
   swrite(data->firstsocket, buf, 3);
   
   printoption(data, "SENT", cmd, option);
}

void set_remote_option(struct UrlData *data, int option, int newstate)
{
   if(newstate == YES)
   {
      switch(him[option])
      {
      case NO:
	 him[option] = WANTYES;
	 send_negotiation(data, DO, option);
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
	 send_negotiation(data, DONT, option);
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

void rec_will(struct UrlData *data, int option)
{
   switch(him[option])
   {
   case NO:
      if(him_preferred[option] == YES)
      {
	 him[option] = YES;
	 send_negotiation(data, DO, option);
      }
      else
      {
	 send_negotiation(data, DONT, option);
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
	 send_negotiation(data, DONT, option);
	 break;
      }
      break;
   }
}
   
void rec_wont(struct UrlData *data, int option)
{
   switch(him[option])
   {
   case NO:
      /* Already disabled */
      break;
	 
   case YES:
      him[option] = NO;
      send_negotiation(data, DONT, option);
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
	 send_negotiation(data, DO, option);
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
   
void set_local_option(struct UrlData *data, int option, int newstate)
{
   if(newstate == YES)
   {
      switch(us[option])
      {
      case NO:
	 us[option] = WANTYES;
	 send_negotiation(data, WILL, option);
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
	 send_negotiation(data, WONT, option);
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

void rec_do(struct UrlData *data, int option)
{
   switch(us[option])
   {
   case NO:
      if(us_preferred[option] == YES)
      {
	 us[option] = YES;
	 send_negotiation(data, WILL, option);
      }
      else
      {
	 send_negotiation(data, WONT, option);
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
	 send_negotiation(data, WONT, option);
	 break;
      }
      break;
   }
}
   
void rec_dont(struct UrlData *data, int option)
{
   switch(us[option])
   {
   case NO:
      /* Already disabled */
      break;
	 
   case YES:
      us[option] = NO;
      send_negotiation(data, WONT, option);
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
	 send_negotiation(data, WILL, option);
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

   if (data->conf & CONF_VERBOSE)
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

      if (TELOPT_OK(pointer[0]))
	 printf("%s (unknown)", TELOPT(pointer[0]));
      else
	 printf("%d (unknown)", pointer[i]);
      for (i = 1; i < length; i++)
	 printf(" %d", pointer[i]);
      
      if (direction)
      {
         printf("\n");
      }
   }
}

/*
 * suboption()
 *
 * Look at the sub-option buffer, and try to be helpful to the other
 * side.
 * No suboptions are supported yet.
 */

static void suboption(struct UrlData *data)
{
   printsub(data, '<', (unsigned char *)subbuffer, SB_LEN()+2);
   return;
}

void telrcv(struct UrlData *data,
	    unsigned char *inbuf,	/* Data received from socket */
	    int count)			/* Number of bytes received */
{
   unsigned char c;
   int index = 0;

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
	 
	 data->fwrite((char *)&c, 1, 1, data->out);
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

	 data->fwrite((char *)&c, 1, 1, data->out);
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
	   data->fwrite((char *)&c, 1, 1, data->out);
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
	 rec_will(data, c);
	 telrcv_state = TS_DATA;
	 continue;
      
      case TS_WONT:
	 printoption(data, "RCVD", WONT, c);
	 rec_wont(data, c);
	 telrcv_state = TS_DATA;
	 continue;
      
      case TS_DO:
	 printoption(data, "RCVD", DO, c);
	 rec_do(data, c);
	 telrcv_state = TS_DATA;
	 continue;
      
      case TS_DONT:
	 printoption(data, "RCVD", DONT, c);
	 rec_dont(data, c);
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
	       suboption(data);   /* handle sub-option */
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
	    suboption(data);   /* handle sub-option */
	    telrcv_state = TS_DATA;
	 }
	 break;
      }
   }
}

void telwrite(struct UrlData *data,
	      unsigned char *buffer,	/* Data to write */
	      int count)		/* Number of bytes to write */
{
   unsigned char outbuf[2];
   int out_count = 0;
   int bytes_written;

   while(count--)
   {
      outbuf[0] = *buffer++;
      out_count = 1;
      if(outbuf[0] == IAC)
	 outbuf[out_count++] = IAC;
      
#ifndef USE_SSLEAY
      bytes_written = swrite(data->firstsocket, outbuf, out_count);
#else
      if (data->use_ssl) {
        bytes_written = SSL_write(data->ssl, (char *)outbuf, out_count);
      }
      else {
        bytes_written = swrite(data->firstsocket, outbuf, out_count);
      }
#endif /* USE_SSLEAY */
   }
}

UrgError telnet(struct UrlData *data)
{
   int sockfd = data->firstsocket;
   fd_set readfd;
   fd_set keepfd;

   bool keepon = TRUE;
   char *buf = data->buffer;
   int nread;

   init_telnet(data);
   
   FD_ZERO (&readfd);		/* clear it */
   FD_SET (sockfd, &readfd);
   FD_SET (1, &readfd);

   keepfd = readfd;

   while (keepon)
   {
      readfd = keepfd;		/* set this every lap in the loop */

      switch (select (sockfd + 1, &readfd, NULL, NULL, NULL))
      {
      case -1:			/* error, stop reading */
	 keepon = FALSE;
	 continue;
      case 0:			/* timeout */
	 break;
      default:			/* read! */
	 if(FD_ISSET(1, &readfd))
	 {
	    nread = read(1, buf, 255);
	    telwrite(data, (unsigned char *)buf, nread);
	 }

	 if(FD_ISSET(sockfd, &readfd))
	 {
#ifndef USE_SSLEAY
	    nread = sread (sockfd, buf, BUFSIZE - 1);
#else
	    if (data->use_ssl) {
	       nread = SSL_read (data->ssl, buf, BUFSIZE - 1);
	    }
	    else {
	       nread = sread (sockfd, buf, BUFSIZE - 1);
	    }
#endif /* USE_SSLEAY */
	 }

	 /* if we receive 0 or less here, the server closed the connection and
	   we bail out from this! */
	if (nread <= 0) {
	  keepon = FALSE;
	  break;
	}

	 telrcv(data, (unsigned char *)buf, nread);
      }
   }
   return URG_OK;
}


