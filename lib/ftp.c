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
 * - Daniel Stenberg <daniel@haxx.se>
 *
 * 	http://curl.haxx.se
 *
 * $Source$
 * $Revision$
 * $Date$
 * $Author$
 * $State$
 * $Locker$
 *
 * ------------------------------------------------------------
 ****************************************************************************/

#include "setup.h"

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include <errno.h>

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#ifdef HAVE_SYS_SELECT_H
#include <sys/select.h>
#endif

#if defined(WIN32) && !defined(__GNUC__) || defined(__MINGW32__)
#include <winsock.h>
#else /* some kind of unix */
#ifdef HAVE_SYS_SOCKET_H
#include <sys/socket.h>
#endif
#include <sys/types.h>
#ifdef HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif
#ifdef HAVE_ARPA_INET_H
#include <arpa/inet.h>
#endif
#include <sys/utsname.h>
#ifdef HAVE_NETDB_H
#include <netdb.h>
#endif
#endif

#if defined(WIN32) && defined(__GNUC__) || defined(__MINGW32__)
#include <errno.h>
#endif

#include <curl/curl.h>
#include "urldata.h"
#include "sendf.h"

#include "if2ip.h"
#include "hostip.h"
#include "progress.h"
#include "download.h"
#include "escape.h"

/* returns last node in linked list */
static struct curl_slist *slist_get_last(struct curl_slist *list)
{
	struct curl_slist	*item;

	/* if caller passed us a NULL, return now */
	if (!list)
		return NULL;

	/* loop through to find the last item */
	item = list;
	while (item->next) {
		item = item->next;
	}
	return item;
}

/* append a struct to the linked list. It always retunrs the address of the
 * first record, so that you can sure this function as an initialization
 * function as well as an append function. If you find this bothersome,
 * then simply create a separate _init function and call it appropriately from
 * within the proram. */
struct curl_slist *curl_slist_append(struct curl_slist *list, char *data)
{
	struct curl_slist	*last;
	struct curl_slist	*new_item;

	new_item = (struct curl_slist *) malloc(sizeof(struct curl_slist));
	if (new_item) {
		new_item->next = NULL;
		new_item->data = strdup(data);
	}
	else {
		fprintf(stderr, "Cannot allocate memory for QUOTE list.\n");
		exit(-1);
	}

	if (list) {
		last = slist_get_last(list);
		last->next = new_item;
		return list;
	}

	/* if this is the first item, then new_item *is* the list */
	return new_item;
}

/* be nice and clean up resources */
void curl_slist_free_all(struct curl_slist *list)
{
	struct curl_slist	*next;
	struct curl_slist	*item;

	if (!list)
		return;

	item = list;
	do {
		next = item->next;
		
		if (item->data) {
			free(item->data);
		}
		free(item);
		item = next;
	} while (next);
}


static CURLcode AllowServerConnect(struct UrlData *data,
                                   int sock)
{
  fd_set rdset;
  struct timeval dt;
  
  FD_ZERO(&rdset);

  FD_SET(sock, &rdset);

  /* we give the server 10 seconds to connect to us */
  dt.tv_sec = 10;
  dt.tv_usec = 0;

  switch ( select(sock+1, &rdset, NULL, NULL, &dt)) {
  case -1: /* error */
    /* let's die here */
    failf(data, "Error while waiting for server connect");
    return CURLE_FTP_PORT_FAILED;
  case 0:  /* timeout */
    /* let's die here */
    failf(data, "Timeout while waiting for server connect");
    return CURLE_FTP_PORT_FAILED;
  default:
    /* we have received data here */
    {
      int s;
      size_t size = sizeof(struct sockaddr_in);
      struct sockaddr_in add;

      getsockname(sock, (struct sockaddr *) &add, (int *)&size);
      s=accept(sock, (struct sockaddr *) &add, (int *)&size);

      if( -1 == s) {
	/* DIE! */
	failf(data, "Error accept()ing server connect");
	return CURLE_FTP_PORT_FAILED;
      }
      infof(data, "Connection accepted from server\n");

      data->secondarysocket = s;
    }
    break;
  }
  return CURLE_OK;
}


/* --- parse FTP server responses --- */

#define lastline(line) (isdigit((int)line[0]) && isdigit((int)line[1]) && \
			isdigit((int)line[2]) && (' ' == line[3]))

int GetLastResponse(int sockfd, char *buf,
                    struct connectdata *conn)
{
  int nread;
  int keepon=TRUE;
  char *ptr;
  int timeout = 3600; /* in seconds */
  struct timeval interval;
  fd_set rkeepfd;
  fd_set readfd;
  struct UrlData *data = conn->data;

#define SELECT_OK      0
#define SELECT_ERROR   1
#define SELECT_TIMEOUT 2
  int error = SELECT_OK;

  if(data->timeout) {
    /* if timeout is requested, find out how much remaining time we have */
    timeout = data->timeout - /* timeout time */
      (tvlong(tvnow()) - tvlong(conn->now)); /* spent time */
    if(timeout <=0 ) {
      failf(data, "Transfer aborted due to timeout");
      return -SELECT_TIMEOUT; /* already too little time */
    }
  }

  FD_ZERO (&readfd);		/* clear it */
  FD_SET (sockfd, &readfd);     /* read socket */

  /* get this in a backup variable to be able to restore it on each lap in the
     select() loop */
  rkeepfd = readfd;

  do {
    ptr=buf;

    /* get us a full line, terminated with a newline */
    nread=0;
    keepon=TRUE;
    while((nread<BUFSIZE) && (keepon && !error)) {
      readfd = rkeepfd;		   /* set every lap */
      interval.tv_sec = timeout;
      interval.tv_usec = 0;

      switch (select (sockfd+1, &readfd, NULL, NULL, &interval)) {
      case -1: /* select() error, stop reading */
        error = SELECT_ERROR;
        failf(data, "Transfer aborted due to select() error");
        break;
      case 0: /* timeout */
        error = SELECT_TIMEOUT;
        infof(data, "Transfer aborted due to timeout\n");
        failf(data, "Transfer aborted due to timeout");
        break;
      default:
#ifdef USE_SSLEAY
        if (data->use_ssl) {
          keepon = SSL_read(data->ssl, ptr, 1);
        }
        else {
#endif
          keepon = sread(sockfd, ptr, 1);
#ifdef USE_SSLEAY
        }
#endif /* USE_SSLEAY */

        if ((*ptr == '\n') || (*ptr == '\r'))
          keepon = FALSE;
      }
      if(keepon) {
        nread++;
        ptr++;
      }
    }
    *ptr=0; /* zero terminate */

    if(data->bits.verbose && buf[0]) {
      fputs("< ", data->err);
      fwrite(buf, 1, nread, data->err);
      fputs("\n", data->err);
    }
  } while(!error &&
	  (nread<4 || !lastline(buf)) );
  
  if(error)
    return -error;

  return nread;
}

/* -- who are we? -- */
char *getmyhost(char *buf, int buf_size)
{
#if defined(HAVE_GETHOSTNAME)
  gethostname(buf, buf_size);
#elif defined(HAVE_UNAME)
  struct utsname ugnm;
  strncpy(buf, uname(&ugnm) < 0 ? "localhost" : ugnm.nodename, buf_size - 1);
  buf[buf_size - 1] = '\0';
#else
  /* We have no means of finding the local host name! */
  strncpy(buf, "localhost", buf_size);
  buf[buf_size - 1] = '\0';
#endif
  return buf;
}

#if 0
/*
 * URLfix()
 *
 * This function returns a string converted FROM the input URL format to a
 * format that is more likely usable for the remote server. That is, all
 * special characters (found as %XX-codes) will be eascaped with \<letter>.
 */

static char *URLfix(char *string)
{
  /* The length of the new string can't be longer than twice the original
     string, if all letters are '+'... */
  int alloc = strlen(string)*2;
  char *ns = malloc(alloc);
  unsigned char in;
  int index=0;
  int hex;
   
  while(*string) {
    in = *string;
    switch(in) {
    case '+':
      ns[index++] = '\\';
      ns[index++] = ' ';
      string++;
      continue;

    case '%':
      /* encoded part */
      if(sscanf(string+1, "%02X", &hex)) {
        ns[index++] = '\\';
        ns[index++] = hex;
        string+=3;
        continue;
      }
      /* FALLTHROUGH */
    default:
      ns[index++] = in;
      string++;
    }
  }
  ns[index]=0; /* terminate it */
  return ns;
}
#endif

/* ftp_connect() should do everything that is to be considered a part
   of the connection phase. */
CURLcode ftp_connect(struct connectdata *conn)
{
  /* this is FTP and no proxy */
  int nread;
  struct UrlData *data=conn->data;
  char *buf = data->buffer; /* this is our buffer */
  struct FTP *ftp;
  CURLcode result;

  myalarm(0); /* switch off the alarm stuff */

  ftp = (struct FTP *)malloc(sizeof(struct FTP));
  if(!ftp)
    return CURLE_OUT_OF_MEMORY;

  memset(ftp, 0, sizeof(struct FTP));
  data->proto.ftp = ftp;

  /* get some initial data into the ftp struct */
  ftp->bytecountp = &conn->bytecount;
  ftp->user = data->user;
  ftp->passwd = data->passwd;

  if (data->bits.tunnel_thru_httpproxy) {
    /* We want "seamless" FTP operations through HTTP proxy tunnel */
    result = GetHTTPProxyTunnel(data, data->firstsocket);
    if(CURLE_OK != result)
      return result;
  }

  /* The first thing we do is wait for the "220*" line: */
  nread = GetLastResponse(data->firstsocket, buf, conn);
  if(nread < 0)
    return CURLE_OPERATION_TIMEOUTED;
  if(strncmp(buf, "220", 3)) {
    failf(data, "This doesn't seem like a nice ftp-server response");
    return CURLE_FTP_WEIRD_SERVER_REPLY;
  }

  /* send USER */
  sendf(data->firstsocket, data, "USER %s\r\n", ftp->user);

  /* wait for feedback */
  nread = GetLastResponse(data->firstsocket, buf, conn);
  if(nread < 0)
    return CURLE_OPERATION_TIMEOUTED;

  if(!strncmp(buf, "530", 3)) {
    /* 530 User ... access denied
       (the server denies to log the specified user) */
    failf(data, "Access denied: %s", &buf[4]);
    return CURLE_FTP_ACCESS_DENIED;
  }
  else if(!strncmp(buf, "331", 3)) {
    /* 331 Password required for ...
       (the server requires to send the user's password too) */
    sendf(data->firstsocket, data, "PASS %s\r\n", ftp->passwd);
    nread = GetLastResponse(data->firstsocket, buf, conn);
    if(nread < 0)
      return CURLE_OPERATION_TIMEOUTED;

    if(!strncmp(buf, "530", 3)) {
      /* 530 Login incorrect.
         (the username and/or the password are incorrect) */
      failf(data, "the username and/or the password are incorrect");
      return CURLE_FTP_USER_PASSWORD_INCORRECT;
    }
    else if(!strncmp(buf, "230", 3)) {
      /* 230 User ... logged in.
         (user successfully logged in) */
        
      infof(data, "We have successfully logged in\n");
    }
    else {
      failf(data, "Odd return code after PASS");
      return CURLE_FTP_WEIRD_PASS_REPLY;
    }
  }
  else if(! strncmp(buf, "230", 3)) {
    /* 230 User ... logged in.
       (the user logged in without password) */
    infof(data, "We have successfully logged in\n");
  }
  else {
    failf(data, "Odd return code after USER");
    return CURLE_FTP_WEIRD_USER_REPLY;
  }

  return CURLE_OK;
}


/* argument is already checked for validity */
CURLcode ftp_done(struct connectdata *conn)
{
  struct UrlData *data = conn->data;
  struct FTP *ftp = data->proto.ftp;
  size_t nread;
  char *buf = data->buffer; /* this is our buffer */
  struct curl_slist *qitem; /* QUOTE item */

  if(data->bits.upload) {
    if((-1 != data->infilesize) && (data->infilesize != *ftp->bytecountp)) {
      failf(data, "Wrote only partial file (%d out of %d bytes)",
            *ftp->bytecountp, data->infilesize);
      return CURLE_PARTIAL_FILE;
    }
  }
  else {
    if((-1 != conn->size) && (conn->size != *ftp->bytecountp) &&
       (data->maxdownload != *ftp->bytecountp)) {
      failf(data, "Received only partial file");
      return CURLE_PARTIAL_FILE;
    }
    else if(!data->bits.no_body && (0 == *ftp->bytecountp)) {
      failf(data, "No data was received!");
      return CURLE_FTP_COULDNT_RETR_FILE;
    }
  }
  /* shut down the socket to inform the server we're done */
  sclose(data->secondarysocket);
  data->secondarysocket = -1;

  if(!data->bits.no_body) {  
    /* now let's see what the server says about the transfer we
       just performed: */
    nread = GetLastResponse(data->firstsocket, buf, conn);
    if(nread < 0)
      return CURLE_OPERATION_TIMEOUTED;

    /* 226 Transfer complete, 250 Requested file action okay, completed. */
    if(!strncmp(buf, "226", 3) && !strncmp(buf, "250", 3)) {
      failf(data, "%s", buf+4);
      return CURLE_FTP_WRITE_ERROR;
    }
  }

  /* Send any post-transfer QUOTE strings? */
  if(data->postquote) {
    qitem = data->postquote;
    /* Send all QUOTE strings in same order as on command-line */
    while (qitem) {
      /* Send string */
      if (qitem->data) {
        sendf(data->firstsocket, data, "%s\r\n", qitem->data);

        nread = GetLastResponse(data->firstsocket, buf, conn);
        if(nread < 0)
          return CURLE_OPERATION_TIMEOUTED;

        if (buf[0] != '2') {
          failf(data, "QUOT string not accepted: %s",
                qitem->data);
          return CURLE_FTP_QUOTE_ERROR;
        }
      }
      qitem = qitem->next;
    }
  }

  if(ftp->file)
    free(ftp->file);
  if(ftp->dir)
    free(ftp->dir);

  /* TBD: the ftp struct is still allocated here */

  return CURLE_OK;
}



static
CURLcode _ftp(struct connectdata *conn)
{
  /* this is FTP and no proxy */
  size_t nread;
  CURLcode result;
  struct UrlData *data=conn->data;
  char *buf = data->buffer; /* this is our buffer */
  /* for the ftp PORT mode */
  int portsock=-1;
  struct sockaddr_in serv_addr;
  char hostent_buf[8192];
#if defined (HAVE_INET_NTOA_R)
  char ntoa_buf[64];
#endif

  struct curl_slist *qitem; /* QUOTE item */
  /* the ftp struct is already inited in ftp_connect() */
  struct FTP *ftp = data->proto.ftp;

  long *bytecountp = ftp->bytecountp;

  /* Send any QUOTE strings? */
  if(data->quote) {
    qitem = data->quote;
    /* Send all QUOTE strings in same order as on command-line */
    while (qitem) {
      /* Send string */
      if (qitem->data) {
        sendf(data->firstsocket, data, "%s\r\n", qitem->data);

        nread = GetLastResponse(data->firstsocket, buf, conn);
        if(nread < 0)
          return CURLE_OPERATION_TIMEOUTED;

        if (buf[0] != '2') {
          failf(data, "QUOT string not accepted: %s",
                qitem->data);
          return CURLE_FTP_QUOTE_ERROR;
        }
      }
      qitem = qitem->next;
    }
  }

  /* change directory first! */
  if(ftp->dir && ftp->dir[0]) {
    sendf(data->firstsocket, data, "CWD %s\r\n", ftp->dir);
    nread = GetLastResponse(data->firstsocket, buf, conn);
    if(nread < 0)
      return CURLE_OPERATION_TIMEOUTED;

    if(strncmp(buf, "250", 3)) {
      failf(data, "Couldn't change to directory %s", ftp->dir);
      return CURLE_FTP_ACCESS_DENIED;
    }
  }

  /* If we have selected NOBODY, it means that we only want file information.
     Which in FTP can't be much more than the file size! */
  if(data->bits.no_body) {
    /* The SIZE command is _not_ RFC 959 specified, and therefor many servers
       may not support it! It is however the only way we have to get a file's
       size! */
    int filesize;
    sendf(data->firstsocket, data, "SIZE %s\r\n", ftp->file);

    nread = GetLastResponse(data->firstsocket, buf, conn);
    if(nread < 0)
      return CURLE_OPERATION_TIMEOUTED;

    if(strncmp(buf, "213", 3)) {
      failf(data, "Couldn't get file size: %s", buf+4);
      return CURLE_FTP_COULDNT_GET_SIZE;
    }
    /* get the size from the ascii string: */
    filesize = atoi(buf+4);

    sprintf(buf, "Content-Length: %d\n", filesize);

    if(strlen(buf) != data->fwrite(buf, 1, strlen(buf), data->out)) {
      failf (data, "Failed writing output");
      return CURLE_WRITE_ERROR;
    }
    if(data->writeheader) {
      /* the header is requested to be written to this file */
      if(strlen(buf) != data->fwrite (buf, 1, strlen(buf),
                                      data->writeheader)) {
        failf (data, "Failed writing output");
        return CURLE_WRITE_ERROR;
      }
    }
    return CURLE_OK;
  }

  /* We have chosen to use the PORT command */
  if(data->bits.ftp_use_port) {
    struct sockaddr_in sa;
    struct hostent *h=NULL;
    size_t size;
    unsigned short porttouse;
    char myhost[256] = "";

    if(data->ftpport) {
      if(if2ip(data->ftpport, myhost, sizeof(myhost))) {
        h = GetHost(data, myhost, hostent_buf, sizeof(hostent_buf));
      }
      else {
        if(strlen(data->ftpport)>1)
          h = GetHost(data, data->ftpport, hostent_buf, sizeof(hostent_buf));
        if(h)
          strcpy(myhost,data->ftpport);
      }
    }
    if(! *myhost) {
      h=GetHost(data, getmyhost(myhost,sizeof(myhost)), hostent_buf, sizeof(hostent_buf));
    }
    infof(data, "We connect from %s\n", myhost);

    if ( h ) {
      if( (portsock = socket(AF_INET, SOCK_STREAM, 0)) >= 0 ) {
        memset((char *)&sa, 0, sizeof(sa));
        memcpy((char *)&sa.sin_addr,
               h->h_addr,
               h->h_length);
        sa.sin_family = AF_INET;
        sa.sin_addr.s_addr = INADDR_ANY;
        sa.sin_port = 0;
        size = sizeof(sa);

        if(bind(portsock, (struct sockaddr *)&sa, size) >= 0) {
          /* we succeeded to bind */
          struct sockaddr_in add;
          size = sizeof(add);

          if(getsockname(portsock, (struct sockaddr *) &add,
                         (int *)&size)<0) {
            failf(data, "getsockname() failed");
            return CURLE_FTP_PORT_FAILED;
          }
          porttouse = ntohs(add.sin_port);

          if ( listen(portsock, 1) < 0 ) {
            failf(data, "listen(2) failed on socket");
            return CURLE_FTP_PORT_FAILED;
          }
        }
        else {
          failf(data, "bind(2) failed on socket");
          return CURLE_FTP_PORT_FAILED;
        }
      }
      else {
        failf(data, "socket(2) failed (%s)");
        return CURLE_FTP_PORT_FAILED;
      }
    }
    else {
      failf(data, "could't find my own IP address (%s)", myhost);
      return CURLE_FTP_PORT_FAILED;
    }
    {
      struct in_addr in;
      unsigned short ip[5];
      (void) memcpy(&in.s_addr, *h->h_addr_list, sizeof (in.s_addr));
#if defined (HAVE_INET_NTOA_R)
      /* ignore the return code from inet_ntoa_r() as it is int or
         char * depending on system */
      inet_ntoa_r(in, ntoa_buf, sizeof(ntoa_buf));
      sscanf( ntoa_buf, "%hu.%hu.%hu.%hu",
              &ip[0], &ip[1], &ip[2], &ip[3]);
#else
      sscanf( inet_ntoa(in), "%hu.%hu.%hu.%hu",
              &ip[0], &ip[1], &ip[2], &ip[3]);
#endif
      sendf(data->firstsocket, data, "PORT %d,%d,%d,%d,%d,%d\r\n",
            ip[0], ip[1], ip[2], ip[3],
            porttouse >> 8,
            porttouse & 255);
    }

    nread = GetLastResponse(data->firstsocket, buf, conn);
    if(nread < 0)
      return CURLE_OPERATION_TIMEOUTED;

    if(strncmp(buf, "200", 3)) {
      failf(data, "Server does not grok PORT, try without it!");
      return CURLE_FTP_PORT_FAILED;
    }     
  }
  else { /* we use the PASV command */

    sendf(data->firstsocket, data, "PASV\r\n");

    nread = GetLastResponse(data->firstsocket, buf, conn);
    if(nread < 0)
      return CURLE_OPERATION_TIMEOUTED;

    if(strncmp(buf, "227", 3)) {
      failf(data, "Odd return code after PASV");
      return CURLE_FTP_WEIRD_PASV_REPLY;
    }
    else {
      int ip[4];
      int port[2];
      unsigned short newport;
      char newhost[32];
      struct hostent *he;
      char *str=buf,*ip_addr;

      /*
       * New 227-parser June 3rd 1999.
       * It now scans for a sequence of six comma-separated numbers and
       * will take them as IP+port indicators.
       *
       * Found reply-strings include:
       * "227 Entering Passive Mode (127,0,0,1,4,51)"
       * "227 Data transfer will passively listen to 127,0,0,1,4,51"
       * "227 Entering passive mode. 127,0,0,1,4,51"
       */
      
      while(*str) {
	 if (6 == sscanf(str, "%d,%d,%d,%d,%d,%d",
			 &ip[0], &ip[1], &ip[2], &ip[3],
			 &port[0], &port[1]))
	    break;
	 str++;
      }
      if(!*str) {
	 failf(data, "Couldn't interpret this 227-reply: %s", buf);
	 return CURLE_FTP_WEIRD_227_FORMAT;
      }
      sprintf(newhost, "%d.%d.%d.%d", ip[0], ip[1], ip[2], ip[3]);
      he = GetHost(data, newhost, hostent_buf, sizeof(hostent_buf));
      if(!he) {
        failf(data, "Can't resolve new host %s", newhost);
        return CURLE_FTP_CANT_GET_HOST;
      }

	
      newport = (port[0]<<8) + port[1];
      data->secondarysocket = socket(AF_INET, SOCK_STREAM, 0);

      memset((char *) &serv_addr, '\0', sizeof(serv_addr));
      memcpy((char *)&(serv_addr.sin_addr), he->h_addr, he->h_length);
      serv_addr.sin_family = he->h_addrtype;
      serv_addr.sin_port = htons(newport);

      if(data->bits.verbose) {
        struct in_addr in;
        struct hostent * answer;

#if defined(HAVE_INET_ADDR)
        unsigned long address;
# if defined(HAVE_GETHOSTBYADDR_R)
        int h_errnop;
# endif

        address = inet_addr(newhost);
# ifdef HAVE_GETHOSTBYADDR_R

#  ifdef HAVE_GETHOSTBYADDR_R_5
        /* AIX, Digital Unix style:
           extern int gethostbyaddr_r(char *addr, size_t len, int type,
           struct hostent *htent, struct hostent_data *ht_data); */

        /* Fred Noz helped me try this out, now it at least compiles! */

        if(gethostbyaddr_r((char *) &address,
                           sizeof(address), AF_INET,
                           (struct hostent *)hostent_buf,
                           hostent_buf + sizeof(*answer)))
           answer=NULL;
                           
#  endif
#  ifdef HAVE_GETHOSTBYADDR_R_7
        /* Solaris and IRIX */
        answer = gethostbyaddr_r((char *) &address, sizeof(address), AF_INET,
                                 (struct hostent *)hostent_buf,
                                 hostent_buf + sizeof(*answer),
                                 sizeof(hostent_buf) - sizeof(*answer),
                                 &h_errnop);
#  endif
#  ifdef HAVE_GETHOSTBYADDR_R_8
        /* Linux style */
        if(gethostbyaddr_r((char *) &address, sizeof(address), AF_INET,
                           (struct hostent *)hostent_buf,
                           hostent_buf + sizeof(*answer),
                           sizeof(hostent_buf) - sizeof(*answer),
                           &answer,
                           &h_errnop))
           answer=NULL; /* error */
#  endif
        
# else
        answer = gethostbyaddr((char *) &address, sizeof(address), AF_INET);
# endif
#else
        answer = NULL;
#endif
        (void) memcpy(&in.s_addr, *he->h_addr_list, sizeof (in.s_addr));
        infof(data, "Connecting to %s (%s) port %u\n",
              answer?answer->h_name:newhost,
#if defined(HAVE_INET_NTOA_R)
              inet_ntoa_r(in, ip_addr=ntoa_buf, sizeof(ntoa_buf)),
#else
              ip_addr = inet_ntoa(in),
#endif
              newport);
      }
	
      if (connect(data->secondarysocket, (struct sockaddr *) &serv_addr,
                  sizeof(serv_addr)) < 0) {
        switch(errno) {
#ifdef ECONNREFUSED
          /* this should be made nicer */
        case ECONNREFUSED:
          failf(data, "Connection refused by ftp server");
          break;
#endif
#ifdef EINTR
        case EINTR:
          failf(data, "Connection timeouted to ftp server");
          break;
#endif
        default:
          failf(data, "Can't connect to ftp server");
          break;
        }
        return CURLE_FTP_CANT_RECONNECT;
      }

      if (data->bits.tunnel_thru_httpproxy) {
        /* We want "seamless" FTP operations through HTTP proxy tunnel */
        result = GetHTTPProxyTunnel(data, data->secondarysocket);
        if(CURLE_OK != result)
          return result;
      }
    }
  }
  /* we have the (new) data connection ready */
  infof(data, "Connected the data stream!\n");

  if(data->bits.upload) {

    /* Set type to binary (unless specified ASCII) */
    sendf(data->firstsocket, data, "TYPE %s\r\n",
          (data->bits.ftp_ascii)?"A":"I");

    nread = GetLastResponse(data->firstsocket, buf, conn);
    if(nread < 0)
      return CURLE_OPERATION_TIMEOUTED;

    if(strncmp(buf, "200", 3)) {
      failf(data, "Couldn't set %s mode",
            (data->bits.ftp_ascii)?"ASCII":"binary");
      return (data->bits.ftp_ascii)? CURLE_FTP_COULDNT_SET_ASCII:
        CURLE_FTP_COULDNT_SET_BINARY;
    }

    if(data->resume_from) {
      /* we're about to continue the uploading of a file */
      /* 1. get already existing file's size. We use the SIZE
         command for this which may not exist in the server!
         The SIZE command is not in RFC959. */

      /* 2. This used to set REST. But since we can do append, we
         don't another ftp command. We just skip the source file
         offset and then we APPEND the rest on the file instead */

      /* 3. pass file-size number of bytes in the source file */
      /* 4. lower the infilesize counter */
      /* => transfer as usual */

      if(data->resume_from < 0 ) {
        /* we could've got a specified offset from the command line,
           but now we know we didn't */

        sendf(data->firstsocket, data, "SIZE %s\r\n", ftp->file);

        nread = GetLastResponse(data->firstsocket, buf, conn);
        if(nread < 0)
          return CURLE_OPERATION_TIMEOUTED;

        if(strncmp(buf, "213", 3)) {
          failf(data, "Couldn't get file size: %s", buf+4);
          return CURLE_FTP_COULDNT_GET_SIZE;
        }

        /* get the size from the ascii string: */
        data->resume_from = atoi(buf+4);
      }

      if(data->resume_from) {
        /* do we still game? */
        int passed=0;
#if 0
        /* Set resume file transfer offset */
        infof(data, "Instructs server to resume from offset %d\n",
              data->resume_from);

        sendf(data->firstsocket, data, "REST %d\r\n", data->resume_from);

        nread = GetLastResponse(data->firstsocket, buf, conn);
        if(nread < 0)
          return CURLE_OPERATION_TIMEOUTED;

        if(strncmp(buf, "350", 3)) {
          failf(data, "Couldn't use REST: %s", buf+4);
          return CURLE_FTP_COULDNT_USE_REST;
        }
#else
        /* enable append instead */
        data->bits.ftp_append = 1;
#endif
        /* Now, let's read off the proper amount of bytes from the
           input. If we knew it was a proper file we could've just
           fseek()ed but we only have a stream here */
        do {
          int readthisamountnow = (data->resume_from - passed);
          int actuallyread;

          if(readthisamountnow > BUFSIZE)
            readthisamountnow = BUFSIZE;

          actuallyread =
            data->fread(data->buffer, 1, readthisamountnow, data->in);

          passed += actuallyread;
          if(actuallyread != readthisamountnow) {
            failf(data, "Could only read %d bytes from the input\n",
                  passed);
            return CURLE_FTP_COULDNT_USE_REST;
          }
        }
        while(passed != data->resume_from);

        /* now, decrease the size of the read */
        if(data->infilesize>0) {
          data->infilesize -= data->resume_from;

          if(data->infilesize <= 0) {
            infof(data, "File already completely uploaded\n");
            return CURLE_OK;
          }
        }
        /* we've passed, proceed as normal */
      }
    }

    /* Send everything on data->in to the socket */
    if(data->bits.ftp_append)
      /* we append onto the file instead of rewriting it */
      sendf(data->firstsocket, data, "APPE %s\r\n", ftp->file);
    else
      sendf(data->firstsocket, data, "STOR %s\r\n", ftp->file);

    nread = GetLastResponse(data->firstsocket, buf, conn);
    if(nread < 0)
      return CURLE_OPERATION_TIMEOUTED;

    if(atoi(buf)>=400) {
      failf(data, "Failed FTP upload:%s", buf+3);
      /* oops, we never close the sockets! */
      return CURLE_FTP_COULDNT_STOR_FILE;
    }

    if(data->bits.ftp_use_port) {
      result = AllowServerConnect(data, portsock);
      if( result )
        return result;
    }

    *bytecountp=0;

    /* When we know we're uploading a specified file, we can get the file
       size prior to the actual upload. */

    pgrsSetUploadSize(data, data->infilesize);
#if 0
    ProgressInit(data, data->infilesize);
#endif
    result = Transfer(conn, -1, -1, FALSE, NULL, /* no download */
                      data->secondarysocket, bytecountp);
    if(result)
      return result;
      
  }
  else {
    /* Retrieve file or directory */
    bool dirlist=FALSE;
    long downloadsize=-1;

    if(data->bits.set_range && data->range) {
      long from, to;
      int totalsize=-1;
      char *ptr;
      char *ptr2;

      from=strtol(data->range, &ptr, 0);
      while(ptr && *ptr && (isspace((int)*ptr) || (*ptr=='-')))
        ptr++;
      to=strtol(ptr, &ptr2, 0);
      if(ptr == ptr2) {
        /* we didn't get any digit */
        to=-1;
      }
      if((-1 == to) && (from>=0)) {
        /* X - */
        data->resume_from = from;
        infof(data, "FTP RANGE %d to end of file\n", from);
      }
      else if(from < 0) {
        /* -Y */
        totalsize = -from;
        data->maxdownload = -from;
        data->resume_from = from;
        infof(data, "FTP RANGE the last %d bytes\n", totalsize);
      }
      else {
        /* X-Y */
        totalsize = to-from;
        data->maxdownload = totalsize+1; /* include the last mentioned byte */
        data->resume_from = from;
        infof(data, "FTP RANGE from %d getting %d bytes\n", from, data->maxdownload);
      }
      infof(data, "range-download from %d to %d, totally %d bytes\n",
            from, to, totalsize);
    }
#if 0
    if(!ppath[0])
      /* make sure this becomes a valid name */
      ppath="./";
#endif
    if((data->bits.ftp_list_only) || !ftp->file) {
      /* The specified path ends with a slash, and therefore we think this
         is a directory that is requested, use LIST. But before that we
         need to set ASCII transfer mode. */
      dirlist = TRUE;

      /* Set type to ASCII */
      sendf(data->firstsocket, data, "TYPE A\r\n");
	
      nread = GetLastResponse(data->firstsocket, buf, conn);
      if(nread < 0)
        return CURLE_OPERATION_TIMEOUTED;
	
      if(strncmp(buf, "200", 3)) {
        failf(data, "Couldn't set ascii mode");
        return CURLE_FTP_COULDNT_SET_ASCII;
      }

      /* if this output is to be machine-parsed, the NLST command will be
         better used since the LIST command output is not specified or
         standard in any way */

      sendf(data->firstsocket, data, "%s\r\n",
            data->customrequest?data->customrequest:
            (data->bits.ftp_list_only?"NLST":"LIST"));
    }
    else {
      /* Set type to binary (unless specified ASCII) */
      sendf(data->firstsocket, data, "TYPE %s\r\n",
            (data->bits.ftp_list_only)?"A":"I");

      nread = GetLastResponse(data->firstsocket, buf, conn);
      if(nread < 0)
        return CURLE_OPERATION_TIMEOUTED;

      if(strncmp(buf, "200", 3)) {
        failf(data, "Couldn't set %s mode",
              (data->bits.ftp_ascii)?"ASCII":"binary");
        return (data->bits.ftp_ascii)? CURLE_FTP_COULDNT_SET_ASCII:
          CURLE_FTP_COULDNT_SET_BINARY;
      }

      if(data->resume_from) {

        /* Daniel: (August 4, 1999)
         *
         * We start with trying to use the SIZE command to figure out the size
         * of the file we're gonna get. If we can get the size, this is by far
         * the best way to know if we're trying to resume beyond the EOF.  */

        sendf(data->firstsocket, data, "SIZE %s\r\n", ftp->file);

        nread = GetLastResponse(data->firstsocket, buf, conn);
        if(nread < 0)
          return CURLE_OPERATION_TIMEOUTED;

        if(strncmp(buf, "213", 3)) {
          infof(data, "server doesn't support SIZE: %s", buf+4);
          /* We couldn't get the size and therefore we can't know if there
             really is a part of the file left to get, although the server
             will just close the connection when we start the connection so it
             won't cause us any harm, just not make us exit as nicely. */
        }
        else {
          int foundsize=atoi(buf+4);
          /* We got a file size report, so we check that there actually is a
             part of the file left to get, or else we go home.  */
          if(data->resume_from< 0) {
            /* We're supposed to download the last abs(from) bytes */
            if(foundsize < -data->resume_from) {
              failf(data, "Offset (%d) was beyond file size (%d)",
                    data->resume_from, foundsize);
              return CURLE_FTP_BAD_DOWNLOAD_RESUME;
            }
            /* convert to size to download */
            downloadsize = -data->resume_from;
            /* download from where? */
            data->resume_from = foundsize - downloadsize;
          }
          else {
            if(foundsize <= data->resume_from) {
              failf(data, "Offset (%d) was beyond file size (%d)",
                    data->resume_from, foundsize);
              return CURLE_FTP_BAD_DOWNLOAD_RESUME;
            }
            /* Now store the number of bytes we are expected to download */
            downloadsize = foundsize-data->resume_from;
          }
        }

        /* Set resume file transfer offset */
        infof(data, "Instructs server to resume from offset %d\n",
              data->resume_from);

        sendf(data->firstsocket, data, "REST %d\r\n", data->resume_from);

        nread = GetLastResponse(data->firstsocket, buf, conn);
        if(nread < 0)
          return CURLE_OPERATION_TIMEOUTED;

        if(strncmp(buf, "350", 3)) {
          failf(data, "Couldn't use REST: %s", buf+4);
          return CURLE_FTP_COULDNT_USE_REST;
        }
      }

      sendf(data->firstsocket, data, "RETR %s\r\n", ftp->file);
    }

    nread = GetLastResponse(data->firstsocket, buf, conn);
    if(nread < 0)
      return CURLE_OPERATION_TIMEOUTED;

    if(!strncmp(buf, "150", 3) || !strncmp(buf, "125", 3)) {

      /*
        A;
        150 Opening BINARY mode data connection for /etc/passwd (2241
        bytes).  (ok, the file is being transfered)
	
        B:
        150 Opening ASCII mode data connection for /bin/ls 

        C:
        150 ASCII data connection for /bin/ls (137.167.104.91,37445) (0 bytes).

        D:
        150 Opening ASCII mode data connection for /linux/fisk/kpanelrc (0.0.0.0,0) (545 bytes).
          
        E:
        125 Data connection already open; Transfer starting. */

      int size=-1; /* default unknown size */

      if(!dirlist &&
         !data->bits.ftp_ascii &&
         (-1 == downloadsize)) {
        /*
         * It seems directory listings either don't show the size or very
         * often uses size 0 anyway. ASCII transfers may very well turn out
         * that the transfered amount of data is not the same as this line
         * tells, why using this number in those cases only confuses us.
         *
         * Example D above makes this parsing a little tricky */
        char *bytes;
        bytes=strstr(buf, " bytes");
        if(bytes--) {
          int index=bytes-buf;
          /* this is a hint there is size information in there! ;-) */
          while(--index) {
            /* scan for the parenthesis and break there */
            if('(' == *bytes)
              break;
            /* if only skip digits, or else we're in deep trouble */
            if(!isdigit((int)*bytes)) {
              bytes=NULL;
              break;
            }
            /* one more estep backwards */
            bytes--;
          }
          /* only if we have nothing but digits: */
          if(bytes++) {
            /* get the number! */
            size = atoi(bytes);
          }
            
        }
#if 0
        if(2 != sscanf(buf, "%*[^(](%d bytes%c", &size, &paren))
          size=-1;
#endif
      }
      else if(downloadsize > -1)
        size = downloadsize;

#if 0
      if((size > -1) && (data->resume_from>0)) {
        size -= data->resume_from;
        if(size <= 0) {
          failf(data, "Offset (%d) was beyond file size (%d)",
                data->resume_from, data->resume_from+size);
          return CURLE_PARTIAL_FILE;
        }
      }
#endif

      if(data->bits.ftp_use_port) {
        result = AllowServerConnect(data, portsock);
        if( result )
          return result;
      }

      infof(data, "Getting file with size: %d\n", size);

      /* FTP download: */
      result=Transfer(conn, data->secondarysocket, size, FALSE,
                      bytecountp,
                      -1, NULL); /* no upload here */
      if(result)
        return result;
    }
    else {
      failf(data, "%s", buf+4);
      return CURLE_FTP_COULDNT_RETR_FILE;
    }
	
  }
  /* end of transfer */

  return CURLE_OK;
}

/* -- deal with the ftp server!  -- */

/* argument is already checked for validity */
CURLcode ftp(struct connectdata *conn)
{
  CURLcode retcode;

  struct UrlData *data = conn->data;
  struct FTP *ftp;
  int dirlength=0; /* 0 forces strlen() */

  /* the ftp struct is already inited in ftp_connect() */
  ftp = data->proto.ftp;

  /* We split the path into dir and file parts *before* we URLdecode
     it */
  ftp->file = strrchr(conn->ppath, '/');
  if(ftp->file) {
    ftp->file++; /* point to the first letter in the file name part or
                    remain NULL */
  }
  else {
    ftp->file = conn->ppath; /* there's only a file part */
  }
  dirlength=ftp->file-conn->ppath;

  if(*ftp->file) {
    ftp->file = curl_unescape(ftp->file, 0);
    if(NULL == ftp->file) {
      failf(data, "no memory");
      return CURLE_OUT_OF_MEMORY;
    }
  }
  else
    ftp->file=NULL; /* instead of point to a zero byte, we make it a NULL
                       pointer */

  ftp->urlpath = conn->ppath;
  if(dirlength) {
    ftp->dir = curl_unescape(ftp->urlpath, dirlength);
    if(NULL == ftp->dir) {
      if(ftp->file)
        free(ftp->file);
      failf(data, "no memory");
      return CURLE_OUT_OF_MEMORY; /* failure */
    }
  }
  else
    ftp->dir = NULL;

  retcode = _ftp(conn);

  return retcode;
}

