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
 ****************************************************************************/

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include <errno.h>

#include "setup.h"

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#ifdef HAVE_SYS_SELECT_H
#include <sys/select.h>
#endif

#if defined(WIN32) && !defined(__GNUC__) || defined(__MINGW32__)
#include <winsock.h>
#else /* some kind of unix */
#include <sys/socket.h>
#include <netinet/in.h>
#ifdef HAVE_ARPA_INET_H
#include <arpa/inet.h>
#endif
#include <sys/utsname.h>
#include <netdb.h>
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


static UrgError AllowServerConnect(struct UrlData *data,
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
    return URG_FTP_PORT_FAILED;
  case 0:  /* timeout */
    /* let's die here */
    failf(data, "Timeout while waiting for server connect");
    return URG_FTP_PORT_FAILED;
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
	return URG_FTP_PORT_FAILED;
      }
      infof(data, "Connection accepted from server\n");

      data->secondarysocket = s;
    }
    break;
  }
  return URG_OK;
}


/* --- parse FTP server responses --- */

#define lastline(line) (isdigit((int)line[0]) && isdigit((int)line[1]) && \
			isdigit((int)line[2]) && (' ' == line[3]))

static int GetLastResponse(int sockfd, char *buf,
			   struct UrlData *data)
{
  int nread;
  int read_rc=1;
  char *ptr;
  do {
    ptr=buf;

    /* get us a full line, terminated with a newline */
    for(nread=0;
        (nread<BUFSIZE) && read_rc;
        nread++, ptr++) {
#ifdef USE_SSLEAY
      if (data->use_ssl) {
        read_rc = SSL_read(data->ssl, ptr, 1);
      }
      else {
#endif
        read_rc = sread(sockfd, ptr, 1);
#ifdef USE_SSLEAY
      }
#endif /* USE_SSLEAY */
      if (*ptr == '\n')
        break;
    }
    *ptr=0; /* zero terminate */

    if(data->conf & CONF_VERBOSE) {
      fputs("< ", data->err);
      fwrite(buf, 1, nread, data->err);
      fputs("\n", data->err);
    }
  } while(read_rc &&
	  (nread<4 || !lastline(buf)) );
  return nread;
}

/* -- who are we? -- */
char *getmyhost(void)
{
  static char myhost[256];
#if !defined(WIN32) && !defined(HAVE_UNAME) && !defined(HAVE_GETHOSTNAME)
  /* We have no means of finding the local host name! */
  strcpy(myhost, "localhost");
#endif
#if defined(WIN32) || !defined(HAVE_UNAME)
  gethostname(myhost, 256);
#else
  struct utsname ugnm;

  if (uname(&ugnm) < 0)
    return "localhost";

  (void) strncpy(myhost, ugnm.nodename, 255);
  myhost[255] = '\0';
#endif
  return myhost;
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

static
UrgError _ftp(struct UrlData *data,
              long *bytecountp,
              char *ftpuser,
              char *ftppasswd,
              char *ppath)
{
  /* this is FTP and no proxy */
  size_t nread;
  UrgError result;
  char *buf = data->buffer; /* this is our buffer */
  /* for the ftp PORT mode */
  int portsock=-1;
  struct sockaddr_in serv_addr;

  struct curl_slist *qitem; /* QUOTE item */

  /* The first thing we do is wait for the "220*" line: */
  nread = GetLastResponse(data->firstsocket, buf, data);
  if(strncmp(buf, "220", 3)) {
    failf(data, "This doesn't seem like a nice ftp-server response");
    return URG_FTP_WEIRD_SERVER_REPLY;
  }

  /* send USER */
  sendf(data->firstsocket, data, "USER %s\r\n", ftpuser);

  /* wait for feedback */
  nread = GetLastResponse(data->firstsocket, buf, data);

  if(!strncmp(buf, "530", 3)) {
    /* 530 User ... access denied
       (the server denies to log the specified user) */
    failf(data, "Access denied: %s", &buf[4]);
    return URG_FTP_ACCESS_DENIED;
  }
  else if(!strncmp(buf, "331", 3)) {
    /* 331 Password required for ...
       (the server requires to send the user's password too) */
    sendf(data->firstsocket, data, "PASS %s\r\n", ftppasswd);
    nread = GetLastResponse(data->firstsocket, buf, data);

    if(!strncmp(buf, "530", 3)) {
      /* 530 Login incorrect.
         (the username and/or the password are incorrect) */
      failf(data, "the username and/or the password are incorrect");
      return URG_FTP_USER_PASSWORD_INCORRECT;
    }
    else if(!strncmp(buf, "230", 3)) {
      /* 230 User ... logged in.
         (user successfully logged in) */
        
      infof(data, "We have successfully logged in\n");
    }
    else {
      failf(data, "Odd return code after PASS");
      return URG_FTP_WEIRD_PASS_REPLY;
    }
  }
  else if(! strncmp(buf, "230", 3)) {
    /* 230 User ... logged in.
       (the user logged in without password) */
    infof(data, "We have successfully logged in\n");
  }
  else {
    failf(data, "Odd return code after USER");
    return URG_FTP_WEIRD_USER_REPLY;
  }

  /* Send any QUOTE strings? */
  if(data->quote) {
    qitem = data->quote;
    /* Send all QUOTE strings in same order as on command-line */
    while (qitem) {
      /* Send string */
      if (qitem->data) {
        sendf(data->firstsocket, data, "%s\r\n", qitem->data);

        nread = GetLastResponse(data->firstsocket, buf, data);

        if (buf[0] != '2') {
          failf(data, "QUOT string not accepted: %s",
                qitem->data);
          return URG_FTP_QUOTE_ERROR;
        }
      }
      qitem = qitem->next;
    }
  }

  /* If we have selected NOBODY, it means that we only want file information.
     Which in FTP can't be much more than the file size! */
  if(data->conf & CONF_NOBODY) {
    /* The SIZE command is _not_ RFC 959 specified, and therefor many servers
       may not support it! It is however the only way we have to get a file's
       size! */
    int filesize;
    sendf(data->firstsocket, data, "SIZE %s\r\n", ppath);

    nread = GetLastResponse(data->firstsocket, buf, data);

    if(strncmp(buf, "213", 3)) {
      failf(data, "Couldn't get file size: %s", buf+4);
      return URG_FTP_COULDNT_GET_SIZE;
    }
    /* get the size from the ascii string: */
    filesize = atoi(buf+4);

    sprintf(buf, "Content-Length: %d\n", filesize);

    if(strlen(buf) != data->fwrite(buf, 1, strlen(buf), data->out)) {
      failf (data, "Failed writing output");
      return URG_WRITE_ERROR;
    }
    if(data->writeheader) {
      /* the header is requested to be written to this file */
      if(strlen(buf) != fwrite (buf, 1, strlen(buf), data->writeheader)) {
        failf (data, "Failed writing output");
        return URG_WRITE_ERROR;
      }
    }
    return URG_OK;
  }

  /* We have chosen to use the PORT command */
  if(data->conf & CONF_FTPPORT) {
    struct sockaddr_in sa;
    struct hostent *h=NULL;
    size_t size;
    unsigned short porttouse;

    char *myhost=NULL;
      
    if(data->ftpport) {
      myhost = if2ip(data->ftpport);
      if(myhost) {
        h = GetHost(data, myhost);
      }
      else {
        if(strlen(data->ftpport)>1)
          h = GetHost(data, data->ftpport);
        if(h)
          myhost=data->ftpport;
      }
    }
    if(!myhost) {
      myhost = getmyhost();
      h=GetHost(data, myhost);
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
            return URG_FTP_PORT_FAILED;
          }
          porttouse = ntohs(add.sin_port);

          if ( listen(portsock, 1) < 0 ) {
            failf(data, "listen(2) failed on socket");
            return URG_FTP_PORT_FAILED;
          }
        }
        else {
          failf(data, "bind(2) failed on socket");
          return URG_FTP_PORT_FAILED;
        }
      }
      else {
        failf(data, "socket(2) failed (%s)");
        return URG_FTP_PORT_FAILED;
      }
    }
    else {
      failf(data, "could't find my own IP address (%s)", myhost);
      return URG_FTP_PORT_FAILED;
    }
    {
      struct in_addr in;
      unsigned short ip[5];
      (void) memcpy(&in.s_addr, *h->h_addr_list, sizeof (in.s_addr));
      sscanf( inet_ntoa(in), "%hu.%hu.%hu.%hu",
              &ip[0], &ip[1], &ip[2], &ip[3]);
      sendf(data->firstsocket, data, "PORT %d,%d,%d,%d,%d,%d\n",
            ip[0], ip[1], ip[2], ip[3],
            porttouse >> 8,
            porttouse & 255);
    }

    nread = GetLastResponse(data->firstsocket, buf, data);

    if(strncmp(buf, "200", 3)) {
      failf(data, "Server does not grok PORT, try without it!");
      return URG_FTP_PORT_FAILED;
    }     
  }
  else { /* we use the PASV command */

    sendf(data->firstsocket, data, "PASV\r\n");

    nread = GetLastResponse(data->firstsocket, buf, data);

    if(strncmp(buf, "227", 3)) {
      failf(data, "Odd return code after PASV");
      return URG_FTP_WEIRD_PASV_REPLY;
    }
    else {
      int ip[4];
      int port[2];
      unsigned short newport;
      char newhost[32];
      struct hostent *he;
      char *str=buf;

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
	 return URG_FTP_WEIRD_227_FORMAT;
      }
      sprintf(newhost, "%d.%d.%d.%d", ip[0], ip[1], ip[2], ip[3]);
      he = GetHost(data, newhost);
      if(!he) {
        failf(data, "Can't resolve new host %s", newhost);
        return URG_FTP_CANT_GET_HOST;
      }

	
      newport = (port[0]<<8) + port[1];
      data->secondarysocket = socket(AF_INET, SOCK_STREAM, 0);

      memset((char *) &serv_addr, '\0', sizeof(serv_addr));
      memcpy((char *)&(serv_addr.sin_addr), he->h_addr, he->h_length);
      serv_addr.sin_family = he->h_addrtype;
      serv_addr.sin_port = htons(newport);

      if(data->conf & CONF_VERBOSE) {
        struct in_addr in;
#if 1
        struct hostent * answer;

        unsigned long address;
#if defined(HAVE_INET_ADDR) || defined(WIN32)
        address = inet_addr(newhost);
        answer = gethostbyaddr((char *) &address, sizeof(address), 
                               AF_INET);
#else
        answer = NULL;
#endif
        (void) memcpy(&in.s_addr, *he->h_addr_list, sizeof (in.s_addr));
        infof(data, "Connecting to %s (%s) port %u\n",
              answer?answer->h_name:newhost, inet_ntoa(in), newport);
#else
        (void) memcpy(&in.s_addr, *he->h_addr_list, sizeof (in.s_addr));
        infof(data, "Connecting to %s (%s) port %u\n",
              he->h_name, inet_ntoa(in), newport);
#endif
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
        return URG_FTP_CANT_RECONNECT;
      }
    }

  }
  /* we have the (new) data connection ready */

  if(data->conf & CONF_UPLOAD) {

    /* Set type to binary (unless specified ASCII) */
    sendf(data->firstsocket, data, "TYPE %s\r\n",
          (data->conf&CONF_FTPASCII)?"A":"I");

    nread = GetLastResponse(data->firstsocket, buf, data);

    if(strncmp(buf, "200", 3)) {
      failf(data, "Couldn't set %s mode",
            (data->conf&CONF_FTPASCII)?"ASCII":"binary");
      return (data->conf&CONF_FTPASCII)? URG_FTP_COULDNT_SET_ASCII:
        URG_FTP_COULDNT_SET_BINARY;
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

        sendf(data->firstsocket, data, "SIZE %s\r\n", ppath);

        nread = GetLastResponse(data->firstsocket, buf, data);

        if(strncmp(buf, "213", 3)) {
          failf(data, "Couldn't get file size: %s", buf+4);
          return URG_FTP_COULDNT_GET_SIZE;
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

        nread = GetLastResponse(data->firstsocket, buf, data);

        if(strncmp(buf, "350", 3)) {
          failf(data, "Couldn't use REST: %s", buf+4);
          return URG_FTP_COULDNT_USE_REST;
        }
#else
        /* enable append instead */
        data->conf |= CONF_FTPAPPEND;
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
            return URG_FTP_COULDNT_USE_REST;
          }
        }
        while(passed != data->resume_from);

        /* now, decrease the size of the read */
        if(data->infilesize>0) {
          data->infilesize -= data->resume_from;

          if(data->infilesize <= 0) {
            infof(data, "File already completely uploaded\n");
            return URG_OK;
          }
        }
        /* we've passed, proceed as normal */
      }
    }

    /* Send everything on data->in to the socket */
    if(data->conf & CONF_FTPAPPEND)
      /* we append onto the file instead of rewriting it */
      sendf(data->firstsocket, data, "APPE %s\r\n", ppath);
    else
      sendf(data->firstsocket, data, "STOR %s\r\n", ppath);

    nread = GetLastResponse(data->firstsocket, buf, data);

    if(atoi(buf)>=400) {
      failf(data, "Failed FTP upload:%s", buf+3);
      /* oops, we never close the sockets! */
      return URG_FTP_COULDNT_STOR_FILE;
    }

    if(data->conf & CONF_FTPPORT) {
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
    result = Transfer(data, -1, -1, FALSE, NULL, /* no download */
                      data->secondarysocket, bytecountp);
    if(result)
      return result;
      
    if((-1 != data->infilesize) && (data->infilesize != *bytecountp)) {
      failf(data, "Wrote only partial file (%d out of %d bytes)",
            *bytecountp, data->infilesize);
      return URG_PARTIAL_FILE;
    }
  }
  else {
    /* Retrieve file or directory */
    bool dirlist=FALSE;
    long downloadsize=-1;

    if(data->conf&CONF_RANGE && data->range) {
      int from, to;
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
      if(-1 == to) {
        /* X - */
        data->resume_from = from;
      }
      else if(from < 0) {
        /* -Y */
        from = 0;
        to = -from;
        totalsize = to-from;
        data->maxdownload = totalsize;
      }
      else {
        /* X- */
        totalsize = to-from;
        data->maxdownload = totalsize;
      }
      infof(data, "range-download from %d to %d, totally %d bytes\n",
            from, to, totalsize);
    }

    if(!ppath[0])
      /* make sure this becomes a valid name */
      ppath="./";

    if((data->conf & CONF_FTPLISTONLY) ||
       ('/' == ppath[strlen(ppath)-1] )) {
      /* The specified path ends with a slash, and therefore we think this
         is a directory that is requested, use LIST. But before that we
         need to set ASCII transfer mode. */
      dirlist = TRUE;

      /* Set type to ASCII */
      sendf(data->firstsocket, data, "TYPE A\r\n");
	
      nread = GetLastResponse(data->firstsocket, buf, data);
	
      if(strncmp(buf, "200", 3)) {
        failf(data, "Couldn't set ascii mode");
        return URG_FTP_COULDNT_SET_ASCII;
      }

      /* if this output is to be machine-parsed, the NLST command will be
         better used since the LIST command output is not specified or
         standard in any way */

      sendf(data->firstsocket, data, "%s %s\r\n",
            data->customrequest?data->customrequest:
            (data->conf&CONF_FTPLISTONLY?"NLST":"LIST"),
            ppath);
    }
    else {
      /* Set type to binary (unless specified ASCII) */
      sendf(data->firstsocket, data, "TYPE %s\r\n",
            (data->conf&CONF_FTPASCII)?"A":"I");

      nread = GetLastResponse(data->firstsocket, buf, data);

      if(strncmp(buf, "200", 3)) {
        failf(data, "Couldn't set %s mode",
              (data->conf&CONF_FTPASCII)?"ASCII":"binary");
        return (data->conf&CONF_FTPASCII)? URG_FTP_COULDNT_SET_ASCII:
          URG_FTP_COULDNT_SET_BINARY;
      }

      if(data->resume_from) {

        /* Daniel: (August 4, 1999)
         *
         * We start with trying to use the SIZE command to figure out the size
         * of the file we're gonna get. If we can get the size, this is by far
         * the best way to know if we're trying to resume beyond the EOF.  */

        sendf(data->firstsocket, data, "SIZE %s\r\n", ppath);

        nread = GetLastResponse(data->firstsocket, buf, data);

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
          if(foundsize <= data->resume_from) {
            failf(data, "Offset (%d) was beyond file size (%d)",
                  data->resume_from, foundsize);
            return URG_FTP_BAD_DOWNLOAD_RESUME;
          }
          /* Now store the number of bytes we are expected to download */
          downloadsize = foundsize-data->resume_from;
        }

        /* Set resume file transfer offset */
        infof(data, "Instructs server to resume from offset %d\n",
              data->resume_from);

        sendf(data->firstsocket, data, "REST %d\r\n", data->resume_from);

        nread = GetLastResponse(data->firstsocket, buf, data);

        if(strncmp(buf, "350", 3)) {
          failf(data, "Couldn't use REST: %s", buf+4);
          return URG_FTP_COULDNT_USE_REST;
        }
      }

      sendf(data->firstsocket, data, "RETR %s\r\n", ppath);
    }

    nread = GetLastResponse(data->firstsocket, buf, data);

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

      if(!dirlist && (-1 == downloadsize)) {
        /*
         * It seems directory listings either don't show the size or very
         * often uses size 0 anyway.
         * Example D above makes this parsing a little tricky
         */
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
          return URG_PARTIAL_FILE;
        }
      }
#endif

      if(data->conf & CONF_FTPPORT) {
        result = AllowServerConnect(data, portsock);
        if( result )
          return result;
      }

      infof(data, "Getting file with size: %d\n", size);

      /* FTP download: */
      result=Transfer(data, data->secondarysocket, size, FALSE,
                      bytecountp,
                      -1, NULL); /* no upload here */
      if(result)
        return result;

      if((-1 != size) && (size != *bytecountp)) {
        failf(data, "Received only partial file");
        return URG_PARTIAL_FILE;
      }
      else if(0 == *bytecountp) {
        failf(data, "No data was received!");
        return URG_FTP_COULDNT_RETR_FILE;
      }
    }
    else {
      failf(data, "%s", buf+4);
      return URG_FTP_COULDNT_RETR_FILE;
    }
	
  }
  /* end of transfer */
#if 0
  ProgressEnd(data);
#endif
  pgrsDone(data);

  /* shut down the socket to inform the server we're done */
  sclose(data->secondarysocket);
  data->secondarysocket = -1;
    
  /* now let's see what the server says about the transfer we
     just performed: */
  nread = GetLastResponse(data->firstsocket, buf, data);

  /* 226 Transfer complete */
  if(strncmp(buf, "226", 3)) {
    failf(data, "%s", buf+4);
    return URG_FTP_WRITE_ERROR;
  }

  /* Send any post-transfer QUOTE strings? */
  if(data->postquote) {
    qitem = data->postquote;
    /* Send all QUOTE strings in same order as on command-line */
    while (qitem) {
      /* Send string */
      if (qitem->data) {
        sendf(data->firstsocket, data, "%s\r\n", qitem->data);

        nread = GetLastResponse(data->firstsocket, buf, data);

        if (buf[0] != '2') {
          failf(data, "QUOT string not accepted: %s",
                qitem->data);
          return URG_FTP_QUOTE_ERROR;
        }
      }
      qitem = qitem->next;
    }
  }


  return URG_OK;
}

/* -- deal with the ftp server!  -- */

UrgError ftp(struct UrlData *data,
             long *bytecountp,
             char *ftpuser,
             char *ftppasswd,
             char *urlpath)
{
  char *realpath;
  UrgError retcode;

#if 0
  realpath = URLfix(urlpath);
#else
  realpath = curl_unescape(urlpath);
#endif
  if(realpath) {
    retcode = _ftp(data, bytecountp, ftpuser, ftppasswd, realpath);
    free(realpath);
  }
  else
    /* then we try the original path */
    retcode = _ftp(data, bytecountp, ftpuser, ftppasswd, urlpath);

  return retcode;
}

