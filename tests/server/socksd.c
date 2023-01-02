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
 * SPDX-License-Identifier: curl
 *
 ***************************************************************************/
#include "server_setup.h"
#include <stdlib.h>

/* Function
 *
 * Accepts a TCP connection on a custom port (IPv4 or IPv6). Connects to a
 * given addr + port backend (that is NOT extracted form the client's
 * request). The backend server default to connect to can be set with
 * --backend and --backendport.
 *
 * Read commands from FILE (set with --config). The commands control how to
 * act and is reset to defaults each client TCP connect.
 *
 * Config file keywords:
 *
 * "version [number: 5]" - requires the communication to use this version.
 * "nmethods_min [number: 1]" - the minimum numberf NMETHODS the client must
 *                              state
 * "nmethods_max [number: 3]" - the minimum numberf NMETHODS the client must
 *                              state
 * "user [string]" - the user name that must match (if method is 2)
 * "password [string]" - the password that must match (if method is 2)
 * "backend [IPv4]" - numerical IPv4 address of backend to connect to
 * "backendport [number:0]" - TCP port of backend to connect to. 0 means use
                              the client's specified port number.
 * "method [number: 0]" - connect method to respond with:
 *                        0 - no auth
 *                        1 - GSSAPI (not supported)
 *                        2 - user + password
 * "response [number]" - the decimal number to respond to a connect
 *                       SOCKS5: 0 is OK, SOCKS4: 90 is ok
 *
 */

/* based on sockfilt.c */

#ifdef HAVE_SIGNAL_H
#include <signal.h>
#endif
#ifdef HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif
#ifdef HAVE_NETINET_IN6_H
#include <netinet/in6.h>
#endif
#ifdef HAVE_ARPA_INET_H
#include <arpa/inet.h>
#endif
#ifdef HAVE_NETDB_H
#include <netdb.h>
#endif

#define ENABLE_CURLX_PRINTF
/* make the curlx header define all printf() functions to use the curlx_*
   versions instead */
#include "curlx.h" /* from the private lib dir */
#include "getpart.h"
#include "inet_pton.h"
#include "util.h"
#include "server_sockaddr.h"
#include "warnless.h"

/* include memdebug.h last */
#include "memdebug.h"

#ifdef USE_WINSOCK
#undef  EINTR
#define EINTR    4 /* errno.h value */
#undef  EAGAIN
#define EAGAIN  11 /* errno.h value */
#undef  ENOMEM
#define ENOMEM  12 /* errno.h value */
#undef  EINVAL
#define EINVAL  22 /* errno.h value */
#endif

#define DEFAULT_PORT 8905

#ifndef DEFAULT_LOGFILE
#define DEFAULT_LOGFILE "log/socksd.log"
#endif

#ifndef DEFAULT_REQFILE
#define DEFAULT_REQFILE "log/socksd-request.log"
#endif

#ifndef DEFAULT_CONFIG
#define DEFAULT_CONFIG "socksd.config"
#endif

static const char *backendaddr = "127.0.0.1";
static unsigned short backendport = 0; /* default is use client's */

struct configurable {
  unsigned char version; /* initial version byte in the request must match
                            this */
  unsigned char nmethods_min; /* minimum number of nmethods to expect */
  unsigned char nmethods_max; /* maximum number of nmethods to expect */
  unsigned char responseversion;
  unsigned char responsemethod;
  unsigned char reqcmd;
  unsigned char connectrep;
  unsigned short port; /* backend port */
  char addr[32]; /* backend IPv4 numerical */
  char user[256];
  char password[256];
};

#define CONFIG_VERSION 5
#define CONFIG_NMETHODS_MIN 1 /* unauth, gssapi, auth */
#define CONFIG_NMETHODS_MAX 3
#define CONFIG_RESPONSEVERSION CONFIG_VERSION
#define CONFIG_RESPONSEMETHOD 0 /* no auth */
#define CONFIG_REQCMD 1 /* CONNECT */
#define CONFIG_PORT backendport
#define CONFIG_ADDR backendaddr
#define CONFIG_CONNECTREP 0

static struct configurable config;

const char *serverlogfile = DEFAULT_LOGFILE;
static const char *reqlogfile = DEFAULT_REQFILE;
static const char *configfile = DEFAULT_CONFIG;

static const char *socket_type = "IPv4";
static unsigned short port = DEFAULT_PORT;

static void resetdefaults(void)
{
  logmsg("Reset to defaults");
  config.version = CONFIG_VERSION;
  config.nmethods_min = CONFIG_NMETHODS_MIN;
  config.nmethods_max = CONFIG_NMETHODS_MAX;
  config.responseversion = CONFIG_RESPONSEVERSION;
  config.responsemethod = CONFIG_RESPONSEMETHOD;
  config.reqcmd = CONFIG_REQCMD;
  config.connectrep = CONFIG_CONNECTREP;
  config.port = CONFIG_PORT;
  strcpy(config.addr, CONFIG_ADDR);
  strcpy(config.user, "user");
  strcpy(config.password, "password");
}

static unsigned char byteval(char *value)
{
  unsigned long num = strtoul(value, NULL, 10);
  return num & 0xff;
}

static unsigned short shortval(char *value)
{
  unsigned long num = strtoul(value, NULL, 10);
  return num & 0xffff;
}

static enum {
  socket_domain_inet = AF_INET
#ifdef ENABLE_IPV6
  , socket_domain_inet6 = AF_INET6
#endif
#ifdef USE_UNIX_SOCKETS
  , socket_domain_unix = AF_UNIX
#endif
} socket_domain = AF_INET;

static void getconfig(void)
{
  FILE *fp = fopen(configfile, FOPEN_READTEXT);
  resetdefaults();
  if(fp) {
    char buffer[512];
    logmsg("parse config file");
    while(fgets(buffer, sizeof(buffer), fp)) {
      char key[32];
      char value[32];
      if(2 == sscanf(buffer, "%31s %31s", key, value)) {
        if(!strcmp(key, "version")) {
          config.version = byteval(value);
          logmsg("version [%d] set", config.version);
        }
        else if(!strcmp(key, "nmethods_min")) {
          config.nmethods_min = byteval(value);
          logmsg("nmethods_min [%d] set", config.nmethods_min);
        }
        else if(!strcmp(key, "nmethods_max")) {
          config.nmethods_max = byteval(value);
          logmsg("nmethods_max [%d] set", config.nmethods_max);
        }
        else if(!strcmp(key, "backend")) {
          strcpy(config.addr, value);
          logmsg("backend [%s] set", config.addr);
        }
        else if(!strcmp(key, "backendport")) {
          config.port = shortval(value);
          logmsg("backendport [%d] set", config.port);
        }
        else if(!strcmp(key, "user")) {
          strcpy(config.user, value);
          logmsg("user [%s] set", config.user);
        }
        else if(!strcmp(key, "password")) {
          strcpy(config.password, value);
          logmsg("password [%s] set", config.password);
        }
        /* Methods:
           o  X'00' NO AUTHENTICATION REQUIRED
           o  X'01' GSSAPI
           o  X'02' USERNAME/PASSWORD
        */
        else if(!strcmp(key, "method")) {
          config.responsemethod = byteval(value);
          logmsg("method [%d] set", config.responsemethod);
        }
        else if(!strcmp(key, "response")) {
          config.connectrep = byteval(value);
          logmsg("response [%d] set", config.connectrep);
        }
      }
    }
    fclose(fp);
  }
}

static void loghex(unsigned char *buffer, ssize_t len)
{
  char data[1200];
  ssize_t i;
  unsigned char *ptr = buffer;
  char *optr = data;
  ssize_t width = 0;
  int left = sizeof(data);

  for(i = 0; i<len && (left >= 0); i++) {
    msnprintf(optr, left, "%02x", ptr[i]);
    width += 2;
    optr += 2;
    left -= 2;
  }
  if(width)
    logmsg("'%s'", data);
}

/* RFC 1928, SOCKS5 byte index */
#define SOCKS5_VERSION 0
#define SOCKS5_NMETHODS 1 /* number of methods that is listed */

/* in the request: */
#define SOCKS5_REQCMD 1
#define SOCKS5_RESERVED 2
#define SOCKS5_ATYP 3
#define SOCKS5_DSTADDR 4

/* connect response */
#define SOCKS5_REP 1
#define SOCKS5_BNDADDR 4

/* auth request */
#define SOCKS5_ULEN 1
#define SOCKS5_UNAME 2

#define SOCKS4_CD 1
#define SOCKS4_DSTPORT 2

/* connect to a given IPv4 address, not the one asked for */
static curl_socket_t socksconnect(unsigned short connectport,
                                  const char *connectaddr)
{
  int rc;
  srvr_sockaddr_union_t me;
  curl_socket_t sock = socket(AF_INET, SOCK_STREAM, 0);
  if(sock == CURL_SOCKET_BAD)
    return CURL_SOCKET_BAD;
  memset(&me.sa4, 0, sizeof(me.sa4));
  me.sa4.sin_family = AF_INET;
  me.sa4.sin_port = htons(connectport);
  me.sa4.sin_addr.s_addr = INADDR_ANY;
  Curl_inet_pton(AF_INET, connectaddr, &me.sa4.sin_addr);

  rc = connect(sock, &me.sa, sizeof(me.sa4));

  if(rc) {
    int error = SOCKERRNO;
    logmsg("Error connecting to %s:%hu: (%d) %s",
           connectaddr, connectport, error, strerror(error));
    return CURL_SOCKET_BAD;
  }
  logmsg("Connected fine to %s:%d", connectaddr, connectport);
  return sock;
}

static curl_socket_t socks4(curl_socket_t fd,
                            unsigned char *buffer,
                            ssize_t rc)
{
  unsigned char response[256 + 16];
  curl_socket_t connfd;
  unsigned char cd;
  unsigned short s4port;

  if(buffer[SOCKS4_CD] != 1) {
    logmsg("SOCKS4 CD is not 1: %d", buffer[SOCKS4_CD]);
    return CURL_SOCKET_BAD;
  }
  if(rc < 9) {
    logmsg("SOCKS4 connect message too short: %d", rc);
    return CURL_SOCKET_BAD;
  }
  if(!config.port)
    s4port = (unsigned short)((buffer[SOCKS4_DSTPORT]<<8) |
                              (buffer[SOCKS4_DSTPORT + 1]));
  else
    s4port = config.port;

  connfd = socksconnect(s4port, config.addr);
  if(connfd == CURL_SOCKET_BAD) {
    /* failed */
    cd = 91;
  }
  else {
    /* success */
    cd = 90;
  }
  response[0] = 0; /* reply version 0 */
  response[1] = cd; /* result */
  /* copy port and address from connect request */
  memcpy(&response[2], &buffer[SOCKS4_DSTPORT], 6);
  rc = (send)(fd, (char *)response, 8, 0);
  if(rc != 8) {
    logmsg("Sending SOCKS4 response failed!");
    return CURL_SOCKET_BAD;
  }
  logmsg("Sent %d bytes", rc);
  loghex(response, rc);

  if(cd == 90)
    /* now do the transfer */
    return connfd;

  if(connfd != CURL_SOCKET_BAD)
    sclose(connfd);

  return CURL_SOCKET_BAD;
}

static curl_socket_t sockit(curl_socket_t fd)
{
  unsigned char buffer[256 + 16];
  unsigned char response[256 + 16];
  ssize_t rc;
  unsigned char len;
  unsigned char type;
  unsigned char rep = 0;
  unsigned char *address;
  unsigned short socksport;
  curl_socket_t connfd = CURL_SOCKET_BAD;
  unsigned short s5port;

  getconfig();

  rc = recv(fd, (char *)buffer, sizeof(buffer), 0);

  logmsg("READ %d bytes", rc);
  loghex(buffer, rc);

  if(buffer[SOCKS5_VERSION] == 4)
    return socks4(fd, buffer, rc);

  if(buffer[SOCKS5_VERSION] != config.version) {
    logmsg("VERSION byte not %d", config.version);
    return CURL_SOCKET_BAD;
  }
  if((buffer[SOCKS5_NMETHODS] < config.nmethods_min) ||
     (buffer[SOCKS5_NMETHODS] > config.nmethods_max)) {
    logmsg("NMETHODS byte not within %d - %d ",
           config.nmethods_min, config.nmethods_max);
    return CURL_SOCKET_BAD;
  }
  /* after NMETHODS follows that many bytes listing the methods the client
     says it supports */
  if(rc != (buffer[SOCKS5_NMETHODS] + 2)) {
    logmsg("Expected %d bytes, got %d", buffer[SOCKS5_NMETHODS] + 2, rc);
    return CURL_SOCKET_BAD;
  }
  logmsg("Incoming request deemed fine!");

  /* respond with two bytes: VERSION + METHOD */
  response[0] = config.responseversion;
  response[1] = config.responsemethod;
  rc = (send)(fd, (char *)response, 2, 0);
  if(rc != 2) {
    logmsg("Sending response failed!");
    return CURL_SOCKET_BAD;
  }
  logmsg("Sent %d bytes", rc);
  loghex(response, rc);

  /* expect the request or auth */
  rc = recv(fd, (char *)buffer, sizeof(buffer), 0);

  logmsg("READ %d bytes", rc);
  loghex(buffer, rc);

  if(config.responsemethod == 2) {
    /* RFC 1929 authentication
       +----+------+----------+------+----------+
       |VER | ULEN |  UNAME   | PLEN |  PASSWD  |
       +----+------+----------+------+----------+
       | 1  |  1   | 1 to 255 |  1   | 1 to 255 |
       +----+------+----------+------+----------+
    */
    unsigned char ulen;
    unsigned char plen;
    bool login = TRUE;
    if(rc < 5) {
      logmsg("Too short auth input: %d", rc);
      return CURL_SOCKET_BAD;
    }
    if(buffer[SOCKS5_VERSION] != 1) {
      logmsg("Auth VERSION byte not 1, got %d", buffer[SOCKS5_VERSION]);
      return CURL_SOCKET_BAD;
    }
    ulen = buffer[SOCKS5_ULEN];
    if(rc < 4 + ulen) {
      logmsg("Too short packet for username: %d", rc);
      return CURL_SOCKET_BAD;
    }
    plen = buffer[SOCKS5_ULEN + ulen + 1];
    if(rc < 3 + ulen + plen) {
      logmsg("Too short packet for ulen %d plen %d: %d", ulen, plen, rc);
      return CURL_SOCKET_BAD;
    }
    if((ulen != strlen(config.user)) ||
       (plen != strlen(config.password)) ||
       memcmp(&buffer[SOCKS5_UNAME], config.user, ulen) ||
       memcmp(&buffer[SOCKS5_UNAME + ulen + 1], config.password, plen)) {
      /* no match! */
      logmsg("mismatched credentials!");
      login = FALSE;
    }
    response[0] = 1;
    response[1] = login ? 0 : 1;
    rc = (send)(fd, (char *)response, 2, 0);
    if(rc != 2) {
      logmsg("Sending auth response failed!");
      return CURL_SOCKET_BAD;
    }
    logmsg("Sent %d bytes", rc);
    loghex(response, rc);
    if(!login)
      return CURL_SOCKET_BAD;

    /* expect the request */
    rc = recv(fd, (char *)buffer, sizeof(buffer), 0);

    logmsg("READ %d bytes", rc);
    loghex(buffer, rc);
  }
  if(rc < 6) {
    logmsg("Too short for request: %d", rc);
    return CURL_SOCKET_BAD;
  }

  if(buffer[SOCKS5_VERSION] != config.version) {
    logmsg("Request VERSION byte not %d", config.version);
    return CURL_SOCKET_BAD;
  }
  /* 1 == CONNECT */
  if(buffer[SOCKS5_REQCMD] != config.reqcmd) {
    logmsg("Request COMMAND byte not %d", config.reqcmd);
    return CURL_SOCKET_BAD;
  }
  /* reserved, should be zero */
  if(buffer[SOCKS5_RESERVED]) {
    logmsg("Request COMMAND byte not %d", config.reqcmd);
    return CURL_SOCKET_BAD;
  }
  /* ATYP:
     o  IP V4 address: X'01'
     o  DOMAINNAME: X'03'
     o  IP V6 address: X'04'
  */
  type = buffer[SOCKS5_ATYP];
  address = &buffer[SOCKS5_DSTADDR];
  switch(type) {
  case 1:
    /* 4 bytes IPv4 address */
    len = 4;
    break;
  case 3:
    /* The first octet of the address field contains the number of octets of
       name that follow */
    len = buffer[SOCKS5_DSTADDR];
    len++;
    break;
  case 4:
    /* 16 bytes IPv6 address */
    len = 16;
    break;
  default:
    logmsg("Unknown ATYP %d", type);
    return CURL_SOCKET_BAD;
  }
  if(rc < (4 + len + 2)) {
    logmsg("Request too short: %d, expected %d", rc, 4 + len + 2);
    return CURL_SOCKET_BAD;
  }
  logmsg("Received ATYP %d", type);

  {
    FILE *dump;
    dump = fopen(reqlogfile, "ab");
    if(dump) {
      int i;
      fprintf(dump, "atyp %u =>", type);
      switch(type) {
      case 1:
        /* 4 bytes IPv4 address */
        fprintf(dump, " %u.%u.%u.%u\n",
                address[0], address[1], address[2], address[3]);
        break;
      case 3:
        /* The first octet of the address field contains the number of octets
           of name that follow */
        fprintf(dump, " %.*s\n", len-1, &address[1]);
        break;
      case 4:
        /* 16 bytes IPv6 address */
        for(i = 0; i < 16; i++) {
          fprintf(dump, " %02x", address[i]);
        }
        fprintf(dump, "\n");
        break;
      }
      fclose(dump);
    }
  }

  if(!config.port) {
    unsigned char *portp = &buffer[SOCKS5_DSTADDR + len];
    s5port = (unsigned short)((portp[0]<<8) | (portp[1]));
  }
  else
    s5port = config.port;

  if(!config.connectrep)
    connfd = socksconnect(s5port, config.addr);

  if(connfd == CURL_SOCKET_BAD) {
    /* failed */
    rep = 1;
  }
  else {
    rep = config.connectrep;
  }

  /* */
  response[SOCKS5_VERSION] = config.responseversion;

  /*
    o  REP    Reply field:
    o  X'00' succeeded
    o  X'01' general SOCKS server failure
    o  X'02' connection not allowed by ruleset
    o  X'03' Network unreachable
    o  X'04' Host unreachable
    o  X'05' Connection refused
    o  X'06' TTL expired
    o  X'07' Command not supported
    o  X'08' Address type not supported
    o  X'09' to X'FF' unassigned
  */
  response[SOCKS5_REP] = rep;
  response[SOCKS5_RESERVED] = 0; /* must be zero */
  response[SOCKS5_ATYP] = type; /* address type */

  /* mirror back the original addr + port */

  /* address or hostname */
  memcpy(&response[SOCKS5_BNDADDR], address, len);

  /* port number */
  memcpy(&response[SOCKS5_BNDADDR + len],
         &buffer[SOCKS5_DSTADDR + len], sizeof(socksport));

  rc = (send)(fd, (char *)response, len + 6, 0);
  if(rc != (len + 6)) {
    logmsg("Sending connect response failed!");
    return CURL_SOCKET_BAD;
  }
  logmsg("Sent %d bytes", rc);
  loghex(response, rc);

  if(!rep)
    return connfd;

  if(connfd != CURL_SOCKET_BAD)
    sclose(connfd);

  return CURL_SOCKET_BAD;
}

struct perclient {
  size_t fromremote;
  size_t fromclient;
  curl_socket_t remotefd;
  curl_socket_t clientfd;
  bool used;
};

/* return non-zero when transfer is done */
static int tunnel(struct perclient *cp, fd_set *fds)
{
  ssize_t nread;
  ssize_t nwrite;
  char buffer[512];
  if(FD_ISSET(cp->clientfd, fds)) {
    /* read from client, send to remote */
    nread = recv(cp->clientfd, buffer, sizeof(buffer), 0);
    if(nread > 0) {
      nwrite = send(cp->remotefd, (char *)buffer,
                    (SEND_TYPE_ARG3)nread, 0);
      if(nwrite != nread)
        return 1;
      cp->fromclient += nwrite;
    }
    else
      return 1;
  }
  if(FD_ISSET(cp->remotefd, fds)) {
    /* read from remote, send to client */
    nread = recv(cp->remotefd, buffer, sizeof(buffer), 0);
    if(nread > 0) {
      nwrite = send(cp->clientfd, (char *)buffer,
                    (SEND_TYPE_ARG3)nread, 0);
      if(nwrite != nread)
        return 1;
      cp->fromremote += nwrite;
    }
    else
      return 1;
  }
  return 0;
}

/*
  sockfdp is a pointer to an established stream or CURL_SOCKET_BAD

  if sockfd is CURL_SOCKET_BAD, listendfd is a listening socket we must
  accept()
*/
static bool incoming(curl_socket_t listenfd)
{
  fd_set fds_read;
  fd_set fds_write;
  fd_set fds_err;
  int clients = 0; /* connected clients */
  struct perclient c[2];

  memset(c, 0, sizeof(c));
  if(got_exit_signal) {
    logmsg("signalled to die, exiting...");
    return FALSE;
  }

#ifdef HAVE_GETPPID
  /* As a last resort, quit if socks5 process becomes orphan. */
  if(getppid() <= 1) {
    logmsg("process becomes orphan, exiting");
    return FALSE;
  }
#endif

  do {
    int i;
    ssize_t rc;
    int error = 0;
    curl_socket_t sockfd = listenfd;
    int maxfd = (int)sockfd;

    FD_ZERO(&fds_read);
    FD_ZERO(&fds_write);
    FD_ZERO(&fds_err);

    /* there's always a socket to wait for */
    FD_SET(sockfd, &fds_read);

    for(i = 0; i < 2; i++) {
      if(c[i].used) {
        curl_socket_t fd = c[i].clientfd;
        FD_SET(fd, &fds_read);
        if((int)fd > maxfd)
          maxfd = (int)fd;
        fd = c[i].remotefd;
        FD_SET(fd, &fds_read);
        if((int)fd > maxfd)
          maxfd = (int)fd;
      }
    }

    do {
      /* select() blocking behavior call on blocking descriptors please */
      rc = select(maxfd + 1, &fds_read, &fds_write, &fds_err, NULL);
      if(got_exit_signal) {
        logmsg("signalled to die, exiting...");
        return FALSE;
      }
    } while((rc == -1) && ((error = errno) == EINTR));

    if(rc < 0) {
      logmsg("select() failed with error: (%d) %s",
             error, strerror(error));
      return FALSE;
    }

    if((clients < 2) && FD_ISSET(sockfd, &fds_read)) {
      curl_socket_t newfd = accept(sockfd, NULL, NULL);
      if(CURL_SOCKET_BAD == newfd) {
        error = SOCKERRNO;
        logmsg("accept(%d, NULL, NULL) failed with error: (%d) %s",
               sockfd, error, strerror(error));
      }
      else {
        curl_socket_t remotefd;
        logmsg("====> Client connect, fd %d. Read config from %s",
               newfd, configfile);
        remotefd = sockit(newfd); /* SOCKS until done */
        if(remotefd == CURL_SOCKET_BAD) {
          logmsg("====> Client disconnect");
          sclose(newfd);
        }
        else {
          struct perclient *cp = &c[0];
          logmsg("====> Tunnel transfer");

          if(c[0].used)
            cp = &c[1];
          cp->fromremote = 0;
          cp->fromclient = 0;
          cp->clientfd = newfd;
          cp->remotefd = remotefd;
          cp->used = TRUE;
          clients++;
        }

      }
    }
    for(i = 0; i < 2; i++) {
      struct perclient *cp = &c[i];
      if(cp->used) {
        if(tunnel(cp, &fds_read)) {
          logmsg("SOCKS transfer completed. Bytes: < %zu > %zu",
                 cp->fromremote, cp->fromclient);
          sclose(cp->clientfd);
          sclose(cp->remotefd);
          cp->used = FALSE;
          clients--;
        }
      }
    }
  } while(clients);

  return TRUE;
}

static curl_socket_t sockdaemon(curl_socket_t sock,
                                unsigned short *listenport
#ifdef USE_UNIX_SOCKETS
        , const char *unix_socket
#endif
        )
{
  /* passive daemon style */
  srvr_sockaddr_union_t listener;
  int flag;
  int rc;
  int totdelay = 0;
  int maxretr = 10;
  int delay = 20;
  int attempt = 0;
  int error = 0;

  do {
    attempt++;
    flag = 1;
    rc = setsockopt(sock, SOL_SOCKET, SO_REUSEADDR,
         (void *)&flag, sizeof(flag));
    if(rc) {
      error = SOCKERRNO;
      logmsg("setsockopt(SO_REUSEADDR) failed with error: (%d) %s",
             error, strerror(error));
      if(maxretr) {
        rc = wait_ms(delay);
        if(rc) {
          /* should not happen */
          error = errno;
          logmsg("wait_ms() failed with error: (%d) %s",
                 error, strerror(error));
          sclose(sock);
          return CURL_SOCKET_BAD;
        }
        if(got_exit_signal) {
          logmsg("signalled to die, exiting...");
          sclose(sock);
          return CURL_SOCKET_BAD;
        }
        totdelay += delay;
        delay *= 2; /* double the sleep for next attempt */
      }
    }
  } while(rc && maxretr--);

  if(rc) {
    logmsg("setsockopt(SO_REUSEADDR) failed %d times in %d ms. Error: (%d) %s",
           attempt, totdelay, error, strerror(error));
    logmsg("Continuing anyway...");
  }

  /* When the specified listener port is zero, it is actually a
     request to let the system choose a non-zero available port. */

  switch(socket_domain) {
    case AF_INET:
      memset(&listener.sa4, 0, sizeof(listener.sa4));
      listener.sa4.sin_family = AF_INET;
      listener.sa4.sin_addr.s_addr = INADDR_ANY;
      listener.sa4.sin_port = htons(*listenport);
      rc = bind(sock, &listener.sa, sizeof(listener.sa4));
      break;
#ifdef ENABLE_IPV6
    case AF_INET6:
      memset(&listener.sa6, 0, sizeof(listener.sa6));
      listener.sa6.sin6_family = AF_INET6;
      listener.sa6.sin6_addr = in6addr_any;
      listener.sa6.sin6_port = htons(*listenport);
      rc = bind(sock, &listener.sa, sizeof(listener.sa6));
      break;
#endif /* ENABLE_IPV6 */
#ifdef USE_UNIX_SOCKETS
    case AF_UNIX:
    rc = bind_unix_socket(sock, unix_socket, &listener.sau);
#endif
  }

  if(rc) {
    error = SOCKERRNO;
    logmsg("Error binding socket on port %hu: (%d) %s",
           *listenport, error, strerror(error));
    sclose(sock);
    return CURL_SOCKET_BAD;
  }

  if(!*listenport
#ifdef USE_UNIX_SOCKETS
          && !unix_socket
#endif
    ) {
    /* The system was supposed to choose a port number, figure out which
       port we actually got and update the listener port value with it. */
    curl_socklen_t la_size;
    srvr_sockaddr_union_t localaddr;
#ifdef ENABLE_IPV6
    if(socket_domain == AF_INET6)
      la_size = sizeof(localaddr.sa6);
    else
#endif
      la_size = sizeof(localaddr.sa4);
    memset(&localaddr.sa, 0, (size_t)la_size);
    if(getsockname(sock, &localaddr.sa, &la_size) < 0) {
      error = SOCKERRNO;
      logmsg("getsockname() failed with error: (%d) %s",
             error, strerror(error));
      sclose(sock);
      return CURL_SOCKET_BAD;
    }
    switch(localaddr.sa.sa_family) {
    case AF_INET:
      *listenport = ntohs(localaddr.sa4.sin_port);
      break;
#ifdef ENABLE_IPV6
    case AF_INET6:
      *listenport = ntohs(localaddr.sa6.sin6_port);
      break;
#endif
    default:
      break;
    }
    if(!*listenport) {
      /* Real failure, listener port shall not be zero beyond this point. */
      logmsg("Apparently getsockname() succeeded, with listener port zero.");
      logmsg("A valid reason for this failure is a binary built without");
      logmsg("proper network library linkage. This might not be the only");
      logmsg("reason, but double check it before anything else.");
      sclose(sock);
      return CURL_SOCKET_BAD;
    }
  }

  /* start accepting connections */
  rc = listen(sock, 5);
  if(0 != rc) {
    error = SOCKERRNO;
    logmsg("listen(%d, 5) failed with error: (%d) %s",
           sock, error, strerror(error));
    sclose(sock);
    return CURL_SOCKET_BAD;
  }

  return sock;
}


int main(int argc, char *argv[])
{
  curl_socket_t sock = CURL_SOCKET_BAD;
  curl_socket_t msgsock = CURL_SOCKET_BAD;
  int wrotepidfile = 0;
  int wroteportfile = 0;
  const char *pidname = ".socksd.pid";
  const char *portname = NULL; /* none by default */
  bool juggle_again;
  int error;
  int arg = 1;

#ifdef USE_UNIX_SOCKETS
  const char *unix_socket = NULL;
  bool unlink_socket = false;
#endif

  while(argc>arg) {
    if(!strcmp("--version", argv[arg])) {
      printf("socksd IPv4%s\n",
#ifdef ENABLE_IPV6
             "/IPv6"
#else
             ""
#endif
             );
      return 0;
    }
    else if(!strcmp("--pidfile", argv[arg])) {
      arg++;
      if(argc>arg)
        pidname = argv[arg++];
    }
    else if(!strcmp("--portfile", argv[arg])) {
      arg++;
      if(argc>arg)
        portname = argv[arg++];
    }
    else if(!strcmp("--config", argv[arg])) {
      arg++;
      if(argc>arg)
        configfile = argv[arg++];
    }
    else if(!strcmp("--backend", argv[arg])) {
      arg++;
      if(argc>arg)
        backendaddr = argv[arg++];
    }
    else if(!strcmp("--backendport", argv[arg])) {
      arg++;
      if(argc>arg)
        backendport = (unsigned short)atoi(argv[arg++]);
    }
    else if(!strcmp("--logfile", argv[arg])) {
      arg++;
      if(argc>arg)
        serverlogfile = argv[arg++];
    }
    else if(!strcmp("--reqfile", argv[arg])) {
      arg++;
      if(argc>arg)
        reqlogfile = argv[arg++];
    }
    else if(!strcmp("--ipv6", argv[arg])) {
#ifdef ENABLE_IPV6
      socket_domain = AF_INET6;
      socket_type = "IPv6";
#endif
      arg++;
    }
    else if(!strcmp("--ipv4", argv[arg])) {
      /* for completeness, we support this option as well */
#ifdef ENABLE_IPV6
      socket_type = "IPv4";
#endif
      arg++;
    }
    else if(!strcmp("--unix-socket", argv[arg])) {
      arg++;
      if(argc>arg) {
#ifdef USE_UNIX_SOCKETS
        struct sockaddr_un sau;
        unix_socket = argv[arg];
        if(strlen(unix_socket) >= sizeof(sau.sun_path)) {
          fprintf(stderr,
                  "socksd: socket path must be shorter than %zu chars\n",
              sizeof(sau.sun_path));
          return 0;
        }
        socket_domain = AF_UNIX;
        socket_type = "unix";
#endif
        arg++;
      }
    }
    else if(!strcmp("--port", argv[arg])) {
      arg++;
      if(argc>arg) {
        char *endptr;
        unsigned long ulnum = strtoul(argv[arg], &endptr, 10);
        port = curlx_ultous(ulnum);
        arg++;
      }
    }
    else {
      puts("Usage: socksd [option]\n"
           " --backend [ipv4 addr]\n"
           " --backendport [TCP port]\n"
           " --config [file]\n"
           " --version\n"
           " --logfile [file]\n"
           " --pidfile [file]\n"
           " --portfile [file]\n"
           " --reqfile [file]\n"
           " --ipv4\n"
           " --ipv6\n"
           " --unix-socket [file]\n"
           " --bindonly\n"
           " --port [port]\n");
      return 0;
    }
  }

#ifdef WIN32
  win32_init();
  atexit(win32_cleanup);

  setmode(fileno(stdin), O_BINARY);
  setmode(fileno(stdout), O_BINARY);
  setmode(fileno(stderr), O_BINARY);
#endif

  install_signal_handlers(false);

  sock = socket(socket_domain, SOCK_STREAM, 0);

  if(CURL_SOCKET_BAD == sock) {
    error = SOCKERRNO;
    logmsg("Error creating socket: (%d) %s",
           error, strerror(error));
    goto socks5_cleanup;
  }

  {
    /* passive daemon style */
    sock = sockdaemon(sock, &port
#ifdef USE_UNIX_SOCKETS
            , unix_socket
#endif
            );
    if(CURL_SOCKET_BAD == sock) {
      goto socks5_cleanup;
    }
#ifdef USE_UNIX_SOCKETS
    unlink_socket = true;
#endif
    msgsock = CURL_SOCKET_BAD; /* no stream socket yet */
  }

  logmsg("Running %s version", socket_type);

#ifdef USE_UNIX_SOCKETS
  if(socket_domain == AF_UNIX)
      logmsg("Listening on unix socket %s", unix_socket);
  else
#endif
  logmsg("Listening on port %hu", port);

  wrotepidfile = write_pidfile(pidname);
  if(!wrotepidfile) {
    goto socks5_cleanup;
  }

  if(portname) {
    wroteportfile = write_portfile(portname, port);
    if(!wroteportfile) {
      goto socks5_cleanup;
    }
  }

  do {
    juggle_again = incoming(sock);
  } while(juggle_again);

socks5_cleanup:

  if((msgsock != sock) && (msgsock != CURL_SOCKET_BAD))
    sclose(msgsock);

  if(sock != CURL_SOCKET_BAD)
    sclose(sock);

#ifdef USE_UNIX_SOCKETS
  if(unlink_socket && socket_domain == AF_UNIX) {
    error = unlink(unix_socket);
    logmsg("unlink(%s) = %d (%s)", unix_socket, error, strerror(error));
  }
#endif

  if(wrotepidfile)
    unlink(pidname);
  if(wroteportfile)
    unlink(portname);

  restore_signal_handlers(false);

  if(got_exit_signal) {
    logmsg("============> socksd exits with signal (%d)", exit_signal);
    /*
     * To properly set the return status of the process we
     * must raise the same signal SIGINT or SIGTERM that we
     * caught and let the old handler take care of it.
     */
    raise(exit_signal);
  }

  logmsg("============> socksd quits");
  return 0;
}
