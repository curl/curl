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
#include "first.h"

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

static const char *backendaddr = "127.0.0.1";
static unsigned short backendport = 0; /* default is use client's */

struct socksd_configurable {
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

static struct socksd_configurable s_config;

static const char *reqlogfile = "log/socksd-request.log";

static void socksd_resetdefaults(void)
{
  logmsg("Reset to defaults");
  s_config.version = CONFIG_VERSION;
  s_config.nmethods_min = CONFIG_NMETHODS_MIN;
  s_config.nmethods_max = CONFIG_NMETHODS_MAX;
  s_config.responseversion = CONFIG_RESPONSEVERSION;
  s_config.responsemethod = CONFIG_RESPONSEMETHOD;
  s_config.reqcmd = CONFIG_REQCMD;
  s_config.connectrep = CONFIG_CONNECTREP;
  s_config.port = CONFIG_PORT;
  strcpy(s_config.addr, CONFIG_ADDR);
  strcpy(s_config.user, "user");
  strcpy(s_config.password, "password");
}

static unsigned short shortval(char *value)
{
  unsigned long num = strtoul(value, NULL, 10);
  return num & 0xffff;
}

static void socksd_getconfig(void)
{
  FILE *fp = fopen(configfile, FOPEN_READTEXT);
  socksd_resetdefaults();
  if(fp) {
    char buffer[512];
    logmsg("parse config file");
    while(fgets(buffer, sizeof(buffer), fp)) {
      char key[32];
      char value[260];
      if(sscanf(buffer, "%31s %259s", key, value) == 2) {
        if(!strcmp(key, "version")) {
          s_config.version = byteval(value);
          logmsg("version [%d] set", s_config.version);
        }
        else if(!strcmp(key, "nmethods_min")) {
          s_config.nmethods_min = byteval(value);
          logmsg("nmethods_min [%d] set", s_config.nmethods_min);
        }
        else if(!strcmp(key, "nmethods_max")) {
          s_config.nmethods_max = byteval(value);
          logmsg("nmethods_max [%d] set", s_config.nmethods_max);
        }
        else if(!strcmp(key, "backend")) {
          strcpy(s_config.addr, value);
          logmsg("backend [%s] set", s_config.addr);
        }
        else if(!strcmp(key, "backendport")) {
          s_config.port = shortval(value);
          logmsg("backendport [%d] set", s_config.port);
        }
        else if(!strcmp(key, "user")) {
          strcpy(s_config.user, value);
          logmsg("user [%s] set", s_config.user);
        }
        else if(!strcmp(key, "password")) {
          strcpy(s_config.password, value);
          logmsg("password [%s] set", s_config.password);
        }
        /* Methods:
           o  X'00' NO AUTHENTICATION REQUIRED
           o  X'01' GSSAPI
           o  X'02' USERNAME/PASSWORD
        */
        else if(!strcmp(key, "method")) {
          s_config.responsemethod = byteval(value);
          logmsg("method [%d] set", s_config.responsemethod);
        }
        else if(!strcmp(key, "response")) {
          s_config.connectrep = byteval(value);
          logmsg("response [%d] set", s_config.connectrep);
        }
      }
    }
    fclose(fp);
  }
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
  curlx_inet_pton(AF_INET, connectaddr, &me.sa4.sin_addr);

  rc = connect(sock, &me.sa, sizeof(me.sa4));

  if(rc) {
    int error = SOCKERRNO;
    logmsg("Failed connecting to %s:%hu (%d) %s",
           connectaddr, connectport, error, sstrerror(error));
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
    logmsg("SOCKS4 connect message too short: %zd", rc);
    return CURL_SOCKET_BAD;
  }
  if(!s_config.port)
    s4port = (unsigned short)((buffer[SOCKS4_DSTPORT] << 8) |
                              (buffer[SOCKS4_DSTPORT + 1]));
  else
    s4port = s_config.port;

  connfd = socksconnect(s4port, s_config.addr);
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
  logmsg("Sent %zd bytes", rc);
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
  unsigned char buffer[2*256 + 16];
  unsigned char response[2*256 + 16];
  ssize_t rc;
  unsigned char len;
  unsigned char type;
  unsigned char rep = 0;
  unsigned char *address;
  unsigned short socksport;
  curl_socket_t connfd = CURL_SOCKET_BAD;
  unsigned short s5port;

  socksd_getconfig();

  rc = recv(fd, (char *)buffer, sizeof(buffer), 0);
  if(rc <= 0) {
    logmsg("SOCKS identifier message missing, recv returned %zd", rc);
    return CURL_SOCKET_BAD;
  }

  logmsg("READ %zd bytes", rc);
  loghex(buffer, rc);

  if(buffer[SOCKS5_VERSION] == 4)
    return socks4(fd, buffer, rc);

  if(rc < 3) {
    logmsg("SOCKS5 identifier message too short: %zd", rc);
    return CURL_SOCKET_BAD;
  }

  if(buffer[SOCKS5_VERSION] != s_config.version) {
    logmsg("VERSION byte not %d", s_config.version);
    return CURL_SOCKET_BAD;
  }
  if((buffer[SOCKS5_NMETHODS] < s_config.nmethods_min) ||
     (buffer[SOCKS5_NMETHODS] > s_config.nmethods_max)) {
    logmsg("NMETHODS byte not within %d - %d ",
           s_config.nmethods_min, s_config.nmethods_max);
    return CURL_SOCKET_BAD;
  }
  /* after NMETHODS follows that many bytes listing the methods the client
     says it supports */
  if(rc != (buffer[SOCKS5_NMETHODS] + 2)) {
    logmsg("Expected %d bytes, got %zd", buffer[SOCKS5_NMETHODS] + 2, rc);
    return CURL_SOCKET_BAD;
  }
  logmsg("Incoming request deemed fine!");

  /* respond with two bytes: VERSION + METHOD */
  response[0] = s_config.responseversion;
  response[1] = s_config.responsemethod;
  rc = (send)(fd, (char *)response, 2, 0);
  if(rc != 2) {
    logmsg("Sending response failed!");
    return CURL_SOCKET_BAD;
  }
  logmsg("Sent %zd bytes", rc);
  loghex(response, rc);

  /* expect the request or auth */
  rc = recv(fd, (char *)buffer, sizeof(buffer), 0);
  if(rc <= 0) {
    logmsg("SOCKS5 request or auth message missing, recv returned %zd", rc);
    return CURL_SOCKET_BAD;
  }

  logmsg("READ %zd bytes", rc);
  loghex(buffer, rc);

  if(s_config.responsemethod == 2) {
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
      logmsg("Too short auth input: %zd", rc);
      return CURL_SOCKET_BAD;
    }
    if(buffer[SOCKS5_VERSION] != 1) {
      logmsg("Auth VERSION byte not 1, got %d", buffer[SOCKS5_VERSION]);
      return CURL_SOCKET_BAD;
    }
    ulen = buffer[SOCKS5_ULEN];
    if(rc < 4 + ulen) {
      logmsg("Too short packet for username: %zd", rc);
      return CURL_SOCKET_BAD;
    }
    plen = buffer[SOCKS5_ULEN + ulen + 1];
    if(rc < 3 + ulen + plen) {
      logmsg("Too short packet for ulen %d plen %d: %zd", ulen, plen, rc);
      return CURL_SOCKET_BAD;
    }
    if((ulen != strlen(s_config.user)) ||
       (plen != strlen(s_config.password)) ||
       memcmp(&buffer[SOCKS5_UNAME], s_config.user, ulen) ||
       memcmp(&buffer[SOCKS5_UNAME + ulen + 1], s_config.password, plen)) {
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
    logmsg("Sent %zd bytes", rc);
    loghex(response, rc);
    if(!login)
      return CURL_SOCKET_BAD;

    /* expect the request */
    rc = recv(fd, (char *)buffer, sizeof(buffer), 0);
    if(rc <= 0) {
      logmsg("SOCKS5 request message missing, recv returned %zd", rc);
      return CURL_SOCKET_BAD;
    }

    logmsg("READ %zd bytes", rc);
    loghex(buffer, rc);
  }
  if(rc < 6) {
    logmsg("Too short for request: %zd", rc);
    return CURL_SOCKET_BAD;
  }

  if(buffer[SOCKS5_VERSION] != s_config.version) {
    logmsg("Request VERSION byte not %d", s_config.version);
    return CURL_SOCKET_BAD;
  }
  /* 1 == CONNECT */
  if(buffer[SOCKS5_REQCMD] != s_config.reqcmd) {
    logmsg("Request COMMAND byte not %d", s_config.reqcmd);
    return CURL_SOCKET_BAD;
  }
  /* reserved, should be zero */
  if(buffer[SOCKS5_RESERVED]) {
    logmsg("Request COMMAND byte not %d", s_config.reqcmd);
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
    logmsg("Request too short: %zd, expected %d", rc, 4 + len + 2);
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

  if(!s_config.port) {
    unsigned char *portp = &buffer[SOCKS5_DSTADDR + len];
    s5port = (unsigned short)((portp[0] << 8) | (portp[1]));
  }
  else
    s5port = s_config.port;

  if(!s_config.connectrep)
    connfd = socksconnect(s5port, s_config.addr);

  if(connfd == CURL_SOCKET_BAD) {
    /* failed */
    rep = 1;
  }
  else {
    rep = s_config.connectrep;
  }

  /* */
  response[SOCKS5_VERSION] = s_config.responseversion;

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

  rc = (send)(fd, (char *)response, (SEND_TYPE_ARG3)(len + 6), 0);
  if(rc != (len + 6)) {
    logmsg("Sending connect response failed!");
    return CURL_SOCKET_BAD;
  }
  logmsg("Sent %zd bytes", rc);
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
static bool socksd_incoming(curl_socket_t listenfd)
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
#ifdef __DJGPP__
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Warith-conversion"
#endif
    FD_SET(sockfd, &fds_read);
#ifdef __DJGPP__
#pragma GCC diagnostic pop
#endif

    for(i = 0; i < 2; i++) {
      if(c[i].used) {
        curl_socket_t fd = c[i].clientfd;
#ifdef __DJGPP__
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Warith-conversion"
#endif
        FD_SET(fd, &fds_read);
#ifdef __DJGPP__
#pragma GCC diagnostic pop
#endif
        if((int)fd > maxfd)
          maxfd = (int)fd;
        fd = c[i].remotefd;
#ifdef __DJGPP__
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Warith-conversion"
#endif
        FD_SET(fd, &fds_read);
#ifdef __DJGPP__
#pragma GCC diagnostic pop
#endif
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
    } while((rc == -1) && ((error = SOCKERRNO) == SOCKEINTR));

    if(rc < 0) {
      logmsg("select() failed with error (%d) %s",
             error, sstrerror(error));
      return FALSE;
    }

    if((clients < 2) && FD_ISSET(sockfd, &fds_read)) {
      curl_socket_t newfd = accept(sockfd, NULL, NULL);
      if(CURL_SOCKET_BAD == newfd) {
        error = SOCKERRNO;
        logmsg("accept() failed with error (%d) %s",
               error, sstrerror(error));
      }
      else {
        curl_socket_t remotefd;
        logmsg("====> Client connect, "
               "Read config from %s", configfile);
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

static int test_socksd(int argc, char *argv[])
{
  curl_socket_t sock = CURL_SOCKET_BAD;
  curl_socket_t msgsock = CURL_SOCKET_BAD;
  int wrotepidfile = 0;
  int wroteportfile = 0;
  bool juggle_again;
  int error;
  int arg = 1;

  const char *unix_socket = NULL;
#ifdef USE_UNIX_SOCKETS
  bool unlink_socket = false;
#endif

  pidname = ".socksd.pid";
  serverlogfile = "log/socksd.log";
  configfile = "socksd.config";
  server_port = 8905;

  while(argc > arg) {
    if(!strcmp("--version", argv[arg])) {
      printf("socksd IPv4%s\n",
#ifdef USE_IPV6
             "/IPv6"
#else
             ""
#endif
             );
      return 0;
    }
    else if(!strcmp("--pidfile", argv[arg])) {
      arg++;
      if(argc > arg)
        pidname = argv[arg++];
    }
    else if(!strcmp("--portfile", argv[arg])) {
      arg++;
      if(argc > arg)
        portname = argv[arg++];
    }
    else if(!strcmp("--config", argv[arg])) {
      arg++;
      if(argc > arg)
        configfile = argv[arg++];
    }
    else if(!strcmp("--backend", argv[arg])) {
      arg++;
      if(argc > arg)
        backendaddr = argv[arg++];
    }
    else if(!strcmp("--backendport", argv[arg])) {
      arg++;
      if(argc > arg)
        backendport = (unsigned short)atoi(argv[arg++]);
    }
    else if(!strcmp("--logfile", argv[arg])) {
      arg++;
      if(argc > arg)
        serverlogfile = argv[arg++];
    }
    else if(!strcmp("--reqfile", argv[arg])) {
      arg++;
      if(argc > arg)
        reqlogfile = argv[arg++];
    }
    else if(!strcmp("--ipv6", argv[arg])) {
#ifdef USE_IPV6
      socket_domain = AF_INET6;
      socket_type = "IPv6";
#endif
      arg++;
    }
    else if(!strcmp("--ipv4", argv[arg])) {
      /* for completeness, we support this option as well */
#ifdef USE_IPV6
      socket_type = "IPv4";
#endif
      arg++;
    }
    else if(!strcmp("--unix-socket", argv[arg])) {
      arg++;
      if(argc > arg) {
#ifdef USE_UNIX_SOCKETS
        struct sockaddr_un sau;
        unix_socket = argv[arg];
        if(strlen(unix_socket) >= sizeof(sau.sun_path)) {
          fprintf(stderr,
                  "socksd: socket path must be shorter than %u chars: %s\n",
                  (unsigned int)sizeof(sau.sun_path), unix_socket);
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
      if(argc > arg) {
        char *endptr;
        unsigned long ulnum = strtoul(argv[arg], &endptr, 10);
        server_port = util_ultous(ulnum);
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

#ifdef _WIN32
  if(win32_init())
    return 2;
#endif

  CURLX_SET_BINMODE(stdin);
  CURLX_SET_BINMODE(stdout);
  CURLX_SET_BINMODE(stderr);

  install_signal_handlers(false);

  sock = socket(socket_domain, SOCK_STREAM, 0);

  if(CURL_SOCKET_BAD == sock) {
    error = SOCKERRNO;
    logmsg("Error creating socket (%d) %s",
           error, sstrerror(error));
    goto socks5_cleanup;
  }

  {
    /* passive daemon style */
    sock = sockdaemon(sock, &server_port, unix_socket, FALSE);
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
    logmsg("Listening on Unix socket %s", unix_socket);
  else
#endif
  logmsg("Listening on port %hu", server_port);

  wrotepidfile = write_pidfile(pidname);
  if(!wrotepidfile) {
    goto socks5_cleanup;
  }

  if(portname) {
    wroteportfile = write_portfile(portname, server_port);
    if(!wroteportfile) {
      goto socks5_cleanup;
    }
  }

  do {
    juggle_again = socksd_incoming(sock);
  } while(juggle_again);

socks5_cleanup:

  if((msgsock != sock) && (msgsock != CURL_SOCKET_BAD))
    sclose(msgsock);

  if(sock != CURL_SOCKET_BAD)
    sclose(sock);

#ifdef USE_UNIX_SOCKETS
  if(unlink_socket && socket_domain == AF_UNIX && unix_socket) {
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
