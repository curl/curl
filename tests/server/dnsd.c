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

#ifdef HAVE_SYS_IOCTL_H
#include <sys/ioctl.h>
#endif
#ifndef UNDER_CE
#include <signal.h>
#endif
#ifdef HAVE_FCNTL_H
#include <fcntl.h>
#endif
#ifdef HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif
#ifdef HAVE_ARPA_INET_H
#include <arpa/inet.h>
#endif
#ifdef HAVE_NETDB_H
#include <netdb.h>
#endif
#ifdef HAVE_SYS_FILIO_H
/* FIONREAD on Solaris 7 */
#include <sys/filio.h>
#endif

#include <setjmp.h>

#include <ctype.h>

#include <curlx.h> /* from the private lib dir */
#include "getpart.h"
#include "util.h"
#include "server_sockaddr.h"

/* include memdebug.h last */
#include <memdebug.h>

static int dnsd_wrotepidfile = 0;
static int dnsd_wroteportfile = 0;

static unsigned short get16bit(const unsigned char **pkt,
                               size_t *size)
{
  const unsigned char *p = *pkt;
  (*pkt) += 2;
  *size -= 2;
  return (unsigned short)((p[0] << 8) | p[1]);
}

static char name[256];

static int qname(const unsigned char **pkt, size_t *size)
{
  unsigned char length;
  int o = 0;
  const unsigned char *p = *pkt;
  do {
    int i;
    length = *p++;
    if(*size < length)
      /* too long */
      return 1;
    if(length && o)
      name[o++] = '.';
    for(i = 0; i < length; i++) {
      name[o++] = *p++;
    }
  } while(length);
  *size -= (p - *pkt);
  *pkt = p;
  name[o++] = '\0';
  return 0;
}

#define QTYPE_A 1
#define QTYPE_AAAA 28

/*
 * Handle initial connection protocol.
 *
 * Return query (qname + type + class), type and id.
 */
static int store_incoming(const unsigned char *data, size_t size,
                          unsigned char *qbuf, size_t *qlen,
                          unsigned short *qtype, unsigned short *idp)
{
  FILE *server;
  char dumpfile[256];
#if 0
  size_t i;
#endif
  unsigned short qd;
  const unsigned char *qptr;
  size_t qsize;

  *qlen = 0;
  *qtype = 0;
  *idp = 0;

  snprintf(dumpfile, sizeof(dumpfile), "%s/dnsd.input", logdir);

  /* Open request dump file. */
  server = fopen(dumpfile, "ab");
  if(!server) {
    int error = errno;
    logmsg("fopen() failed with error (%d) %s", error, strerror(error));
    logmsg("Error opening file '%s'", dumpfile);
    return -1;
  }

  /*
                                    1  1  1  1  1  1
      0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                      ID                       |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |QR|   Opcode  |AA|TC|RD|RA|   Z    |   RCODE   |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                    QDCOUNT                    |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                    ANCOUNT                    |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                    NSCOUNT                    |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                    ARCOUNT                    |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
   */
  *idp = get16bit(&data, &size);
  data += 2; /* skip the next 16 bits */
  size -= 2;
#if 0
  fprintf(server, "QR: %x\n", (id & 0x8000) > 15);
  fprintf(server, "OPCODE: %x\n", (id & 0x7800) >> 11);
  fprintf(server, "TC: %x\n", (id & 0x200) >> 9);
  fprintf(server, "RD: %x\n", (id & 0x100) >> 8);
  fprintf(server, "Z: %x\n", (id & 0x70) >> 4);
  fprintf(server, "RCODE: %x\n", (id & 0x0f));
#endif
  qd = get16bit(&data, &size);
  fprintf(server, "QDCOUNT: %04x\n", qd);

  data += 6; /* skip ANCOUNT, NSCOUNT and ARCOUNT */
  size -= 6;

  /* store pointer and size at the QD point */
  qsize = size;
  qptr = data;

  if(!qname(&data, &size)) {
    fprintf(server, "QNAME: %s\n", name);
    qd = get16bit(&data, &size);
    fprintf(server, "QTYPE: %04x\n", qd);
    *qtype = qd;
    logmsg("Question for '%s' type %x", name, qd);

    qd = get16bit(&data, &size);
    fprintf(server, "QCLASS: %04x\n", qd);

    *qlen = qsize - size; /* total size of the query */
    memcpy(qbuf, qptr, *qlen);
  }
#if 0
  for(i = 0; i < size; i++) {
    fprintf(server, "%02d", (unsigned int)data[i]);
  }
  fprintf(server, "\n");
#endif

  fclose(server);

  return 0;
}

#if 0
static int send_response(curl_socket_t sock,
                         struct sockaddr *addr,
                         curl_socklen_t addrlen,
                         unsigned short id)
{
  ssize_t rc;
  unsigned char bytes[] = {
    0x80, 0xea, /* ID, overwrite */
    0x81, 0x80,
    /*
    Flags: 0x8180 Standard query response, No error
        1... .... .... .... = Response: Message is a response
        .000 0... .... .... = Opcode: Standard query (0)
        .... .0.. .... .... = Authoritative: Server is not an authority for
                              domain
        .... ..0. .... .... = Truncated: Message is not truncated
        .... ...1 .... .... = Recursion desired: Do query recursively
        .... .... 1... .... = Recursion available: Server can do recursive
                              queries
        .... .... .0.. .... = Z: reserved (0)
        .... .... ..0. .... = Answer authenticated: Answer/authority portion
                              was not authenticated by the server
        .... .... ...0 .... = Non-authenticated data: Unacceptable
        .... .... .... 0000 = Reply code: No error (0)
    */
    0x0, 0x1, /* QDCOUNT */
    0x0, 0x4, /* ANCOUNT */
    0x0, 0x0, /* NSCOUNT */
    0x0, 0x0, /* ARCOUNT */

    /* here's the question */
    0x4, 0x63, 0x75, 0x72, 0x6c, 0x2, 0x73, 0x65, 0x0, /* curl.se */
    0x0, 0x1, /* QTYPE: A */
    0x0, 0x1, /* QCLASS: IN */

    /* 4 answers */
    0xc0, 0xc, /* points to curl.se */
    0x0, 0x1, /* QTYPE A */
    0x0, 0x1, /* QCLASS IN */
    0x0, 0x0, 0xa, 0x14, /* Time to live: 2580 (43 minutes) */
    0x0, 0x4, /* data length */
    0x97, 0x65, 0x41, 0x5b, /* Address: 151.101.65.91 */

    0xc0, 0xc, 0x0, 0x1, 0x0, 0x1, 0x0, 0x0, 0xa, 0x14,
    0x0, 0x4, 0x97, 0x65, 0x81, 0x5b, /* Address: 151.101.129.91 */
    0xc0, 0xc, 0x0, 0x1, 0x0, 0x1, 0x0, 0x0, 0xa, 0x14,
    0x0, 0x4, 0x97, 0x65, 0xc1, 0x5b, /* Address: 151.101.193.91 */
    0xc0, 0xc, 0x0, 0x1, 0x0, 0x1, 0x0, 0x0, 0xa, 0x14,
    0x0, 0x4, 0x97, 0x65, 0x1, 0x5b,  /* Address: 151.101.1.91 */
#if 0
    /* 1 additional record (ARCOUNT) */

    0x0, 0x0, 0x29, 0x4, 0xd0, 0x0, 0x0,
    0x0, 0x0, 0x0, 0x0
#endif
  };
  size_t len = sizeof(bytes);

  bytes[0] = (unsigned char)(id >> 8);
  bytes[1] = (unsigned char)(id & 0xff);

  rc = sendto(sock, bytes, len, 0, addr, addrlen);
  if(rc != (ssize_t)len) {
    fprintf(stderr, "failed sending %d bytes\n", (int)len);
  }
  return 0;
}
#endif

static void add_answer(unsigned char *bytes, size_t *w,
                       const unsigned char *a, size_t alen,
                       unsigned short qtype)
{
  size_t i = *w;

  /* add answer */
  bytes[i++] = 0xc0;
  bytes[i++] = 0x0c; /* points to the query at this fixed packet index */

  /* QTYPE */
  bytes[i++] = (unsigned char)(qtype >> 8);
  bytes[i++] = (unsigned char)(qtype & 0xff);

  /* QCLASS IN */
  bytes[i++] = 0x00;
  bytes[i++] = 0x01;

  /* TTL, Time to live: 2580 (43 minutes) */
  bytes[i++] = 0x00;
  bytes[i++] = 0x00;
  bytes[i++] = 0x0a;
  bytes[i++] = 0x14;

  /* QTYPE size */
  bytes[i++] = (unsigned char)(alen >> 8);
  bytes[i++] = (unsigned char)(alen & 0xff);

  memcpy(&bytes[i], a, alen);
  i += alen;

  *w = i;
}

#ifdef _WIN32
#define SENDTO3 int
#else
#define SENDTO3 size_t
#endif

/* this is an answer to a question */
static int send_response(curl_socket_t sock,
                         const struct sockaddr *addr, curl_socklen_t addrlen,
                         unsigned char *qbuf, size_t qlen,
                         unsigned short qtype, unsigned short id)
{
  ssize_t rc;
  size_t i;
  int a;
  unsigned char ancount = 3;
  unsigned char bytes[256] = {
    0x80, 0xea, /* ID, overwrite */
    0x81, 0x80,
    /*
    Flags: 0x8180 Standard query response, No error
        1... .... .... .... = Response: Message is a response
        .000 0... .... .... = Opcode: Standard query (0)
        .... .0.. .... .... = Authoritative: Server is not an authority for
                              domain
        .... ..0. .... .... = Truncated: Message is not truncated
        .... ...1 .... .... = Recursion desired: Do query recursively
        .... .... 1... .... = Recursion available: Server can do recursive
                              queries
        .... .... .0.. .... = Z: reserved (0)
        .... .... ..0. .... = Answer authenticated: Answer/authority portion
                              was not authenticated by the server
        .... .... ...0 .... = Non-authenticated data: Unacceptable
        .... .... .... 0000 = Reply code: No error (0)
    */
    0x0, 0x1, /* QDCOUNT a single question */
    0x0, 0x0, /* ANCOUNT number of answers */
    0x0, 0x0, /* NSCOUNT */
    0x0, 0x0  /* ARCOUNT */
  };
  static const unsigned char ipv4_localhost[] = { 127, 0, 0, 1 };
  static const unsigned char ipv6_localhost[] = {
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1
  };

  bytes[0] = (unsigned char)(id >> 8);
  bytes[1] = (unsigned char)(id & 0xff);
  bytes[7] = ancount;

  if(qlen > (sizeof(bytes) - 12))
    return -1;

  /* append query, includes QTYPE and QCLASS */
  memcpy(&bytes[12], qbuf, qlen);

  i = 12 + qlen;

  for(a = 0; a < ancount; a++) {
    switch(qtype) {
    case QTYPE_A:
      add_answer(bytes, &i, ipv4_localhost, sizeof(ipv4_localhost), QTYPE_A);
      break;
    case QTYPE_AAAA:
      add_answer(bytes, &i, ipv6_localhost, sizeof(ipv6_localhost),
                 QTYPE_AAAA);
      break;
    }
  }

#ifdef __AMIGA__
  /* Amiga breakage */
  (void)rc;
  (void)sock;
  (void)addr;
  (void)addrlen;
  fprintf(stderr, "Not working\n");
  return -1;
#else
  rc = sendto(sock, (const void *)bytes, (SENDTO3) i, 0, addr, addrlen);
  if(rc != (ssize_t)i) {
    fprintf(stderr, "failed sending %d bytes\n", (int)i);
  }
#endif
  return 0;
}

int main(int argc, char **argv)
{
  srvr_sockaddr_union_t me;
  ssize_t n = 0;
  int arg = 1;
  unsigned short port = 9123; /* UDP */
  curl_socket_t sock = CURL_SOCKET_BAD;
  int flag;
  int rc;
  int error;
  int result = 0;

  pidname = ".dnsd.pid";
  serverlogfile = "log/dnsd.log";
  serverlogslocked = 0;

  while(argc > arg) {
    if(!strcmp("--verbose", argv[arg])) {
      arg++;
      /* nothing yet */
    }
    else if(!strcmp("--version", argv[arg])) {
      printf("dnsd IPv4%s\n",
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
    else if(!strcmp("--logfile", argv[arg])) {
      arg++;
      if(argc > arg)
        serverlogfile = argv[arg++];
    }
    else if(!strcmp("--logdir", argv[arg])) {
      arg++;
      if(argc > arg)
        logdir = argv[arg++];
    }
    else if(!strcmp("--ipv4", argv[arg])) {
#ifdef USE_IPV6
      ipv_inuse = "IPv4";
      use_ipv6 = FALSE;
#endif
      arg++;
    }
    else if(!strcmp("--ipv6", argv[arg])) {
#ifdef USE_IPV6
      ipv_inuse = "IPv6";
      use_ipv6 = TRUE;
#endif
      arg++;
    }
    else if(!strcmp("--port", argv[arg])) {
      arg++;
      if(argc > arg) {
        char *endptr;
        unsigned long ulnum = strtoul(argv[arg], &endptr, 10);
        port = util_ultous(ulnum);
        arg++;
      }
    }
    else {
      if(argv[arg])
        fprintf(stderr, "unknown option: %s\n", argv[arg]);
      puts("Usage: dnsd [option]\n"
           " --version\n"
           " --logfile [file]\n"
           " --logdir [directory]\n"
           " --pidfile [file]\n"
           " --portfile [file]\n"
           " --ipv4\n"
           " --ipv6\n"
           " --port [port]\n");
      return 0;
    }
  }

  snprintf(loglockfile, sizeof(loglockfile), "%s/%s/dnsd-%s.lock",
            logdir, SERVERLOGS_LOCKDIR, ipv_inuse);

#ifdef _WIN32
  if(win32_init())
    return 2;
#endif

#ifdef USE_IPV6
  if(!use_ipv6)
#endif
    sock = socket(AF_INET, SOCK_DGRAM, 0);
#ifdef USE_IPV6
  else
    sock = socket(AF_INET6, SOCK_DGRAM, 0);
#endif

  if(CURL_SOCKET_BAD == sock) {
    error = SOCKERRNO;
    logmsg("Error creating socket (%d) %s", error, sstrerror(error));
    result = 1;
    goto dnsd_cleanup;
  }

  flag = 1;
  if(0 != setsockopt(sock, SOL_SOCKET, SO_REUSEADDR,
            (void *)&flag, sizeof(flag))) {
    error = SOCKERRNO;
    logmsg("setsockopt(SO_REUSEADDR) failed with error (%d) %s",
           error, sstrerror(error));
    result = 1;
    goto dnsd_cleanup;
  }

#ifdef USE_IPV6
  if(!use_ipv6) {
#endif
    memset(&me.sa4, 0, sizeof(me.sa4));
    me.sa4.sin_family = AF_INET;
    me.sa4.sin_addr.s_addr = INADDR_ANY;
    me.sa4.sin_port = htons(port);
    rc = bind(sock, &me.sa, sizeof(me.sa4));
#ifdef USE_IPV6
  }
  else {
    memset(&me.sa6, 0, sizeof(me.sa6));
    me.sa6.sin6_family = AF_INET6;
    me.sa6.sin6_addr = in6addr_any;
    me.sa6.sin6_port = htons(port);
    rc = bind(sock, &me.sa, sizeof(me.sa6));
  }
#endif /* USE_IPV6 */
  if(0 != rc) {
    error = SOCKERRNO;
    logmsg("Error binding socket on port %hu (%d) %s", port, error,
           sstrerror(error));
    result = 1;
    goto dnsd_cleanup;
  }

  if(!port) {
    /* The system was supposed to choose a port number, figure out which
       port we actually got and update the listener port value with it. */
    curl_socklen_t la_size;
    srvr_sockaddr_union_t localaddr;
#ifdef USE_IPV6
    if(!use_ipv6)
#endif
      la_size = sizeof(localaddr.sa4);
#ifdef USE_IPV6
    else
      la_size = sizeof(localaddr.sa6);
#endif
    memset(&localaddr.sa, 0, (size_t)la_size);
    if(getsockname(sock, &localaddr.sa, &la_size) < 0) {
      error = SOCKERRNO;
      logmsg("getsockname() failed with error (%d) %s",
             error, sstrerror(error));
      sclose(sock);
      goto dnsd_cleanup;
    }
    switch(localaddr.sa.sa_family) {
    case AF_INET:
      port = ntohs(localaddr.sa4.sin_port);
      break;
#ifdef USE_IPV6
    case AF_INET6:
      port = ntohs(localaddr.sa6.sin6_port);
      break;
#endif
    default:
      break;
    }
    if(!port) {
      /* Real failure, listener port shall not be zero beyond this point. */
      logmsg("Apparently getsockname() succeeded, with listener port zero.");
      logmsg("A valid reason for this failure is a binary built without");
      logmsg("proper network library linkage. This might not be the only");
      logmsg("reason, but double check it before anything else.");
      result = 2;
      goto dnsd_cleanup;
    }
  }

  dnsd_wrotepidfile = write_pidfile(pidname);
  if(!dnsd_wrotepidfile) {
    result = 1;
    goto dnsd_cleanup;
  }

  if(portname) {
    dnsd_wroteportfile = write_portfile(portname, port);
    if(!dnsd_wroteportfile) {
      result = 1;
      goto dnsd_cleanup;
    }
  }

  logmsg("Running %s version on port UDP/%d", ipv_inuse, (int)port);

  for(;;) {
    unsigned short id = 0;
    unsigned char inbuffer[1500];
    srvr_sockaddr_union_t from;
    curl_socklen_t fromlen;
    unsigned char qbuf[256]; /* query storage */
    size_t qlen = 0; /* query size */
    unsigned short qtype = 0;
    fromlen = sizeof(from);
#ifdef USE_IPV6
    if(!use_ipv6)
#endif
      fromlen = sizeof(from.sa4);
#ifdef USE_IPV6
    else
      fromlen = sizeof(from.sa6);
#endif
    n = (ssize_t)recvfrom(sock, (char *)inbuffer, sizeof(inbuffer), 0,
                          &from.sa, &fromlen);
    if(got_exit_signal)
      break;
    if(n < 0) {
      logmsg("recvfrom");
      result = 3;
      break;
    }

    store_incoming(inbuffer, n, qbuf, &qlen, &qtype, &id);

    set_advisor_read_lock(loglockfile);
    serverlogslocked = 1;

    send_response(sock, &from.sa, fromlen, qbuf, qlen, qtype, id);

    if(got_exit_signal)
      break;

    if(serverlogslocked) {
      serverlogslocked = 0;
      clear_advisor_read_lock(loglockfile);
    }

    logmsg("end of one transfer");

  }

dnsd_cleanup:

#if 0
  if((peer != sock) && (peer != CURL_SOCKET_BAD))
    sclose(peer);
#endif

  if(sock != CURL_SOCKET_BAD)
    sclose(sock);

  if(got_exit_signal)
    logmsg("signalled to die");

  if(dnsd_wrotepidfile)
    unlink(pidname);
  if(dnsd_wroteportfile)
    unlink(portname);

  if(serverlogslocked) {
    serverlogslocked = 0;
    clear_advisor_read_lock(loglockfile);
  }

  restore_signal_handlers(true);

  if(got_exit_signal) {
    logmsg("========> %s dnsd (port: %d pid: %ld) exits with signal (%d)",
           ipv_inuse, (int)port, (long)our_getpid(), exit_signal);
    /*
     * To properly set the return status of the process we
     * must raise the same signal SIGINT or SIGTERM that we
     * caught and let the old handler take care of it.
     */
    raise(exit_signal);
  }

  logmsg("========> dnsd quits");
  return result;
}
