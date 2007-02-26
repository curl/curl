/* $Id$ */

/* Copyright 1998 by the Massachusetts Institute of Technology.
 *
 * Permission to use, copy, modify, and distribute this
 * software and its documentation for any purpose and without
 * fee is hereby granted, provided that the above copyright
 * notice appear in all copies and that both that copyright
 * notice and this permission notice appear in supporting
 * documentation, and that the name of M.I.T. not be used in
 * advertising or publicity pertaining to distribution of the
 * software without specific, written prior permission.
 * M.I.T. makes no representations about the suitability of
 * this software for any purpose.  It is provided "as is"
 * without express or implied warranty.
 */

#include "setup.h"

#if defined(WIN32) && !defined(WATT32)
#include "nameser.h"

#else
#include <sys/socket.h>
#ifdef HAVE_SYS_UIO_H
#include <sys/uio.h>
#endif
#include <netinet/in.h>
#include <netdb.h>
#include <arpa/nameser.h>
#ifdef HAVE_ARPA_NAMESER_COMPAT_H
#include <arpa/nameser_compat.h>
#endif
#endif /* WIN32 && !WATT32 */

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#ifdef HAVE_SYS_IOCTL_H
#include <sys/ioctl.h>
#endif
#ifdef NETWARE
#include <sys/filio.h>
#endif

#include <string.h>
#include <stdlib.h>
#include <fcntl.h>
#include <time.h>
#include <errno.h>

#include "ares.h"
#include "ares_dns.h"
#include "ares_private.h"


static int try_again(int errnum);
static void write_tcp_data(ares_channel channel, fd_set *write_fds,
                           time_t now);
static void read_tcp_data(ares_channel channel, fd_set *read_fds, time_t now);
static void read_udp_packets(ares_channel channel, fd_set *read_fds,
                             time_t now);
static void process_timeouts(ares_channel channel, time_t now);
static void process_answer(ares_channel channel, unsigned char *abuf,
                           int alen, int whichserver, int tcp, int now);
static void handle_error(ares_channel channel, int whichserver, time_t now);
static struct query *next_server(ares_channel channel, struct query *query, time_t now);
static int open_tcp_socket(ares_channel channel, struct server_state *server);
static int open_udp_socket(ares_channel channel, struct server_state *server);
static int same_questions(const unsigned char *qbuf, int qlen,
                          const unsigned char *abuf, int alen);
static struct query *end_query(ares_channel channel, struct query *query, int status,
                      unsigned char *abuf, int alen);

/* Something interesting happened on the wire, or there was a timeout.
 * See what's up and respond accordingly.
 */
void ares_process(ares_channel channel, fd_set *read_fds, fd_set *write_fds)
{
  time_t now;

  time(&now);
  write_tcp_data(channel, write_fds, now);
  read_tcp_data(channel, read_fds, now);
  read_udp_packets(channel, read_fds, now);
  process_timeouts(channel, now);
}

/* Return 1 if the specified error number describes a readiness error, or 0
 * otherwise. This is mostly for HP-UX, which could return EAGAIN or
 * EWOULDBLOCK. See this man page
 *
 * 	http://devrsrc1.external.hp.com/STKS/cgi-bin/man2html?manpage=/usr/share/man/man2.Z/send.2
 */
static int try_again(int errnum)
{
#if !defined EWOULDBLOCK && !defined EAGAIN
#error "Neither EWOULDBLOCK nor EAGAIN defined"
#endif
  switch (errnum)
    {
#ifdef EWOULDBLOCK
    case EWOULDBLOCK:
      return 1;
#endif
#if defined EAGAIN && EAGAIN != EWOULDBLOCK
    case EAGAIN:
      return 1;
#endif
    }
  return 0;
}

/* If any TCP sockets select true for writing, write out queued data
 * we have for them.
 */
static void write_tcp_data(ares_channel channel, fd_set *write_fds, time_t now)
{
  struct server_state *server;
  struct send_request *sendreq;
  struct iovec *vec;
  int i;
  ssize_t scount;
  ssize_t wcount;
  size_t n;

  for (i = 0; i < channel->nservers; i++)
    {
      /* Make sure server has data to send and is selected in write_fds. */
      server = &channel->servers[i];
      if (!server->qhead || server->tcp_socket == ARES_SOCKET_BAD
          || !FD_ISSET(server->tcp_socket, write_fds))
        continue;

      /* Count the number of send queue items. */
      n = 0;
      for (sendreq = server->qhead; sendreq; sendreq = sendreq->next)
        n++;

      /* Allocate iovecs so we can send all our data at once. */
      vec = malloc(n * sizeof(struct iovec));
      if (vec)
        {
          /* Fill in the iovecs and send. */
          n = 0;
          for (sendreq = server->qhead; sendreq; sendreq = sendreq->next)
            {
              vec[n].iov_base = (char *) sendreq->data;
              vec[n].iov_len = sendreq->len;
              n++;
            }
          wcount = (ssize_t)writev(server->tcp_socket, vec, (int)n);
          free(vec);
          if (wcount < 0)
            {
              if (!try_again(SOCKERRNO))
                  handle_error(channel, i, now);
              continue;
            }

          /* Advance the send queue by as many bytes as we sent. */
          while (wcount)
            {
              sendreq = server->qhead;
              if ((size_t)wcount >= sendreq->len)
                {
                  wcount -= sendreq->len;
                  server->qhead = sendreq->next;
                  if (server->qhead == NULL)
                    {
                      SOCK_STATE_CALLBACK(channel, server->tcp_socket, 1, 0);
                      server->qtail = NULL;
                    }
                  free(sendreq);
                }
              else
                {
                  sendreq->data += wcount;
                  sendreq->len -= wcount;
                  break;
                }
            }
        }
      else
        {
          /* Can't allocate iovecs; just send the first request. */
          sendreq = server->qhead;

          scount = swrite(server->tcp_socket, sendreq->data, sendreq->len);
          if (scount < 0)
            {
              if (!try_again(SOCKERRNO))
                  handle_error(channel, i, now);
              continue;
            }

          /* Advance the send queue by as many bytes as we sent. */
          if ((size_t)scount == sendreq->len)
            {
              server->qhead = sendreq->next;
              if (server->qhead == NULL)
                {
                  SOCK_STATE_CALLBACK(channel, server->tcp_socket, 1, 0);
                  server->qtail = NULL;
                }
              free(sendreq);
            }
          else
            {
              sendreq->data += scount;
              sendreq->len -= scount;
            }
        }
    }
}

/* If any TCP socket selects true for reading, read some data,
 * allocate a buffer if we finish reading the length word, and process
 * a packet if we finish reading one.
 */
static void read_tcp_data(ares_channel channel, fd_set *read_fds, time_t now)
{
  struct server_state *server;
  int i;
  ssize_t count;

  for (i = 0; i < channel->nservers; i++)
    {
      /* Make sure the server has a socket and is selected in read_fds. */
      server = &channel->servers[i];
      if (server->tcp_socket == ARES_SOCKET_BAD ||
          !FD_ISSET(server->tcp_socket, read_fds))
        continue;

      if (server->tcp_lenbuf_pos != 2)
        {
          /* We haven't yet read a length word, so read that (or
           * what's left to read of it).
           */
          count = sread(server->tcp_socket,
                        server->tcp_lenbuf + server->tcp_lenbuf_pos,
                        2 - server->tcp_lenbuf_pos);
          if (count <= 0)
            {
              if (!(count == -1 && try_again(SOCKERRNO)))
                  handle_error(channel, i, now);
              continue;
            }

          server->tcp_lenbuf_pos += (int)count;
          if (server->tcp_lenbuf_pos == 2)
            {
              /* We finished reading the length word.  Decode the
               * length and allocate a buffer for the data.
               */
              server->tcp_length = server->tcp_lenbuf[0] << 8
                | server->tcp_lenbuf[1];
              server->tcp_buffer = malloc(server->tcp_length);
              if (!server->tcp_buffer)
                handle_error(channel, i, now);
              server->tcp_buffer_pos = 0;
            }
        }
      else
        {
          /* Read data into the allocated buffer. */
          count = sread(server->tcp_socket,
                        server->tcp_buffer + server->tcp_buffer_pos,
                        server->tcp_length - server->tcp_buffer_pos);
          if (count <= 0)
            {
              if (!(count == -1 && try_again(SOCKERRNO)))
                  handle_error(channel, i, now);
              continue;
            }

          server->tcp_buffer_pos += (int)count;
          if (server->tcp_buffer_pos == server->tcp_length)
            {
              /* We finished reading this answer; process it and
               * prepare to read another length word.
               */
              process_answer(channel, server->tcp_buffer, server->tcp_length,
                             i, 1, now);
          if (server->tcp_buffer)
                        free(server->tcp_buffer);
              server->tcp_buffer = NULL;
              server->tcp_lenbuf_pos = 0;
              server->tcp_buffer_pos = 0;
            }
        }
    }
}

/* If any UDP sockets select true for reading, process them. */
static void read_udp_packets(ares_channel channel, fd_set *read_fds,
                             time_t now)
{
  struct server_state *server;
  int i;
  ssize_t count;
  unsigned char buf[PACKETSZ + 1];

  for (i = 0; i < channel->nservers; i++)
    {
      /* Make sure the server has a socket and is selected in read_fds. */
      server = &channel->servers[i];

      if (server->udp_socket == ARES_SOCKET_BAD ||
          !FD_ISSET(server->udp_socket, read_fds))
        continue;

      count = sread(server->udp_socket, buf, sizeof(buf));
      if (count == -1 && try_again(SOCKERRNO))
        continue;
      else if (count <= 0)
        handle_error(channel, i, now);

      process_answer(channel, buf, (int)count, i, 0, now);
    }
}

/* If any queries have timed out, note the timeout and move them on. */
static void process_timeouts(ares_channel channel, time_t now)
{
  struct query *query, *next;

  for (query = channel->queries; query; query = next)
    {
      next = query->next;
      if (query->timeout != 0 && now >= query->timeout)
        {
          query->error_status = ARES_ETIMEOUT;
          next = next_server(channel, query, now);
        }
    }
}

/* Handle an answer from a server. */
static void process_answer(ares_channel channel, unsigned char *abuf,
                           int alen, int whichserver, int tcp, int now)
{
  int id, tc, rcode;
  struct query *query;

  /* If there's no room in the answer for a header, we can't do much
   * with it. */
  if (alen < HFIXEDSZ)
    return;

  /* Grab the query ID, truncate bit, and response code from the packet. */
  id = DNS_HEADER_QID(abuf);
  tc = DNS_HEADER_TC(abuf);
  rcode = DNS_HEADER_RCODE(abuf);

  /* Find the query corresponding to this packet. */
  for (query = channel->queries; query; query = query->next)
    {
      if (query->qid == id)
        break;
    }
  if (!query)
    return;

  /* If we got a truncated UDP packet and are not ignoring truncation,
   * don't accept the packet, and switch the query to TCP if we hadn't
   * done so already.
   */
  if ((tc || alen > PACKETSZ) && !tcp && !(channel->flags & ARES_FLAG_IGNTC))
    {
      if (!query->using_tcp)
        {
          query->using_tcp = 1;
          ares__send_query(channel, query, now);
        }
      return;
    }

  /* Limit alen to PACKETSZ if we aren't using TCP (only relevant if we
   * are ignoring truncation.
   */
  if (alen > PACKETSZ && !tcp)
    alen = PACKETSZ;

  /* If we aren't passing through all error packets, discard packets
   * with SERVFAIL, NOTIMP, or REFUSED response codes.
   */
  if (!(channel->flags & ARES_FLAG_NOCHECKRESP))
    {
      if (rcode == SERVFAIL || rcode == NOTIMP || rcode == REFUSED)
        {
          query->skip_server[whichserver] = 1;
          if (query->server == whichserver)
            next_server(channel, query, now);
          return;
        }
      if (!same_questions(query->qbuf, query->qlen, abuf, alen))
        {
          if (query->server == whichserver)
            next_server(channel, query, now);
          return;
        }
    }

  end_query(channel, query, ARES_SUCCESS, abuf, alen);
}

static void handle_error(ares_channel channel, int whichserver, time_t now)
{
  struct query *query, *next;

  /* Reset communications with this server. */
  ares__close_sockets(channel, &channel->servers[whichserver]);

  /* Tell all queries talking to this server to move on and not try
   * this server again.
   */

  for (query = channel->queries; query; query = next)
    {
      next = query->next;
      if (query->server == whichserver)
        {
          query->skip_server[whichserver] = 1;
          next = next_server(channel, query, now);
        }
    }
}

static struct query *next_server(ares_channel channel, struct query *query, time_t now)
{
  /* Advance to the next server or try. */
  query->server++;
  for (; query->try < channel->tries; query->try++)
    {
      for (; query->server < channel->nservers; query->server++)
        {
          if (!query->skip_server[query->server])
            {
              ares__send_query(channel, query, now);
              return (query->next);
            }
        }
      query->server = 0;

      /* Only one try if we're using TCP. */
      if (query->using_tcp)
        break;
    }
  return end_query(channel, query, query->error_status, NULL, 0);
}

void ares__send_query(ares_channel channel, struct query *query, time_t now)
{
  struct send_request *sendreq;
  struct server_state *server;

  server = &channel->servers[query->server];
  if (query->using_tcp)
    {
      /* Make sure the TCP socket for this server is set up and queue
       * a send request.
       */
      if (server->tcp_socket == ARES_SOCKET_BAD)
        {
          if (open_tcp_socket(channel, server) == -1)
            {
              query->skip_server[query->server] = 1;
              next_server(channel, query, now);
              return;
            }
        }
      sendreq = calloc(sizeof(struct send_request), 1);
      if (!sendreq)
        {
        end_query(channel, query, ARES_ENOMEM, NULL, 0);
          return;
        }
      sendreq->data = query->tcpbuf;
      sendreq->len = query->tcplen;
      sendreq->next = NULL;
      if (server->qtail)
        server->qtail->next = sendreq;
      else
        {
          SOCK_STATE_CALLBACK(channel, server->tcp_socket, 1, 1);
          server->qhead = sendreq;
        }
      server->qtail = sendreq;
      query->timeout = 0;
    }
  else
    {
      if (server->udp_socket == ARES_SOCKET_BAD)
        {
          if (open_udp_socket(channel, server) == -1)
            {
              query->skip_server[query->server] = 1;
              next_server(channel, query, now);
              return;
            }
        }
      if (swrite(server->udp_socket, query->qbuf, query->qlen) == -1)
        {
          /* FIXME: Handle EAGAIN here since it likely can happen. */
          query->skip_server[query->server] = 1;
          next_server(channel, query, now);
          return;
        }
      query->timeout = now
          + ((query->try == 0) ? channel->timeout
             : channel->timeout << query->try / channel->nservers);
    }
}

/*
 * nonblock() set the given socket to either blocking or non-blocking mode
 * based on the 'nonblock' boolean argument. This function is highly portable.
 */
static int nonblock(ares_socket_t sockfd,    /* operate on this */
                    int nonblock   /* TRUE or FALSE */)
{
#undef SETBLOCK
#define SETBLOCK 0
#ifdef HAVE_O_NONBLOCK
  /* most recent unix versions */
  int flags;

  flags = fcntl(sockfd, F_GETFL, 0);
  if (FALSE != nonblock)
    return fcntl(sockfd, F_SETFL, flags | O_NONBLOCK);
  else
    return fcntl(sockfd, F_SETFL, flags & (~O_NONBLOCK));
#undef SETBLOCK
#define SETBLOCK 1
#endif

#if defined(HAVE_FIONBIO) && (SETBLOCK == 0)
  /* older unix versions */
  int flags;

  flags = nonblock;
  return ioctl(sockfd, FIONBIO, &flags);
#undef SETBLOCK
#define SETBLOCK 2
#endif

#if defined(HAVE_IOCTLSOCKET) && (SETBLOCK == 0)
#ifdef WATT32
  char flags;
#else
  /* Windows? */
  unsigned long flags;
#endif
  flags = nonblock;

  return ioctlsocket(sockfd, FIONBIO, &flags);
#undef SETBLOCK
#define SETBLOCK 3
#endif

#if defined(HAVE_IOCTLSOCKET_CASE) && (SETBLOCK == 0)
  /* presumably for Amiga */
  return IoctlSocket(sockfd, FIONBIO, (long)nonblock);
#undef SETBLOCK
#define SETBLOCK 4
#endif

#if defined(HAVE_SO_NONBLOCK) && (SETBLOCK == 0)
  /* BeOS */
  long b = nonblock ? 1 : 0;
  return setsockopt(sockfd, SOL_SOCKET, SO_NONBLOCK, &b, sizeof(b));
#undef SETBLOCK
#define SETBLOCK 5
#endif

#ifdef HAVE_DISABLED_NONBLOCKING
  return 0; /* returns success */
#undef SETBLOCK
#define SETBLOCK 6
#endif

#if (SETBLOCK == 0)
#error "no non-blocking method was found/used/set"
#endif
}

static int open_tcp_socket(ares_channel channel, struct server_state *server)
{
  ares_socket_t s;
  struct sockaddr_in sockin;

  /* Acquire a socket. */
  s = socket(AF_INET, SOCK_STREAM, 0);
  if (s == ARES_SOCKET_BAD)
    return -1;

  /* Set the socket non-blocking. */
  nonblock(s, TRUE);

  /* Connect to the server. */
  memset(&sockin, 0, sizeof(sockin));
  sockin.sin_family = AF_INET;
  sockin.sin_addr = server->addr;
  sockin.sin_port = (unsigned short)(channel->tcp_port & 0xffff);
  if (connect(s, (struct sockaddr *) &sockin, sizeof(sockin)) == -1) {
    int err = SOCKERRNO;

    if (err != EINPROGRESS && err != EWOULDBLOCK) {
      closesocket(s);
      return -1;
    }
  }

  SOCK_STATE_CALLBACK(channel, s, 1, 0);
  server->tcp_buffer_pos = 0;
  server->tcp_socket = s;
  return 0;
}

static int open_udp_socket(ares_channel channel, struct server_state *server)
{
  ares_socket_t s;
  struct sockaddr_in sockin;

  /* Acquire a socket. */
  s = socket(AF_INET, SOCK_DGRAM, 0);
  if (s == ARES_SOCKET_BAD)
    return -1;

  /* Set the socket non-blocking. */
  nonblock(s, TRUE);

  /* Connect to the server. */
  memset(&sockin, 0, sizeof(sockin));
  sockin.sin_family = AF_INET;
  sockin.sin_addr = server->addr;
  sockin.sin_port = (unsigned short)(channel->udp_port & 0xffff);
  if (connect(s, (struct sockaddr *) &sockin, sizeof(sockin)) == -1)
    {
      closesocket(s);
      return -1;
    }

  SOCK_STATE_CALLBACK(channel, s, 1, 0);

  server->udp_socket = s;
  return 0;
}

static int same_questions(const unsigned char *qbuf, int qlen,
                          const unsigned char *abuf, int alen)
{
  struct {
    const unsigned char *p;
    int qdcount;
    char *name;
    long namelen;
    int type;
    int dnsclass;
  } q, a;
  int i, j;

  if (qlen < HFIXEDSZ || alen < HFIXEDSZ)
    return 0;

  /* Extract qdcount from the request and reply buffers and compare them. */
  q.qdcount = DNS_HEADER_QDCOUNT(qbuf);
  a.qdcount = DNS_HEADER_QDCOUNT(abuf);
  if (q.qdcount != a.qdcount)
    return 0;

  /* For each question in qbuf, find it in abuf. */
  q.p = qbuf + HFIXEDSZ;
  for (i = 0; i < q.qdcount; i++)
    {
      /* Decode the question in the query. */
      if (ares_expand_name(q.p, qbuf, qlen, &q.name, &q.namelen)
          != ARES_SUCCESS)
        return 0;
      q.p += q.namelen;
      if (q.p + QFIXEDSZ > qbuf + qlen)
        {
          free(q.name);
          return 0;
        }
      q.type = DNS_QUESTION_TYPE(q.p);
      q.dnsclass = DNS_QUESTION_CLASS(q.p);
      q.p += QFIXEDSZ;

      /* Search for this question in the answer. */
      a.p = abuf + HFIXEDSZ;
      for (j = 0; j < a.qdcount; j++)
        {
          /* Decode the question in the answer. */
          if (ares_expand_name(a.p, abuf, alen, &a.name, &a.namelen)
              != ARES_SUCCESS)
            {
              free(q.name);
              return 0;
            }
          a.p += a.namelen;
          if (a.p + QFIXEDSZ > abuf + alen)
            {
              free(q.name);
              free(a.name);
              return 0;
            }
          a.type = DNS_QUESTION_TYPE(a.p);
          a.dnsclass = DNS_QUESTION_CLASS(a.p);
          a.p += QFIXEDSZ;

          /* Compare the decoded questions. */
          if (strcasecmp(q.name, a.name) == 0 && q.type == a.type
              && q.dnsclass == a.dnsclass)
            {
              free(a.name);
              break;
            }
          free(a.name);
        }

      free(q.name);
      if (j == a.qdcount)
        return 0;
    }
  return 1;
}

static struct query *end_query (ares_channel channel, struct query *query, int status,
                      unsigned char *abuf, int alen)
{
  struct query **q, *next;
  int i;

  query->callback(query->arg, status, abuf, alen);
  for (q = &channel->queries; *q; q = &(*q)->next)
    {
      if (*q == query)
        break;
    }
  *q = query->next;
  if (*q)
    next = (*q)->next;
  else
    next = NULL;
  free(query->tcpbuf);
  free(query->skip_server);
  free(query);

  /* Simple cleanup policy: if no queries are remaining, close all
   * network sockets unless STAYOPEN is set.
   */
  if (!channel->queries && !(channel->flags & ARES_FLAG_STAYOPEN))
    {
      for (i = 0; i < channel->nservers; i++)
        ares__close_sockets(channel, &channel->servers[i]);
    }
  return (next);
}
