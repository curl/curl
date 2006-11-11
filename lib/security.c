/* This source code was modified by Martin Hedenfalk <mhe@stacken.kth.se> for
 * use in Curl. His latest changes were done 2000-09-18.
 *
 * It has since been patched and modified a lot by Daniel Stenberg
 * <daniel@haxx.se> to make it better applied to curl conditions, and to make
 * it not use globals, pollute name space and more. This source code awaits a
 * rewrite to work around the paragraph 2 in the BSD licenses as explained
 * below.
 *
 * Copyright (c) 1998, 1999 Kungliga Tekniska Högskolan
 * (Royal Institute of Technology, Stockholm, Sweden).
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * 3. Neither the name of the Institute nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE INSTITUTE AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE INSTITUTE OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.  */

#include "setup.h"

#ifndef CURL_DISABLE_FTP
#ifdef HAVE_KRB4

#define _MPRINTF_REPLACE /* we want curl-functions instead of native ones */
#include <curl/mprintf.h>

#include <stdlib.h>
#include <string.h>
#include <netdb.h>

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif

#include "urldata.h"
#include "krb4.h"
#include "base64.h"
#include "sendf.h"
#include "ftp.h"
#include "memory.h"

/* The last #include file should be: */
#include "memdebug.h"

#define min(a, b)   ((a) < (b) ? (a) : (b))

static const struct {
    enum protection_level level;
    const char *name;
} level_names[] = {
    { prot_clear, "clear" },
    { prot_safe, "safe" },
    { prot_confidential, "confidential" },
    { prot_private, "private" }
};

static enum protection_level
name_to_level(const char *name)
{
  int i;
  for(i = 0; i < (int)sizeof(level_names)/(int)sizeof(level_names[0]); i++)
    if(curl_strnequal(level_names[i].name, name, strlen(name)))
      return level_names[i].level;
  return (enum protection_level)-1;
}

static const struct Curl_sec_client_mech * const mechs[] = {
#ifdef KRB5
  /* not supported */
#endif
#ifdef HAVE_KRB4
    &Curl_krb4_client_mech,
#endif
    NULL
};

int
Curl_sec_getc(struct connectdata *conn, FILE *F)
{
  if(conn->sec_complete && conn->data_prot) {
    char c;
    if(Curl_sec_read(conn, fileno(F), &c, 1) <= 0)
      return EOF;
    return c;
  }
  else
    return getc(F);
}

static int
block_read(int fd, void *buf, size_t len)
{
  unsigned char *p = buf;
  int b;
  while(len) {
    b = read(fd, p, len);
    if (b == 0)
      return 0;
    else if (b < 0)
      return -1;
    len -= b;
    p += b;
  }
  return p - (unsigned char*)buf;
}

static int
block_write(int fd, void *buf, size_t len)
{
  unsigned char *p = buf;
  int b;
  while(len) {
    b = write(fd, p, len);
    if(b < 0)
      return -1;
    len -= b;
    p += b;
  }
  return p - (unsigned char*)buf;
}

static int
sec_get_data(struct connectdata *conn,
             int fd, struct krb4buffer *buf)
{
  int len;
  int b;

  b = block_read(fd, &len, sizeof(len));
  if (b == 0)
    return 0;
  else if (b < 0)
    return -1;
  len = ntohl(len);
  buf->data = realloc(buf->data, len);
  b = block_read(fd, buf->data, len);
  if (b == 0)
    return 0;
  else if (b < 0)
    return -1;
  buf->size = (conn->mech->decode)(conn->app_data, buf->data, len,
                                   conn->data_prot, conn);
  buf->index = 0;
  return 0;
}

static size_t
buffer_read(struct krb4buffer *buf, void *data, size_t len)
{
    len = min(len, buf->size - buf->index);
    memcpy(data, (char*)buf->data + buf->index, len);
    buf->index += len;
    return len;
}

static size_t
buffer_write(struct krb4buffer *buf, void *data, size_t len)
{
    if(buf->index + len > buf->size) {
        void *tmp;
        if(buf->data == NULL)
            tmp = malloc(1024);
        else
            tmp = realloc(buf->data, buf->index + len);
        if(tmp == NULL)
            return -1;
        buf->data = tmp;
        buf->size = buf->index + len;
    }
    memcpy((char*)buf->data + buf->index, data, len);
    buf->index += len;
    return len;
}

int
Curl_sec_read(struct connectdata *conn, int fd, void *buffer, int length)
{
    size_t len;
    int rx = 0;

    if(conn->sec_complete == 0 || conn->data_prot == 0)
      return read(fd, buffer, length);

    if(conn->in_buffer.eof_flag){
      conn->in_buffer.eof_flag = 0;
      return 0;
    }

    len = buffer_read(&conn->in_buffer, buffer, length);
    length -= len;
    rx += len;
    buffer = (char*)buffer + len;

    while(length) {
      if(sec_get_data(conn, fd, &conn->in_buffer) < 0)
        return -1;
      if(conn->in_buffer.size == 0) {
        if(rx)
          conn->in_buffer.eof_flag = 1;
        return rx;
      }
      len = buffer_read(&conn->in_buffer, buffer, length);
      length -= len;
      rx += len;
      buffer = (char*)buffer + len;
    }
    return rx;
}

static int
sec_send(struct connectdata *conn, int fd, char *from, int length)
{
  int bytes;
  void *buf;
  bytes = (conn->mech->encode)(conn->app_data, from, length, conn->data_prot,
                               &buf, conn);
  bytes = htonl(bytes);
  block_write(fd, &bytes, sizeof(bytes));
  block_write(fd, buf, ntohl(bytes));
  free(buf);
  return length;
}

int
Curl_sec_fflush_fd(struct connectdata *conn, int fd)
{
  if(conn->data_prot != prot_clear) {
    if(conn->out_buffer.index > 0){
      Curl_sec_write(conn, fd,
                conn->out_buffer.data, conn->out_buffer.index);
      conn->out_buffer.index = 0;
    }
    sec_send(conn, fd, NULL, 0);
  }
  return 0;
}

int
Curl_sec_write(struct connectdata *conn, int fd, char *buffer, int length)
{
  int len = conn->buffer_size;
  int tx = 0;

  if(conn->data_prot == prot_clear)
    return write(fd, buffer, length);

  len -= (conn->mech->overhead)(conn->app_data, conn->data_prot, len);
  while(length){
    if(length < len)
      len = length;
    sec_send(conn, fd, buffer, len);
    length -= len;
    buffer += len;
    tx += len;
  }
  return tx;
}

ssize_t
Curl_sec_send(struct connectdata *conn, int num, char *buffer, int length)
{
  curl_socket_t fd = conn->sock[num];
  return (ssize_t)Curl_sec_write(conn, fd, buffer, length);
}

int
Curl_sec_putc(struct connectdata *conn, int c, FILE *F)
{
  char ch = c;
  if(conn->data_prot == prot_clear)
    return putc(c, F);

  buffer_write(&conn->out_buffer, &ch, 1);
  if(c == '\n' || conn->out_buffer.index >= 1024 /* XXX */) {
    Curl_sec_write(conn, fileno(F), conn->out_buffer.data,
                   conn->out_buffer.index);
    conn->out_buffer.index = 0;
  }
  return c;
}

int
Curl_sec_read_msg(struct connectdata *conn, char *s, int level)
{
  int len;
  unsigned char *buf;
  int code;

  len = Curl_base64_decode(s + 4, &buf); /* XXX */
  if(len > 0)
    len = (conn->mech->decode)(conn->app_data, buf, len, level, conn);
  else
    return -1;

  if(len < 0) {
    free(buf);
    return -1;
  }

  buf[len] = '\0';

  if(buf[3] == '-')
    code = 0;
  else
    sscanf((char *)buf, "%d", &code);
  if(buf[len-1] == '\n')
    buf[len-1] = '\0';
  strcpy(s, (char *)buf);
  free(buf);
  return code;
}

enum protection_level
Curl_set_command_prot(struct connectdata *conn, enum protection_level level)
{
  enum protection_level old = conn->command_prot;
  conn->command_prot = level;
  return old;
}

static int
sec_prot_internal(struct connectdata *conn, int level)
{
  char *p;
  unsigned int s = 1048576;
  ssize_t nread;

  if(!conn->sec_complete){
    infof(conn->data, "No security data exchange has taken place.\n");
    return -1;
  }

  if(level){
    int code;
    if(Curl_ftpsendf(conn, "PBSZ %u", s))
      return -1;

    if(Curl_GetFTPResponse(&nread, conn, &code))
      return -1;

    if(code/100 != '2'){
      failf(conn->data, "Failed to set protection buffer size.");
      return -1;
    }
    conn->buffer_size = s;

    p = strstr(conn->data->state.buffer, "PBSZ=");
    if(p)
      sscanf(p, "PBSZ=%u", &s);
    if(s < conn->buffer_size)
      conn->buffer_size = s;
  }

  if(Curl_ftpsendf(conn, "PROT %c", level["CSEP"]))
    return -1;

  if(Curl_GetFTPResponse(&nread, conn, NULL))
    return -1;

  if(conn->data->state.buffer[0] != '2'){
    failf(conn->data, "Failed to set protection level.");
    return -1;
  }

  conn->data_prot = (enum protection_level)level;
  return 0;
}

void
Curl_sec_set_protection_level(struct connectdata *conn)
{
  if(conn->sec_complete && conn->data_prot != conn->request_data_prot)
    sec_prot_internal(conn, conn->request_data_prot);
}


int
Curl_sec_request_prot(struct connectdata *conn, const char *level)
{
  int l = name_to_level(level);
  if(l == -1)
    return -1;
  conn->request_data_prot = (enum protection_level)l;
  return 0;
}

int
Curl_sec_login(struct connectdata *conn)
{
  int ret;
  const struct Curl_sec_client_mech * const *m;
  ssize_t nread;
  struct SessionHandle *data=conn->data;
  int ftpcode;

  for(m = mechs; *m && (*m)->name; m++) {
    void *tmp;

    tmp = realloc(conn->app_data, (*m)->size);
    if (tmp == NULL) {
      failf (data, "realloc %u failed", (*m)->size);
      return -1;
    }
    conn->app_data = tmp;

    if((*m)->init && (*(*m)->init)(conn->app_data) != 0) {
      infof(data, "Skipping %s...\n", (*m)->name);
      continue;
    }
    infof(data, "Trying %s...\n", (*m)->name);

    if(Curl_ftpsendf(conn, "AUTH %s", (*m)->name))
      return -1;

    if(Curl_GetFTPResponse(&nread, conn, &ftpcode))
      return -1;

    if(conn->data->state.buffer[0] != '3'){
      switch(ftpcode) {
      case 504:
        infof(data,
              "%s is not supported by the server.\n", (*m)->name);
        break;
      case 534:
        infof(data, "%s rejected as security mechanism.\n", (*m)->name);
        break;
      default:
        if(conn->data->state.buffer[0] == '5') {
          infof(data, "The server doesn't support the FTP "
                "security extensions.\n");
          return -1;
        }
        break;
      }
      continue;
    }

    ret = (*(*m)->auth)(conn->app_data, conn);

    if(ret == AUTH_CONTINUE)
      continue;
    else if(ret != AUTH_OK){
      /* mechanism is supposed to output error string */
      return -1;
    }
    conn->mech = *m;
    conn->sec_complete = 1;
    conn->command_prot = prot_safe;
    break;
  }

  return *m == NULL;
}

void
Curl_sec_end(struct connectdata *conn)
{
  if (conn->mech != NULL) {
    if(conn->mech->end)
      (conn->mech->end)(conn->app_data);
    memset(conn->app_data, 0, conn->mech->size);
    free(conn->app_data);
    conn->app_data = NULL;
  }
  conn->sec_complete = 0;
  conn->data_prot = (enum protection_level)0;
  conn->mech=NULL;
}

#endif /* HAVE_KRB4 */
#endif /* CURL_DISABLE_FTP */
