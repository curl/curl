/* modified by Martin Hedenfalk <mhe@stacken.kth.se> for use in Curl
 * last modified 2000-09-18
 * Even more obscurified to merge better into libcurl by Daniel Stenberg.
 */

/*
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
 * SUCH DAMAGE.
 */

#include "setup.h"

#ifdef KRB4

#define _MPRINTF_REPLACE /* we want curl-functions instead of native ones */
#include <curl/mprintf.h>

#include "security.h"
#include <stdlib.h>
#include <string.h>
#include <netdb.h>

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif

#include "base64.h"
#include "sendf.h"
#include "ftp.h"

/* The last #include file should be: */
#ifdef MALLOCDEBUG
#include "memdebug.h"
#endif

#define min(a, b)   ((a) < (b) ? (a) : (b))

static struct {
    enum protection_level level;
    const char *name;
} level_names[] = {
    { prot_clear, "clear" },
    { prot_safe, "safe" },
    { prot_confidential, "confidential" },
    { prot_private, "private" }
};

#if 0
static const char *
level_to_name(enum protection_level level)
{
    int i;
    for(i = 0; i < sizeof(level_names) / sizeof(level_names[0]); i++)
	if(level_names[i].level == level)
	    return level_names[i].name;
    return "unknown";
}
#endif

#ifndef FTP_SERVER /* not used in server */
static enum protection_level 
name_to_level(const char *name)
{
    int i;
    for(i = 0; i < sizeof(level_names) / sizeof(level_names[0]); i++)
	if(!strncasecmp(level_names[i].name, name, strlen(name)))
	    return level_names[i].level;
    return (enum protection_level)-1;
}
#endif

#ifdef FTP_SERVER

static struct sec_server_mech *mechs[] = {
#ifdef KRB5
    &gss_server_mech,
#endif
#ifdef KRB4
    &krb4_server_mech,
#endif
    NULL
};

static struct sec_server_mech *mech;

#else

static struct sec_client_mech *mechs[] = {
#ifdef KRB5
    &gss_client_mech,
#endif
#ifdef KRB4
    &krb4_client_mech,
#endif
    NULL
};

static struct sec_client_mech *mech;

#endif

int
sec_getc(struct connectdata *conn, FILE *F)
{
  if(conn->sec_complete && conn->data_prot) {
    char c;
    if(sec_read(conn, fileno(F), &c, 1) <= 0)
      return EOF;
    return c;
  } else
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
             int fd, struct krb4buffer *buf, int level)
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
  buf->size = (*mech->decode)(conn->app_data, buf->data, len,
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
sec_read(struct connectdata *conn, int fd, void *buffer, int length)
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
      if(sec_get_data(conn, fd, &conn->in_buffer, conn->data_prot) < 0)
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
  bytes = (*mech->encode)(conn->app_data, from, length, conn->data_prot, &buf, conn);
  bytes = htonl(bytes);
  block_write(fd, &bytes, sizeof(bytes));
  block_write(fd, buf, ntohl(bytes));
  free(buf);
  return length;
}

int
sec_fflush(struct connectdata *conn, FILE *F)
{
  if(conn->data_prot != prot_clear) {
    if(conn->out_buffer.index > 0){
      sec_write(conn, fileno(F),
                conn->out_buffer.data, conn->out_buffer.index);
      conn->out_buffer.index = 0;
    }
    sec_send(conn, fileno(F), NULL, 0);
  }
  fflush(F);
  return 0;
}

int
sec_fflush_fd(struct connectdata *conn, int fd)
{
  if(conn->data_prot != prot_clear) {
    if(conn->out_buffer.index > 0){
      sec_write(conn, fd,
                conn->out_buffer.data, conn->out_buffer.index);
      conn->out_buffer.index = 0;
    }
    sec_send(conn, fd, NULL, 0);
  }
  return 0;
}

int
sec_write(struct connectdata *conn, int fd, char *buffer, int length)
{
  int len = conn->buffer_size;
  int tx = 0;
      
  if(conn->data_prot == prot_clear)
    return write(fd, buffer, length);

  len -= (*mech->overhead)(conn->app_data, conn->data_prot, len);
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

int
sec_vfprintf2(struct connectdata *conn, FILE *f, const char *fmt, va_list ap)
{
  char *buf;
  int ret;
  if(conn->data_prot == prot_clear)
    return vfprintf(f, fmt, ap);
  else {
    buf = aprintf(fmt, ap);
    ret = buffer_write(&conn->out_buffer, buf, strlen(buf));
    free(buf);
    return ret;
  }
}

int
sec_fprintf2(struct connectdata *conn, FILE *f, const char *fmt, ...)
{
    int ret;
    va_list ap;
    va_start(ap, fmt);
    ret = sec_vfprintf2(conn, f, fmt, ap);
    va_end(ap);
    return ret;
}

int
sec_putc(struct connectdata *conn, int c, FILE *F)
{
  char ch = c;
  if(conn->data_prot == prot_clear)
    return putc(c, F);
    
  buffer_write(&conn->out_buffer, &ch, 1);
  if(c == '\n' || conn->out_buffer.index >= 1024 /* XXX */) {
    sec_write(conn, fileno(F), conn->out_buffer.data, conn->out_buffer.index);
    conn->out_buffer.index = 0;
  }
  return c;
}

int
sec_read_msg(struct connectdata *conn, char *s, int level)
{
    int len;
    char *buf;
    int code;
    
    buf = malloc(strlen(s));
    len = Curl_base64_decode(s + 4, buf); /* XXX */
    
    len = (*mech->decode)(conn->app_data, buf, len, level, conn);
    if(len < 0)
	return -1;
    
    buf[len] = '\0';

    if(buf[3] == '-')
	code = 0;
    else
	sscanf(buf, "%d", &code);
    if(buf[len-1] == '\n')
	buf[len-1] = '\0';
    strcpy(s, buf);
    free(buf);
    return code;
}

/* modified to return how many bytes written, or -1 on error ***/
int
sec_vfprintf(struct connectdata *conn, FILE *f, const char *fmt, va_list ap)
{
    int ret = 0;
    char *buf;
    void *enc;
    int len;
    if(!conn->sec_complete)
	return vfprintf(f, fmt, ap);
    
    buf = aprintf(fmt, ap);
    len = (*mech->encode)(conn->app_data, buf, strlen(buf),
                          conn->command_prot, &enc,
			  conn);
    free(buf);
    if(len < 0) {
	failf(conn->data, "Failed to encode command.\n");
	return -1;
    }
    if(Curl_base64_encode(enc, len, &buf) < 0){
      failf(conn->data, "Out of memory base64-encoding.\n");
      return -1;
    }
#ifdef FTP_SERVER
    if(command_prot == prot_safe)
	fprintf(f, "631 %s\r\n", buf);
    else if(command_prot == prot_private)
	fprintf(f, "632 %s\r\n", buf);
    else if(command_prot == prot_confidential)
	fprintf(f, "633 %s\r\n", buf);
#else
    if(conn->command_prot == prot_safe)
	ret = fprintf(f, "MIC %s", buf);
    else if(conn->command_prot == prot_private)
	ret = fprintf(f, "ENC %s", buf);
    else if(conn->command_prot == prot_confidential)
	ret = fprintf(f, "CONF %s", buf);
#endif
    free(buf);
    return ret;
}

int
sec_fprintf(struct connectdata *conn, FILE *f, const char *fmt, ...)
{
    va_list ap;
    int ret;
    va_start(ap, fmt);
    ret = sec_vfprintf(conn, f, fmt, ap);
    va_end(ap);
    return ret;
}

/* end common stuff */

#ifdef FTP_SERVER

/* snip */

#else /* FTP_SERVER */

#if 0
void
sec_status(void)
{
    if(conn->sec_complete){
	printf("Using %s for authentication.\n", mech->name);
	printf("Using %s command channel.\n", level_to_name(command_prot));
	printf("Using %s data channel.\n", level_to_name(data_prot));
	if(buffer_size > 0)
	    printf("Protection buffer size: %lu.\n", 
		   (unsigned long)buffer_size);
    }else{
	printf("Not using any security mechanism.\n");
    }
}
#endif

static int
sec_prot_internal(struct connectdata *conn, int level)
{
    char *p;
    unsigned int s = 1048576;
    size_t nread;

    if(!conn->sec_complete){
      infof(conn->data, "No security data exchange has taken place.\n");
      return -1;
    }

    if(level){
      Curl_ftpsendf(conn->firstsocket, conn,
                    "PBSZ %u", s);
      /* wait for feedback */
      nread = Curl_GetFTPResponse(conn->firstsocket,
                                  conn->data->buffer, conn, NULL);
      if(nread < 0)
        return /*CURLE_OPERATION_TIMEOUTED*/-1;
      if(/*ret != COMPLETE*/conn->data->buffer[0] != '2'){
        failf(conn->data, "Failed to set protection buffer size.\n");
        return -1;
      }
      conn->buffer_size = s;
      p = strstr(/*reply_string*/conn->data->buffer, "PBSZ=");
      if(p)
        sscanf(p, "PBSZ=%u", &s);
      if(s < conn->buffer_size)
        conn->buffer_size = s;
    }

    Curl_ftpsendf(conn->firstsocket, conn,
                  "PROT %c", level["CSEP"]);
    /* wait for feedback */
    nread = Curl_GetFTPResponse(conn->firstsocket,
                                conn->data->buffer, conn, NULL);
    if(nread < 0)
      return /*CURLE_OPERATION_TIMEOUTED*/-1;
    if(/*ret != COMPLETE*/conn->data->buffer[0] != '2'){
      failf(conn->data, "Failed to set protection level.\n");
      return -1;
    }
    
    conn->data_prot = (enum protection_level)level;
    return 0;
}

enum protection_level
set_command_prot(struct connectdata *conn, enum protection_level level)
{
    enum protection_level old = conn->command_prot;
    conn->command_prot = level;
    return old;
}

#if 0
void
sec_prot(int argc, char **argv)
{
    int level = -1;

    if(argc < 2 || argc > 3)
	goto usage;
    if(!sec_complete) {
	printf("No security data exchange has taken place.\n");
	code = -1;
	return;
    }
    level = name_to_level(argv[argc - 1]);
    
    if(level == -1)
	goto usage;
    
    if((*mech->check_prot)(conn->app_data, level)) {
	printf("%s does not implement %s protection.\n", 
	       mech->name, level_to_name(level));
	code = -1;
	return;
    }
    
    if(argc == 2 || strncasecmp(argv[1], "data", strlen(argv[1])) == 0) {
	if(sec_prot_internal(level) < 0){
	    code = -1;
	    return;
	}
    } else if(strncasecmp(argv[1], "command", strlen(argv[1])) == 0)
	set_command_prot(level);
    else
	goto usage;
    code = 0;
    return;
 usage:
    printf("usage: %s [command|data] [clear|safe|confidential|private]\n",
	   argv[0]);
    code = -1;
}
#endif

void
sec_set_protection_level(struct connectdata *conn)
{
  if(conn->sec_complete && conn->data_prot != conn->request_data_prot)
    sec_prot_internal(conn, conn->request_data_prot);
}


int
sec_request_prot(struct connectdata *conn, char *level)
{
  int l = name_to_level(level);
  if(l == -1)
    return -1;
  conn->request_data_prot = (enum protection_level)l;
  return 0;
}

int
sec_login(struct connectdata *conn)
{
    int ret;
    struct sec_client_mech **m;
    size_t nread;
    struct UrlData *data=conn->data;

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
	/*ret = command("AUTH %s", (*m)->name);***/
	Curl_ftpsendf(conn->firstsocket, conn,
                 "AUTH %s", (*m)->name);
	/* wait for feedback */
	nread = Curl_GetFTPResponse(conn->firstsocket,
                                    conn->data->buffer, conn, NULL);
	if(nread < 0)
	    return /*CURLE_OPERATION_TIMEOUTED*/-1;
	if(/*ret != CONTINUE*/conn->data->buffer[0] != '3'){
	    if(/*code == 504*/strncmp(conn->data->buffer,"504",3) == 0) {
		infof(data,
                      "%s is not supported by the server.\n", (*m)->name);
	    }
            else if(/*code == 534*/strncmp(conn->data->buffer,"534",3) == 0) {
              infof(data, "%s rejected as security mechanism.\n", (*m)->name);
	    }
            else if(/*ret == ERROR*/conn->data->buffer[0] == '5') {
              infof(data, "The server doesn't support the FTP "
                    "security extensions.\n");
              return -1;
	    }
	    continue;
	}

	ret = (*(*m)->auth)(conn->app_data, /*host***/conn);
	
	if(ret == AUTH_CONTINUE)
          continue;
	else if(ret != AUTH_OK){
          /* mechanism is supposed to output error string */
	    return -1;
	}
	mech = *m;
	conn->sec_complete = 1;
	conn->command_prot = prot_safe;
	break;
    }
    
    return *m == NULL;
}

void
sec_end(struct connectdata *conn)
{
    if (mech != NULL) {
	if(mech->end)
	    (*mech->end)(conn->app_data);
	memset(conn->app_data, 0, mech->size);
	free(conn->app_data);
	conn->app_data = NULL;
    }
    conn->sec_complete = 0;
    conn->data_prot = (enum protection_level)0;
}

#endif /* FTP_SERVER */

#endif /* KRB4 */
