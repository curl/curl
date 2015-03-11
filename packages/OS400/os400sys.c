/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) 1998 - 2014, Daniel Stenberg, <daniel@haxx.se>, et al.
 *
 * This software is licensed as described in the file COPYING, which
 * you should have received as part of this distribution. The terms
 * are also available at http://curl.haxx.se/docs/copyright.html.
 *
 * You may opt to use, copy, modify, merge, publish, distribute and/or sell
 * copies of the Software, and permit persons to whom the Software is
 * furnished to do so, under the terms of the COPYING file.
 *
 * This software is distributed on an "AS IS" basis, WITHOUT WARRANTY OF ANY
 * KIND, either express or implied.
 *
 *
 ***************************************************************************/

/* OS/400 additional support. */

#include "curlbuild.h"
#include "config-os400.h"  /* Not curl_setup.h: we only need some defines. */

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>

#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#include <pthread.h>
#include <netdb.h>
#include <qadrt.h>
#include <errno.h>

#ifdef HAVE_ZLIB_H
#include <zlib.h>
#endif

#ifdef USE_GSKIT
#include <gskssl.h>
#include <qsoasync.h>
#endif

#ifdef HAVE_GSSAPI
#include <gssapi.h>
#endif

#ifndef CURL_DISABLE_LDAP
#include <ldap.h>
#endif

#include <netinet/in.h>
#include <arpa/inet.h>

#include "os400sys.h"


/**
***     QADRT OS/400 ASCII runtime defines only the most used procedures, but
***             but a lot of them are not supported. This module implements
***             ASCII wrappers for those that are used by libcurl, but not
***             defined by QADRT.
**/

#pragma convert(0)                              /* Restore EBCDIC. */


#define MIN_BYTE_GAIN   1024    /* Minimum gain when shortening a buffer. */

typedef struct {
        unsigned long   size;                   /* Buffer size. */
        char *          buf;                    /* Buffer address. */
}               buffer_t;


static char *   buffer_undef(localkey_t key, long size);
static char *   buffer_threaded(localkey_t key, long size);
static char *   buffer_unthreaded(localkey_t key, long size);

static pthread_mutex_t  mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_key_t    thdkey;
static buffer_t *       locbufs;

char *  (* Curl_thread_buffer)(localkey_t key, long size) = buffer_undef;


static void
thdbufdestroy(void * private)

{
  if(private) {
    buffer_t * p = (buffer_t *) private;
    localkey_t i;

    for(i = (localkey_t) 0; i < LK_LAST; i++) {
      free(p->buf);
      p++;
      }

    free(private);
    }
}


static void
terminate(void)

{
  if(Curl_thread_buffer == buffer_threaded) {
    locbufs = pthread_getspecific(thdkey);
    pthread_setspecific(thdkey, (void *) NULL);
    pthread_key_delete(thdkey);
    }

  if(Curl_thread_buffer != buffer_undef) {
    thdbufdestroy((void *) locbufs);
    locbufs = (buffer_t *) NULL;
    }

  Curl_thread_buffer = buffer_undef;
}


static char *
get_buffer(buffer_t * buf, long size)

{
  char * cp;

  /* If `size' >= 0, make sure buffer at `buf' is at least `size'-byte long.
     Return the buffer address. */

  if(size < 0)
    return buf->buf;

  if(!buf->buf) {
    if((buf->buf = malloc(size)))
      buf->size = size;

    return buf->buf;
    }

  if((unsigned long) size <= buf->size) {
    /* Shorten the buffer only if it frees a significant byte count. This
       avoids some realloc() overhead. */

    if(buf->size - size < MIN_BYTE_GAIN)
      return buf->buf;
    }

  /* Resize the buffer. */

  if((cp = realloc(buf->buf, size))) {
    buf->buf = cp;
    buf->size = size;
    }
  else if(size <= buf->size)
    cp = buf->buf;

  return cp;
}


static char *
buffer_unthreaded(localkey_t key, long size)

{
  return get_buffer(locbufs + key, size);
}


static char *
buffer_threaded(localkey_t key, long size)

{
  buffer_t * bufs;

  /* Get the buffer for the given local key in the current thread, and
     make sure it is at least `size'-byte long. Set `size' to < 0 to get
     its address only. */

  bufs = (buffer_t *) pthread_getspecific(thdkey);

  if(!bufs) {
    if(size < 0)
      return (char *) NULL;             /* No buffer yet. */

    /* Allocate buffer descriptors for the current thread. */

    if(!(bufs = calloc((size_t) LK_LAST, sizeof *bufs)))
      return (char *) NULL;

    if(pthread_setspecific(thdkey, (void *) bufs)) {
      free(bufs);
      return (char *) NULL;
      }
    }

  return get_buffer(bufs + key, size);
}


static char *
buffer_undef(localkey_t key, long size)

{
  /* Define the buffer system, get the buffer for the given local key in
     the current thread, and make sure it is at least `size'-byte long.
     Set `size' to < 0 to get its address only. */

  pthread_mutex_lock(&mutex);

  /* Determine if we can use pthread-specific data. */

  if(Curl_thread_buffer == buffer_undef) {      /* If unchanged during lock. */
    if(!pthread_key_create(&thdkey, thdbufdestroy))
      Curl_thread_buffer = buffer_threaded;
    else if(!(locbufs = calloc((size_t) LK_LAST, sizeof *locbufs))) {
      pthread_mutex_unlock(&mutex);
      return (char *) NULL;
      }
    else
        Curl_thread_buffer = buffer_unthreaded;

    atexit(terminate);
    }

  pthread_mutex_unlock(&mutex);
  return Curl_thread_buffer(key, size);
}


static char *
set_thread_string(localkey_t key, const char * s)

{
  int i;
  char * cp;

  if(!s)
    return (char *) NULL;

  i = strlen(s) + 1;
  cp = Curl_thread_buffer(key, MAX_CONV_EXPANSION * i + 1);

  if(cp) {
    i = QadrtConvertE2A(cp, s, MAX_CONV_EXPANSION * i, i);
    cp[i] = '\0';
  }

  return cp;
}


int
Curl_getnameinfo_a(const struct sockaddr * sa, curl_socklen_t salen,
              char * nodename, curl_socklen_t nodenamelen,
              char * servname, curl_socklen_t servnamelen,
              int flags)

{
  char * enodename;
  char * eservname;
  int status;
  int i;

  enodename = (char *) NULL;
  eservname = (char *) NULL;

  if(nodename && nodenamelen)
    if(!(enodename = malloc(nodenamelen)))
      return EAI_MEMORY;

  if(servname && servnamelen)
    if(!(eservname = malloc(servnamelen))) {
      free(enodename);
      return EAI_MEMORY;
      }

  status = getnameinfo(sa, salen, enodename, nodenamelen,
                       eservname, servnamelen, flags);

  if(!status) {
    if(enodename) {
      i = QadrtConvertE2A(nodename, enodename,
        nodenamelen - 1, strlen(enodename));
      nodename[i] = '\0';
      }

    if(eservname) {
      i = QadrtConvertE2A(servname, eservname,
        servnamelen - 1, strlen(eservname));
      servname[i] = '\0';
      }
    }

  free(enodename);
  free(eservname);
  return status;
}


int
Curl_getaddrinfo_a(const char * nodename, const char * servname,
            const struct addrinfo * hints,
            struct addrinfo * * res)

{
  char * enodename;
  char * eservname;
  int status;
  int i;

  enodename = (char *) NULL;
  eservname = (char *) NULL;

  if(nodename) {
    i = strlen(nodename);

    if(!(enodename = malloc(i + 1)))
      return EAI_MEMORY;

    i = QadrtConvertA2E(enodename, nodename, i, i);
    enodename[i] = '\0';
    }

  if(servname) {
    i = strlen(servname);

    if(!(eservname = malloc(i + 1))) {
      free(enodename);
      return EAI_MEMORY;
      }

    QadrtConvertA2E(eservname, servname, i, i);
    eservname[i] = '\0';
    }

  status = getaddrinfo(enodename, eservname, hints, res);
  free(enodename);
  free(eservname);
  return status;
}


#ifdef USE_GSKIT

/* ASCII wrappers for the GSKit procedures. */

/*
 * EBCDIC --> ASCII string mapping table.
 * Some strings returned by GSKit are dynamically allocated and automatically
 * released when closing the handle.
 * To provide the same functionality, we use a "private" handle that
 * holds the GSKit handle and a list of string mappings. This will allow
 * avoid conversion of already converted strings and releasing them upon
 * close time.
 */

struct gskstrlist {
  struct gskstrlist * next;
  const char * ebcdicstr;
  const char * asciistr;
};

struct Curl_gsk_descriptor {
  gsk_handle h;
  struct gskstrlist * strlist;
};


int
Curl_gsk_environment_open(gsk_handle * my_env_handle)

{
  struct Curl_gsk_descriptor * p;
  gsk_handle h;
  int rc;

  if(!my_env_handle)
    return GSK_OS400_ERROR_INVALID_POINTER;
  if(!(p = (struct Curl_gsk_descriptor *) malloc(sizeof *p)))
    return GSK_INSUFFICIENT_STORAGE;
  p->strlist = (struct gskstrlist *) NULL;
  if((rc = gsk_environment_open(&p->h)) != GSK_OK)
    free(p);
  else
    *my_env_handle = (gsk_handle) p;
  return rc;
}


int
Curl_gsk_secure_soc_open(gsk_handle my_env_handle,
                         gsk_handle * my_session_handle)

{
  struct Curl_gsk_descriptor * p;
  gsk_handle h;
  int rc;

  if(!my_env_handle)
    return GSK_INVALID_HANDLE;
  if(!my_session_handle)
    return GSK_OS400_ERROR_INVALID_POINTER;
  h = ((struct Curl_gsk_descriptor *) my_env_handle)->h;
  if(!(p = (struct Curl_gsk_descriptor *) malloc(sizeof *p)))
    return GSK_INSUFFICIENT_STORAGE;
  p->strlist = (struct gskstrlist *) NULL;
  if((rc = gsk_secure_soc_open(h, &p->h)) != GSK_OK)
    free(p);
  else
    *my_session_handle = (gsk_handle) p;
  return rc;
}


static void
gsk_free_handle(struct Curl_gsk_descriptor * p)

{
  struct gskstrlist * q;

  while((q = p->strlist)) {
    p->strlist = q;
    free((void *) q->asciistr);
    free(q);
  }
  free(p);
}


int
Curl_gsk_environment_close(gsk_handle * my_env_handle)

{
  struct Curl_gsk_descriptor * p;
  int rc;

  if(!my_env_handle)
    return GSK_OS400_ERROR_INVALID_POINTER;
  if(!*my_env_handle)
    return GSK_INVALID_HANDLE;
  p = (struct Curl_gsk_descriptor *) *my_env_handle;
  if((rc = gsk_environment_close(&p->h)) == GSK_OK) {
    gsk_free_handle(p);
    *my_env_handle = (gsk_handle) NULL;
  }
  return rc;
}


int
Curl_gsk_secure_soc_close(gsk_handle * my_session_handle)

{
  struct Curl_gsk_descriptor * p;
  int rc;

  if(!my_session_handle)
    return GSK_OS400_ERROR_INVALID_POINTER;
  if(!*my_session_handle)
    return GSK_INVALID_HANDLE;
  p = (struct Curl_gsk_descriptor *) *my_session_handle;
  if((rc = gsk_secure_soc_close(&p->h)) == GSK_OK) {
    gsk_free_handle(p);
    *my_session_handle = (gsk_handle) NULL;
  }
  return rc;
}


int
Curl_gsk_environment_init(gsk_handle my_env_handle)

{
  struct Curl_gsk_descriptor * p;

  if(!my_env_handle)
    return GSK_INVALID_HANDLE;
  p = (struct Curl_gsk_descriptor *) my_env_handle;
  return gsk_environment_init(p->h);
}


int
Curl_gsk_secure_soc_init(gsk_handle my_session_handle)

{
  struct Curl_gsk_descriptor * p;

  if(!my_session_handle)
    return GSK_INVALID_HANDLE;
  p = (struct Curl_gsk_descriptor *) my_session_handle;
  return gsk_secure_soc_init(p->h);
}


int
Curl_gsk_attribute_set_buffer_a(gsk_handle my_gsk_handle, GSK_BUF_ID bufID,
                                const char * buffer, int bufSize)

{
  struct Curl_gsk_descriptor * p;
  char * ebcdicbuf;
  int rc;

  if(!my_gsk_handle)
    return GSK_INVALID_HANDLE;
  if(!buffer)
    return GSK_OS400_ERROR_INVALID_POINTER;
  if(bufSize < 0)
    return GSK_ATTRIBUTE_INVALID_LENGTH;
  p = (struct Curl_gsk_descriptor *) my_gsk_handle;
  if(!bufSize)
    bufSize = strlen(buffer);
  if(!(ebcdicbuf = malloc(bufSize + 1)))
      return GSK_INSUFFICIENT_STORAGE;
  QadrtConvertA2E(ebcdicbuf, buffer, bufSize, bufSize);
  ebcdicbuf[bufSize] = '\0';
  rc = gsk_attribute_set_buffer(p->h, bufID, ebcdicbuf, bufSize);
  free(ebcdicbuf);
  return rc;
}


int
Curl_gsk_attribute_set_enum(gsk_handle my_gsk_handle, GSK_ENUM_ID enumID,
                            GSK_ENUM_VALUE enumValue)

{
  struct Curl_gsk_descriptor * p;

  if(!my_gsk_handle)
    return GSK_INVALID_HANDLE;
  p = (struct Curl_gsk_descriptor *) my_gsk_handle;
  return gsk_attribute_set_enum(p->h, enumID, enumValue);
}


int
Curl_gsk_attribute_set_numeric_value(gsk_handle my_gsk_handle,
                                     GSK_NUM_ID numID, int numValue)

{
  struct Curl_gsk_descriptor * p;

  if(!my_gsk_handle)
    return GSK_INVALID_HANDLE;
  p = (struct Curl_gsk_descriptor *) my_gsk_handle;
  return gsk_attribute_set_numeric_value(p->h, numID, numValue);
}


int
Curl_gsk_attribute_set_callback(gsk_handle my_gsk_handle,
                                GSK_CALLBACK_ID callBackID,
                                void * callBackAreaPtr)

{
  struct Curl_gsk_descriptor * p;

  if(!my_gsk_handle)
    return GSK_INVALID_HANDLE;
  p = (struct Curl_gsk_descriptor *) my_gsk_handle;
  return gsk_attribute_set_callback(p->h, callBackID, callBackAreaPtr);
}


static int
cachestring(struct Curl_gsk_descriptor * p,
            const char * ebcdicbuf, int bufsize, const char * * buffer)

{
  int rc;
  char * asciibuf;
  struct gskstrlist * sp;

  for(sp = p->strlist; sp; sp = sp->next)
    if(sp->ebcdicstr == ebcdicbuf)
      break;
  if(!sp) {
    if(!(sp = (struct gskstrlist *) malloc(sizeof *sp)))
      return GSK_INSUFFICIENT_STORAGE;
    if(!(asciibuf = malloc(bufsize + 1))) {
      free(sp);
      return GSK_INSUFFICIENT_STORAGE;
    }
    QadrtConvertE2A(asciibuf, ebcdicbuf, bufsize, bufsize);
    asciibuf[bufsize] = '\0';
    sp->ebcdicstr = ebcdicbuf;
    sp->asciistr = asciibuf;
    sp->next = p->strlist;
    p->strlist = sp;
  }
  *buffer = sp->asciistr;
  return GSK_OK;
}


int
Curl_gsk_attribute_get_buffer_a(gsk_handle my_gsk_handle, GSK_BUF_ID bufID,
                                const char * * buffer, int * bufSize)

{
  struct Curl_gsk_descriptor * p;
  int rc;
  const char * mybuf;
  int mylen;

  if(!my_gsk_handle)
    return GSK_INVALID_HANDLE;
  if(!buffer || !bufSize)
    return GSK_OS400_ERROR_INVALID_POINTER;
  p = (struct Curl_gsk_descriptor *) my_gsk_handle;
  if((rc = gsk_attribute_get_buffer(p->h, bufID, &mybuf, &mylen)) != GSK_OK)
    return rc;
  if((rc = cachestring(p, mybuf, mylen, buffer)) == GSK_OK)
    *bufSize = mylen;
  return rc;
}


int
Curl_gsk_attribute_get_enum(gsk_handle my_gsk_handle, GSK_ENUM_ID enumID,
                            GSK_ENUM_VALUE * enumValue)

{
  struct Curl_gsk_descriptor * p;

  if(!my_gsk_handle)
    return GSK_INVALID_HANDLE;
  p = (struct Curl_gsk_descriptor *) my_gsk_handle;
  return gsk_attribute_get_enum(p->h, enumID, enumValue);
}


int
Curl_gsk_attribute_get_numeric_value(gsk_handle my_gsk_handle,
                                     GSK_NUM_ID numID, int * numValue)

{
  struct Curl_gsk_descriptor * p;

  if(!my_gsk_handle)
    return GSK_INVALID_HANDLE;
  p = (struct Curl_gsk_descriptor *) my_gsk_handle;
  return gsk_attribute_get_numeric_value(p->h, numID, numValue);
}


int
Curl_gsk_attribute_get_cert_info(gsk_handle my_gsk_handle,
                                 GSK_CERT_ID certID,
                                 const gsk_cert_data_elem * * certDataElem,
                                 int * certDataElementCount)

{
  struct Curl_gsk_descriptor * p;

  if(!my_gsk_handle)
    return GSK_INVALID_HANDLE;
  p = (struct Curl_gsk_descriptor *) my_gsk_handle;
  /* No need to convert code: text results are already in ASCII. */
  return gsk_attribute_get_cert_info(p->h, certID,
                                     certDataElem, certDataElementCount);
}


int
Curl_gsk_secure_soc_misc(gsk_handle my_session_handle, GSK_MISC_ID miscID)

{
  struct Curl_gsk_descriptor * p;

  if(!my_session_handle)
    return GSK_INVALID_HANDLE;
  p = (struct Curl_gsk_descriptor *) my_session_handle;
  return gsk_secure_soc_misc(p->h, miscID);
}


int
Curl_gsk_secure_soc_read(gsk_handle my_session_handle, char * readBuffer,
                         int readBufSize, int * amtRead)

{
  struct Curl_gsk_descriptor * p;

  if(!my_session_handle)
    return GSK_INVALID_HANDLE;
  p = (struct Curl_gsk_descriptor *) my_session_handle;
  return gsk_secure_soc_read(p->h, readBuffer, readBufSize, amtRead);
}


int
Curl_gsk_secure_soc_write(gsk_handle my_session_handle, char * writeBuffer,
                          int writeBufSize, int * amtWritten)

{
  struct Curl_gsk_descriptor * p;

  if(!my_session_handle)
    return GSK_INVALID_HANDLE;
  p = (struct Curl_gsk_descriptor *) my_session_handle;
  return gsk_secure_soc_write(p->h, writeBuffer, writeBufSize, amtWritten);
}


const char *
Curl_gsk_strerror_a(int gsk_return_value)

{
  return set_thread_string(LK_GSK_ERROR, gsk_strerror(gsk_return_value));
}

int
Curl_gsk_secure_soc_startInit(gsk_handle my_session_handle,
                              int IOCompletionPort,
                              Qso_OverlappedIO_t * communicationsArea)

{
  struct Curl_gsk_descriptor * p;

  if(!my_session_handle)
    return GSK_INVALID_HANDLE;
  p = (struct Curl_gsk_descriptor *) my_session_handle;
  return gsk_secure_soc_startInit(p->h, IOCompletionPort, communicationsArea);
}

#endif /* USE_GSKIT */



#ifdef HAVE_GSSAPI

/* ASCII wrappers for the GSSAPI procedures. */

static int
Curl_gss_convert_in_place(OM_uint32 * minor_status, gss_buffer_t buf)

{
  unsigned int i;
  char * t;

  /* Convert `buf' in place, from EBCDIC to ASCII.
     If error, release the buffer and return -1. Else return 0. */

  i = buf->length;

  if(i) {
    if(!(t = malloc(i))) {
      gss_release_buffer(minor_status, buf);

      if(minor_status)
        *minor_status = ENOMEM;

      return -1;
      }

    QadrtConvertE2A(t, buf->value, i, i);
    memcpy(buf->value, t, i);
    free(t);
    }

  return 0;
}


OM_uint32
Curl_gss_import_name_a(OM_uint32 * minor_status, gss_buffer_t in_name,
                       gss_OID in_name_type, gss_name_t * out_name)

{
  int rc;
  unsigned int i;
  gss_buffer_desc in;

  if(!in_name || !in_name->value || !in_name->length)
    return gss_import_name(minor_status, in_name, in_name_type, out_name);

  memcpy((char *) &in, (char *) in_name, sizeof in);
  i = in.length;

  if(!(in.value = malloc(i + 1))) {
    if(minor_status)
      *minor_status = ENOMEM;

    return GSS_S_FAILURE;
    }

  QadrtConvertA2E(in.value, in_name->value, i, i);
  ((char *) in.value)[i] = '\0';
  rc = gss_import_name(minor_status, &in, in_name_type, out_name);
  free(in.value);
  return rc;
}


OM_uint32
Curl_gss_display_status_a(OM_uint32 * minor_status, OM_uint32 status_value,
                   int status_type, gss_OID mech_type,
                   gss_msg_ctx_t * message_context, gss_buffer_t status_string)

{
  int rc;

  rc = gss_display_status(minor_status, status_value, status_type,
                              mech_type, message_context, status_string);

  if(rc != GSS_S_COMPLETE || !status_string ||
     !status_string->length || !status_string->value)
    return rc;

  /* No way to allocate a buffer here, because it will be released by
     gss_release_buffer(). The solution is to overwrite the EBCDIC buffer
     with ASCII to return it. */

  if(Curl_gss_convert_in_place(minor_status, status_string))
    return GSS_S_FAILURE;

  return rc;
}


OM_uint32
Curl_gss_init_sec_context_a(OM_uint32 * minor_status,
                            gss_cred_id_t cred_handle,
                            gss_ctx_id_t * context_handle,
                            gss_name_t target_name, gss_OID mech_type,
                            gss_flags_t req_flags, OM_uint32 time_req,
                            gss_channel_bindings_t input_chan_bindings,
                            gss_buffer_t input_token,
                            gss_OID * actual_mech_type,
                            gss_buffer_t output_token, gss_flags_t * ret_flags,
                            OM_uint32 * time_rec)

{
  int rc;
  unsigned int i;
  gss_buffer_desc in;
  gss_buffer_t inp;

  in.value = NULL;

  if((inp = input_token))
    if(inp->length && inp->value) {
      i = inp->length;

      if(!(in.value = malloc(i + 1))) {
        if(minor_status)
          *minor_status = ENOMEM;

        return GSS_S_FAILURE;
        }

      QadrtConvertA2E(in.value, input_token->value, i, i);
      ((char *) in.value)[i] = '\0';
      in.length = i;
      inp = &in;
      }

  rc = gss_init_sec_context(minor_status, cred_handle, context_handle,
                             target_name, mech_type, req_flags, time_req,
                             input_chan_bindings, inp, actual_mech_type,
                             output_token, ret_flags, time_rec);
  free(in.value);

  if(rc != GSS_S_COMPLETE || !output_token ||
      !output_token->length || !output_token->value)
    return rc;

  /* No way to allocate a buffer here, because it will be released by
     gss_release_buffer(). The solution is to overwrite the EBCDIC buffer
     with ASCII to return it. */

  if(Curl_gss_convert_in_place(minor_status, output_token))
    return GSS_S_FAILURE;

  return rc;
}


OM_uint32
Curl_gss_delete_sec_context_a(OM_uint32 * minor_status,
                              gss_ctx_id_t * context_handle,
                              gss_buffer_t output_token)

{
  int rc;

  rc = gss_delete_sec_context(minor_status, context_handle, output_token);

  if(rc != GSS_S_COMPLETE || !output_token ||
      !output_token->length || !output_token->value)
    return rc;

  /* No way to allocate a buffer here, because it will be released by
     gss_release_buffer(). The solution is to overwrite the EBCDIC buffer
     with ASCII to return it. */

  if(Curl_gss_convert_in_place(minor_status, output_token))
    return GSS_S_FAILURE;

  return rc;
}

#endif /* HAVE_GSSAPI */


#ifndef CURL_DISABLE_LDAP

/* ASCII wrappers for the LDAP procedures. */

void *
Curl_ldap_init_a(char * host, int port)

{
  unsigned int i;
  char * ehost;
  void * result;

  if(!host)
    return (void *) ldap_init(host, port);

  i = strlen(host);

  if(!(ehost = malloc(i + 1)))
    return (void *) NULL;

  QadrtConvertA2E(ehost, host, i, i);
  ehost[i] = '\0';
  result = (void *) ldap_init(ehost, port);
  free(ehost);
  return result;
}


int
Curl_ldap_simple_bind_s_a(void * ld, char * dn, char * passwd)

{
  int i;
  char * edn;
  char * epasswd;

  edn = (char *) NULL;
  epasswd = (char *) NULL;

  if(dn) {
    i = strlen(dn);

    if(!(edn = malloc(i + 1)))
      return LDAP_NO_MEMORY;

    QadrtConvertA2E(edn, dn, i, i);
    edn[i] = '\0';
    }

  if(passwd) {
    i = strlen(passwd);

    if(!(epasswd = malloc(i + 1))) {
      free(edn);
      return LDAP_NO_MEMORY;
      }

    QadrtConvertA2E(epasswd, passwd, i, i);
    epasswd[i] = '\0';
    }

  i = ldap_simple_bind_s(ld, edn, epasswd);
  free(epasswd);
  free(edn);
  return i;
}


int
Curl_ldap_search_s_a(void * ld, char * base, int scope, char * filter,
                     char * * attrs, int attrsonly, LDAPMessage * * res)

{
  int i;
  int j;
  char * ebase;
  char * efilter;
  char * * eattrs;
  int status;

  ebase = (char *) NULL;
  efilter = (char *) NULL;
  eattrs = (char * *) NULL;
  status = LDAP_SUCCESS;

  if(base) {
    i = strlen(base);

    if(!(ebase = malloc(i + 1)))
      status = LDAP_NO_MEMORY;
    else {
      QadrtConvertA2E(ebase, base, i, i);
      ebase[i] = '\0';
      }
    }

  if(filter && status == LDAP_SUCCESS) {
    i = strlen(filter);

    if(!(efilter = malloc(i + 1)))
      status = LDAP_NO_MEMORY;
    else {
      QadrtConvertA2E(efilter, filter, i, i);
      efilter[i] = '\0';
      }
    }

  if(attrs && status == LDAP_SUCCESS) {
    for(i = 0; attrs[i++];)
      ;

    if(!(eattrs = calloc(i, sizeof *eattrs)))
      status = LDAP_NO_MEMORY;
    else {
      for(j = 0; attrs[j]; j++) {
        i = strlen(attrs[j]);

        if(!(eattrs[j] = malloc(i + 1))) {
          status = LDAP_NO_MEMORY;
          break;
          }

        QadrtConvertA2E(eattrs[j], attrs[j], i, i);
        eattrs[j][i] = '\0';
        }
      }
    }

  if(status == LDAP_SUCCESS)
    status = ldap_search_s(ld, ebase? ebase: "", scope,
                           efilter? efilter: "(objectclass=*)",
                           eattrs, attrsonly, res);

  if(eattrs) {
    for(j = 0; eattrs[j]; j++)
      free(eattrs[j]);

    free(eattrs);
    }

  free(efilter);
  free(ebase);
  return status;
}


struct berval * *
Curl_ldap_get_values_len_a(void * ld, LDAPMessage * entry, const char * attr)

{
  char * cp;
  struct berval * * result;

  cp = (char *) NULL;

  if(attr) {
    int i = strlen(attr);

    if(!(cp = malloc(i + 1))) {
      ldap_set_lderrno(ld, LDAP_NO_MEMORY, NULL,
                       ldap_err2string(LDAP_NO_MEMORY));
      return (struct berval * *) NULL;
      }

    QadrtConvertA2E(cp, attr, i, i);
    cp[i] = '\0';
    }

  result = ldap_get_values_len(ld, entry, cp);
  free(cp);

  /* Result data are binary in nature, so they haven't been
     converted to EBCDIC. Therefore do not convert. */

  return result;
}


char *
Curl_ldap_err2string_a(int error)

{
  return set_thread_string(LK_LDAP_ERROR, ldap_err2string(error));
}


char *
Curl_ldap_get_dn_a(void * ld, LDAPMessage * entry)

{
  int i;
  char * cp;
  char * cp2;

  cp = ldap_get_dn(ld, entry);

  if(!cp)
    return cp;

  i = strlen(cp);

  if(!(cp2 = malloc(i + 1)))
    return cp2;

  QadrtConvertE2A(cp2, cp, i, i);
  cp2[i] = '\0';

  /* No way to allocate a buffer here, because it will be released by
     ldap_memfree() and ldap_memalloc() does not exist. The solution is to
     overwrite the EBCDIC buffer with ASCII to return it. */

  strcpy(cp, cp2);
  free(cp2);
  return cp;
}


char *
Curl_ldap_first_attribute_a(void * ld,
                            LDAPMessage * entry, BerElement * * berptr)

{
  int i;
  char * cp;
  char * cp2;

  cp = ldap_first_attribute(ld, entry, berptr);

  if(!cp)
    return cp;

  i = strlen(cp);

  if(!(cp2 = malloc(i + 1)))
    return cp2;

  QadrtConvertE2A(cp2, cp, i, i);
  cp2[i] = '\0';

  /* No way to allocate a buffer here, because it will be released by
     ldap_memfree() and ldap_memalloc() does not exist. The solution is to
     overwrite the EBCDIC buffer with ASCII to return it. */

  strcpy(cp, cp2);
  free(cp2);
  return cp;
}


char *
Curl_ldap_next_attribute_a(void * ld,
                           LDAPMessage * entry, BerElement * berptr)

{
  int i;
  char * cp;
  char * cp2;

  cp = ldap_next_attribute(ld, entry, berptr);

  if(!cp)
    return cp;

  i = strlen(cp);

  if(!(cp2 = malloc(i + 1)))
    return cp2;

  QadrtConvertE2A(cp2, cp, i, i);
  cp2[i] = '\0';

  /* No way to allocate a buffer here, because it will be released by
     ldap_memfree() and ldap_memalloc() does not exist. The solution is to
     overwrite the EBCDIC buffer with ASCII to return it. */

  strcpy(cp, cp2);
  free(cp2);
  return cp;
}

#endif /* CURL_DISABLE_LDAP */


static int
convert_sockaddr(struct sockaddr_storage * dstaddr,
                                const struct sockaddr * srcaddr, int srclen)

{
  const struct sockaddr_un * srcu;
  struct sockaddr_un * dstu;
  unsigned int i;
  unsigned int dstsize;

  /* Convert a socket address into job CCSID, if needed. */

  if(!srcaddr || srclen < offsetof(struct sockaddr, sa_family) +
     sizeof srcaddr->sa_family || srclen > sizeof *dstaddr) {
    errno = EINVAL;
    return -1;
    }

  memcpy((char *) dstaddr, (char *) srcaddr, srclen);

  switch (srcaddr->sa_family) {

  case AF_UNIX:
    srcu = (const struct sockaddr_un *) srcaddr;
    dstu = (struct sockaddr_un *) dstaddr;
    dstsize = sizeof *dstaddr - offsetof(struct sockaddr_un, sun_path);
    srclen -= offsetof(struct sockaddr_un, sun_path);
    i = QadrtConvertA2E(dstu->sun_path, srcu->sun_path, dstsize - 1, srclen);
    dstu->sun_path[i] = '\0';
    i += offsetof(struct sockaddr_un, sun_path);
    srclen = i;
    }

  return srclen;
}


int
Curl_os400_connect(int sd, struct sockaddr * destaddr, int addrlen)

{
  int i;
  struct sockaddr_storage laddr;

  i = convert_sockaddr(&laddr, destaddr, addrlen);

  if(i < 0)
    return -1;

  return connect(sd, (struct sockaddr *) &laddr, i);
}


int
Curl_os400_bind(int sd, struct sockaddr * localaddr, int addrlen)

{
  int i;
  struct sockaddr_storage laddr;

  i = convert_sockaddr(&laddr, localaddr, addrlen);

  if(i < 0)
    return -1;

  return bind(sd, (struct sockaddr *) &laddr, i);
}


int
Curl_os400_sendto(int sd, char * buffer, int buflen, int flags,
                                struct sockaddr * dstaddr, int addrlen)

{
  int i;
  struct sockaddr_storage laddr;

  i = convert_sockaddr(&laddr, dstaddr, addrlen);

  if(i < 0)
    return -1;

  return sendto(sd, buffer, buflen, flags, (struct sockaddr *) &laddr, i);
}


int
Curl_os400_recvfrom(int sd, char * buffer, int buflen, int flags,
                                struct sockaddr * fromaddr, int * addrlen)

{
  int i;
  int rcvlen;
  int laddrlen;
  const struct sockaddr_un * srcu;
  struct sockaddr_un * dstu;
  struct sockaddr_storage laddr;

  if(!fromaddr || !addrlen || *addrlen <= 0)
    return recvfrom(sd, buffer, buflen, flags, fromaddr, addrlen);

  laddrlen = sizeof laddr;
  laddr.ss_family = AF_UNSPEC;          /* To detect if unused. */
  rcvlen = recvfrom(sd, buffer, buflen, flags,
                    (struct sockaddr *) &laddr, &laddrlen);

  if(rcvlen < 0)
    return rcvlen;

  switch (laddr.ss_family) {

  case AF_UNIX:
    srcu = (const struct sockaddr_un *) &laddr;
    dstu = (struct sockaddr_un *) fromaddr;
    i = *addrlen - offsetof(struct sockaddr_un, sun_path);
    laddrlen -= offsetof(struct sockaddr_un, sun_path);
    i = QadrtConvertE2A(dstu->sun_path, srcu->sun_path, i, laddrlen);
    laddrlen = i + offsetof(struct sockaddr_un, sun_path);

    if(laddrlen < *addrlen)
      dstu->sun_path[i] = '\0';

    break;

  case AF_UNSPEC:
    break;

  default:
    if(laddrlen > *addrlen)
      laddrlen = *addrlen;

    if(laddrlen)
      memcpy((char *) fromaddr, (char *) &laddr, laddrlen);

    break;
    }

  *addrlen = laddrlen;
  return rcvlen;
}


#ifdef HAVE_LIBZ
const char *
Curl_os400_zlibVersion(void)

{
  return set_thread_string(LK_ZLIB_VERSION, zlibVersion());
}


int
Curl_os400_inflateInit_(z_streamp strm, const char * version, int stream_size)

{
  z_const char * msgb4 = strm->msg;
  int ret;

  ret = inflateInit(strm);

  if(strm->msg != msgb4)
    strm->msg = set_thread_string(LK_ZLIB_MSG, strm->msg);

  return ret;
}


int
Curl_os400_inflateInit2_(z_streamp strm, int windowBits,
                                        const char * version, int stream_size)

{
  z_const char * msgb4 = strm->msg;
  int ret;

  ret = inflateInit2(strm, windowBits);

  if(strm->msg != msgb4)
    strm->msg = set_thread_string(LK_ZLIB_MSG, strm->msg);

  return ret;
}


int
Curl_os400_inflate(z_streamp strm, int flush)

{
  z_const char * msgb4 = strm->msg;
  int ret;

  ret = inflate(strm, flush);

  if(strm->msg != msgb4)
    strm->msg = set_thread_string(LK_ZLIB_MSG, strm->msg);

  return ret;
}


int
Curl_os400_inflateEnd(z_streamp strm)

{
  z_const char * msgb4 = strm->msg;
  int ret;

  ret = inflateEnd(strm);

  if(strm->msg != msgb4)
    strm->msg = set_thread_string(LK_ZLIB_MSG, strm->msg);

  return ret;
}

#endif
