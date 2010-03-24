/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) 1998 - 2009, Daniel Stenberg, <daniel@haxx.se>, et al.
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
#include "config-os400.h"       /* Not setup.h: we only need some defines. */

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

#ifdef USE_QSOSSL
#include <qsossl.h>
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
  localkey_t i;
  buffer_t * p;

  if (private) {
    p = (buffer_t *) private;

    for (i = (localkey_t) 0; i < LK_LAST; i++) {
      if (p->buf)
        free(p->buf);

      p++;
      }

    free(private);
    }
}


static void
terminate(void)

{
  if (Curl_thread_buffer == buffer_threaded) {
    locbufs = pthread_getspecific(thdkey);
    pthread_setspecific(thdkey, (void *) NULL);
    pthread_key_delete(thdkey);
    }

  if (Curl_thread_buffer != buffer_undef) {
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

  if (size < 0)
    return buf->buf;

  if (!buf->buf) {
    if ((buf->buf = malloc(size)))
      buf->size = size;

    return buf->buf;
    }

  if ((unsigned long) size <= buf->size) {
    /* Shorten the buffer only if it frees a significant byte count. This
       avoids some realloc() overhead. */

    if (buf->size - size < MIN_BYTE_GAIN)
      return buf->buf;
    }

  /* Resize the buffer. */

  if ((cp = realloc(buf->buf, size))) {
    buf->buf = cp;
    buf->size = size;
    }
  else if (size <= buf->size)
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

  if (!bufs) {
    if (size < 0)
      return (char *) NULL;             /* No buffer yet. */

    /* Allocate buffer descriptors for the current thread. */

    if (!(bufs = calloc((size_t) LK_LAST, sizeof *bufs)))
      return (char *) NULL;

    if (pthread_setspecific(thdkey, (void *) bufs)) {
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

  if (Curl_thread_buffer == buffer_undef) {     /* If unchanged during lock. */
    if (!pthread_key_create(&thdkey, thdbufdestroy))
      Curl_thread_buffer = buffer_threaded;
    else if (!(locbufs = calloc((size_t) LK_LAST,
                                             sizeof *locbufs))) {
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

  if (nodename && nodenamelen)
    if (!(enodename = malloc(nodenamelen)))
      return EAI_MEMORY;

  if (servname && servnamelen)
    if (!(eservname = malloc(servnamelen))) {
      if (enodename)
        free(enodename);

      return EAI_MEMORY;
      }

  status = getnameinfo(sa, salen, enodename, nodenamelen,
                       eservname, servnamelen, flags);

  if (!status) {
    if (enodename) {
      i = QadrtConvertE2A(nodename, enodename,
        nodenamelen - 1, strlen(enodename));
      nodename[i] = '\0';
      }

    if (eservname) {
      i = QadrtConvertE2A(servname, eservname,
        servnamelen - 1, strlen(eservname));
      servname[i] = '\0';
      }
    }

  if (enodename)
    free(enodename);

  if (eservname)
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

  if (nodename) {
    i = strlen(nodename);

    if (!(enodename = malloc(i + 1)))
      return EAI_MEMORY;

    i = QadrtConvertA2E(enodename, nodename, i, i);
    enodename[i] = '\0';
    }

  if (servname) {
    i = strlen(servname);

    if (!(eservname = malloc(i + 1))) {
      if (enodename)
        free(enodename);

      return EAI_MEMORY;
      }

    QadrtConvertA2E(eservname, servname, i, i);
    eservname[i] = '\0';
    }

  status = getaddrinfo(enodename, eservname, hints, res);

  if (enodename)
    free(enodename);

  if (eservname)
    free(eservname);

  return status;
}


#ifdef USE_QSOSSL

/* ASCII wrappers for the SSL procedures. */

int
Curl_SSL_Init_Application_a(SSLInitApp * init_app)

{
  int rc;
  unsigned int i;
  SSLInitApp ia;

  if (!init_app || !init_app->applicationID || !init_app->applicationIDLen)
    return SSL_Init_Application(init_app);

  memcpy((char *) &ia, (char *) init_app, sizeof ia);
  i = ia.applicationIDLen;

  if (!(ia.applicationID = malloc(i + 1))) {
    errno = ENOMEM;
    return SSL_ERROR_IO;
    }

  QadrtConvertA2E(ia.applicationID, init_app->applicationID, i, i);
  ia.applicationID[i] = '\0';
  rc = SSL_Init_Application(&ia);
  free(ia.applicationID);
  init_app->localCertificateLen = ia.localCertificateLen;
  init_app->sessionType = ia.sessionType;
  return rc;
}


int
Curl_SSL_Init_a(SSLInit * init)

{
  int rc;
  unsigned int i;
  SSLInit ia;

  if (!init || (!init->keyringFileName && !init->keyringPassword))
    return SSL_Init(init);

  memcpy((char *) &ia, (char *) init, sizeof ia);

  if (ia.keyringFileName) {
    i = strlen(ia.keyringFileName);

    if (!(ia.keyringFileName = malloc(i + 1))) {
      errno = ENOMEM;
      return SSL_ERROR_IO;
      }

    QadrtConvertA2E(ia.keyringFileName, init->keyringFileName, i, i);
    ia.keyringFileName[i] = '\0';
    }

  if (ia.keyringPassword) {
    i = strlen(ia.keyringPassword);

    if (!(ia.keyringPassword = malloc(i + 1))) {
      if (ia.keyringFileName)
        free(ia.keyringFileName);

      errno = ENOMEM;
      return SSL_ERROR_IO;
      }

    QadrtConvertA2E(ia.keyringPassword, init->keyringPassword, i, i);
    ia.keyringPassword[i] = '\0';
    }

  rc = SSL_Init(&ia);

  if (ia.keyringFileName)
    free(ia.keyringFileName);

  if (ia.keyringPassword)
    free(ia.keyringPassword);

  return rc;
}


char *
Curl_SSL_Strerror_a(int sslreturnvalue, SSLErrorMsg * serrmsgp)

{
  int i;
  char * cp;
  char * cp2;

  cp = SSL_Strerror(sslreturnvalue, serrmsgp);

  if (!cp)
    return cp;

  i = strlen(cp);

  if (!(cp2 = Curl_thread_buffer(LK_SSL_ERROR, MAX_CONV_EXPANSION * i + 1)))
    return cp2;

  i = QadrtConvertE2A(cp2, cp, MAX_CONV_EXPANSION * i, i);
  cp2[i] = '\0';
  return cp2;
}

#endif /* USE_QSOSSL */


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

  if (i) {
    if (!(t = malloc(i))) {
      gss_release_buffer(minor_status, buf);

      if (minor_status)
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

  if (!in_name || !in_name->value || !in_name->length)
    return gss_import_name(minor_status, in_name, in_name_type, out_name);

  memcpy((char *) &in, (char *) in_name, sizeof in);
  i = in.length;

  if (!(in.value = malloc(i + 1))) {
    if (minor_status)
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

  if (rc != GSS_S_COMPLETE || !status_string ||
      !status_string->length || !status_string->value)
    return rc;

  /* No way to allocate a buffer here, because it will be released by
     gss_release_buffer(). The solution is to overwrite the EBCDIC buffer
     with ASCII to return it. */

  if (Curl_gss_convert_in_place(minor_status, status_string))
    return GSS_S_FAILURE;

  return rc;
}


OM_uint32
Curl_gss_init_sec_context_a(OM_uint32 * minor_status, gss_cred_id_t cred_handle,
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

  if ((inp = input_token))
    if (inp->length && inp->value) {
      i = inp->length;

      if (!(in.value = malloc(i + 1))) {
        if (minor_status)
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

  if (in.value)
    free(in.value);

  if (rc != GSS_S_COMPLETE || !output_token ||
      !output_token->length || !output_token->value)
    return rc;

  /* No way to allocate a buffer here, because it will be released by
     gss_release_buffer(). The solution is to overwrite the EBCDIC buffer
     with ASCII to return it. */

  if (Curl_gss_convert_in_place(minor_status, output_token))
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

  if (rc != GSS_S_COMPLETE || !output_token ||
      !output_token->length || !output_token->value)
    return rc;

  /* No way to allocate a buffer here, because it will be released by
     gss_release_buffer(). The solution is to overwrite the EBCDIC buffer
     with ASCII to return it. */

  if (Curl_gss_convert_in_place(minor_status, output_token))
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

  if (!host)
    return (void *) ldap_init(host, port);

  i = strlen(host);

  if (!(ehost = malloc(i + 1)))
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

  if (dn) {
    i = strlen(dn);

    if (!(edn = malloc(i + 1)))
      return LDAP_NO_MEMORY;

    QadrtConvertA2E(edn, dn, i, i);
    edn[i] = '\0';
    }

  if (passwd) {
    i = strlen(passwd);

    if (!(epasswd = malloc(i + 1))) {
      if (edn)
        free(edn);

      return LDAP_NO_MEMORY;
      }

    QadrtConvertA2E(epasswd, passwd, i, i);
    epasswd[i] = '\0';
    }

  i = ldap_simple_bind_s(ld, edn, epasswd);

  if (epasswd)
    free(epasswd);

  if (edn)
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

  if (base) {
    i = strlen(base);

    if (!(ebase = malloc(i + 1)))
      status = LDAP_NO_MEMORY;
    else {
      QadrtConvertA2E(ebase, base, i, i);
      ebase[i] = '\0';
      }
    }

  if (filter && status == LDAP_SUCCESS) {
    i = strlen(filter);

    if (!(efilter = malloc(i + 1)))
      status = LDAP_NO_MEMORY;
    else {
      QadrtConvertA2E(efilter, filter, i, i);
      efilter[i] = '\0';
      }
    }

  if (attrs && status == LDAP_SUCCESS) {
    for (i = 0; attrs[i++];)
      ;

    if (!(eattrs = calloc(i, sizeof *eattrs)))
      status = LDAP_NO_MEMORY;
    else {
      for (j = 0; attrs[j]; j++) {
        i = strlen(attrs[j]);

        if (!(eattrs[j] = malloc(i + 1))) {
          status = LDAP_NO_MEMORY;
          break;
          }

        QadrtConvertA2E(eattrs[j], attrs[j], i, i);
        eattrs[j][i] = '\0';
        }
      }
    }

  if (status == LDAP_SUCCESS)
    status = ldap_search_s(ld, ebase? ebase: "", scope,
                           efilter? efilter: "(objectclass=*)",
                           eattrs, attrsonly, res);

  if (eattrs) {
    for (j = 0; eattrs[j]; j++)
      free(eattrs[j]);

    free(eattrs);
    }

  if (efilter)
    free(efilter);

  if (ebase)
    free(ebase);

  return status;
}


struct berval * *
Curl_ldap_get_values_len_a(void * ld, LDAPMessage * entry, const char * attr)

{
  int i;
  char * cp;
  struct berval * * result;

  cp = (char *) NULL;

  if (attr) {
    i = strlen(attr);

    if (!(cp = malloc(i + 1))) {
      ldap_set_lderrno(ld, LDAP_NO_MEMORY, NULL,
                       ldap_err2string(LDAP_NO_MEMORY));
      return (struct berval * *) NULL;
      }

    QadrtConvertA2E(cp, attr, i, i);
    cp[i] = '\0';
    }

  result = ldap_get_values_len(ld, entry, cp);

  if (cp)
    free(cp);

  /* Result data are binary in nature, so they haven't been converted to EBCDIC.
     Therefore do not convert. */

  return result;
}


char *
Curl_ldap_err2string_a(int error)

{
  int i;
  char * cp;
  char * cp2;

  cp = ldap_err2string(error);

  if (!cp)
    return cp;

  i = strlen(cp);

  if (!(cp2 = Curl_thread_buffer(LK_LDAP_ERROR, MAX_CONV_EXPANSION * i + 1)))
    return cp2;

  i = QadrtConvertE2A(cp2, cp, MAX_CONV_EXPANSION * i, i);
  cp2[i] = '\0';
  return cp2;
}


char *
Curl_ldap_get_dn_a(void * ld, LDAPMessage * entry)

{
  int i;
  char * cp;
  char * cp2;

  cp = ldap_get_dn(ld, entry);

  if (!cp)
    return cp;

  i = strlen(cp);

  if (!(cp2 = malloc(i + 1)))
    return cp2;

  QadrtConvertE2A(cp2, cp, i, i);

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

  if (!cp)
    return cp;

  i = strlen(cp);

  if (!(cp2 = malloc(i + 1)))
    return cp2;

  QadrtConvertE2A(cp2, cp, i, i);

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

  if (!cp)
    return cp;

  i = strlen(cp);

  if (!(cp2 = malloc(i + 1)))
    return cp2;

  QadrtConvertE2A(cp2, cp, i, i);

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

  if (!srcaddr || srclen < offsetof(struct sockaddr, sa_family) +
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

  if (i < 0)
    return -1;

  return connect(sd, (struct sockaddr *) &laddr, i);
}


int
Curl_os400_bind(int sd, struct sockaddr * localaddr, int addrlen)

{
  int i;
  struct sockaddr_storage laddr;

  i = convert_sockaddr(&laddr, localaddr, addrlen);

  if (i < 0)
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

  if (i < 0)
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

  if (!fromaddr || !addrlen || *addrlen <= 0)
    return recvfrom(sd, buffer, buflen, flags, fromaddr, addrlen);

  laddrlen = sizeof laddr;
  laddr.ss_family = AF_UNSPEC;          /* To detect if unused. */
  rcvlen = recvfrom(sd, buffer, buflen, flags,
                    (struct sockaddr *) &laddr, &laddrlen);

  if (rcvlen < 0)
    return rcvlen;

  switch (laddr.ss_family) {

  case AF_UNIX:
    srcu = (const struct sockaddr_un *) &laddr;
    dstu = (struct sockaddr_un *) fromaddr;
    i = *addrlen - offsetof(struct sockaddr_un, sun_path);
    laddrlen -= offsetof(struct sockaddr_un, sun_path);
    i = QadrtConvertE2A(dstu->sun_path, srcu->sun_path, i, laddrlen);
    laddrlen = i + offsetof(struct sockaddr_un, sun_path);

    if (laddrlen < *addrlen)
      dstu->sun_path[i] = '\0';

    break;

  case AF_UNSPEC:
    break;

  default:
    if (laddrlen > *addrlen)
      laddrlen = *addrlen;

    if (laddrlen)
      memcpy((char *) fromaddr, (char *) &laddr, laddrlen);

    break;
    }

  *addrlen = laddrlen;
  return rcvlen;
}
