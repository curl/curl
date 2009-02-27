/* GSSAPI/krb5 support for FTP - loosely based on old krb4.c
 *
 * Copyright (c) 1995, 1996, 1997, 1998, 1999 Kungliga Tekniska Högskolan
 * (Royal Institute of Technology, Stockholm, Sweden).
 * Copyright (c) 2004 - 2008 Daniel Stenberg
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
#ifdef HAVE_GSSAPI

#ifdef HAVE_OLD_GSSMIT
#define GSS_C_NT_HOSTBASED_SERVICE gss_nt_service_name
#endif

#include <stdlib.h>
#ifdef HAVE_NETDB_H
#include <netdb.h>
#endif
#include <string.h>
#ifdef HAVE_GSSMIT
/* MIT style */
#include <gssapi/gssapi.h>
#include <gssapi/gssapi_generic.h>
#include <gssapi/gssapi_krb5.h>
#else
/* Heimdal-style */
#include <gssapi.h>
#endif

#include "urldata.h"
#include "curl_base64.h"
#include "ftp.h"
#include "sendf.h"
#include "krb4.h"
#include "memory.h"

#define _MPRINTF_REPLACE /* use our functions only */
#include <curl/mprintf.h>

/* The last #include file should be: */
#include "memdebug.h"

#define LOCAL_ADDR (&conn->local_addr)
#define REMOTE_ADDR conn->ip_addr->ai_addr

static int
krb5_check_prot(void *app_data, int level)
{
  app_data = NULL; /* prevent compiler warning */
  if(level == prot_confidential)
    return -1;
  return 0;
}

static int
krb5_decode(void *app_data, void *buf, int len, int level,
            struct connectdata *conn)
{
  gss_ctx_id_t *context = app_data;
  OM_uint32 maj, min;
  gss_buffer_desc enc, dec;

  /* shut gcc up */
  level = 0;
  conn = NULL;

  enc.value = buf;
  enc.length = len;
  maj = gss_unseal(&min, *context, &enc, &dec, NULL, NULL);
  if(maj != GSS_S_COMPLETE) {
    if(len >= 4)
      strcpy(buf, "599 ");
    return -1;
  }

  memcpy(buf, dec.value, dec.length);
  len = dec.length;
  gss_release_buffer(&min, &dec);

  return len;
}

static int
krb5_overhead(void *app_data, int level, int len)
{
  /* no arguments are used, just init them to prevent compiler warnings */
  app_data = NULL;
  level = 0;
  len = 0;
  return 0;
}

static int
krb5_encode(void *app_data, const void *from, int length, int level, void **to,
            struct connectdata *conn)
{
  gss_ctx_id_t *context = app_data;
  gss_buffer_desc dec, enc;
  OM_uint32 maj, min;
  int state;
  int len;

  /* shut gcc up */
  conn = NULL;

  /* NOTE that the cast is safe, neither of the krb5, gnu gss and heimdal
   * libraries modify the input buffer in gss_seal()
   */
  dec.value = (void*)from;
  dec.length = length;
  maj = gss_seal(&min, *context,
                 level == prot_private,
                 GSS_C_QOP_DEFAULT,
                 &dec, &state, &enc);

  if(maj != GSS_S_COMPLETE)
    return -1;

  /* malloc a new buffer, in case gss_release_buffer doesn't work as expected */
  *to = malloc(enc.length);
  if(!*to)
    return -1;
  memcpy(*to, enc.value, enc.length);
  len = enc.length;
  gss_release_buffer(&min, &enc);
  return len;
}

static int
krb5_auth(void *app_data, struct connectdata *conn)
{
  int ret;
  char *p;
  const char *host = conn->dns_entry->addr->ai_canonname;
  ssize_t nread;
  socklen_t l = sizeof(conn->local_addr);
  struct SessionHandle *data = conn->data;
  CURLcode result;
  const char *service = "ftp", *srv_host = "host";
  gss_buffer_desc gssbuf, _gssresp, *gssresp;
  OM_uint32 maj, min;
  gss_name_t gssname;
  gss_ctx_id_t *context = app_data;
  struct gss_channel_bindings_struct chan;

  if(getsockname(conn->sock[FIRSTSOCKET],
                 (struct sockaddr *)LOCAL_ADDR, &l) < 0)
    perror("getsockname()");

  chan.initiator_addrtype = GSS_C_AF_INET;
  chan.initiator_address.length = l - 4;
  chan.initiator_address.value =
    &((struct sockaddr_in *)LOCAL_ADDR)->sin_addr.s_addr;
  chan.acceptor_addrtype = GSS_C_AF_INET;
  chan.acceptor_address.length = l - 4;
  chan.acceptor_address.value =
    &((struct sockaddr_in *)REMOTE_ADDR)->sin_addr.s_addr;
  chan.application_data.length = 0;
  chan.application_data.value = NULL;

  /* this loop will execute twice (once for service, once for host) */
  while(1) {
    /* this really shouldn't be repeated here, but can't help it */
    if(service == srv_host) {
      result = Curl_ftpsendf(conn, "AUTH GSSAPI");

      if(result)
        return -2;
      if(Curl_GetFTPResponse(&nread, conn, NULL))
        return -1;

      if(data->state.buffer[0] != '3')
        return -1;
    }

    gssbuf.value = data->state.buffer;
    gssbuf.length = snprintf(gssbuf.value, BUFSIZE, "%s@%s", service, host);
    maj = gss_import_name(&min, &gssbuf, GSS_C_NT_HOSTBASED_SERVICE, &gssname);
    if(maj != GSS_S_COMPLETE) {
      gss_release_name(&min, &gssname);
      if(service == srv_host) {
        Curl_failf(data, "Error importing service name %s", gssbuf.value);
        return AUTH_ERROR;
      }
      service = srv_host;
      continue;
    }
    {
      gss_OID t;
      gss_display_name(&min, gssname, &gssbuf, &t);
      Curl_infof(data, "Trying against %s\n", gssbuf.value);
      gss_release_buffer(&min, &gssbuf);
    }
    gssresp = GSS_C_NO_BUFFER;
    *context = GSS_C_NO_CONTEXT;

    do {
      ret = AUTH_OK;
      maj = gss_init_sec_context(&min,
                                 GSS_C_NO_CREDENTIAL,
                                 context,
                                 gssname,
                                 GSS_C_NO_OID,
                                 GSS_C_MUTUAL_FLAG | GSS_C_REPLAY_FLAG,
                                 0,
                                 &chan,
                                 gssresp,
                                 NULL,
                                 &gssbuf,
                                 NULL,
                                 NULL);

      if(gssresp) {
        free(_gssresp.value);
        gssresp = NULL;
      }

      if(maj != GSS_S_COMPLETE && maj != GSS_S_CONTINUE_NEEDED) {
        Curl_infof(data, "Error creating security context");
        ret = AUTH_ERROR;
        break;
      }

      if(gssbuf.length != 0) {
        if(Curl_base64_encode(data, (char *)gssbuf.value, gssbuf.length, &p)
           < 1) {
          Curl_infof(data, "Out of memory base64-encoding");
          ret = AUTH_CONTINUE;
          break;
        }

        result = Curl_ftpsendf(conn, "ADAT %s", p);

        free(p);

        if(result) {
          ret = -2;
          break;
        }

        if(Curl_GetFTPResponse(&nread, conn, NULL)) {
          ret = -1;
          break;
        }

        if(data->state.buffer[0] != '2' && data->state.buffer[0] != '3'){
          Curl_infof(data, "Server didn't accept auth data\n");
          ret = AUTH_ERROR;
          break;
        }

        p = data->state.buffer + 4;
        p = strstr(p, "ADAT=");
        if(p) {
          _gssresp.length = Curl_base64_decode(p + 5, (unsigned char **)
                                               &_gssresp.value);
          if(_gssresp.length < 1) {
            Curl_failf(data, "Out of memory base64-encoding");
            ret = AUTH_CONTINUE;
            break;
          }
        }

        gssresp = &_gssresp;
      }
    } while(maj == GSS_S_CONTINUE_NEEDED);

    gss_release_name(&min, &gssname);

    if(gssresp)
      free(_gssresp.value);

    if(ret == AUTH_OK || service == srv_host)
      return ret;

    service = srv_host;
  }
}

struct Curl_sec_client_mech Curl_krb5_client_mech = {
    "GSSAPI",
    sizeof(gss_ctx_id_t),
    NULL, /* init */
    krb5_auth,
    NULL, /* end */
    krb5_check_prot,
    krb5_overhead,
    krb5_encode,
    krb5_decode
};

#endif /* HAVE_GSSAPI */
#endif /* CURL_DISABLE_FTP */
