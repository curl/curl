/* This source code was modified by Martin Hedenfalk <mhe@stacken.kth.se> for
 * use in Curl. His latest changes were done 2000-09-18.
 *
 * It has since been patched away like a madman by Daniel Stenberg
 * <daniel@haxx.se> to make it better applied to curl conditions, and to make
 * it not use globals, pollute name space and more. This source code awaits a
 * rewrite to work around the paragraph 2 in the BSD licenses as explained
 * below.
 *
 * Copyright (c) 1995, 1996, 1997, 1998, 1999 Kungliga Tekniska Högskolan
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

#include "security.h"
#include "base64.h"
#include <stdlib.h>
#ifdef HAVE_NETDB_H
#include <netdb.h>
#endif
#include <string.h>
#include <krb.h>
#include <des.h>

#ifdef HAVE_UNISTD_H
#include <unistd.h> /* for getpid() */
#endif

#include "ftp.h"
#include "sendf.h"
#include "krb4.h"

#if defined(HAVE_INET_NTOA_R) && !defined(HAVE_INET_NTOA_R_DECL)
#include "inet_ntoa_r.h"
#endif

/* The last #include file should be: */
#ifdef CURLDEBUG
#include "memdebug.h"
#endif

#define LOCAL_ADDR (&conn->local_addr)
#define REMOTE_ADDR (&conn->serv_addr)
#define myctladdr LOCAL_ADDR
#define hisctladdr REMOTE_ADDR

struct krb4_data {
  des_cblock key;
  des_key_schedule schedule;
  char name[ANAME_SZ];
  char instance[INST_SZ];
  char realm[REALM_SZ];
};

#ifndef HAVE_STRLCPY
/* if it ever goes non-static, make it Curl_ prefixed! */
static size_t
strlcpy (char *dst, const char *src, size_t dst_sz)
{
  size_t n;
  char *p;

  for (p = dst, n = 0;
       n + 1 < dst_sz && *src != '\0';
       ++p, ++src, ++n)
    *p = *src;
  *p = '\0';
  if (*src == '\0')
    return n;
  else
    return n + strlen (src);
}
#else
size_t strlcpy (char *dst, const char *src, size_t dst_sz);
#endif

static int
krb4_check_prot(void *app_data, int level)
{
  app_data = NULL; /* prevent compiler warning */
  if(level == prot_confidential)
    return -1;
  return 0;
}

static int
krb4_decode(void *app_data, void *buf, int len, int level,
	    struct connectdata *conn)
{
  MSG_DAT m;
  int e;
  struct krb4_data *d = app_data;
  
  if(level == prot_safe)
    e = krb_rd_safe(buf, len, &d->key,
                    (struct sockaddr_in *)REMOTE_ADDR,
                    (struct sockaddr_in *)LOCAL_ADDR, &m);
  else
    e = krb_rd_priv(buf, len, d->schedule, &d->key, 
                    (struct sockaddr_in *)REMOTE_ADDR,
                    (struct sockaddr_in *)LOCAL_ADDR, &m);
  if(e) {
    struct SessionHandle *data = conn->data;
    infof(data, "krb4_decode: %s\n", krb_get_err_text(e));
    return -1;
  }
  memmove(buf, m.app_data, m.app_length);
  return m.app_length;
}

static int
krb4_overhead(void *app_data, int level, int len)
{
  /* no arguments are used, just init them to prevent compiler warnings */
  app_data = NULL;
  level = 0;
  len = 0;
  return 31;
}

static int
krb4_encode(void *app_data, void *from, int length, int level, void **to,
	    struct connectdata *conn)
{
  struct krb4_data *d = app_data;
  *to = malloc(length + 31);
  if(level == prot_safe)
    return krb_mk_safe(from, *to, length, &d->key, 
                       (struct sockaddr_in *)LOCAL_ADDR,
                       (struct sockaddr_in *)REMOTE_ADDR);
  else if(level == prot_private)
    return krb_mk_priv(from, *to, length, d->schedule, &d->key, 
                       (struct sockaddr_in *)LOCAL_ADDR,
                       (struct sockaddr_in *)REMOTE_ADDR);
  else
    return -1;
}

static int
mk_auth(struct krb4_data *d, KTEXT adat, 
	const char *service, char *host, int checksum)
{
  int ret;
  CREDENTIALS cred;
  char sname[SNAME_SZ], inst[INST_SZ], realm[REALM_SZ];

  strlcpy(sname, service, sizeof(sname));
  strlcpy(inst, krb_get_phost(host), sizeof(inst));
  strlcpy(realm, krb_realmofhost(host), sizeof(realm));
  ret = krb_mk_req(adat, sname, inst, realm, checksum);
  if(ret)
    return ret;
  strlcpy(sname, service, sizeof(sname));
  strlcpy(inst, krb_get_phost(host), sizeof(inst));
  strlcpy(realm, krb_realmofhost(host), sizeof(realm));
  ret = krb_get_cred(sname, inst, realm, &cred);
  memmove(&d->key, &cred.session, sizeof(des_cblock));
  des_key_sched(&d->key, d->schedule);
  memset(&cred, 0, sizeof(cred));
  return ret;
}

#ifdef HAVE_KRB_GET_OUR_IP_FOR_REALM
int krb_get_our_ip_for_realm(char *, struct in_addr *);
#endif

static int
krb4_auth(void *app_data, struct connectdata *conn)
{
  int ret;
  char *p;
  int len;
  KTEXT_ST adat;
  MSG_DAT msg_data;
  int checksum;
  u_int32_t cs;
  struct krb4_data *d = app_data;
  char *host = conn->hostname;
  ssize_t nread;
  int l = sizeof(conn->local_addr);
  struct SessionHandle *data = conn->data;
  CURLcode result;

  if(getsockname(conn->sock[FIRSTSOCKET],
                 (struct sockaddr *)LOCAL_ADDR, &l) < 0)
    perror("getsockname()");

  checksum = getpid();
  ret = mk_auth(d, &adat, "ftp", host, checksum);
  if(ret == KDC_PR_UNKNOWN)
    ret = mk_auth(d, &adat, "rcmd", host, checksum);
  if(ret) {
    Curl_infof(data, "%s\n", krb_get_err_text(ret));
    return AUTH_CONTINUE;
  }
  
#ifdef HAVE_KRB_GET_OUR_IP_FOR_REALM
  if (krb_get_config_bool("nat_in_use")) {
    struct sockaddr_in *localaddr  = (struct sockaddr_in *)LOCAL_ADDR;
    struct in_addr natAddr;

    if (krb_get_our_ip_for_realm(krb_realmofhost(host),
                                 &natAddr) != KSUCCESS
        && krb_get_our_ip_for_realm(NULL, &natAddr) != KSUCCESS)
      Curl_infof(data, "Can't get address for realm %s\n",
                 krb_realmofhost(host));
    else {
      if (natAddr.s_addr != localaddr->sin_addr.s_addr) {
#ifdef HAVE_INET_NTOA_R
        char ntoa_buf[64];
        char *ip = (char *)inet_ntoa_r(natAddr, ntoa_buf, sizeof(ntoa_buf));
#else
        char *ip = (char *)inet_ntoa(natAddr);
#endif
        Curl_infof(data, "Using NAT IP address (%s) for kerberos 4\n", ip);
        localaddr->sin_addr = natAddr;
      }
    }
  }
#endif

  if(Curl_base64_encode((char *)adat.dat, adat.length, &p) < 1) {
    Curl_failf(data, "Out of memory base64-encoding");
    return AUTH_CONTINUE;
  }

  result = Curl_ftpsendf(conn, "ADAT %s", p);

  free(p);

  if(result)
    return -2;

  if(Curl_GetFTPResponse(&nread, conn, NULL))
    return -1;

  if(data->state.buffer[0] != '2'){
    Curl_failf(data, "Server didn't accept auth data");
    return AUTH_ERROR;
  }

  p = strstr(data->state.buffer, "ADAT=");
  if(!p) {
    Curl_failf(data, "Remote host didn't send adat reply");
    return AUTH_ERROR;
  }
  p += 5;
  len = Curl_base64_decode(p, (char *)adat.dat);
  if(len < 0) {
    Curl_failf(data, "Failed to decode base64 from server");
    return AUTH_ERROR;
  }
  adat.length = len;
  ret = krb_rd_safe(adat.dat, adat.length, &d->key, 
                    (struct sockaddr_in *)hisctladdr, 
                    (struct sockaddr_in *)myctladdr, &msg_data);
  if(ret) {
    Curl_failf(data, "Error reading reply from server: %s", 
               krb_get_err_text(ret));
    return AUTH_ERROR;
  }
  krb_get_int(msg_data.app_data, &cs, 4, 0);
  if(cs - checksum != 1) {
    Curl_failf(data, "Bad checksum returned from server");
    return AUTH_ERROR;
  }
  return AUTH_OK;
}

struct Curl_sec_client_mech Curl_krb4_client_mech = {
    "KERBEROS_V4",
    sizeof(struct krb4_data),
    NULL, /* init */
    krb4_auth,
    NULL, /* end */
    krb4_check_prot,
    krb4_overhead,
    krb4_encode,
    krb4_decode
};

CURLcode Curl_krb_kauth(struct connectdata *conn)
{
  des_cblock key;
  des_key_schedule schedule;
  KTEXT_ST tkt, tktcopy;
  char *name;
  char *p;
  char passwd[100];
  int tmp;
  ssize_t nread;
  int save;
  CURLcode result;

  save = Curl_set_command_prot(conn, prot_private);

  result = Curl_ftpsendf(conn, "SITE KAUTH %s", conn->user);

  if(result)
    return result;

  result = Curl_GetFTPResponse(&nread, conn, NULL);
  if(result)
    return result;

  if(conn->data->state.buffer[0] != '3'){
    Curl_set_command_prot(conn, save);
    return CURLE_FTP_WEIRD_SERVER_REPLY;
  }

  p = strstr(conn->data->state.buffer, "T=");
  if(!p) {
    Curl_failf(conn->data, "Bad reply from server");
    Curl_set_command_prot(conn, save);
    return CURLE_FTP_WEIRD_SERVER_REPLY;
  }

  p += 2;
  tmp = Curl_base64_decode(p, (char *)tkt.dat);
  if(tmp < 0) {
    Curl_failf(conn->data, "Failed to decode base64 in reply.\n");
    Curl_set_command_prot(conn, save);
    return CURLE_FTP_WEIRD_SERVER_REPLY;
  }
  tkt.length = tmp;
  tktcopy.length = tkt.length;
    
  p = strstr(conn->data->state.buffer, "P=");
  if(!p) {
    Curl_failf(conn->data, "Bad reply from server");
    Curl_set_command_prot(conn, save);
    return CURLE_FTP_WEIRD_SERVER_REPLY;
  }
  name = p + 2;
  for(; *p && *p != ' ' && *p != '\r' && *p != '\n'; p++);
  *p = 0;

  des_string_to_key (conn->passwd, &key);
  des_key_sched(&key, schedule);
    
  des_pcbc_encrypt((void *)tkt.dat, (void *)tktcopy.dat,
                   tkt.length,
                   schedule, &key, DES_DECRYPT);
  if (strcmp ((char*)tktcopy.dat + 8,
              KRB_TICKET_GRANTING_TICKET) != 0) {
    afs_string_to_key(passwd,
                      krb_realmofhost(conn->hostname),
                      &key);
    des_key_sched(&key, schedule);
    des_pcbc_encrypt((void *)tkt.dat, (void *)tktcopy.dat,
                     tkt.length,
                     schedule, &key, DES_DECRYPT);
  }
  memset(key, 0, sizeof(key));
  memset(schedule, 0, sizeof(schedule));
  memset(passwd, 0, sizeof(passwd));
  if(Curl_base64_encode((char *)tktcopy.dat, tktcopy.length, &p) < 1) {
    failf(conn->data, "Out of memory base64-encoding.");
    Curl_set_command_prot(conn, save);
    return CURLE_OUT_OF_MEMORY;
  }
  memset (tktcopy.dat, 0, tktcopy.length);

  result = Curl_ftpsendf(conn, "SITE KAUTH %s %s", name, p);
  free(p);
  if(result)
    return result;

  result = Curl_GetFTPResponse(&nread, conn, NULL);
  if(result)
    return result;
  Curl_set_command_prot(conn, save);

  return CURLE_OK;
}

#endif /* HAVE_KRB4 */
#endif /* CURL_DISABLE_FTP */
