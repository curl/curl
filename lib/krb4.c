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

#ifdef KRB4

#include "security.h"
#include "base64.h"
#include <stdlib.h>
#include <netdb.h>
#include <syslog.h>
#include <string.h>
#include <krb.h>

#ifdef HAVE_UNISTD_H
#include <unistd.h> /* for getpid() */
#endif

#include "ftp.h"
#include "sendf.h"

/* The last #include file should be: */
#ifdef MALLOCDEBUG
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
    if(e){
	syslog(LOG_ERR, "krb4_decode: %s", krb_get_err_text(e));
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
  struct sockaddr_in *localaddr  = (struct sockaddr_in *)LOCAL_ADDR;
  char *host = conn->hp->h_name;
  ssize_t nread;
  int l = sizeof(conn->local_addr);

  if(getsockname(conn->firstsocket,
                 (struct sockaddr *)LOCAL_ADDR, &l) < 0)
    perror("getsockname()");

  checksum = getpid();
  ret = mk_auth(d, &adat, "ftp", host, checksum);
  if(ret == KDC_PR_UNKNOWN)
    ret = mk_auth(d, &adat, "rcmd", host, checksum);
  if(ret) {
    printf("%s\n", krb_get_err_text(ret));
    return AUTH_CONTINUE;
  }
  
#ifdef HAVE_KRB_GET_OUR_IP_FOR_REALM
  if (krb_get_config_bool("nat_in_use")) {
    struct in_addr natAddr;

    if (krb_get_our_ip_for_realm(krb_realmofhost(host),
                                 &natAddr) != KSUCCESS
        && krb_get_our_ip_for_realm(NULL, &natAddr) != KSUCCESS)
      printf("Can't get address for realm %s\n",
             krb_realmofhost(host));
    else {
      if (natAddr.s_addr != localaddr->sin_addr.s_addr) {
        printf("Using NAT IP address (%s) for kerberos 4\n",
               (char *)inet_ntoa(natAddr));
        localaddr->sin_addr = natAddr;
        
        /*
         * This not the best place to do this, but it is here we know that
         * (probably) NAT is in use!  */

        /*passivemode = 1;***/
        /*printf("Setting: Passive mode on.\n");***/
      }
    }
  }
#endif

  /*printf("Local address is %s\n", inet_ntoa(localaddr->sin_addr));***/
  /*printf("Remote address is %s\n", inet_ntoa(remoteaddr->sin_addr));***/

  if(Curl_base64_encode(adat.dat, adat.length, &p) < 0) {
    printf("Out of memory base64-encoding.\n");
    return AUTH_CONTINUE;
  }

  Curl_ftpsendf(conn->firstsocket, conn, "ADAT %s", p);

  nread = Curl_GetFTPResponse(conn->firstsocket,
                              conn->data->state.buffer, conn, NULL);
  if(nread < 0)
    return /*CURLE_OPERATION_TIMEOUTED*/-1;
  free(p);

  if(/*ret != COMPLETE*/conn->data->state.buffer[0] != '2'){
    printf("Server didn't accept auth data.\n");
    return AUTH_ERROR;
  }

  p = strstr(conn->data->state.buffer, "ADAT=");
  if(!p){
    printf("Remote host didn't send adat reply.\n");
    return AUTH_ERROR;
  }
  p += 5;
  len = Curl_base64_decode(p, adat.dat);
  if(len < 0){
    printf("Failed to decode base64 from server.\n");
    return AUTH_ERROR;
  }
  adat.length = len;
  ret = krb_rd_safe(adat.dat, adat.length, &d->key, 
                    (struct sockaddr_in *)hisctladdr, 
                    (struct sockaddr_in *)myctladdr, &msg_data);
  if(ret){
    printf("Error reading reply from server: %s.\n", 
           krb_get_err_text(ret));
    return AUTH_ERROR;
  }
  krb_get_int(msg_data.app_data, &cs, 4, 0);
  if(cs - checksum != 1){
    printf("Bad checksum returned from server.\n");
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

void Curl_krb_kauth(struct connectdata *conn)
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

  save = Curl_set_command_prot(conn, prot_private);

  Curl_ftpsendf(conn->firstsocket, conn,
                "SITE KAUTH %s", conn->data->state.user);

  nread = Curl_GetFTPResponse(conn->firstsocket, conn->data->state.buffer,
                              conn, NULL);
  if(nread < 0)
    return /*CURLE_OPERATION_TIMEOUTED*/;

  if(/*ret != CONTINUE*/conn->data->state.buffer[0] != '3'){
    Curl_set_command_prot(conn, save);
    /*code = -1;***/
    return;
  }

  p = strstr(conn->data->state.buffer, "T=");
  if(!p) {
    printf("Bad reply from server.\n");
    Curl_set_command_prot(conn, save);
    return;
  }

  p += 2;
  tmp = Curl_base64_decode(p, &tkt.dat);
  if(tmp < 0) {
    printf("Failed to decode base64 in reply.\n");
    Curl_set_command_prot(conn, save);
    return;
  }
  tkt.length = tmp;
  tktcopy.length = tkt.length;
    
  p = strstr(conn->data->state.buffer, "P=");
  if(!p) {
    printf("Bad reply from server.\n");
    Curl_set_command_prot(conn, save);
    return;
  }
  name = p + 2;
  for(; *p && *p != ' ' && *p != '\r' && *p != '\n'; p++);
  *p = 0;

  des_string_to_key (conn->data->state.passwd, &key);
  des_key_sched(&key, schedule);
    
  des_pcbc_encrypt((des_cblock*)tkt.dat, (des_cblock*)tktcopy.dat,
                   tkt.length,
                   schedule, &key, DES_DECRYPT);
  if (strcmp ((char*)tktcopy.dat + 8,
              KRB_TICKET_GRANTING_TICKET) != 0) {
    afs_string_to_key (passwd,
                       krb_realmofhost(/*hostname*/conn->hp->h_name),
                       &key);
    des_key_sched (&key, schedule);
    des_pcbc_encrypt((des_cblock*)tkt.dat, (des_cblock*)tktcopy.dat,
                     tkt.length,
                     schedule, &key, DES_DECRYPT);
  }
  memset(key, 0, sizeof(key));
  memset(schedule, 0, sizeof(schedule));
  memset(passwd, 0, sizeof(passwd));
  if(Curl_base64_encode(tktcopy.dat, tktcopy.length, &p) < 0) {
    failf(conn->data, "Out of memory base64-encoding.\n");
    Curl_set_command_prot(conn, save);
    return;
  }
  memset (tktcopy.dat, 0, tktcopy.length);

  Curl_ftpsendf(conn->firstsocket, conn,
                "SITE KAUTH %s %s", name, p);

  nread = Curl_GetFTPResponse(conn->firstsocket, conn->data->state.buffer,
                              conn, NULL);
  if(nread < 0)
    return /*CURLE_OPERATION_TIMEOUTED*/;
  free(p);
  Curl_set_command_prot(conn, save);
}

#endif /* KRB4 */

/*
 * local variables:
 * eval: (load-file "../curl-mode.el")
 * end:
 * vim600: et sw=2 ts=2 sts=2 tw=78 fdm=marker
 * vim<600: et sw=2 ts=2 sts=2 tw=78
 */
