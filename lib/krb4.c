/* modified by Martin Hedenfalk <mhe@stacken.kth.se> for use in Curl
 * last modified 2000-09-18
 */

/*
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
 * SUCH DAMAGE.
 */

#include "setup.h"

#ifdef KRB4

#include "security.h"
#include "base64.h"
#include <stdlib.h>
#include <netdb.h>
#include <syslog.h>
#include <string.h>
#include <krb.h>

#include "ftp.h"
#include "sendf.h"

/* The last #include file should be: */
#ifdef MALLOCDEBUG
#include "memdebug.h"
#endif

#ifdef FTP_SERVER
#define LOCAL_ADDR ctrl_addr
#define REMOTE_ADDR his_addr
#else
/*#define LOCAL_ADDR myctladdr***/
/*#define REMOTE_ADDR hisctladdr***/
#endif

/*extern struct sockaddr *LOCAL_ADDR, *REMOTE_ADDR;***/

#define LOCAL_ADDR (&local_addr)
#define REMOTE_ADDR (&conn->serv_addr)
#define myctladdr LOCAL_ADDR
#define hisctladdr REMOTE_ADDR

static struct sockaddr_in local_addr;

struct krb4_data {
    des_cblock key;
    des_key_schedule schedule;
    char name[ANAME_SZ];
    char instance[INST_SZ];
    char realm[REALM_SZ];
};

#ifndef HAVE_STRLCPY

size_t
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

#ifdef FTP_SERVER

static int
krb4_adat(void *app_data, void *buf, size_t len)
{
    KTEXT_ST tkt;
    AUTH_DAT auth_dat;
    char *p;
    int kerror;
    u_int32_t cs;
    char msg[35]; /* size of encrypted block */
    int tmp_len;
    struct krb4_data *d = app_data;
    char inst[INST_SZ];
    struct sockaddr_in *his_addr_sin = (struct sockaddr_in *)his_addr;

    memcpy(tkt.dat, buf, len);
    tkt.length = len;

    k_getsockinst(0, inst, sizeof(inst));
    kerror = krb_rd_req(&tkt, "ftp", inst, 
			his_addr_sin->sin_addr.s_addr, &auth_dat, "");
    if(kerror == RD_AP_UNDEC){
	k_getsockinst(0, inst, sizeof(inst));
	kerror = krb_rd_req(&tkt, "rcmd", inst, 
			    his_addr_sin->sin_addr.s_addr, &auth_dat, "");
    }

    if(kerror){
	reply(535, "Error reading request: %s.", krb_get_err_text(kerror));
	return -1;
    }
    
    memcpy(d->key, auth_dat.session, sizeof(d->key));
    des_set_key(&d->key, d->schedule);

    strlcpy(d->name, auth_dat.pname, sizeof(d->name));
    strlcpy(d->instance, auth_dat.pinst, sizeof(d->instance));
    strlcpy(d->realm, auth_dat.prealm, sizeof(d->instance));

    cs = auth_dat.checksum + 1;
    {
	unsigned char tmp[4];
	KRB_PUT_INT(cs, tmp, 4, sizeof(tmp));
	tmp_len = krb_mk_safe(tmp, msg, 4, &d->key,
			      (struct sockaddr_in *)LOCAL_ADDR,
			      (struct sockaddr_in *)REMOTE_ADDR);
    }
    if(tmp_len < 0){
	reply(535, "Error creating reply: %s.", strerror(errno));
	return -1;
    }
    len = tmp_len;
    if(base64_encode(msg, len, &p) < 0) {
	reply(535, "Out of memory base64-encoding.");
	return -1;
    }
    reply(235, "ADAT=%s", p);
    sec_complete = 1;
    free(p);
    return 0;
}

static int
krb4_userok(void *app_data, char *user)
{
    struct krb4_data *d = app_data;
    return krb_kuserok(d->name, d->instance, d->realm, user);
}

struct sec_server_mech krb4_server_mech = {
    "KERBEROS_V4",
    sizeof(struct krb4_data),
    NULL, /* init */
    NULL, /* end */
    krb4_check_prot,
    krb4_overhead,
    krb4_encode,
    krb4_decode,
    /* */
    NULL,
    krb4_adat,
    NULL, /* pbsz */
    NULL, /* ccc */
    krb4_userok
};

#else /* FTP_SERVER */

static int
mk_auth(struct krb4_data *d, KTEXT adat, 
	char *service, char *host, int checksum)
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
#if 0
    struct sockaddr_in *remoteaddr = (struct sockaddr_in *)REMOTE_ADDR;
#endif
    char *host = conn->hp->h_name;
    size_t nread;
    int l = sizeof(local_addr);

    if(getsockname(conn->firstsocket,
                   (struct sockaddr *)LOCAL_ADDR, &l) < 0)
	perror("getsockname()");

    checksum = getpid();
    ret = mk_auth(d, &adat, "ftp", host, checksum);
    if(ret == KDC_PR_UNKNOWN)
	ret = mk_auth(d, &adat, "rcmd", host, checksum);
    if(ret){
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
	   * This not the best place to do this, but it
	   * is here we know that (probably) NAT is in
	   * use!
	   */

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
    /*ret = command("ADAT %s", p)*/
    Curl_ftpsendf(conn->firstsocket, conn, "ADAT %s", p);
    /* wait for feedback */
    nread = Curl_GetFTPResponse(conn->firstsocket,
                                conn->data->buffer, conn, NULL);
    if(nread < 0)
	return /*CURLE_OPERATION_TIMEOUTED*/-1;
    free(p);

    if(/*ret != COMPLETE*/conn->data->buffer[0] != '2'){
	printf("Server didn't accept auth data.\n");
	return AUTH_ERROR;
    }

    p = strstr(/*reply_string*/conn->data->buffer, "ADAT=");
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

struct sec_client_mech krb4_client_mech = {
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

#endif /* FTP_SERVER */

void krb_kauth(struct connectdata *conn)
{
    des_cblock key;
    des_key_schedule schedule;
    KTEXT_ST tkt, tktcopy;
    char *name;
    char *p;
    char passwd[100];
    int tmp;
    size_t nread;
	
    int save;

    save = set_command_prot(conn, prot_private);
    /*ret = command("SITE KAUTH %s", name);***/
    Curl_ftpsendf(conn->firstsocket, conn,
             "SITE KAUTH %s", conn->data->user);
    /* wait for feedback */
    nread = Curl_GetFTPResponse(conn->firstsocket, conn->data->buffer,
                                conn, NULL);
    if(nread < 0)
	return /*CURLE_OPERATION_TIMEOUTED*/;

    if(/*ret != CONTINUE*/conn->data->buffer[0] != '3'){
	set_command_prot(conn, save);
	/*code = -1;***/
	return;
    }
    p = strstr(/*reply_string***/conn->data->buffer, "T=");
    if(!p){
	printf("Bad reply from server.\n");
	set_command_prot(conn, save);
	/*code = -1;***/
	return;
    }
    p += 2;
    tmp = Curl_base64_decode(p, &tkt.dat);
    if(tmp < 0){
	printf("Failed to decode base64 in reply.\n");
	set_command_prot(conn, save);
	/*code = -1;***/
	return;
    }
    tkt.length = tmp;
    tktcopy.length = tkt.length;
    
    p = strstr(/*reply_string***/conn->data->buffer, "P=");
    if(!p){
	printf("Bad reply from server.\n");
	set_command_prot(conn, save);
	/*code = -1;***/
	return;
    }
    name = p + 2;
    for(; *p && *p != ' ' && *p != '\r' && *p != '\n'; p++);
    *p = 0;

#if 0
    snprintf(buf, sizeof(buf), "Password for %s:", name);
    if (des_read_pw_string (passwd, sizeof(passwd)-1, buf, 0))
        *passwd = '\0';
    des_string_to_key (passwd, &key);
#else
    des_string_to_key (conn->data->passwd, &key);
#endif

    des_key_sched(&key, schedule);
    
    des_pcbc_encrypt((des_cblock*)tkt.dat, (des_cblock*)tktcopy.dat,
		     tkt.length,
		     schedule, &key, DES_DECRYPT);
    if (strcmp ((char*)tktcopy.dat + 8,
		KRB_TICKET_GRANTING_TICKET) != 0) {
        afs_string_to_key (passwd,
			   krb_realmofhost(/*hostname***/conn->hp->h_name),
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
      set_command_prot(conn, save);
      /*code = -1;***/
      return;
    }
    memset (tktcopy.dat, 0, tktcopy.length);
    /*ret = command("SITE KAUTH %s %s", name, p);***/
    Curl_ftpsendf(conn->firstsocket, conn,
             "SITE KAUTH %s %s", name, p);
    /* wait for feedback */
    nread = Curl_GetFTPResponse(conn->firstsocket, conn->data->buffer,
                                conn, NULL);
    if(nread < 0)
	return /*CURLE_OPERATION_TIMEOUTED*/;
    free(p);
    set_command_prot(conn, save);
}

#endif /* KRB4 */
