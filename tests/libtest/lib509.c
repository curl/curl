#include "test.h"

#ifdef USE_SSLEAY

#include <sys/time.h>
#include <sys/types.h>

#include <openssl/opensslv.h>
#include <openssl/x509v3.h>
#include <openssl/x509_vfy.h>
#include <openssl/crypto.h>
#include <openssl/lhash.h>
#include <openssl/objects.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/x509.h>
#include <openssl/pkcs12.h>
#include <openssl/bio.h>
#include <openssl/ssl.h>


typedef struct sslctxparm_st {
   CURL* curl;
   int accesstype ;
   unsigned char * accessinfoURL ;

} sslctxparm;


static unsigned char *i2s_ASN1_IA5STRING( ASN1_IA5STRING *ia5)
{
	unsigned char *tmp;
	if(!ia5 || !ia5->length) return NULL;
	tmp = OPENSSL_malloc(ia5->length + 1);
	memcpy(tmp, ia5->data, ia5->length);
	tmp[ia5->length] = 0;
	return tmp;
}

/* A conveniance routine to get an access URI. */

static unsigned char *my_get_ext(X509 * cert, const int type,
                                 int extensiontype)
{
  int i;
  STACK_OF(ACCESS_DESCRIPTION) * accessinfo ;
  accessinfo =  X509_get_ext_d2i(cert, extensiontype, NULL, NULL) ;
  
  if (!sk_ACCESS_DESCRIPTION_num(accessinfo))
    return NULL;
  
  for (i = 0; i < sk_ACCESS_DESCRIPTION_num(accessinfo); i++) {
    ACCESS_DESCRIPTION * ad = sk_ACCESS_DESCRIPTION_value(accessinfo, i);
    if (OBJ_obj2nid(ad->method) == type) {
      if (ad->location->type == GEN_URI) {
        return i2s_ASN1_IA5STRING(ad->location->d.ia5);
      }
      return NULL;
    }
  }	
  return NULL;
}

void * globalparm = NULL;

static int ssl_app_verify_callback(X509_STORE_CTX *ctx, void *arg)
{
  sslctxparm * p = (sslctxparm *) arg;
  int ok, err;

  fprintf(stderr,"ssl_app_verify_callback sslctxparm=%p ctx=%p\n",
          (void *)p, (void*)ctx);

#if OPENSSL_VERSION_NUMBER<0x00907000L
/* not necessary in openssl 0.9.7 or later */
        
  fprintf(stderr,"This version %s of openssl does not support a parm (%p)"
          ", getting a global static %p \n",
          OPENSSL_VERSION_TEXT, (void *)p, (void *)globalparm);
  
  p = globalparm;
#endif

/* The following error should not occur. We test this to avoid segfault. */
  if (!p || !ctx) { 
    fprintf(stderr,"Internal error in ssl_app_verify_callback "
            "sslctxparm=%p ctx=%p\n",(void *)p,(void*)ctx);
    return 0;
  }

  ok= X509_verify_cert(ctx);
  err=X509_STORE_CTX_get_error(ctx);

/* The following seems to be a problem in 0.9.7/8 openssl versions */

#if 1
  if (err == X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT ||
      err == X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY) {
    fprintf(stderr,"X509_verify_cert: repairing self signed\n") ; 
    X509_STORE_CTX_set_error(ctx,X509_V_OK);
    ok = 1;
  }
#endif

  if (ok && ctx->cert) {
    unsigned char * accessinfoURL ;
		
    accessinfoURL = my_get_ext(ctx->cert,p->accesstype ,NID_info_access);
    if (accessinfoURL) {

      if (strcmp((char *)p->accessinfoURL, (char *)accessinfoURL)) {	
        fprintf(stderr, "Setting URL <%s>, was <%s>\n",
                accessinfoURL,p->accessinfoURL);
        OPENSSL_free(p->accessinfoURL);
        p->accessinfoURL = accessinfoURL;
        curl_easy_setopt(p->curl, CURLOPT_URL,p->accessinfoURL);
      }
      else 
        OPENSSL_free(accessinfoURL);
    }           
  }
  return(ok);
}


static CURLcode sslctxfun(CURL * curl, void * sslctx, void * parm)
{
  sslctxparm * p = (sslctxparm *) parm;
	
  SSL_CTX * ctx = (SSL_CTX *) sslctx ;
  fprintf(stderr,"sslctxfun start curl=%p ctx=%p parm=%p\n",
          (void *)curl,(void *)ctx,(void *)p);
		
  SSL_CTX_set_quiet_shutdown(ctx,1);
  SSL_CTX_set_cipher_list(ctx,"RC4-MD5");
  SSL_CTX_set_mode(ctx, SSL_MODE_AUTO_RETRY);

/* one might assume that the cert validaton would not fail when setting this,
   but it still does, see the error handling in the call back */

  SSL_CTX_set_verify_depth(ctx,0);
  SSL_CTX_set_verify(ctx,SSL_VERIFY_NONE,NULL); 

#if OPENSSL_VERSION_NUMBER<0x00907000L
/* in newer openssl versions we can set a parameter for the call back. */
  fprintf(stderr,"This version %s of openssl does not support a parm,"
          " setting global one\n", OPENSSL_VERSION_TEXT);
  /* this is only done to support 0.9.6 version */
  globalparm = parm;

/* in 0.9.6 the parm is not taken */ 
#endif
  SSL_CTX_set_cert_verify_callback(ctx, ssl_app_verify_callback, parm); 
  fprintf(stderr,"sslctxfun end\n");

  return CURLE_OK ;
}

int test(char *URL)
{
  CURLM* multi;
  sslctxparm p;

  int i;
  CURLMsg *msg;

  curl_global_init(CURL_GLOBAL_ALL);

  p.curl = curl_easy_init(); 

  p.accessinfoURL = (unsigned char *) strdup(URL);
  p.accesstype = OBJ_obj2nid(OBJ_txt2obj("AD_DVCS",0)) ;
 
  curl_easy_setopt(p.curl, CURLOPT_URL, p.accessinfoURL);

  curl_easy_setopt(p.curl, CURLOPT_SSL_CTX_FUNCTION, sslctxfun)  ; 
  curl_easy_setopt(p.curl, CURLOPT_SSL_CTX_DATA, &p);  

  curl_easy_setopt(p.curl, CURLOPT_SSL_VERIFYPEER, FALSE); 
  curl_easy_setopt(p.curl, CURLOPT_SSL_VERIFYHOST, 1);

  fprintf(stderr,"Going to perform %s\n",p.accessinfoURL);

  {
    CURLMcode res;
    int running;
    char done=FALSE;

    multi = curl_multi_init();

    res = curl_multi_add_handle(multi, p.curl);

    while(!done) {
      fd_set rd, wr, exc;
      int max_fd;
      struct timeval interval;

      interval.tv_sec = 1;
      interval.tv_usec = 0;

      while (res == CURLM_CALL_MULTI_PERFORM) {
        res = curl_multi_perform(multi, &running);
        fprintf(stderr, "running=%d res=%d\n",running,res);
        if (running <= 0) {
          done = TRUE;
          break;
        }
      }
      if(done)
        break;
      
      if (res != CURLM_OK) {
        fprintf(stderr, "not okay???\n");
        return 80;
      }

      FD_ZERO(&rd);
      FD_ZERO(&wr);
      FD_ZERO(&exc);
      max_fd = 0;

      if (curl_multi_fdset(multi, &rd, &wr, &exc, &max_fd) != CURLM_OK) {
        fprintf(stderr, "unexpected failured of fdset.\n");
        return 89;
      }

      if (select(max_fd+1, &rd, &wr, &exc, &interval) == -1) {
        fprintf(stderr, "bad select??\n");
        return 95;
      }

      res = CURLM_CALL_MULTI_PERFORM;
    }
    msg = curl_multi_info_read(multi, &running);
    /* this should now contain a result code from the easy handle, get it */
    i = msg->data.result;
  }

  fprintf(stderr, "all done\n");

  curl_multi_remove_handle(multi, p.curl);
  curl_easy_cleanup(p.curl);
  curl_multi_cleanup(multi);

  curl_global_cleanup(); 
  free(p.accessinfoURL);

  return i; 
}
#else /* USE_SSLEAY */
int test(char *URL)
{
  (void)URL;
  return CURLE_FAILED_INIT;
}
#endif /* USE_SSLEAY */
