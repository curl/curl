/*
  curlx.c  Authors: Peter Sylvester, Jean-Paul Merlin

  This is a little program to demonstrate the usage of

  - an ssl initialisation callback setting a user key and trustbases
  coming from a pkcs12 file
  - using an ssl application callback to find a URI in the
  certificate presented during ssl session establishment.

*/


/*
 * Copyright (c) 2003 The OpenEvidence Project.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions, the following disclaimer,
 *    and the original OpenSSL and SSLeay Licences below.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions, the following disclaimer
 *    and the original OpenSSL and SSLeay Licences below in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * 3. All advertising materials mentioning features or use of this
 *    software must display the following acknowledgments:
 *    "This product includes software developed by the Openevidence Project
 *    for use in the OpenEvidence Toolkit. (http://www.openevidence.org/)"
 *    This product includes software developed by the OpenSSL Project
 *    for use in the OpenSSL Toolkit (http://www.openssl.org/)"
 *    This product includes cryptographic software written by Eric Young
 *    (eay@cryptsoft.com).  This product includes software written by Tim
 *    Hudson (tjh@cryptsoft.com)."
 *
 * 4. The names "OpenEvidence Toolkit" and "OpenEvidence Project" must not be
 *    used to endorse or promote products derived from this software without
 *    prior written permission. For written permission, please contact
 *    openevidence-core@openevidence.org.
 *
 * 5. Products derived from this software may not be called "OpenEvidence"
 *    nor may "OpenEvidence" appear in their names without prior written
 *    permission of the OpenEvidence Project.
 *
 * 6. Redistributions of any form whatsoever must retain the following
 *    acknowledgments:
 *    "This product includes software developed by the OpenEvidence Project
 *    for use in the OpenEvidence Toolkit (http://www.openevidence.org/)
 *    This product includes software developed by the OpenSSL Project
 *    for use in the OpenSSL Toolkit (http://www.openssl.org/)"
 *    This product includes cryptographic software written by Eric Young
 *    (eay@cryptsoft.com).  This product includes software written by Tim
 *    Hudson (tjh@cryptsoft.com)."
 *
 * THIS SOFTWARE IS PROVIDED BY THE OpenEvidence PROJECT ``AS IS'' AND ANY
 * EXPRESSED OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE OpenEvidence PROJECT OR
 * ITS CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 * ====================================================================
 *
 * This product includes software developed by the OpenSSL Project
 * for use in the OpenSSL Toolkit (http://www.openssl.org/)
 * This product includes cryptographic software written by Eric Young
 * (eay@cryptsoft.com).  This product includes software written by Tim
 * Hudson (tjh@cryptsoft.com).
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <curl/curl.h>
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

static char *curlx_usage[]={
  "usage: curlx args\n",
  " -p12 arg         - tia  file ",
  " -envpass arg     - environement variable which content the tia private key password",
  " -out arg         - output file (response)- default stdout",
  " -in arg          - input file (request)- default stdin",
  " -connect arg     - URL of the server for the connection ex: www.openevidenve.org",
  " -mimetype arg    - MIME type for data in ex : application/timestamp-query or application/dvcs -default application/timestamp-query",
  " -acceptmime arg  - MIME type acceptable for the response ex : application/timestamp-response or application/dvcs -default none",
  " -accesstype arg  - an Object identifier in an AIA/SIA method, e.g. AD_DVCS or ad_timestamping",
  NULL
};

/*

./curlx -p12 psy.p12 -envpass XX -in request -verbose -accesstype AD_DVCS
-mimetype application/dvcs -acceptmime application/dvcs -out response

*/

/* This is a context that we pass to all callbacks */

typedef struct sslctxparm_st {
  unsigned char * p12file ;
  const char * pst ;
  PKCS12 * p12 ;
  EVP_PKEY * pkey ;
  X509 * usercert ;
  STACK_OF(X509) * ca ;
  CURL * curl;
  BIO * errorbio;
  int accesstype ;
  int verbose;

} sslctxparm;

/* some helper function. */

static char *i2s_ASN1_IA5STRING( ASN1_IA5STRING *ia5)
{
  char *tmp;
  if(!ia5 || !ia5->length)
    return NULL;
  tmp = OPENSSL_malloc(ia5->length + 1);
  memcpy(tmp, ia5->data, ia5->length);
  tmp[ia5->length] = 0;
  return tmp;
}

/* A conveniance routine to get an access URI. */

static unsigned char *my_get_ext(X509 * cert, const int type, int extensiontype) {

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

/* This is an application verification call back, it does not
   perform any addition verification but tries to find a URL
   in the presented certificat. If found, this will become
   the URL to be used in the POST.
*/

static int ssl_app_verify_callback(X509_STORE_CTX *ctx, void *arg)
{
  sslctxparm * p = (sslctxparm *) arg;
  int ok;

  if (p->verbose > 2)
    BIO_printf(p->errorbio,"entering ssl_app_verify_callback\n");

  if ((ok= X509_verify_cert(ctx)) && ctx->cert) {
    unsigned char * accessinfo ;
    if (p->verbose > 1)
      X509_print_ex(p->errorbio,ctx->cert,0,0);

    if (accessinfo = my_get_ext(ctx->cert,p->accesstype ,NID_sinfo_access)) {
      if (p->verbose)
        BIO_printf(p->errorbio,"Setting URL from SIA to: %s\n", accessinfo);

      curl_easy_setopt(p->curl, CURLOPT_URL,accessinfo);
    }
    else if (accessinfo = my_get_ext(ctx->cert,p->accesstype,
                                     NID_info_access)) {
      if (p->verbose)
        BIO_printf(p->errorbio,"Setting URL from AIA to: %s\n", accessinfo);

      curl_easy_setopt(p->curl, CURLOPT_URL,accessinfo);
    }
  }
  if (p->verbose > 2)
    BIO_printf(p->errorbio,"leaving ssl_app_verify_callback with %d\n", ok);
  return(ok);
}


/* This is an example of an curl SSL initialisation call back. The callback sets:
   - a private key and certificate
   - a trusted ca certificate
   - a preferred cipherlist
   - an application verification callback (the function above)
*/

static CURLcode sslctxfun(CURL * curl, void * sslctx, void * parm) {

  sslctxparm * p = (sslctxparm *) parm;
  SSL_CTX * ctx = (SSL_CTX *) sslctx ;

  if (!SSL_CTX_use_certificate(ctx,p->usercert)) {
    BIO_printf(p->errorbio, "SSL_CTX_use_certificate problem\n"); goto err;
  }
  if (!SSL_CTX_use_PrivateKey(ctx,p->pkey)) {
    BIO_printf(p->errorbio, "SSL_CTX_use_PrivateKey\n"); goto err;
  }

  if (!SSL_CTX_check_private_key(ctx)) {
    BIO_printf(p->errorbio, "SSL_CTX_check_private_key\n"); goto err;
  }

  SSL_CTX_set_quiet_shutdown(ctx,1);
  SSL_CTX_set_cipher_list(ctx,"RC4-MD5");
  SSL_CTX_set_mode(ctx, SSL_MODE_AUTO_RETRY);

  X509_STORE_add_cert(ctx->cert_store,sk_X509_value(p->ca,
                                                    sk_X509_num(p->ca)-1));

  SSL_CTX_set_verify_depth(ctx,2);

  SSL_CTX_set_verify(ctx,SSL_VERIFY_PEER,NULL);

  SSL_CTX_set_cert_verify_callback(ctx, ssl_app_verify_callback, parm);


  return CURLE_OK ;
  err:
  ERR_print_errors(p->errorbio);
  return CURLE_SSL_CERTPROBLEM;

}

int main(int argc, char **argv) {

  BIO* in=NULL;
  BIO* out=NULL;

  char * outfile = NULL;
  char * infile = NULL ;

  int tabLength=100;
  char *binaryptr;
  char* mimetype;
  char* mimetypeaccept=NULL;
  char* contenttype;
  char** pp;
  unsigned char* hostporturl = NULL;
  binaryptr=(char*)malloc(tabLength);
  BIO * p12bio ;
  char **args = argv + 1;
  unsigned char * serverurl;
  sslctxparm p;
  char *response;
  p.verbose = 0;

  CURLcode res;
  struct curl_slist * headers=NULL;

  p.errorbio = BIO_new_fp (stderr, BIO_NOCLOSE);

  curl_global_init(CURL_GLOBAL_DEFAULT);

  /* we need some more for the P12 decoding */

  OpenSSL_add_all_ciphers();
  OpenSSL_add_all_digests();
  ERR_load_crypto_strings();


  int badarg=0;

  while (*args && *args[0] == '-') {
    if (!strcmp (*args, "-in")) {
      if (args[1]) {
        infile=*(++args);
      } else badarg=1;
    } else if (!strcmp (*args, "-out")) {
      if (args[1]) {
        outfile=*(++args);
      } else badarg=1;
    } else if (!strcmp (*args, "-p12")) {
      if (args[1]) {
        p.p12file = *(++args);
      } else badarg=1;
    } else if (strcmp(*args,"-envpass") == 0) {
      if (args[1]) {
        p.pst = getenv(*(++args));
      } else badarg=1;
    } else if (strcmp(*args,"-connect") == 0) {
      if (args[1]) {
        hostporturl = *(++args);
      } else badarg=1;
    } else if (strcmp(*args,"-mimetype") == 0) {
      if (args[1]) {
        mimetype = *(++args);
      } else badarg=1;
    } else if (strcmp(*args,"-acceptmime") == 0) {
      if (args[1]) {
        mimetypeaccept = *(++args);
      } else badarg=1;
    } else if (strcmp(*args,"-accesstype") == 0) {
      if (args[1]) {
        if ((p.accesstype = OBJ_obj2nid(OBJ_txt2obj(*++args,0))) == 0) badarg=1;
      } else badarg=1;
    } else if (strcmp(*args,"-verbose") == 0) {
      p.verbose++;
    } else badarg=1;
    args++;
  }

  if (mimetype==NULL || mimetypeaccept == NULL) badarg = 1;

  if (badarg) {
    for (pp=curlx_usage; (*pp != NULL); pp++)
      BIO_printf(p.errorbio,"%s\n",*pp);
    BIO_printf(p.errorbio,"\n");
    goto err;
  }



  /* set input */

  if ((in=BIO_new(BIO_s_file())) == NULL) {
    BIO_printf(p.errorbio, "Error setting input bio\n");
    goto err;
  } else if (infile == NULL)
    BIO_set_fp(in,stdin,BIO_NOCLOSE|BIO_FP_TEXT);
  else if (BIO_read_filename(in,infile) <= 0) {
    BIO_printf(p.errorbio, "Error opening input file %s\n", infile);
    BIO_free(in);
    goto err;
  }

  /* set output  */

  if ((out=BIO_new(BIO_s_file())) == NULL) {
    BIO_printf(p.errorbio, "Error setting output bio.\n");
    goto err;
  } else if (outfile == NULL)
    BIO_set_fp(out,stdout,BIO_NOCLOSE|BIO_FP_TEXT);
  else if (BIO_write_filename(out,outfile) <= 0) {
    BIO_printf(p.errorbio, "Error opening output file %s\n", outfile);
    BIO_free(out);
    goto err;
  }


  p.errorbio = BIO_new_fp (stderr, BIO_NOCLOSE);

  if (!(p.curl = curl_easy_init())) {
    BIO_printf(p.errorbio, "Cannot init curl lib\n");
    goto err;
  }



  if (!(p12bio = BIO_new_file(p.p12file , "rb"))) {
    BIO_printf(p.errorbio, "Error opening P12 file %s\n", p.p12file); goto err;
  }
  if (!(p.p12 = d2i_PKCS12_bio (p12bio, NULL))) {
    BIO_printf(p.errorbio, "Cannot decode P12 structure %s\n", p.p12file); goto err;
  }

  p.ca= NULL;
  if (!(PKCS12_parse (p.p12, p.pst, &(p.pkey), &(p.usercert), &(p.ca) ) )) {
    BIO_printf(p.errorbio,"Invalid P12 structure in %s\n", p.p12file); goto err;
  }

  if (sk_X509_num(p.ca) <= 0) {
    BIO_printf(p.errorbio,"No trustworthy CA given.%s\n", p.p12file); goto err;
  }

  if (p.verbose > 1)
    X509_print_ex(p.errorbio,p.usercert,0,0);

  /* determine URL to go */

  if (hostporturl) {
    serverurl=(char*) malloc(9+strlen(hostporturl));
    sprintf(serverurl,"https://%s",hostporturl);
  }
  else if (p.accesstype != 0) { /* see whether we can find an AIA or SIA for a given access type */
    if (!(serverurl = my_get_ext(p.usercert,p.accesstype,NID_info_access))) {
      BIO_printf(p.errorbio,"no service URL in user cert "
                 "cherching in others certificats\n");
      int j=0;
      int find=0;
      for (j=0;j<sk_X509_num(p.ca);j++) {
        if ((serverurl = my_get_ext(sk_X509_value(p.ca,j),p.accesstype,
                                    NID_info_access)))
          break;
        if ((serverurl = my_get_ext(sk_X509_value(p.ca,j),p.accesstype,
                                    NID_sinfo_access)))
          break;
      }
    }
  }

  if (!serverurl) {
    BIO_printf(p.errorbio, "no service URL in certificats,"
               " check '-accesstype (AD_DVCS | ad_timestamping)'"
               " or use '-connect'\n");
    goto err;
  }

  if (p.verbose)
    BIO_printf(p.errorbio, "Service URL: <%s>\n", serverurl);

  curl_easy_setopt(p.curl, CURLOPT_URL, serverurl);

  /* Now specify the POST binary data */

  curl_easy_setopt(p.curl, CURLOPT_POSTFIELDS, binaryptr);
  curl_easy_setopt(p.curl, CURLOPT_POSTFIELDSIZE,tabLength);

  /* pass our list of custom made headers */

  contenttype=(char*) malloc(15+strlen(mimetype));
  sprintf(contenttype,"Content-type: %s",mimetype);
  headers = curl_slist_append(headers,contenttype);
  curl_easy_setopt(p.curl, CURLOPT_HTTPHEADER, headers);

  if (p.verbose)
    BIO_printf(p.errorbio, "Service URL: <%s>\n", serverurl);

  {
    FILE *outfp;
    BIO_get_fp(out,&outfp);
    curl_easy_setopt(p.curl, CURLOPT_FILE,outfp);
  }

  res = curl_easy_setopt(p.curl, CURLOPT_SSL_CTX_FUNCTION, sslctxfun)  ;

  if (res != CURLE_OK)
    BIO_printf(p.errorbio,"%d %s=%d %d\n", __LINE__, "CURLOPT_SSL_CTX_FUNCTION",CURLOPT_SSL_CTX_FUNCTION,res);

  curl_easy_setopt(p.curl, CURLOPT_SSL_CTX_DATA, &p);

  {
    int lu; int i=0;
    while ((lu = BIO_read (in,&binaryptr[i],tabLength-i)) >0 ) {
      i+=lu;
      if (i== tabLength) {
        tabLength+=100;
        binaryptr=(char*)realloc(binaryptr,tabLength); /* should be more careful */
      }
    }
    tabLength = i;
  }
  /* Now specify the POST binary data */

  curl_easy_setopt(p.curl, CURLOPT_POSTFIELDS, binaryptr);
  curl_easy_setopt(p.curl, CURLOPT_POSTFIELDSIZE,tabLength);


  /* Perform the request, res will get the return code */

  BIO_printf(p.errorbio,"%d %s %d\n", __LINE__, "curl_easy_perform",
             res = curl_easy_perform(p.curl));
  {
    int result =curl_easy_getinfo(p.curl,CURLINFO_CONTENT_TYPE,&response);
    if( mimetypeaccept && p.verbose)
      if(!strcmp(mimetypeaccept,response))
        BIO_printf(p.errorbio,"the response has a correct mimetype : %s\n",
                   response);
      else
        BIO_printf(p.errorbio,"the reponse doesn\'t has an acceptable "
                   "mime type, it is %s instead of %s\n",
                   response,mimetypeaccept);
  }

  /*** code d'erreur si accept mime ***, egalement code return HTTP != 200 ***/

/* free the header list*/

  curl_slist_free_all(headers);

  /* always cleanup */
  curl_easy_cleanup(p.curl);

  BIO_free(in);
  BIO_free(out);
  return (EXIT_SUCCESS);

  err: BIO_printf(p.errorbio,"error");
  exit(1);
}
