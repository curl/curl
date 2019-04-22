/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) 1998 - 2015, Daniel Stenberg, <daniel@haxx.se>, et al.
 *
 * This software is licensed as described in the file COPYING, which
 * you should have received as part of this distribution. The terms
 * are also available at https://curl.haxx.se/docs/copyright.html.
 *
 * You may opt to use, copy, modify, merge, publish, distribute and/or sell
 * copies of the Software, and permit persons to whom the Software is
 * furnished to do so, under the terms of the COPYING file.
 *
 * This software is distributed on an "AS IS" basis, WITHOUT WARRANTY OF ANY
 * KIND, either express or implied.
 *
 ***************************************************************************/
/* <DESC>
 * CUSTOM HTTPS CERTIFICATE REVOCATION CHECK USING CRL AND OCSP.
 * </DESC>
 */
#include <stdio.h>
#include <curl/curl.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>
#include <openssl/ocsp.h>
#include <openssl/stack.h>

#define DEBUG_CURL_OUTPUT 0L

/*write callback to store something in SSL BIO*/
static size_t bio_write_cb(void *buffer, size_t size, size_t nmemb,
                           void *stream)
{
  BIO *bio = (BIO *)stream;
  return BIO_write(bio, buffer, size * nmemb);
}

/*read callback to read something from SSL BIO*/
static size_t bio_read_cb(void *dest, size_t size, size_t nmemb, void *userp)
{
  BIO *bio = (BIO *)(userp);
  size_t buffer_size = size * nmemb;
  return BIO_read(bio, dest, buffer_size);
}

/*try to find certificate issuer from trusted ssl store*/
X509 *get_certificate_issuer_from_store(X509_STORE *cert_store,
                                        X509 *certificate)
{
  X509_STORE_CTX *store_ctx = NULL;
  X509 *resultIssuer = NULL;
  X509_OBJECT *xobj;

  if(!cert_store) {
    fprintf(stderr, "SSL_CTX_get_cert_store failed\n");
    goto end;
  }

  store_ctx = X509_STORE_CTX_new();

  if(!store_ctx) {
    fprintf(stderr, "SSL_get_peer_cert_chain failed\n");
    goto end;
  }

  if(X509_STORE_CTX_init(store_ctx, cert_store, NULL, NULL) != 1) {
    fprintf(stderr, "X509_STORE_CTX_init failed\n");
    goto end;
  }

  xobj = X509_STORE_CTX_get_obj_by_subject(
    store_ctx, X509_LU_X509, X509_get_issuer_name(certificate));

  resultIssuer = X509_OBJECT_get0_X509(xobj);
  X509_up_ref(resultIssuer);

end:
  if(xobj)
    X509_OBJECT_free(xobj);
  if(store_ctx)
    X509_STORE_CTX_free(store_ctx);
  return resultIssuer;
}

/*get first CRL url from certificate. TODO: in real world you might want to use
 * all urls from certificate.*/
int get_crl_url(STACK_OF(DIST_POINT) * dist_points, const char **crlUrl)
{
  int result = 0;

  if(!dist_points) {
    fprintf(stderr, "NO X509_get_ext_d2i found\n");
    goto end;
  }

  for(int j = 0; j < sk_DIST_POINT_num(dist_points); j++) {
    DIST_POINT *dp = sk_DIST_POINT_value(dist_points, j);
    DIST_POINT_NAME *distpoint = dp->distpoint;

    if(distpoint->type == 0) { /* fullname GENERALIZEDNAME	*/
      for(int k = 0; k < sk_GENERAL_NAME_num(distpoint->name.fullname); k++) {
        GENERAL_NAME *gen;
        ASN1_IA5STRING *asn1_str;

        gen = sk_GENERAL_NAME_value(distpoint->name.fullname, k);
        asn1_str = gen->d.uniformResourceIdentifier;
        *crlUrl = (char *)ASN1_STRING_get0_data(asn1_str);

        result = 1;
        goto end;
      }
    }
    else if(distpoint->type == 1) { /* relativename X509NAME */
      STACK_OF(X509_NAME_ENTRY) *sk_relname = distpoint->name.relativename;
      for(int k = 0; k < sk_X509_NAME_ENTRY_num(sk_relname); k++) {
        X509_NAME_ENTRY *e;
        ASN1_STRING *d;

        e = sk_X509_NAME_ENTRY_value(sk_relname, k);
        d = X509_NAME_ENTRY_get_data(e);

        *crlUrl = (char *)ASN1_STRING_get0_data(d);
        result = 1;
        goto end;
      }
    }
  }

end:
  return result;
}

/*check crl signature using issuer certificate*/
int check_crl_signature(X509_CRL *crl, X509 *certificate_issuer)
{
  char name_buffer[256];
  EVP_PKEY *pkey;
  int crl_verify_result;

  if(X509_NAME_cmp(X509_CRL_get_issuer(crl),
                   X509_get_subject_name(certificate_issuer)) != 0) {

    fprintf(stderr,
            "Certificate issuer '%s' does not match CRL issuer\n",
            X509_NAME_oneline(X509_get_subject_name(certificate_issuer),
                              name_buffer,
                              sizeof(name_buffer)));
    fprintf(stderr,
            "%s",
            X509_NAME_oneline(
              X509_CRL_get_issuer(crl), name_buffer, sizeof(name_buffer)));
    return 0;
  }

  fprintf(stderr,
          "CRL issuer %s\n",
          X509_NAME_oneline(
            X509_CRL_get_issuer(crl), name_buffer, sizeof(name_buffer)));

  pkey = X509_get0_pubkey(certificate_issuer);
  crl_verify_result = X509_CRL_verify(crl, pkey);

  return crl_verify_result;
}

/*download crl from crl_url. and check certificate for revocation using
 * downloaded crl*/
static int check_certificate_using_crl(X509 *certificate, X509 *issuer)
{
  STACK_OF(DIST_POINT) *dist_points = NULL;
  BIO *crl_bio = NULL;
  CURL *curl = NULL;
  X509_REVOKED *revoked = NULL;
  int result = 0;
  CURLcode res;
  X509_CRL *crl = NULL;
  long http_status = 0;
  const char *crl_url;

  dist_points = (STACK_OF(DIST_POINT) *)X509_get_ext_d2i(
    certificate, NID_crl_distribution_points, NULL, NULL);

  if(!get_crl_url(dist_points, &crl_url)) {
    fprintf(stderr, "get_crl_url - crl url was not found\n");
    result = 1;
    goto end;
  }

  fprintf(stdout, "\tCRL url: `%s`\n", crl_url);

  curl = curl_easy_init();
  if(!curl) {
    fprintf(stderr, "curl_easy_init() failed\n");
    goto end;
  }

  /*create BIO to hold our crl body*/
  crl_bio = BIO_new(BIO_s_mem());
  if(!crl_bio) {
    fprintf(stderr, "BIO_new() failed\n");
    goto end;
  }

  /*download crl*/
  curl_easy_setopt(curl, CURLOPT_URL, crl_url);
  curl_easy_setopt(curl, CURLOPT_VERBOSE, DEBUG_CURL_OUTPUT);
  curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, &bio_write_cb);
  curl_easy_setopt(curl, CURLOPT_WRITEDATA, crl_bio);
  res = curl_easy_perform(curl);

  if(res != CURLE_OK) {
    fprintf(
      stderr, "curl_easy_perform() failed: %s\n", curl_easy_strerror(res));
    goto end;
  }

  curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_status);
  if(http_status != 200) {
    fprintf(stderr, "http_status %i != 200\n", (int)(http_status));
    goto end;
  }

  /*create SSL crl structure*/
  crl = d2i_X509_CRL_bio(crl_bio, NULL);
  if(!crl) {
    fprintf(stderr, "d2i_X509_CRL_bio() failed\n");
    goto end;
  }

  if(!check_crl_signature(crl, issuer)) {
    fprintf(stderr, "check_crl_signature failed\n");
    goto end;
  }

  /*TODO: in production code user might want to cache downloadeed crls*/

  /*check if certificate is in revocation list*/
  if(X509_CRL_get0_by_cert(crl, &revoked, certificate)) {
    fprintf(stderr, "certificate was revoked\n");
    goto end;
  }

  fprintf(stdout, "CRL: certificate was not revoked!\n");
  result = 1;

end:
  if(dist_points)
    sk_DIST_POINT_pop_free(dist_points, DIST_POINT_free);
  if(crl)
    X509_CRL_free(crl);
  if(crl_bio)
    BIO_vfree(crl_bio);
  if(curl)
    curl_easy_cleanup(curl);

  return result;
}

/*take ocsp_req_bio as input for http request body, perform POST http request
 * to ocsp_responder_url, write result to ocsp_response_bio*/
int perform_ocsp_http_request(char *ocsp_responder_url, BIO *ocsp_req_bio,
                              BIO *ocsp_response_bio)
{
  int result = 0;
  CURL *curl = NULL;
  CURLcode res;
  BUF_MEM *buf_mem = NULL;
  struct curl_slist *header_list = 0;
  long http_status = 0;

  BIO_get_mem_ptr(ocsp_req_bio, &buf_mem);
  if(!buf_mem) {
    fprintf(stderr, "BIO_get_mem_ptr failed\n");
    goto end;
  }

  curl = curl_easy_init();
  if(!curl) {
    fprintf(stderr, "curl_easy_init failed\n");
    goto end;
  }

  header_list =
    curl_slist_append(header_list, "Content-Type:application/ocsp-request");
  curl_easy_setopt(curl, CURLOPT_HTTPHEADER, header_list);

  curl_easy_setopt(curl, CURLOPT_URL, ocsp_responder_url);
  curl_easy_setopt(curl, CURLOPT_POST, 1L);
  curl_easy_setopt(curl, CURLOPT_READFUNCTION, bio_read_cb);
  curl_easy_setopt(curl, CURLOPT_READDATA, ocsp_req_bio);
  curl_easy_setopt(
    curl, CURLOPT_POSTFIELDSIZE_LARGE, (curl_off_t)(buf_mem->length));
  curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, &bio_write_cb);
  curl_easy_setopt(curl, CURLOPT_VERBOSE, DEBUG_CURL_OUTPUT);
  curl_easy_setopt(curl, CURLOPT_WRITEDATA, ocsp_response_bio);
  res = curl_easy_perform(curl);

  if(res != CURLE_OK) {
    fprintf(
      stderr, "curl_easy_perform() failed: %s\n", curl_easy_strerror(res));
    goto end;
  }

  curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_status);

  if(http_status != 200) {
    fprintf(stderr, "http status code %i != 200\n", (int)(http_status));
    goto end;
  }

  result = 1;

end:
  if(header_list)
    curl_slist_free_all(header_list);
  if(curl)
    curl_easy_cleanup(curl);

  return result;
}

/*verify response using certificateChain and store, and check certificate with
 * certId using ocsp response*/
int verify_certificate_using_ocsp_response(OCSP_RESPONSE *response,
                                           OCSP_CERTID *certId,
                                           STACK_OF(X509) * certificateChain,
                                           X509_STORE *store)
{
  int result = 0;
  OCSP_BASICRESP *basic_response = NULL;
  int certificateRevokeStatus = -1;
  int response_status;
  int revokeReason = 0;
  ASN1_GENERALIZEDTIME *revokeTime = NULL, *thisUpdate = NULL,
                       *nextUpdate = NULL;

  /*check OCSP response status*/
  response_status = OCSP_response_status(response);
  if(response_status != OCSP_RESPONSE_STATUS_SUCCESSFUL) {
    fprintf(stderr,
            "OCSP_response_status %i != OCSP_RESPONSE_STATUS_SUCCESSFUL\n",
            response_status);
    goto end;
  }

  basic_response = OCSP_response_get1_basic(response);

  if(!OCSP_basic_verify(
       basic_response, certificateChain, store, OCSP_TRUSTOTHER)) {
    fprintf(stderr, "OCSP_basic_verify failed \n");
    goto end;
  }

  if(!OCSP_resp_find_status(basic_response,
                            certId,
                            &certificateRevokeStatus,
                            &revokeReason,
                            &revokeTime,
                            &thisUpdate,
                            &nextUpdate)) {
    fprintf(stderr, "certificate was not found in response\n");
    goto end;
  }

  /*TODO: in production code user might want to cache downloadeed OCSP
   * response*/

  if(certificateRevokeStatus != V_OCSP_CERTSTATUS_GOOD) {
    fprintf(stderr,
            "certificate revoke status is not good %i\n",
            certificateRevokeStatus);
    goto end;
  }

  fprintf(
    stdout, "OCSP: certificate revoke status %i\n", certificateRevokeStatus);

  /*TODO: check response time values*/

  result = 1;

end:
  if(basic_response)
    OCSP_BASICRESP_free(basic_response);

  return result;
}

/*check certificate using OCSP*/
int check_certificate_using_ocsp(X509 *certificate, X509 *issuer,
                                 STACK_OF(X509) * certificate_chain,
                                 X509_STORE *store)
{
  int result = 0;
  char *ocsp_responder_url;
  const EVP_MD *cert_id_md = EVP_sha1();
  OCSP_CERTID *cert_id = NULL;
  STACK_OF(OPENSSL_STRING) *ocsp_list = NULL;

  OCSP_REQUEST *req = NULL;
  OCSP_CERTID *cert_id_dup = NULL;
  BIO *ocsp_req_bio = NULL;
  BIO *ocsp_response_bio = NULL;
  OCSP_RESPONSE *response = NULL;

  /*get ocsp info from certificate*/
  ocsp_list = X509_get1_ocsp(certificate);

  /*if ocsp info was not found, then it is nothing to do*/
  if(sk_OPENSSL_STRING_num(ocsp_list) == 0) {
    fprintf(stdout, "No ocsp responders were found\n");
    result = 1;
    goto end;
  }

  /*get the first ocsp url. TODO: iterate over all responders*/
  ocsp_responder_url = sk_OPENSSL_STRING_value(ocsp_list, 0);
  if(!ocsp_responder_url) {
    goto end;
  }

  /*create current certificate id*/
  cert_id = OCSP_cert_to_id(cert_id_md, certificate, issuer);
  if(!cert_id) {
    fprintf(stdout, "OCSP_cert_to_id failed\n");
    goto end;
  }

  /*create SSL BIO to hold our ocsp request body*/
  ocsp_req_bio = BIO_new(BIO_s_mem());
  if(!ocsp_req_bio) {
    fprintf(stderr, "BIO_new failed\n");
    goto end;
  }

  /*create new ocsp request and fill it*/
  req = OCSP_REQUEST_new();
  if(!req) {
    goto end;
  }
  cert_id_dup = OCSP_CERTID_dup(cert_id);
  if(!OCSP_request_add0_id(req, cert_id_dup)) {
    fprintf(stderr, "OCSP_request_add0_id failed\n");
    goto end;
  }
  cert_id_dup = NULL;

  /*write ocsp request to SSL bio*/
  if(!ASN1_item_i2d_bio(
       ASN1_ITEM_rptr(OCSP_REQUEST), ocsp_req_bio, (ASN1_VALUE *)req)) {
    fprintf(stderr, "ASN1_item_i2d_bio failed\n");
    goto end;
  }

  /*create SSL BIO to hold server ocsp response*/
  ocsp_response_bio = BIO_new(BIO_s_mem());
  if(!ocsp_response_bio) {
    fprintf(stderr, "BIO_new() failed\n");
    goto end;
  }

  /*perform http request*/
  if(!perform_ocsp_http_request(
       ocsp_responder_url, ocsp_req_bio, ocsp_response_bio)) {
    goto end;
  }

  /*decode server response*/
  if(!ASN1_item_d2i_bio(
       ASN1_ITEM_rptr(OCSP_RESPONSE), ocsp_response_bio, &response)) {
    fprintf(stderr, "ASN1_item_d2i_bio failed\n");
    goto end;
  }

  if(!response) {
    fprintf(stderr, "ASN1_item_d2i_bio failed");
    goto end;
  }

  /*verify response and check our certificate*/
  if(!verify_certificate_using_ocsp_response(
       response, cert_id, certificate_chain, store)) {
    goto end;
  }

  result = 1;

end:
  if(response)
    OCSP_RESPONSE_free(response);

  if(cert_id)
    OCSP_CERTID_free(cert_id);

  if(cert_id_dup)
    OCSP_CERTID_free(cert_id_dup);

  if(ocsp_list)
    X509_email_free(ocsp_list);

  if(ocsp_response_bio)
    BIO_vfree(ocsp_response_bio);

  if(ocsp_req_bio)
    BIO_vfree(ocsp_req_bio);

  if(req)
    OCSP_REQUEST_free(req);

  return result;
}

/*check certificate using ocsp stapling response data*/
int check_ocsp_stapling_status(unsigned char *status, long len,
                               X509 *certificate, X509 *issuer,
                               X509_STORE *cert_store, STACK_OF(X509) * chain)
{
  const unsigned char *p;
  OCSP_RESPONSE *rsp = NULL;
  const EVP_MD *cert_id_md = EVP_sha1();
  OCSP_CERTID *cert_id = NULL;
  int result = 0;

  p = status;
  rsp = d2i_OCSP_RESPONSE(NULL, &p, len);
  if(!rsp) {
    fprintf(stderr, "---------------------------------\n");
    goto end;
  }

  /*create current certificate id*/
  cert_id = OCSP_cert_to_id(cert_id_md, certificate, issuer);
  if(!cert_id) {
    fprintf(stdout, "OCSP_cert_to_id failed\n");
    goto end;
  }

  if(!verify_certificate_using_ocsp_response(
       rsp, cert_id, chain, cert_store)) {
    goto end;
  }

  result = 1;

end:
  if(rsp)
    OCSP_RESPONSE_free(rsp);

  if(cert_id)
    OCSP_CERTID_free(cert_id);

  return result;
}

/*custom verify_status_callback*/
static CURLcode user_verify_status_callback(CURL *curl, void *s, void *userptr)
{
  SSL *ssl = NULL;

  int chainLength = 0;
  STACK_OF(X509) *chain = NULL;
  X509_STORE *cert_store = NULL;

  CURLcode result = CURLE_SSL_INVALIDCERTSTATUS;
  char name_buffer[256];
  unsigned char *status = NULL;
  long len;

  const char *crlUrl = NULL;
  const char *ocspUrl = NULL;
  X509 *certificate;
  X509 *issuer;
  SSL_CTX *ctx = NULL;

  (void)curl; /* unused */
  (void)userptr; /* unused */

  fprintf(stdout,
          "user_verify_status_callback\n"
          "---------------------------------------\n");

  ssl = (SSL *)s;
  len = SSL_get_tlsext_status_ocsp_resp(ssl, &status);
  ctx = SSL_get_SSL_CTX(ssl);
  cert_store = SSL_CTX_get_cert_store(ctx);

  chain = SSL_get_peer_cert_chain(ssl);

  if(!chain) {
    fprintf(stderr, "SSL_get_peer_cert_chain failed\n");
    goto end;
  }

  chainLength = sk_X509_num(chain);
  if(chainLength == 0) {
    goto end;
  }

  certificate = sk_X509_value(chain, 0);
  if(chainLength < 2) {
    issuer = get_certificate_issuer_from_store(cert_store, certificate);
  }
  else {
    issuer = sk_X509_value(chain, 1);
    X509_up_ref(issuer);
  }

  if(!issuer) {
    fprintf(stderr, "cant find certificate issuer\n");
    goto end;
  }

  fprintf(stdout, "Certificate info :\n");

  fprintf(stdout,
          "\tsubj:   `%s`\n",
          X509_NAME_oneline(X509_get_subject_name(certificate),
                            name_buffer,
                            sizeof(name_buffer)));

  fprintf(stdout,
          "\tissuer: `%s`\n",
          X509_NAME_oneline(X509_get_issuer_name(certificate),
                            name_buffer,
                            sizeof(name_buffer)));

  if(!status) {
    fprintf(stdout,
            "ocsp status was not received. trying to check revocation using "
            "CRL/OCSP\n");

    if(!check_certificate_using_crl(certificate, issuer)) {
      goto end;
    }

    fprintf(stdout, "---------------------------------\n");

    if(!check_certificate_using_ocsp(certificate, issuer, chain, cert_store)) {
      goto end;
    }
  }
  else {
    fprintf(stdout, "ocsp status was received\n");

    if(!check_ocsp_stapling_status(
         status, len, certificate, issuer, cert_store, chain)) {
      goto end;
    }
  }

  result = CURLE_OK;

end:
  if(issuer)
    X509_free(issuer);

  fprintf(stdout,
          "user_verify_status_callback result %i\n"
          "---------------------------------\n",
          result);

  return result;
}

int main(int argc, char **argv)
{
  CURL *curl;
  CURLcode res;

  if(argc != 3) {
    fprintf(stderr, "provide options: url certificate.pem\n");
    return -1;
  }

  curl_global_init(CURL_GLOBAL_DEFAULT);

  curl = curl_easy_init();
  if(curl) {
    fprintf(stdout,
            "Http GET from url %s \n certificates file %s\n",
            argv[1],
            argv[2]);

    curl_easy_setopt(curl, CURLOPT_URL, argv[1]);
    curl_easy_setopt(curl, CURLOPT_CAINFO, argv[2]);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 1L);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 1L);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYSTATUS, 1L);
    curl_easy_setopt(curl, CURLOPT_VERBOSE, DEBUG_CURL_OUTPUT);
    curl_easy_setopt(
      curl, CURLOPT_SSL_VERIFYSTATUS_FUNCTION, &user_verify_status_callback);

    res = curl_easy_perform(curl);
    if(res != CURLE_OK)
      fprintf(
        stderr, "curl_easy_perform() failed: %s\n", curl_easy_strerror(res));

    curl_easy_cleanup(curl);
  }

  curl_global_cleanup();

  return 0;
}
