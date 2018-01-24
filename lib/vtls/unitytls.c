/*
 * Source file for all unitytls-specific code for the TLS/SSL layer. No code
 * but vtls.c should ever call or use these functions.
 *
 */

#include "curl_setup.h"

#ifdef USE_UNITYTLS

#include "unitytls_interface.h"
#include "urldata.h"
#include "sendf.h"
#include "vtls.h"
#include "connect.h" /* for the connect timeout */
#include "select.h"

#if !defined(WIN32)
#include <dirent.h>
#endif

/* The last #include files should be: */
#include "curl_memory.h"
#include "memdebug.h"

/*
* UnityTls interface
*
* Usually we expect the user to call curl_unitytls_set_interface before using curl.
* However, this does not work for running curls' tests in which case we define UNITYTLS_LINKED and link directly against the UnityTLS module
*/
//#define UNITYTLS_LINKED

static unitytls_interface_struct* unitytls = NULL;

#if defined(UNITYTLS_LINKED)
extern unitytls_interface_struct* unitytls_get_interface_struct();
#endif

void curl_unitytls_set_interface(unitytls_interface_struct* interface)
{
  unitytls = interface;
}

static bool unitytls_check_interface_available(struct Curl_easy* data)
{
  if(!unitytls) {
#if defined(UNITYTLS_LINKED)
    curl_unitytls_set_interface(unitytls_get_interface_struct());
#else
    if(data)
      failf(data, "UnityTls interface was not set. Call Curl_unitytls_set_interface first.");
    return false;
#endif
  }
  return true;
}

/*
* Implementation
*
*/

static char* load_file(const char* filepath, long* out_size)
{
  char* filecontent;
  FILE* file = fopen(filepath, "rb");

  if(!file)
    return NULL;

  fseek(file, 0, SEEK_END);
  *out_size = ftell(file);
  fseek(file, 0, SEEK_SET);

  filecontent = malloc(*out_size);
  fread(filecontent, *out_size, 1, file);
  fclose(file);

  return filecontent;
}

static bool unitytls_append_pem_file(const char* filepath, unitytls_x509list* list, unitytls_errorstate* err)
{
  long fsize;
  char* filecontent = load_file(filepath, &fsize);
  if (!filecontent)
    return false;

  unitytls->unitytls_x509list_append_pem(list, filecontent, fsize, err);

  free(filecontent);
  return true;
}

static unitytls_key* unitytls_key_parse_pem_from_file(const char* filepath, const char* password, unitytls_errorstate* err)
{
  long fsize;
  unitytls_key* key = NULL;
  char* filecontent = load_file(filepath, &fsize);
  if (!filecontent)
    return NULL;

  unitytls->unitytls_key_parse_pem(filecontent, fsize, password, strlen(password), err);

  free(filecontent);
  return key;
}

static bool unitytls_parse_all_pem_in_dir(struct Curl_easy* data, const char* path, unitytls_x509list* list, unitytls_errorstate* err)
{
  bool success = false;
#if defined(WIN32)
  size_t len = strlen(path);
  WIN32_FIND_DATAA file_data;
  char filename[MAX_PATH];
  HANDLE hFind;

  if(err->code != UNITYTLS_SUCCESS)
    return false;

  /* Path needs to end with '\*' */
  if(len + 2 >= MAX_PATH)
    return false;
  memset(filename, 0, MAX_PATH);
  memcpy(filename, path, len);
  filename[len++] = '\\';
  filename[len++] = '*';

  hFind = FindFirstFileA(filename, &file_data);
  if(hFind == INVALID_HANDLE_VALUE)
    return CURLE_SSL_CACERT;

  do
  {
    if(file_data.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
      continue;

    /* Try adding the file. Might or might not be a PEM file, so failure is not an error */
    unitytls_append_pem_file(file_data.cFileName, list, err);
    if(err->code != UNITYTLS_SUCCESS)
      *err = unitytls->unitytls_errorstate_create(); /* Need to reset to keep future falls to unitytls_append_pem_file working */
    else
      success = true;
  }
  while(FindNextFileA(hFind, &file_data) != 0);

  FindClose(hFind);
#else /* WIN32 */
  int snp_ret;
  struct dirent *entry;
  struct stat sb;
  char entry_name[512];
  DIR *dp;

  if(err->code != UNITYTLS_SUCCESS)
    return false;

  dp = opendir(path);
  if(dp == NULL)
    success = false;

  while((entry = readdir(dp)) != NULL) {
    snp_ret = snprintf(entry_name, sizeof(entry_name), "%s/%s", path, entry->d_name);
    if(snp_ret < 0 || (size_t)snp_ret >= sizeof(entry_name)) {
      break;
    }

    if(!S_ISREG(sb.st_mode))
      continue;

    /* Try adding the file. Might or might not be a PEM file, so failure is not an error */
    unitytls_append_pem_file(entry_name, list, err);
    if(err->code != UNITYTLS_SUCCESS)
      *err = unitytls->unitytls_errorstate_create(); /* Need to reset to keep future falls to unitytls_append_pem_file working */
    else
      success = true;
  }

  closedir(dp);
#endif /* WIN32 */

  return success;
}

static size_t on_read(void* userData, UInt8* buffer, size_t bufferLen, unitytls_errorstate* errorState)
{
  struct ssl_connect_data* connssl = (struct ssl_connect_data*)userData;
  CURLcode result;
  ssize_t read = 0;

  result = Curl_read_plain(connssl->sockfd, (char*)(buffer), bufferLen, &read);
  if(result == CURLE_AGAIN) {
    unitytls->unitytls_errorstate_raise_error(errorState, UNITYTLS_USER_WOULD_BLOCK);
    return 0;
  }
  else if(result != CURLE_OK) {
    unitytls->unitytls_errorstate_raise_error(errorState, UNITYTLS_USER_READ_FAILED);
    return 0;
  }

  return read;
}

static size_t on_write(void* userData, const UInt8* data, size_t bufferLen, unitytls_errorstate* errorState)
{
  struct ssl_connect_data* connssl = (struct ssl_connect_data*)userData;
  CURLcode result;
  ssize_t written = 0;

  result = Curl_write_plain(connssl->conn, connssl->sockfd, data, bufferLen, &written);
  if(result == CURLE_AGAIN) {
    unitytls->unitytls_errorstate_raise_error(errorState, UNITYTLS_USER_WOULD_BLOCK);
    return 0;
  }
  else if(result != CURLE_OK) {
    unitytls->unitytls_errorstate_raise_error(errorState, UNITYTLS_USER_WRITE_FAILED);
    return 0;
  }

  return written;
}

static void on_certificate_request(void* userData, unitytls_tlsctx* ctx,
                                   const char* cn, size_t cnLen,
                                   unitytls_x509name* caList, size_t caListLen,
                                   unitytls_x509list_ref* chain, unitytls_key_ref* key,
                                   unitytls_errorstate* errorState)
{
  struct ssl_connect_data* connssl = (struct ssl_connect_data*)userData;

  if(connssl->clicert)
    *chain = unitytls->unitytls_x509list_get_ref(connssl->clicert, errorState);
  if(connssl->pk)
    *key = unitytls->unitytls_key_get_ref(connssl->pk, errorState);
}

static unitytls_x509verify_result on_verify(void* userData, unitytls_x509list_ref chain, unitytls_errorstate* errorState)
{
  struct ssl_connect_data* connssl = (struct ssl_connect_data*)userData;
  struct connectdata* conn = connssl->conn;
  const bool verifypeer = SSL_CONN_CONFIG(verifypeer);
  const bool verifyhost = SSL_CONN_CONFIG(verifyhost);
  const char* const hostname = SSL_IS_PROXY() ? conn->http_proxy.host.name : conn->host.name;
  unitytls_x509verify_result verify_result = UNITYTLS_X509VERIFY_SUCCESS;

  /* According to documentation the options verifypeer and verifyhost are independent of each other! */
  /* UnityTls however, verifies both the certificate as well as the hostname in the same call. */
  if(verifypeer || verifyhost) {
    if(connssl->cacert) {
      unitytls_x509list_ref trustCAref = unitytls->unitytls_x509list_get_ref(connssl->cacert, errorState);
      verify_result = unitytls->unitytls_x509verify_explicit_ca(chain, trustCAref, hostname, strlen(hostname), NULL, NULL, errorState);
    }
    else {
      verify_result = unitytls->unitytls_x509verify_default_ca(chain, hostname, strlen(hostname), NULL, NULL, errorState);
    }

    /* Filter out special codes right away, so we can safely filter bitflags later on. */
    if(verify_result == UNITYTLS_X509VERIFY_NOT_DONE || verify_result == UNITYTLS_X509VERIFY_FATAL_ERROR)
      return verify_result;

    /* not interested in hostname verification */
    if(!verifyhost) {
      verify_result &= ~((unitytls_x509verify_result)UNITYTLS_X509VERIFY_FLAG_CN_MISMATCH);
    }
    /* only interested in hostname verification */
    else if(!verifypeer) {
      verify_result &=  ((unitytls_x509verify_result)UNITYTLS_X509VERIFY_FLAG_CN_MISMATCH);
    }
  }

  return verify_result;
}

static ssize_t unitytls_send(struct connectdata *conn, int sockindex,
                             const void *mem, size_t len,
                             CURLcode *curlcode)
{
  size_t written = 0;
  unitytls_errorstate err = unitytls->unitytls_errorstate_create();

  written = unitytls->unitytls_tlsctx_write(conn->ssl[sockindex].ctx, (const UInt8*)mem, len, &err);

  if(err.code != UNITYTLS_SUCCESS) {
    if(err.code == UNITYTLS_USER_WOULD_BLOCK)
      *curlcode = CURLE_AGAIN;
    else {
      *curlcode = CURLE_SEND_ERROR;
      failf(conn->data, "Sending data failed with unitytls error code %i", err.code);
    }
    return -1;
  }

  return written;
}

static ssize_t unitytls_recv(struct connectdata *conn, int sockindex,
                             char *buf, size_t buffersize,
                             CURLcode *curlcode)
{
  size_t read = 0;
  unitytls_errorstate err = unitytls->unitytls_errorstate_create();

  read = unitytls->unitytls_tlsctx_read(conn->ssl[sockindex].ctx, (UInt8*)buf, buffersize, &err);

  if(err.code != UNITYTLS_SUCCESS) {
    if(err.code == UNITYTLS_USER_WOULD_BLOCK)
      *curlcode = CURLE_AGAIN;
    else {
      *curlcode = CURLE_RECV_ERROR;
      failf(conn->data, "Receiving data failed with unitytls error code %i", err.code);
    }
    return -1;
  }

  return read;
}


static CURLcode unitytls_connect_step1(struct connectdata* conn, int sockindex)
{
  struct Curl_easy* data = conn->data;
  struct ssl_connect_data* connssl = &conn->ssl[sockindex];
  const char* const ssl_cafile = SSL_CONN_CONFIG(CAfile);
  const bool verifypeer = SSL_CONN_CONFIG(verifypeer);
  const char* const ssl_capath = SSL_CONN_CONFIG(CApath);
  char* const ssl_cert = SSL_SET_OPTION(cert);
  const char* const ssl_crlfile = SSL_SET_OPTION(CRLfile);
  const char* const hostname = SSL_IS_PROXY() ? conn->http_proxy.host.name : conn->host.name;

  unitytls_errorstate err = unitytls->unitytls_errorstate_create();
  unitytls_tlsctx_protocolrange protocol_range;
  unitytls_tlsctx_callbacks callbacks = { on_read, on_write, connssl };

  /* unitytls only supports TLS 1.0-1.2 */
  if(SSL_CONN_CONFIG(version) != CURL_SSLVERSION_DEFAULT &&
     SSL_CONN_CONFIG(version) != CURL_SSLVERSION_TLSv1_0 &&
     SSL_CONN_CONFIG(version) != CURL_SSLVERSION_TLSv1_1 &&
     SSL_CONN_CONFIG(version) != CURL_SSLVERSION_TLSv1_2) {
    failf(data, "unitytls only supports TLS 1.0-1.2");
    return CURLE_SSL_CONNECT_ERROR;
  }

  /* Load the trusted CA */
  if (ssl_cafile || ssl_capath)
    connssl->cacert = unitytls->unitytls_x509list_create(&err);

  if(ssl_cafile) {
    if(!unitytls_append_pem_file(ssl_cafile, connssl->cacert, &err) || err.code != UNITYTLS_SUCCESS) {
      failf(data, "Error reading ca cert file from %s", ssl_cafile);
      if(verifypeer)
        return CURLE_SSL_CACERT_BADFILE;
      err = unitytls->unitytls_errorstate_create(); /* ignore any errors that came up */
    }
  }

  if(ssl_capath) {
    if(!unitytls_parse_all_pem_in_dir(data, ssl_capath, connssl->cacert, &err) || err.code != UNITYTLS_SUCCESS) {
      failf(data, "Error reading ca cert path from %s", ssl_cafile);
      if(verifypeer)
        return CURLE_SSL_CACERT;
      err = unitytls->unitytls_errorstate_create(); /* ignore any errors that came up */
    }
  }

  /* Load the client certificate */
  if(ssl_cert) {
    connssl->clicert = unitytls->unitytls_x509list_create(&err);
    if(unitytls_append_pem_file(ssl_cert, connssl->clicert, &err) != CURLE_OK || err.code != UNITYTLS_SUCCESS) {
      failf(data, "Error reading client cert file %s", ssl_cafile);
      return CURLE_SSL_CERTPROBLEM;
    }
  }

  /* Load the client private key */
  if(SSL_SET_OPTION(key)) {
    connssl->pk = unitytls_key_parse_pem_from_file(SSL_SET_OPTION(key), SSL_SET_OPTION(key_passwd), &err);
    if(!connssl->pk || err.code != UNITYTLS_SUCCESS) {
      failf(data, "Error reading private key %s", SSL_SET_OPTION(key));
      return CURLE_SSL_CERTPROBLEM;
    }
  }
  else {
    connssl->pk = NULL;
  }

  /* We don't support CRL */
  if(ssl_crlfile) {
    failf(data, "UnityTls does not suppport crl");
  }

  /* Create and configure context */
  switch(SSL_CONN_CONFIG(version)) {
    case CURL_SSLVERSION_DEFAULT:
      protocol_range = unitytls->UNITYTLS_TLSCTX_PROTOCOLRANGE_DEFAULT;
      break;
    case CURL_SSLVERSION_TLSv1_0:
      protocol_range.max = protocol_range.min = UNITYTLS_PROTOCOL_TLS_1_0;
      break;
    case CURL_SSLVERSION_TLSv1_1:
      protocol_range.max = protocol_range.min = UNITYTLS_PROTOCOL_TLS_1_1;
      break;
    case CURL_SSLVERSION_TLSv1_2:
      protocol_range.max = protocol_range.min = UNITYTLS_PROTOCOL_TLS_1_2;
      break;
    default:
      failf(data, "Unrecognized/unsupported parameter passed via CURLOPT_SSLVERSION");
      return CURLE_SSL_CONNECT_ERROR;
  }

  connssl->ctx = unitytls->unitytls_tlsctx_create_client(protocol_range, callbacks, hostname, strlen(hostname), &err);
  unitytls->unitytls_tlsctx_set_certificate_callback(connssl->ctx, on_certificate_request, connssl, &err);
  unitytls->unitytls_tlsctx_set_x509verify_callback(connssl->ctx, on_verify, connssl, &err);
  if(err.code != UNITYTLS_SUCCESS) {
    failf(data, "Error creating and configuring untiytls context: %i", err.code);
    return CURLE_SSL_CONNECT_ERROR;
  }

  connssl->conn = conn;
  connssl->sockfd = conn->sock[sockindex];
  connssl->connecting_state = ssl_connect_2;

  /* give application a chance to interfere with SSL set up. */
  if(data->set.ssl.fsslctx) {
    CURLcode result = (*data->set.ssl.fsslctx)(data, connssl->ctx, data->set.ssl.fsslctxp);
    if(result != CURLE_OK) {
      failf(data, "error signaled by ssl ctx callback");
      return result;
    }
  }

  return CURLE_OK;
}

static CURLcode unitytls_connect_step2(struct Curl_easy* data, struct ssl_connect_data* connssl)
{
  unitytls_errorstate err = unitytls->unitytls_errorstate_create();
  unitytls_x509verify_result verifyresult = unitytls->unitytls_tlsctx_process_handshake(connssl->ctx, &err);
  CURLcode result = CURLE_OK;

  if (err.code == UNITYTLS_USER_WOULD_BLOCK) {
    return CURLE_OK;  /* all fine but no state change yet */
  }

  if(verifyresult != UNITYTLS_X509VERIFY_SUCCESS) {
    if(verifyresult == UNITYTLS_X509VERIFY_FATAL_ERROR)
      failf(data, "Cert handshake failed. verify result: UNITYTLS_X509VERIFY_FATAL_ERROR. error state: %i", err.code);
    else {
      if(verifyresult & UNITYTLS_X509VERIFY_FLAG_EXPIRED)
        failf(data, "Cert verify failed: UNITYTLS_X509VERIFY_FLAG_EXPIRED");
      if(verifyresult & UNITYTLS_X509VERIFY_FLAG_CN_MISMATCH)
        failf(data, "Cert verify failed: UNITYTLS_X509VERIFY_FLAG_CN_MISMATCH");
      if(verifyresult & UNITYTLS_X509VERIFY_FLAG_NOT_TRUSTED)
        failf(data, "Cert verify failed: UNITYTLS_X509VERIFY_FLAG_NOT_TRUSTED");

      if(verifyresult & UNITYTLS_X509VERIFY_FLAG_USER_ERROR1)
        failf(data, "Cert verify failed: UNITYTLS_X509VERIFY_FLAG_USER_ERROR1");
      if(verifyresult & UNITYTLS_X509VERIFY_FLAG_USER_ERROR2)
        failf(data, "Cert verify failed: UNITYTLS_X509VERIFY_FLAG_USER_ERROR2");
      if(verifyresult & UNITYTLS_X509VERIFY_FLAG_USER_ERROR3)
        failf(data, "Cert verify failed: UNITYTLS_X509VERIFY_FLAG_USER_ERROR3");
      if(verifyresult & UNITYTLS_X509VERIFY_FLAG_USER_ERROR4)
        failf(data, "Cert verify failed: UNITYTLS_X509VERIFY_FLAG_USER_ERROR4");
      if(verifyresult & UNITYTLS_X509VERIFY_FLAG_USER_ERROR5)
        failf(data, "Cert verify failed: UNITYTLS_X509VERIFY_FLAG_USER_ERROR5");
      if(verifyresult & UNITYTLS_X509VERIFY_FLAG_USER_ERROR6)
        failf(data, "Cert verify failed: UNITYTLS_X509VERIFY_FLAG_USER_ERROR6");
      if(verifyresult & UNITYTLS_X509VERIFY_FLAG_USER_ERROR7)
        failf(data, "Cert verify failed: UNITYTLS_X509VERIFY_FLAG_USER_ERROR7");
      if(verifyresult & UNITYTLS_X509VERIFY_FLAG_USER_ERROR8)
        failf(data, "Cert verify failed: UNITYTLS_X509VERIFY_FLAG_USER_ERROR8");

      if(verifyresult & UNITYTLS_X509VERIFY_FLAG_UNKNOWN_ERROR)
        failf(data, "Cert verify failed: UNITYTLS_X509VERIFY_FLAG_UNKNOWN_ERROR");

      if(verifyresult & UNITYTLS_X509VERIFY_FLAG_REVOKED) {
        failf(data, "Cert verify failed: UNITYTLS_X509VERIFY_FLAG_REVOKED");
        return CURLE_SSL_CACERT;
      }
    }
    
    /* Note that UNITYTLS_X509VERIFY_NOT_DONE is always always an error as well since we are never running in server mode (unitytls_tlsctx_create_server)
      * which means that authentification method should always be called. 
      * However, this usually has a different reason so it is not CURLE_PEER_FAILED_VERIFICATION */
    if (verifyresult == UNITYTLS_X509VERIFY_NOT_DONE) {
      failf(data, "Handshake did not perform verification. UnityTls error code: %i", err.code);
      return CURLE_SSL_CONNECT_ERROR;
    }
    else
      return CURLE_PEER_FAILED_VERIFICATION;
  }

  /* We almost certainly have a verifyresult!=UNITYTLS_X509VERIFY_SUCCESS as well, but in theory it is still possible to hit this code. */
  if (err.code == UNITYTLS_SUCCESS) {
    connssl->connecting_state = ssl_connect_3;
    return CURLE_OK;
  }
  else {
    failf(data, "Handshake failed. UnityTls error code: %i", err.code);
    return CURLE_SSL_CONNECT_ERROR;
  }
}

static CURLcode unitytls_connect_step3(struct ssl_connect_data* connssl)
{
  /* TODO: Session suppport. */
  connssl->connecting_state = ssl_connect_done;
  return CURLE_OK;
}

static CURLcode unitytls_connect_common(struct connectdata *conn,
                                        int sockindex,
                                        bool nonblocking,
                                        bool *done)
{
  CURLcode retcode;
  struct Curl_easy *data = conn->data;
  struct ssl_connect_data* connssl = &conn->ssl[sockindex];
  curl_socket_t sockfd = conn->sock[sockindex];

  if(!unitytls_check_interface_available(data))
    return CURLE_USE_SSL_FAILED;

  /* check if the connection has already been established */
  if(ssl_connection_complete == connssl->state) {
    *done = true;
    return CURLE_OK;
  }

  if(ssl_connect_1 == connssl->connecting_state) {
    /* Find out how much more time we're allowed */
    if(Curl_timeleft(data, NULL, true) < 0) {
      /* no need to continue if time already is up */
      failf(data, "SSL connection timeout");
      return CURLE_OPERATION_TIMEDOUT;
    }
    retcode = unitytls_connect_step1(conn, sockindex);
    if(retcode)
      return retcode;
  }


  while(ssl_connect_2 == connssl->connecting_state ||
        ssl_connect_2_reading == connssl->connecting_state ||
        ssl_connect_2_writing == connssl->connecting_state) {
    /* check allowed time left */
    if(Curl_timeleft(data, NULL, TRUE) < 0) {
      /* no need to continue if time already is up */
      failf(data, "SSL connection timeout");
      return CURLE_OPERATION_TIMEDOUT;
    }

    retcode = unitytls_connect_step2(data, connssl);
    if(retcode != CURLE_OK || (nonblocking && ssl_connect_2 == connssl->connecting_state))
      return retcode;
  } /* repeat step2 until all transactions are done. */

  if(ssl_connect_3 == connssl->connecting_state) {
    retcode = unitytls_connect_step3(connssl);
    if(retcode)
      return retcode;
  }

  if(ssl_connect_done==connssl->connecting_state) {
    connssl->state = ssl_connection_complete;
    conn->recv[sockindex] = unitytls_recv;
    conn->send[sockindex] = unitytls_send;
    *done = TRUE;
  }
  else
    *done = FALSE;

  /* Reset our connect state machine */
  connssl->connecting_state = ssl_connect_1;

  return CURLE_OK;
}

CURLcode Curl_unitytls_connect(struct connectdata *conn, int sockindex)
{
  CURLcode retcode;
  bool done = false;

  retcode = unitytls_connect_common(conn, sockindex, false, &done);
  if(retcode)
    return retcode;

  DEBUGASSERT(done);

  return CURLE_OK;
}

CURLcode Curl_unitytls_connect_nonblocking(struct connectdata *conn, int sockindex, bool *done)
{
  return unitytls_connect_common(conn, sockindex, true, done);
}

void Curl_unitytls_close(struct connectdata *conn, int sockindex)
{
  struct ssl_connect_data* connssl = &conn->ssl[sockindex];
  if(!unitytls_check_interface_available(NULL))
    return;

  unitytls->unitytls_x509list_free(connssl->cacert);
  connssl->cacert = NULL;
  unitytls->unitytls_x509list_free(connssl->clicert);
  connssl->clicert = NULL;
  unitytls->unitytls_key_free(connssl->pk);
  connssl->pk = NULL;
  unitytls->unitytls_tlsctx_free(connssl->ctx);
  connssl->ctx = NULL;
}

size_t Curl_unitytls_version(char *buffer, size_t size)
{
  return snprintf(buffer, size, "UnityTls");
}

#endif /* USE_UNITYTLS */
