/*
 * Source file for all unitytls-specific code for the TLS/SSL layer. No code
 * but vtls.c should ever call or use these functions.
 *
 */

#include "curl_setup.h"

#ifdef USE_UNITYTLS

/* The last #include files should be: */
#include "curl_printf.h"
#include "curl_memory.h"
#include "memdebug.h"

int Curl_unitytls_data_pending(const struct connectdata *conn, int sockindex)
{
  return 0;
}

CURLcode Curl_unitytls_connect(struct connectdata *conn, int sockindex)
{
  return 0;
}

CURLcode Curl_unitytls_connect_nonblocking(struct connectdata *conn, int sockindex, bool *done)
{
  return 0;
}

void Curl_unitytls_close_all(struct Curl_easy *data)
{

}

void Curl_unitytls_close(struct connectdata *conn, int sockindex)
{

}

void Curl_unitytls_session_free(void *ptr)
{

}

size_t Curl_unitytls_version(char *buffer, size_t size)
{
  return 0;
}

int Curl_unitytls_shutdown(struct connectdata *conn, int sockindex)
{

}


#endif /* USE_UNITYTLS */
