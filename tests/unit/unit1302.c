#include <stdlib.h>
#include "curl_config.h"
#include "setup.h"

#include "urldata.h"
#include "curl_base64.h"
#include "curlcheck.h"
#include "memdebug.h" /* LAST include file */

static struct SessionHandle *data;

static void unit_setup( void )
{
  data = curl_easy_init();
}
static void unit_stop( void )
{
  curl_easy_cleanup(data);
}

UNITTEST_START

char *output;
unsigned char *decoded;
size_t rc;

rc = Curl_base64_encode(data, "i", 1, &output);
fail_unless( rc == 4 , "return code should be 4" );
verify_memory( output, "aQ==", 4);
free(output);

rc = Curl_base64_encode(data, "ii", 2, &output);
fail_unless( rc == 4 , "return code should be 4" );
verify_memory( output, "aWk=", 4);
free(output);

rc = Curl_base64_encode(data, "iii", 3, &output);
fail_unless( rc == 4 , "return code should be 4" );
verify_memory( output, "aWlp", 4);
free(output);

rc = Curl_base64_encode(data, "iiii", 4, &output);
fail_unless( rc == 8 , "return code should be 8" );
verify_memory( output, "aWlpaQ==", 8);
free(output);

/* 0 length makes it do strlen() */
rc = Curl_base64_encode(data, "iiii", 0, &output);
fail_unless( rc == 8 , "return code should be 8" );
verify_memory( output, "aWlpaQ==", 8);
free(output);

rc = Curl_base64_decode("aWlpaQ==", &decoded);
fail_unless(rc == 4, "return code should be 4");
verify_memory(decoded, "iiii", 4);
free(decoded);

rc = Curl_base64_decode("aWlp", &decoded);
fail_unless(rc == 3, "return code should be 3");
verify_memory(decoded, "iii", 3);
free(decoded);

rc = Curl_base64_decode("aWk=", &decoded);
fail_unless(rc == 2, "return code should be 2");
verify_memory(decoded, "ii", 2);
free(decoded);

rc = Curl_base64_decode("aQ==", &decoded);
fail_unless(rc == 1, "return code should be 1");
verify_memory(decoded, "i", 2);
free(decoded);

/* this is an illegal input */
rc = Curl_base64_decode("aQ", &decoded);
fail_unless(rc == 0, "return code should be 0");

/* this is garbage input that libcurl decodes as far as possible */
rc = Curl_base64_decode("a\x1f==", &decoded);
fail_unless(rc == 1, "return code should be 1");
free(decoded);

UNITTEST_STOP
