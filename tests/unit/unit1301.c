#include <stdlib.h>
#include "curl_config.h"
#include "setup.h"

#include "strequal.h"
#include "curlcheck.h"

static void unit_setup( void ) {}
static void unit_stop( void ) {}

UNITTEST_START

int rc;

rc = curl_strequal("iii", "III");
fail_unless( rc != 0 , "return code should be zero" );

rc = curl_strequal("iiia", "III");
fail_unless( rc == 0 , "return code should be zero" );

rc = curl_strequal("iii", "IIIa");
fail_unless( rc == 0 , "return code should be zero" );

rc = curl_strequal("iiiA", "IIIa");
fail_unless( rc != 0 , "return code should be non-zero" );

rc = curl_strnequal("iii", "III", 3);
fail_unless( rc != 0 , "return code should be non-zero" );

rc = curl_strnequal("iiiABC", "IIIcba", 3);
fail_unless( rc != 0 , "return code should be non-zero" );

rc = curl_strnequal("ii", "II", 3);
fail_unless( rc != 0 , "return code should be non-zero" );

UNITTEST_STOP
