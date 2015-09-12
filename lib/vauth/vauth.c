/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) 2014 - 2015, Steve Holme, <steve_holme@hotmail.com>.
 *
 * This software is licensed as described in the file COPYING, which
 * you should have received as part of this distribution. The terms
 * are also available at http://curl.haxx.se/docs/copyright.html.
 *
 * You may opt to use, copy, modify, merge, publish, distribute and/or sell
 * copies of the Software, and permit persons to whom the Software is
 * furnished to do so, under the terms of the COPYING file.
 *
 * This software is distributed on an "AS IS" basis, WITHOUT WARRANTY OF ANY
 * KIND, either express or implied.
 *
 ***************************************************************************/

#include "curl_setup.h"

#include <curl/curl.h>

#include "vauth.h"
#include "curl_multibyte.h"
#include "curl_printf.h"

/* The last #include files should be: */
#include "curl_memory.h"
#include "memdebug.h"

/*
 * Curl_sasl_build_spn()
 *
 * This is used to build a SPN string in the format service/instance.
 *
 * Parameters:
 *
 * service  [in] - The service type such as www, smtp, pop or imap.
 * instance [in] - The host name or realm.
 *
 * Returns a pointer to the newly allocated SPN.
 */
#if !defined(USE_WINDOWS_SSPI)
char *Curl_sasl_build_spn(const char *service, const char *instance)
{
  /* Generate and return our SPN */
  return aprintf("%s/%s", service, instance);
}
#else
TCHAR *Curl_sasl_build_spn(const char *service, const char *instance)
{
  char *utf8_spn = NULL;
  TCHAR *tchar_spn = NULL;

  /* Note: We could use DsMakeSPN() or DsClientMakeSpnForTargetServer() rather
     than doing this ourselves but the first is only available in Windows XP
     and Windows Server 2003 and the latter is only available in Windows 2000
     but not Windows95/98/ME or Windows NT4.0 unless the Active Directory
     Client Extensions are installed. As such it is far simpler for us to
     formulate the SPN instead. */

  /* Allocate our UTF8 based SPN */
  utf8_spn = aprintf("%s/%s", service, instance);
  if(!utf8_spn) {
    return NULL;
  }

  /* Allocate our TCHAR based SPN */
  tchar_spn = Curl_convert_UTF8_to_tchar(utf8_spn);
  if(!tchar_spn) {
    free(utf8_spn);

    return NULL;
  }

  /* Release the UTF8 variant when operating with Unicode */
  Curl_unicodefree(utf8_spn);

  /* Return our newly allocated SPN */
  return tchar_spn;
}
#endif /* USE_WINDOWS_SSPI */

#if defined(HAVE_GSSAPI)
/*
 * Curl_sasl_build_gssapi_spn()
 *
 * This is used to build a SPN string in the format service@instance.
 *
 * Parameters:
 *
 * service  [in] - The service type such as www, smtp, pop or imap.
 * instance [in] - The host name or realm.
 *
 * Returns a pointer to the newly allocated SPN.
 */
char *Curl_sasl_build_gssapi_spn(const char *service, const char *instance)
{
  /* Generate and return our SPN */
  return aprintf("%s@%s", service, instance);
}
#endif /* HAVE_GSSAPI */
