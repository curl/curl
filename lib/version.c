/*****************************************************************************
 *                                  _   _ ____  _     
 *  Project                     ___| | | |  _ \| |    
 *                             / __| | | | |_) | |    
 *                            | (__| |_| |  _ <| |___ 
 *                             \___|\___/|_| \_\_____|
 *
 *  The contents of this file are subject to the Mozilla Public License
 *  Version 1.0 (the "License"); you may not use this file except in
 *  compliance with the License. You may obtain a copy of the License at
 *  http://www.mozilla.org/MPL/
 *
 *  Software distributed under the License is distributed on an "AS IS"
 *  basis, WITHOUT WARRANTY OF ANY KIND, either express or implied. See the
 *  License for the specific language governing rights and limitations
 *  under the License.
 *
 *  The Original Code is Curl.
 *
 *  The Initial Developer of the Original Code is Daniel Stenberg.
 *
 *  Portions created by the Initial Developer are Copyright (C) 1998.
 *  All Rights Reserved.
 *
 * ------------------------------------------------------------
 * Main author:
 * - Daniel Stenberg <Daniel.Stenberg@haxx.nu>
 *
 * 	http://curl.haxx.nu
 *
 * $Source$
 * $Revision$
 * $Date$
 * $Author$
 * $State$
 * $Locker$
 *
 * ------------------------------------------------------------
 ****************************************************************************/

#include <string.h>
#include <stdio.h>

#include "setup.h"
#include <curl/curl.h>
#include "urldata.h"

char *curl_version(void)
{
  static char version[200];
  char *ptr;
#if defined(USE_SSLEAY)
  static char sub[2];
#endif
  strcpy(version, LIBCURL_NAME " " LIBCURL_VERSION );
  ptr=strchr(version, '\0');

#ifdef USE_SSLEAY

#if (SSLEAY_VERSION_NUMBER >= 0x900000)
  sprintf(ptr, " (SSL %x.%x.%x)",
          (SSLEAY_VERSION_NUMBER>>28)&0xff,
          (SSLEAY_VERSION_NUMBER>>20)&0xff,
          (SSLEAY_VERSION_NUMBER>>12)&0xf);
#else
  if(SSLEAY_VERSION_NUMBER&0x0f) {
    sub[0]=(SSLEAY_VERSION_NUMBER&0x0f) + 'a' -1;
  }
  else
    sub[0]=0;

  sprintf(ptr, " (SSL %x.%x.%x%s)",
          (SSLEAY_VERSION_NUMBER>>12)&0xff,
          (SSLEAY_VERSION_NUMBER>>8)&0xf,
          (SSLEAY_VERSION_NUMBER>>4)&0xf, sub);

#endif
  ptr=strchr(ptr, '\0');
#endif

#ifdef USE_ZLIB
  sprintf(ptr, " (zlib %s)", zlibVersion());
#endif

  return version;
}
