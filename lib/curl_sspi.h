#ifndef HEADER_CURL_SSPI_H
#define HEADER_CURL_SSPI_H
/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) 1998 - 2010, Daniel Stenberg, <daniel@haxx.se>, et al.
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

#include "setup.h"

#ifdef USE_WINDOWS_SSPI

#include <curl/curl.h>

/*
 * When including the following three headers, it is mandatory to define either
 * SECURITY_WIN32 or SECURITY_KERNEL, indicating who is compiling the code.
 */

#undef SECURITY_WIN32
#undef SECURITY_KERNEL
#define SECURITY_WIN32 1
#include <security.h>
#include <sspi.h>
#include <rpc.h>

/* Provide some definitions missing in MinGW's headers */

#ifndef SEC_I_CONTEXT_EXPIRED
# define SEC_I_CONTEXT_EXPIRED ((HRESULT)0x00090317L)
#endif
#ifndef SEC_E_BUFFER_TOO_SMALL
# define SEC_E_BUFFER_TOO_SMALL ((HRESULT)0x80090321L)
#endif
#ifndef SEC_E_CONTEXT_EXPIRED
# define SEC_E_CONTEXT_EXPIRED ((HRESULT)0x80090317L)
#endif
#ifndef SEC_E_CRYPTO_SYSTEM_INVALID
# define SEC_E_CRYPTO_SYSTEM_INVALID ((HRESULT)0x80090337L)
#endif
#ifndef SEC_E_MESSAGE_ALTERED
# define SEC_E_MESSAGE_ALTERED ((HRESULT)0x8009030FL)
#endif
#ifndef SEC_E_OUT_OF_SEQUENCE
# define SEC_E_OUT_OF_SEQUENCE ((HRESULT)0x80090310L)
#endif

CURLcode Curl_sspi_global_init(void);
void Curl_sspi_global_cleanup(void);

/* Forward-declaration of global variables defined in curl_sspi.c */

extern HMODULE s_hSecDll;
extern PSecurityFunctionTableA s_pSecFn;

#endif /* USE_WINDOWS_SSPI */
#endif /* HEADER_CURL_SSPI_H */
