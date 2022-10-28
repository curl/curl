/* File: report_openssl_version.c
 *
 * $Id$
 *
 * This file dynamically loads the openssl shared image to report the
 * version string.
 *
 * It will optionally place that version string in a DCL symbol.
 *
 * Usage:  report_openssl_version <shared_image> [<dcl_symbol>]
 *
 * Copyright 2013 - 2022, John Malmberg
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT
 * OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 *
 * SPDX-License-Identifier: ISC
 *
 */

#include <dlfcn.h>
#include <openssl/opensslv.h>
#include <openssl/crypto.h>

#include <string.h>
#include <descrip.h>
#include <libclidef.h>
#include <stsdef.h>
#include <errno.h>

unsigned long LIB$SET_SYMBOL(
    const struct dsc$descriptor_s * symbol,
    const struct dsc$descriptor_s * value,
    const unsigned long * table_type);

int main(int argc, char ** argv) {


void * libptr;
const char * (*ssl_version)(int t);
const char * version;

   if(argc < 1) {
       puts("report_openssl_version filename");
       exit(1);
   }

   libptr = dlopen(argv[1], 0);

   ssl_version = (const char * (*)(int))dlsym(libptr, "SSLeay_version");
   if(ssl_version == NULL) {
      ssl_version = (const char * (*)(int))dlsym(libptr, "ssleay_version");
      if(ssl_version == NULL) {
         ssl_version = (const char * (*)(int))dlsym(libptr, "SSLEAY_VERSION");
      }
   }

   dlclose(libptr);

   if(ssl_version == NULL) {
      puts("Unable to lookup version of OpenSSL");
      exit(1);
   }

   version = ssl_version(SSLEAY_VERSION);

   puts(version);

   /* Was a symbol argument given? */
   if(argc > 1) {
      int status;
      struct dsc$descriptor_s symbol_dsc;
      struct dsc$descriptor_s value_dsc;
      const unsigned long table_type = LIB$K_CLI_LOCAL_SYM;

      symbol_dsc.dsc$a_pointer = argv[2];
      symbol_dsc.dsc$w_length = strlen(argv[2]);
      symbol_dsc.dsc$b_dtype = DSC$K_DTYPE_T;
      symbol_dsc.dsc$b_class = DSC$K_CLASS_S;

      value_dsc.dsc$a_pointer = (char *)version; /* Cast ok */
      value_dsc.dsc$w_length = strlen(version);
      value_dsc.dsc$b_dtype = DSC$K_DTYPE_T;
      value_dsc.dsc$b_class = DSC$K_CLASS_S;

      status = LIB$SET_SYMBOL(&symbol_dsc, &value_dsc, &table_type);
      if(!$VMS_STATUS_SUCCESS(status)) {
         exit(status);
      }
   }

   exit(0);
}
