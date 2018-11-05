/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) 1998 - 2018, Daniel Stenberg, <daniel@haxx.se>, et al.
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
 *
 ***************************************************************************/

#ifndef __CURL_CCSIDCURL_H
#define __CURL_CCSIDCURL_H

#include "curl.h"
#include "easy.h"
#include "multi.h"


CURL_EXTERN char * curl_version_ccsid(unsigned int ccsid);
CURL_EXTERN char * curl_easy_escape_ccsid(CURL * handle,
                                          const char * string, int length,
                                          unsigned int sccsid,
                                          unsigned int dccsid);
CURL_EXTERN char * curl_easy_unescape_ccsid(CURL * handle, const char * string,
                                            int length, int * outlength,
                                            unsigned int sccsid,
                                            unsigned int dccsid);
CURL_EXTERN struct curl_slist * curl_slist_append_ccsid(struct curl_slist * l,
                                                        const char * data,
                                                        unsigned int ccsid);
CURL_EXTERN time_t curl_getdate_ccsid(const char * p, const time_t * unused,
                                      unsigned int ccsid);
CURL_EXTERN curl_version_info_data * curl_version_info_ccsid(CURLversion stamp,
                                                             unsigned int cid);
CURL_EXTERN const char * curl_easy_strerror_ccsid(CURLcode error,
                                                  unsigned int ccsid);
CURL_EXTERN const char * curl_share_strerror_ccsid(CURLSHcode error,
                                                   unsigned int ccsid);
CURL_EXTERN const char * curl_multi_strerror_ccsid(CURLMcode error,
                                                   unsigned int ccsid);
CURL_EXTERN CURLcode curl_easy_getinfo_ccsid(CURL * curl, CURLINFO info, ...);
CURL_EXTERN CURLFORMcode curl_formadd_ccsid(struct curl_httppost * * httppost,
                                            struct curl_httppost * * last_post,
                                            ...);
CURL_EXTERN char * curl_form_long_value(long value);
CURL_EXTERN int curl_formget_ccsid(struct curl_httppost * form, void * arg,
                                   curl_formget_callback append,
                                   unsigned int ccsid);
CURL_EXTERN CURLcode curl_easy_setopt_ccsid(CURL * curl, CURLoption tag, ...);
CURL_EXTERN void curl_certinfo_free_all(struct curl_certinfo *info);
CURL_EXTERN char *curl_pushheader_bynum_cssid(struct curl_pushheaders *h,
                                              size_t num, unsigned int ccsid);
CURL_EXTERN char *curl_pushheader_byname_ccsid(struct curl_pushheaders *h,
                                               const char *header,
                                               unsigned int ccsidin,
                                               unsigned int ccsidout);
CURL_EXTERN CURLcode curl_mime_name_ccsid(curl_mimepart *part,
                                          const char *name,
                                          unsigned int ccsid);
CURL_EXTERN CURLcode curl_mime_filename_ccsid(curl_mimepart *part,
                                              const char *filename,
                                              unsigned int ccsid);
CURL_EXTERN CURLcode curl_mime_type_ccsid(curl_mimepart *part,
                                          const char *mimetype,
                                          unsigned int ccsid);
CURL_EXTERN CURLcode curl_mime_encoder_ccsid(curl_mimepart *part,
                                             const char *encoding,
                                             unsigned int ccsid);
CURL_EXTERN CURLcode curl_mime_filedata_ccsid(curl_mimepart *part,
                                              const char *filename,
                                              unsigned int ccsid);
CURL_EXTERN CURLcode curl_mime_data_ccsid(curl_mimepart *part,
                                          const char *data, size_t datasize,
                                          unsigned int ccsid);
CURL_EXTERN CURLUcode curl_url_get_ccsid(CURLU *handle, CURLUPart what,
                                         char **part, unsigned int flags,
                                         unsigned int ccsid);
CURL_EXTERN CURLUcode curl_url_set_ccsid(CURLU *handle, CURLUPart what,
                                         const char *part, unsigned int flags,
                                         unsigned int ccsid);

#endif
