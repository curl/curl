#ifndef FETCHINC_CCSIDFETCH_H
#define FETCHINC_CCSIDFETCH_H
/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
 *
 * This software is licensed as described in the file COPYING, which
 * you should have received as part of this distribution. The terms
 * are also available at https://curl.se/docs/copyright.html.
 *
 * You may opt to use, copy, modify, merge, publish, distribute and/or sell
 * copies of the Software, and permit persons to whom the Software is
 * furnished to do so, under the terms of the COPYING file.
 *
 * This software is distributed on an "AS IS" basis, WITHOUT WARRANTY OF ANY
 * KIND, either express or implied.
 *
 * SPDX-License-Identifier: fetch
 *
 *
 ***************************************************************************/
#include "fetch.h"
#include "easy.h"
#include "multi.h"

FETCH_EXTERN char *fetch_version_ccsid(unsigned int ccsid);
FETCH_EXTERN char *fetch_easy_escape_ccsid(FETCH *handle,
                                           const char *string, int length,
                                           unsigned int sccsid,
                                           unsigned int dccsid);
FETCH_EXTERN char *fetch_easy_unescape_ccsid(FETCH *handle, const char *string,
                                             int length, int *outlength,
                                             unsigned int sccsid,
                                             unsigned int dccsid);
FETCH_EXTERN struct fetch_slist *fetch_slist_append_ccsid(struct fetch_slist *l,
                                                          const char *data,
                                                          unsigned int ccsid);
FETCH_EXTERN time_t fetch_getdate_ccsid(const char *p, const time_t *unused,
                                        unsigned int ccsid);
FETCH_EXTERN fetch_version_info_data *fetch_version_info_ccsid(FETCHversion stamp,
                                                               unsigned int cid);
FETCH_EXTERN const char *fetch_easy_strerror_ccsid(FETCHcode error,
                                                   unsigned int ccsid);
FETCH_EXTERN const char *fetch_share_strerror_ccsid(FETCHSHcode error,
                                                    unsigned int ccsid);
FETCH_EXTERN const char *fetch_multi_strerror_ccsid(FETCHMcode error,
                                                    unsigned int ccsid);
FETCH_EXTERN FETCHcode fetch_easy_getinfo_ccsid(FETCH *fetch, FETCHINFO info, ...);
FETCH_EXTERN FETCHFORMcode fetch_formadd_ccsid(struct fetch_httppost **httppost,
                                               struct fetch_httppost **last_post,
                                               ...);
FETCH_EXTERN char *fetch_form_long_value(long value);
FETCH_EXTERN int fetch_formget_ccsid(struct fetch_httppost *form, void *arg,
                                     fetch_formget_callback append,
                                     unsigned int ccsid);
FETCH_EXTERN FETCHcode fetch_easy_setopt_ccsid(FETCH *fetch, FETCHoption tag, ...);
FETCH_EXTERN void fetch_certinfo_free_all(struct fetch_certinfo *info);
FETCH_EXTERN char *fetch_pushheader_bynum_cssid(struct fetch_pushheaders *h,
                                                size_t num, unsigned int ccsid);
FETCH_EXTERN char *fetch_pushheader_byname_ccsid(struct fetch_pushheaders *h,
                                                 const char *header,
                                                 unsigned int ccsidin,
                                                 unsigned int ccsidout);
FETCH_EXTERN FETCHcode fetch_mime_name_ccsid(fetch_mimepart *part,
                                             const char *name,
                                             unsigned int ccsid);
FETCH_EXTERN FETCHcode fetch_mime_filename_ccsid(fetch_mimepart *part,
                                                 const char *filename,
                                                 unsigned int ccsid);
FETCH_EXTERN FETCHcode fetch_mime_type_ccsid(fetch_mimepart *part,
                                             const char *mimetype,
                                             unsigned int ccsid);
FETCH_EXTERN FETCHcode fetch_mime_encoder_ccsid(fetch_mimepart *part,
                                                const char *encoding,
                                                unsigned int ccsid);
FETCH_EXTERN FETCHcode fetch_mime_filedata_ccsid(fetch_mimepart *part,
                                                 const char *filename,
                                                 unsigned int ccsid);
FETCH_EXTERN FETCHcode fetch_mime_data_ccsid(fetch_mimepart *part,
                                             const char *data, size_t datasize,
                                             unsigned int ccsid);
FETCH_EXTERN FETCHUcode fetch_url_get_ccsid(FETCHU *handle, FETCHUPart what,
                                            char **part, unsigned int flags,
                                            unsigned int ccsid);
FETCH_EXTERN FETCHUcode fetch_url_set_ccsid(FETCHU *handle, FETCHUPart what,
                                            const char *part, unsigned int flags,
                                            unsigned int ccsid);
FETCH_EXTERN const struct fetch_easyoption *fetch_easy_option_by_name_ccsid(
    const char *name, unsigned int ccsid);
FETCH_EXTERN const char *fetch_easy_option_get_name_ccsid(
    const struct fetch_easyoption *option,
    unsigned int ccsid);
FETCH_EXTERN const char *fetch_url_strerror_ccsid(FETCHUcode error,
                                                  unsigned int ccsid);
FETCH_EXTERN FETCHHcode fetch_easy_header_ccsid(FETCH *easy, const char *name,
                                                size_t index, unsigned int origin,
                                                int request,
                                                struct fetch_header **hout,
                                                unsigned int ccsid);
FETCH_EXTERN const char *fetch_from_ccsid(const char *s, unsigned int ccsid);
FETCH_EXTERN const char *fetch_to_ccsid(const char *s, unsigned int ccsid);
FETCH_EXTERN FETCHcode fetch_easy_setopt_RPGnum_(FETCH *easy,
                                                 FETCHoption tag, fetch_off_t arg);
FETCH_EXTERN FETCHcode fetch_multi_setopt_RPGnum_(FETCHM *multi, FETCHMoption tag,
                                                  fetch_off_t arg);

#endif
