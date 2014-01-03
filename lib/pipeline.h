#ifndef HEADER_CURL_PIPELINE_H
#define HEADER_CURL_PIPELINE_H
/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) 2013 - 2014, Linus Nielsen Feltzing, <linus@haxx.se>
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

CURLcode Curl_add_handle_to_pipeline(struct SessionHandle *handle,
                                     struct connectdata *conn);
void Curl_move_handle_from_send_to_recv_pipe(struct SessionHandle *handle,
                                             struct connectdata *conn);
bool Curl_pipeline_penalized(struct SessionHandle *data,
                             struct connectdata *conn);

bool Curl_pipeline_site_blacklisted(struct SessionHandle *handle,
                                    struct connectdata *conn);

CURLMcode Curl_pipeline_set_site_blacklist(char **sites,
                                           struct curl_llist **list_ptr);

bool Curl_pipeline_server_blacklisted(struct SessionHandle *handle,
                                      char *server_name);

CURLMcode Curl_pipeline_set_server_blacklist(char **servers,
                                             struct curl_llist **list_ptr);

#endif /* HEADER_CURL_PIPELINE_H */
