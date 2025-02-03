#ifndef HEADER_FETCHMSG_VMS_H
#define HEADER_FETCHMSG_VMS_H
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
 * are also available at https://fetch.se/docs/copyright.html.
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
 ***************************************************************************/

/*                                                                          */
/* FETCHMSG_VMS.H                                                            */
/*                                                                          */
/* This defines the necessary bits to change FETCHE_* error codes to VMS     */
/* style error codes.  FETCHMSG.H is built from FETCHMSG.SDL which is built   */
/* from FETCHMSG.MSG.  The vms_cond array is used to return VMS errors by    */
/* putting the VMS error codes into the array offset based on FETCHE_* code. */
/*                                                                          */
/* If you update FETCHMSG.MSG make sure to update this file to match.        */
/*                                                                          */

#include "fetchmsg.h"

/*
#define   FAC_FETCH      0xC01
#define   FAC_SYSTEM    0
#define   MSG_NORMAL    0
*/

/*
#define   SEV_WARNING   0
#define   SEV_SUCCESS   1
#define   SEV_ERROR     2
#define   SEV_INFO      3
#define   SEV_FATAL     4
*/

static const long vms_cond[] =
    {
        FETCH_OK,
        FETCH_UNSUPPORTED_PROTOCOL,
        FETCH_FAILED_INIT,
        FETCH_URL_MALFORMAT,
        FETCH_OBSOLETE4,
        FETCH_COULDNT_RESOLVE_PROXY,
        FETCH_COULDNT_RESOLVE_HOST,
        FETCH_COULDNT_CONNECT,
        FETCH_WEIRD_SERVER_REPLY,
        FETCH_FTP_ACCESS_DENIED,
        FETCH_OBSOLETE10,
        FETCH_FTP_WEIRD_PASS_REPLY,
        FETCH_OBSOLETE12,
        FETCH_FTP_WEIRD_PASV_REPLY,
        FETCH_FTP_WEIRD_227_FORMAT,
        FETCH_FTP_CANT_GET_HOST,
        FETCH_OBSOLETE16,
        FETCH_FTP_COULDNT_SET_TYPE,
        FETCH_PARTIAL_FILE,
        FETCH_FTP_COULDNT_RETR_FILE,
        FETCH_OBSOLETE20,
        FETCH_QUOTE_ERROR,
        FETCH_HTTP_RETURNED_ERROR,
        FETCH_WRITE_ERROR,
        FETCH_OBSOLETE24,
        FETCH_UPLOAD_FAILED,
        FETCH_READ_ERROR,
        FETCH_OUT_OF_MEMORY,
        FETCH_OPERATION_TIMEOUTED,
        FETCH_OBSOLETE29,
        FETCH_FTP_PORT_FAILED,
        FETCH_FTP_COULDNT_USE_REST,
        FETCH_OBSOLETE32,
        FETCH_RANGE_ERROR,
        FETCH_HTTP_POST_ERROR,
        FETCH_SSL_CONNECT_ERROR,
        FETCH_BAD_DOWNLOAD_RESUME,
        FETCH_FILE_COULDNT_READ_FILE,
        FETCH_LDAP_CANNOT_BIND,
        FETCH_LDAP_SEARCH_FAILED,
        FETCH_OBSOLETE40,
        FETCH_FUNCTION_NOT_FOUND,
        FETCH_ABORTED_BY_CALLBACK,
        FETCH_BAD_FUNCTION_ARGUMENT,
        FETCH_OBSOLETE44,
        FETCH_INTERFACE_FAILED,
        FETCH_OBSOLETE46,
        FETCH_TOO_MANY_REDIRECTS,
        FETCH_UNKNOWN_TELNET_OPTION,
        FETCH_TELNET_OPTION_SYNTAX,
        FETCH_OBSOLETE50,
        FETCH_PEER_FAILED_VERIF,
        FETCH_GOT_NOTHING,
        FETCH_SSL_ENGINE_NOTFOUND,
        FETCH_SSL_ENGINE_SETFAILED,
        FETCH_SEND_ERROR,
        FETCH_RECV_ERROR,
        FETCH_OBSOLETE57,
        FETCH_SSL_CERTPROBLEM,
        FETCH_SSL_CIPHER,
        FETCH_SSL_CACERT,
        FETCH_BAD_CONTENT_ENCODING,
        FETCH_LDAP_INVALID_URL,
        FETCH_FILESIZE_EXCEEDED,
        FETCH_USE_SSL_FAILED,
        FETCH_SEND_FAIL_REWIND,
        FETCH_SSL_ENGINE_INITFAILED,
        FETCH_LOGIN_DENIED,
        FETCH_TFTP_NOTFOUND,
        FETCH_TFTP_PERM,
        FETCH_REMOTE_DISK_FULL,
        FETCH_TFTP_ILLEGAL,
        FETCH_TFTP_UNKNOWNID,
        FETCH_REMOTE_FILE_EXISTS,
        FETCH_TFTP_NOSUCHUSER,
        FETCH_CONV_FAILED,
        FETCH_CONV_REQD,
        FETCH_SSL_CACERT_BADFILE,
        FETCH_REMOTE_FILE_NOT_FOUND,
        FETCH_SSH,
        FETCH_SSL_SHUTDOWN_FAILED,
        FETCH_AGAIN,
        FETCHE_SSL_CRL_BADFILE,
        FETCHE_SSL_ISSUER_ERROR,
        FETCH_FETCH_LAST};

#endif /* HEADER_FETCHMSG_VMS_H */
