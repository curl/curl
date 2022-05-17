#ifndef HEADER_CURLMSG_VMS_H
#define HEADER_CURLMSG_VMS_H
/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) 1998 - 2022, Daniel Stenberg, <daniel@haxx.se>, et al.
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
 * SPDX-License-Identifier: curl
 *
 ***************************************************************************/

/*                                                                          */
/* CURLMSG_VMS.H                                                            */
/*                                                                          */
/* This defines the necessary bits to change CURLE_* error codes to VMS     */
/* style error codes.  CURLMSG.H is built from CURLMSG.SDL which is built   */
/* from CURLMSG.MSG.  The vms_cond array is used to return VMS errors by    */
/* putting the VMS error codes into the array offset based on CURLE_* code. */
/*                                                                          */
/* If you update CURLMSG.MSG make sure to update this file to match.        */
/*                                                                          */

#include "curlmsg.h"

/*
#define   FAC_CURL      0xC01
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
        CURL_OK,
	CURL_UNSUPPORTED_PROTOCOL,
	CURL_FAILED_INIT,
	CURL_URL_MALFORMAT,
	CURL_OBSOLETE4,
	CURL_COULDNT_RESOLVE_PROXY,
	CURL_COULDNT_RESOLVE_HOST,
	CURL_COULDNT_CONNECT,
	CURL_WEIRD_SERVER_REPLY,
	CURL_FTP_ACCESS_DENIED,
	CURL_OBSOLETE10,
	CURL_FTP_WEIRD_PASS_REPLY,
	CURL_OBSOLETE12,
	CURL_FTP_WEIRD_PASV_REPLY,
	CURL_FTP_WEIRD_227_FORMAT,
	CURL_FTP_CANT_GET_HOST,
	CURL_OBSOLETE16,
	CURL_FTP_COULDNT_SET_TYPE,
	CURL_PARTIAL_FILE,
	CURL_FTP_COULDNT_RETR_FILE,
	CURL_OBSOLETE20,
	CURL_QUOTE_ERROR,
	CURL_HTTP_RETURNED_ERROR,
	CURL_WRITE_ERROR,
	CURL_OBSOLETE24,
	CURL_UPLOAD_FAILED,
	CURL_READ_ERROR,
	CURL_OUT_OF_MEMORY,
	CURL_OPERATION_TIMEOUTED,
	CURL_OBSOLETE29,
	CURL_FTP_PORT_FAILED,
	CURL_FTP_COULDNT_USE_REST,
	CURL_OBSOLETE32,
	CURL_RANGE_ERROR,
	CURL_HTTP_POST_ERROR,
	CURL_SSL_CONNECT_ERROR,
	CURL_BAD_DOWNLOAD_RESUME,
	CURL_FILE_COULDNT_READ_FILE,
	CURL_LDAP_CANNOT_BIND,
	CURL_LDAP_SEARCH_FAILED,
	CURL_OBSOLETE40,
	CURL_FUNCTION_NOT_FOUND,
	CURL_ABORTED_BY_CALLBACK,
	CURL_BAD_FUNCTION_ARGUMENT,
	CURL_OBSOLETE44,
	CURL_INTERFACE_FAILED,
	CURL_OBSOLETE46,
	CURL_TOO_MANY_REDIRECTS,
	CURL_UNKNOWN_TELNET_OPTION,
	CURL_TELNET_OPTION_SYNTAX,
	CURL_OBSOLETE50,
	CURL_PEER_FAILED_VERIF,
	CURL_GOT_NOTHING,
	CURL_SSL_ENGINE_NOTFOUND,
	CURL_SSL_ENGINE_SETFAILED,
	CURL_SEND_ERROR,
	CURL_RECV_ERROR,
	CURL_OBSOLETE57,
	CURL_SSL_CERTPROBLEM,
	CURL_SSL_CIPHER,
	CURL_SSL_CACERT,
	CURL_BAD_CONTENT_ENCODING,
	CURL_LDAP_INVALID_URL,
	CURL_FILESIZE_EXCEEDED,
	CURL_USE_SSL_FAILED,
	CURL_SEND_FAIL_REWIND,
	CURL_SSL_ENGINE_INITFAILED,
	CURL_LOGIN_DENIED,
	CURL_TFTP_NOTFOUND,
	CURL_TFTP_PERM,
	CURL_REMOTE_DISK_FULL,
	CURL_TFTP_ILLEGAL,
	CURL_TFTP_UNKNOWNID,
	CURL_REMOTE_FILE_EXISTS,
	CURL_TFTP_NOSUCHUSER,
	CURL_CONV_FAILED,
	CURL_CONV_REQD,
	CURL_SSL_CACERT_BADFILE,
	CURL_REMOTE_FILE_NOT_FOUND,
	CURL_SSH,
	CURL_SSL_SHUTDOWN_FAILED,
	CURL_AGAIN,
	CURLE_SSL_CRL_BADFILE,
	CURLE_SSL_ISSUER_ERROR,
        CURL_CURL_LAST
        };

#endif /* HEADER_CURLMSG_VMS_H */
