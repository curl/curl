/* CURLMSG_VMS.H                                                            */
/* This defines the necessary bits to change CURLE_* error codes to VMS     */
/* style error codes.  CURLMSG.H is built from CURLMSG.SDL which is built   */
/* from CURLMSG.MSG.  The vms_cond array is used to return VMS errors by    */
/* putting the VMS error codes into the array offset based on CURLE_* code. */
/*                                                                          */
#include "curlmsg.h"
int       vms_show = 0;
/*
#define   FAC_CURL      0xC01
#define   FAC_SYSTEM    0
#define   MSG_NORMAL    0
*/
#define   VMS_STS(c,f,e,s) (((c&0xF)<<28)|((f&0xFFF)<<16)|((e&0x1FFF)<3)|(s&7))
#define   VMSSTS_HIDE   VMS_STS(1,0,0,0)
/*
#define   SEV_WARNING   0
#define   SEV_SUCCESS   1
#define   SEV_ERROR     2
#define   SEV_INFO      3   
#define   SEV_FATAL     4
*/
long vms_cond[] = 
        {
        CURL_OK,
        CURL_UNSUPPORTED_PROTOCOL,
        CURL_FAILED_INIT,
        CURL_URL_MALFORMAT,
        CURL_URL_MALFORMAT_USER,
        CURL_COULDNT_RESOLVE_PROXY,
        CURL_COULDNT_RESOLVE_HOST,
        CURL_COULDNT_CONNECT,
        CURL_FTP_WEIRD_SERVER_REPLY,
        CURL_FTP_ACCESS_DENIED,
        CURL_FTP_USER_PWD_INCORRECT,
        CURL_FTP_WEIRD_PASS_REPLY,
        CURL_FTP_WEIRD_USER_REPLY,
        CURL_FTP_WEIRD_PASV_REPLY,
        CURL_FTP_WEIRD_227_FORMAT,
        CURL_FTP_CANT_GET_HOST,
        CURL_FTP_CANT_RECONNECT,
        CURL_FTP_COULDNT_SET_BINARY,
        CURL_PARTIAL_FILE,
        CURL_FTP_COULDNT_RETR_FILE,
        CURL_FTP_WRITE_ERROR,
        CURL_FTP_QUOTE_ERROR,
        CURL_HTTP_RETURNED_ERROR,
        CURL_WRITE_ERROR,
        CURL_MALFORMAT_USER,
        CURL_FTP_COULDNT_STOR_FILE,
        CURL_READ_ERROR,
        CURL_OUT_OF_MEMORY,
        CURL_OPERATION_TIMEOUTED,
        CURL_FTP_COULDNT_SET_ASCII,
        CURL_FTP_PORT_FAILED,
        CURL_FTP_COULDNT_USE_REST,
        CURL_FTP_COULDNT_GET_SIZE,
        CURL_HTTP_RANGE_ERROR,
        CURL_HTTP_POST_ERROR,
        CURL_SSL_CONNECT_ERROR,
        CURL_BAD_DOWNLOAD_RESUME,
        CURL_FILE_COULDNT_READ_FILE,
        CURL_LDAP_CANNOT_BIND,
        CURL_LDAP_SEARCH_FAILED,
        CURL_LIBRARY_NOT_FOUND,
        CURL_FUNCTION_NOT_FOUND,
        CURL_ABORTED_BY_CALLBACK,
        CURL_BAD_FUNCTION_ARGUMENT,
        CURL_BAD_CALLING_ORDER,
        CURL_HTTP_PORT_FAILED,
        CURL_BAD_PASSWORD_ENTERED,
        CURL_TOO_MANY_REDIRECTS,
        CURL_UNKNOWN_TELNET_OPTION,
        CURL_TELNET_OPTION_SYNTAX,
        CURL_OBSOLETE,
        CURL_SSL_PEER_CERTIFICATE,
        CURL_GOT_NOTHING,
        CURL_SSL_ENGINE_NOTFOUND,
        CURL_SSL_ENGINE_SETFAILED,
        CURL_SEND_ERROR,
        CURL_RECV_ERROR,
        CURL_SHARE_IN_USE,
        CURL_SSL_CERTPROBLEM,
        CURL_SSL_CIPHER,
        CURL_SSL_CACERT,
        CURL_BAD_CONTENT_ENCODING,
        CURL_LDAP_INVALID_URL,
        CURL_FILESIZE_EXCEEDED,
        CURL_CURL_LAST
        };
