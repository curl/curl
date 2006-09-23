#ifndef __SOCKS_H
#define __SOCKS_H

/*
 * This function logs in to a SOCKS4 proxy and sends the specifics to the
 * final destination server.
 */
CURLcode Curl_SOCKS4(const char *proxy_name,
                     struct connectdata *conn);

/*
 * This function logs in to a SOCKS5 proxy and sends the specifics to the
 * final destination server.
 */
CURLcode Curl_SOCKS5(const char *proxy_name,
                     const char *proxy_password,
                     struct connectdata *conn);

#endif
