#ifndef __INET_NTOA_R_H
#define __INET_NTOA_R_H
/*
 * My solaris 5.6 system running gcc 2.8.1 does *not* have this prototype
 * in any system include file! Isn't that weird?
 */
char *inet_ntoa_r(const struct in_addr in, char *buffer, int buflen);

#endif
