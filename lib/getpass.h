#ifndef __GETPASS_H
#define __GETPASS_H
/*
 * Returning non-zero will abort the continued operation!
 */
int getpass_r(char *prompt, char* buffer, int buflen );

#endif
