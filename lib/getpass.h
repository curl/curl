#ifndef __GETPASS_H
#define __GETPASS_H
/*
 * Returning non-zero will abort the continued operation!
 */
int my_getpass(void *client, char *prompt, char* buffer, int buflen );

#endif
