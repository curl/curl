#ifndef __GETPASS_H
#define __GETPASS_H
/*
 * Returning NULL will abort the continued operation!
 */
char* getpass_r(char *prompt, char* buffer, size_t buflen );

#endif
