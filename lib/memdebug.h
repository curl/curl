#ifdef MALLOCDEBUG

#include <sys/socket.h>
#include <stdio.h>

/* memory functions */
void *curl_domalloc(size_t size, int line, char *source);
void *curl_dorealloc(void *ptr, size_t size, int line, char *source);
void curl_dofree(void *ptr, int line, char *source);
char *curl_dostrdup(const char *str, int line, char *source);
void curl_memdebug(char *logname);

/* file descriptor manipulators */
int curl_socket(int domain, int type, int protocol, int, char *);
int curl_sclose(int sockfd, int, char *);
int curl_accept(int s, struct sockaddr *addr, socklen_t *addrlen,
                int line, char *source);

/* FILE functions */
FILE *curl_fopen(char *file, char *mode, int line, char *source);
int curl_fclose(FILE *file, int line, char *source);

/* Set this symbol on the command-line, recompile all lib-sources */
#define strdup(ptr) curl_dostrdup(ptr, __LINE__, __FILE__)
#define malloc(size) curl_domalloc(size, __LINE__, __FILE__)
#define realloc(ptr,size) curl_dorealloc(ptr, size, __LINE__, __FILE__)
#define free(ptr) curl_dofree(ptr, __LINE__, __FILE__)

#define socket(domain,type,protocol)\
 curl_socket(domain,type,protocol,__LINE__,__FILE__)
#define accept(sock,addr,len)\
 curl_accept(sock,addr,len,__LINE__,__FILE__)

/* sclose is probably already defined, redefine it! */
#undef sclose
#define sclose(sockfd) curl_sclose(sockfd,__LINE__,__FILE__)

#undef fopen
#define fopen(file,mode) curl_fopen(file,mode,__LINE__,__FILE__)
#define fclose(file) curl_fclose(file,__LINE__,__FILE__)

#endif
