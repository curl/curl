#ifdef MALLOCDEBUG
/* memory functions */
void *curl_domalloc(size_t size, int line, char *source);
void *curl_dorealloc(void *ptr, size_t size, int line, char *source);
void curl_dofree(void *ptr, int line, char *source);
char *curl_dostrdup(char *str, int line, char *source);
void curl_memdebug(char *logname);

/* file descriptor manipulators */
int curl_socket(int domain, int type, int protocol, int, char *);
int curl_sclose(int sockfd, int, char *);

/* Set this symbol on the command-line, recompile all lib-sources */
#define strdup(ptr) curl_dostrdup(ptr, __LINE__, __FILE__)
#define malloc(size) curl_domalloc(size, __LINE__, __FILE__)
#define realloc(ptr,size) curl_dorealloc(ptr, size, __LINE__, __FILE__)
#define free(ptr) curl_dofree(ptr, __LINE__, __FILE__)

#define socket(domain,type,protocol)\
 curl_socket(domain,type,protocol,__LINE__,__FILE__)

/* sclose is probably already defined, redefine it! */
#undef sclose
#define sclose(sockfd) curl_sclose(sockfd,__LINE__,__FILE__)

#endif
