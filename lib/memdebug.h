#ifdef MALLOCDEBUG
void *curl_domalloc(size_t size, int line, char *source);
void *curl_dorealloc(void *ptr, size_t size, int line, char *source);
void curl_dofree(void *ptr, int line, char *source);
char *curl_dostrdup(char *str, int line, char *source);
void curl_memdebug(char *logname);

/* Set this symbol on the command-line, recompile all lib-sources */
#define strdup(ptr) curl_dostrdup(ptr, __LINE__, __FILE__)
#define malloc(size) curl_domalloc(size, __LINE__, __FILE__)
#define realloc(ptr,size) curl_dorealloc(ptr, size, __LINE__, __FILE__)
#define free(ptr) curl_dofree(ptr, __LINE__, __FILE__)
#endif
