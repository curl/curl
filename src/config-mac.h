#define HAVE_UNISTD_H		1
#define HAVE_FCNTL_H		1
#define HAVE_UTIME_H		1
#define HAVE_SYS_UTIME_H	1

#define HAVE_SETVBUF		1
#define HAVE_UTIME			1

#define main(x,y) curl_main(x,y)

/* we provide our own strdup prototype */
char *strdup(char *s1);
