
#define socklen_t int

#define HAVE_SYS_SOCKET_H
#define HAVE_ARPA_INET_H
#define HAVE_SYS_SELECT_H
#define HAVE_FCNTL_H
#define HAVE_GETTIMEOFDAY

#define HAVE_SELECT
#define HAVE_SOCKET
#define ifr_dstaddr ifr_addr


#include <sys/socket.h>
#include <sys/if.h>
#include <sys/fcntl.h>
#include <sys/ioctl.h>
#include <netinet/in.h>
#include <netdb.h>

#define ioctl(a,b,c,d) (ioctl(a,b,c) * (d==d))


#define OS "RISC OS"
