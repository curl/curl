#include <sys/types.h>
#include <attr/xattr.h>
#include <string.h>
#include <stdio.h>

int set_xattr_url( const char *origin, const char *filename ) {
  int err = setxattr( filename, "user.curl.origin", origin, strlen(origin), 0 );
  if (err) {
    fprintf(stderr, "setxattr: %s\n", strerror (errno));
  }
  return err;
}
