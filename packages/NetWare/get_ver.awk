# fetch libcurl version number from input file and write them to STDOUT
BEGIN {
  while ((getline < ARGV[1]) > 0) {
    if (match ($0, /^#define LIBCURL_VERSION_MAJOR [^"]+/)) {
      libcurl_ver_major = substr($3, 1, length($3));
    }
    else if (match ($0, /^#define LIBCURL_VERSION_MINOR [^"]+/)) {
      libcurl_ver_minor = substr($3, 1, length($3));
    }
    else if (match ($0, /^#define LIBCURL_VERSION_PATCH [^"]+/)) {
      libcurl_ver_patch = substr($3, 1, length($3));
    }
  }
  libcurl_ver = libcurl_ver_major "," libcurl_ver_minor "," libcurl_ver_patch;
  libcurl_ver_str = libcurl_ver_major "." libcurl_ver_minor "." libcurl_ver_patch;

  print "LIBCURL_VERSION = " libcurl_ver "";
  print "LIBCURL_VERSION_STR = " libcurl_ver_str "";

}
