#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(int argc, char **argv) {
  char *values[] = {
    /* -E parameter */        /* exp. cert name */  /* exp. passphrase */
    "foo:bar:baz",            "foo",                "bar:baz",
    "foo\\:bar:baz",          "foo:bar",            "baz",
    "foo\\\\:bar:baz",        "foo\\",              "bar:baz",
    "foo:bar\\:baz",          "foo",                "bar\\:baz",
    "foo:bar\\\\:baz",        "foo",                "bar\\\\:baz",
    "foo\\bar\\baz",          "foo\\bar\\baz",      NULL,
    "foo\\\\bar\\\\baz",      "foo\\bar\\baz",      NULL,
    "foo\\",                  "foo\\",              NULL,
    "foo\\\\",                "foo\\",              NULL,
    "foo:bar\\",              "foo",                "bar\\",
    "foo:bar\\\\",            "foo",                "bar\\\\",
    "foo:bar:",               "foo",                "bar:",
    "foo\\::bar\\:",          "foo:",               "bar\\:",
    "c:\\foo:bar:baz",        "c:\\foo",            "bar:baz",
    "c:\\foo\\:bar:baz",      "c:\\foo:bar",        "baz",
    "c:\\foo\\\\:bar:baz",    "c:\\foo\\",          "bar:baz",
    "c:\\foo:bar\\:baz",      "c:\\foo",            "bar\\:baz",
    "c:\\foo:bar\\\\:baz",    "c:\\foo",            "bar\\\\:baz",
    "c:\\foo\\bar\\baz",      "c:\\foo\\bar\\baz",  NULL,
    "c:\\foo\\\\bar\\\\baz",  "c:\\foo\\bar\\baz",  NULL,
    "c:\\foo\\",              "c:\\foo\\",          NULL,
    "c:\\foo\\\\",            "c:\\foo\\",          NULL,
    "c:\\foo:bar\\",          "c:\\foo",            "bar\\",
    "c:\\foo:bar\\\\",        "c:\\foo",            "bar\\\\",
    "c:\\foo:bar:",           "c:\\foo",            "bar:",
    "c:\\foo\\::bar\\:",      "c:\\foo:",           "bar\\:",
    NULL,                     NULL,                 NULL,
  };
  char **p;
  char *certname, *passphrase;
  for(p = values; *p; p += 3) {
    parse_cert_parameter(p[0], &certname, &passphrase);
    if(p[1]) {
      if(certname) {
        if(strcmp(p[1], certname)) {
          printf("expected certname '%s' but got '%s' "
              "for -E param '%s'\n", p[1], certname, p[0]);
        }
      } else {
        printf("expected certname '%s' but got NULL "
            "for -E param '%s'\n", p[1], p[0]);
      }
    } else {
      if(certname) {
        printf("expected certname NULL but got '%s' "
            "for -E param '%s'\n", certname, p[0]);
      }
    }
    if(p[2]) {
      if(passphrase) {
        if(strcmp(p[2], passphrase)) {
          printf("expected passphrase '%s' but got '%s'"
              "for -E param '%s'\n", p[2], passphrase, p[0]);
        }
      } else {
        printf("expected passphrase '%s' but got NULL "
            "for -E param '%s'\n", p[2], p[0]);
      }
    } else {
      if(passphrase) {
        printf("expected passphrase NULL but got '%s' "
            "for -E param '%s'\n", passphrase, p[0]);
      }
    }
    if(certname) free(certname);
    if(passphrase) free(passphrase);
  }
}
