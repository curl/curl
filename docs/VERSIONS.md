Version Numbers and Releases
============================

 Curl is not only curl. Curl is also libcurl. They are actually individually
 versioned, but they usually follow each other closely.

 The version numbering is always built up using the same system:

        X.Y.Z

  - X is main version number
  - Y is release number
  - Z is patch number

## Bumping numbers

 One of these numbers will get bumped in each new release. The numbers to the
 right of a bumped number will be reset to zero.

 The main version number will get bumped when *really* big, world colliding
 changes are made. The release number is bumped when changes are performed or
 things/features are added. The patch number is bumped when the changes are
 mere bugfixes.

 It means that after release 1.2.3, we can release 2.0.0 if something really
 big has been made, 1.3.0 if not that big changes were made or 1.2.4 if only
 bugs were fixed.

 Bumping, as in increasing the number with 1, is unconditionally only
 affecting one of the numbers (except the ones to the right of it, that may be
 set to zero). 1 becomes 2, 3 becomes 4, 9 becomes 10, 88 becomes 89 and 99
 becomes 100. So, after 1.2.9 comes 1.2.10. After 3.99.3, 3.100.0 might come.

 All original curl source release archives are named according to the libcurl
 version (not according to the curl client version that, as said before, might
 differ).

 As a service to any application that might want to support new libcurl
 features while still being able to build with older versions, all releases
 have the libcurl version stored in the `curl/curlver.h` file using a static
 numbering scheme that can be used for comparison. The version number is
 defined as:

```c
#define LIBCURL_VERSION_NUM 0xXXYYZZ
```

 Where `XX`, `YY` and `ZZ` are the main version, release and patch numbers in
 hexadecimal. All three number fields are always represented using two digits
 (eight bits each). 1.2 would appear as "0x010200" while version 9.11.7
 appears as `0x090b07`.

 This 6-digit hexadecimal number is always a greater number in a more recent
 release. It makes comparisons with greater than and less than work.

 This number is also available as three separate defines:
 `LIBCURL_VERSION_MAJOR`, `LIBCURL_VERSION_MINOR` and `LIBCURL_VERSION_PATCH`.
