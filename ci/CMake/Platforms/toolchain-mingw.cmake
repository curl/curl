# the name of the target operating system
SET(CMAKE_SYSTEM_NAME Windows)

# Choose an appropriate compiler prefix

# for classical mingw32
# see http://www.mingw.org/
#set(COMPILER_PREFIX "i586-mingw32msvc")

# for 32 or 64 bits mingw-w64
# see https://mingw-w64.sourceforge.io/
if("$ENV{CURL_BUILD_CROSS_HOST}")
    set(COMPILER_PREFIX "$ENV{CURL_BUILD_CROSS_HOST}")
else("$ENV{CURL_BUILD_CROSS_HOST}")
    set(COMPILER_PREFIX "i686-w64-mingw32")
endif("$ENV{CURL_BUILD_CROSS_HOST}")

# which compilers to use for C and C++
find_program(CMAKE_RC_COMPILER NAMES ${COMPILER_PREFIX}-windres)
find_program(CMAKE_C_COMPILER NAMES ${COMPILER_PREFIX}-gcc)
find_program(CMAKE_CXX_COMPILER NAMES ${COMPILER_PREFIX}-g++)
find_program(CMAKE_ASM_COMPILER NAMES ${COMPILER_PREFIX}-gcc)
find_program(CMAKE_AR NAMES ${COMPILER_PREFIX}-gcc-ar)
find_program(CMAKE_NM NAMES ${COMPILER_PREFIX}-gcc-nm)
find_program(CMAKE_RANLIB NAMES ${COMPILER_PREFIX}-gcc-ranlib)

# here is the target environment located
SET(CMAKE_FIND_ROOT_PATH $ENV{CURL_BUILD_CROSS_SYSROOT}) 
SET(CMAKE_SYSROOT $ENV{CURL_BUILD_CROSS_SYSROOT})
# adjust the default behaviour of the FIND_XXX() commands:
# search headers and libraries in the target environment, search 
# programs in the host and target environment
#set(CMAKE_FIND_ROOT_PATH_MODE_PROGRAM ONLY)
set(CMAKE_FIND_ROOT_PATH_MODE_LIBRARY ONLY)
set(CMAKE_FIND_ROOT_PATH_MODE_INCLUDE ONLY)

