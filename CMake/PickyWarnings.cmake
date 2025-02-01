#***************************************************************************
#                                  _   _ ____  _
#  Project                     ___| | | |  _ \| |
#                             / __| | | | |_) | |
#                            | (__| |_| |  _ <| |___
#                             \___|\___/|_| \_\_____|
#
# Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
#
# This software is licensed as described in the file COPYING, which
# you should have received as part of this distribution. The terms
# are also available at https://curl.se/docs/copyright.html.
#
# You may opt to use, copy, modify, merge, publish, distribute and/or sell
# copies of the Software, and permit persons to whom the Software is
# furnished to do so, under the terms of the COPYING file.
#
# This software is distributed on an "AS IS" basis, WITHOUT WARRANTY OF ANY
# KIND, either express or implied.
#
# SPDX-License-Identifier: curl
#
###########################################################################
include(CheckCCompilerFlag)

set(_picky "")

if(CURL_WERROR AND
   ((CMAKE_COMPILER_IS_GNUCC AND
     NOT DOS AND  # Watt-32 headers use the '#include_next' GCC extension
     NOT CMAKE_C_COMPILER_VERSION VERSION_LESS 5.0 AND
     NOT CMAKE_VERSION VERSION_LESS 3.23.0) OR  # to avoid check_symbol_exists() conflicting with GCC -pedantic-errors
   CMAKE_C_COMPILER_ID MATCHES "Clang"))
  list(APPEND _picky "-pedantic-errors")
endif()

if(APPLE AND
   (CMAKE_C_COMPILER_ID STREQUAL "Clang"      AND NOT CMAKE_C_COMPILER_VERSION VERSION_LESS 3.6) OR
   (CMAKE_C_COMPILER_ID STREQUAL "AppleClang" AND NOT CMAKE_C_COMPILER_VERSION VERSION_LESS 6.3))
  list(APPEND _picky "-Werror=partial-availability")  # clang 3.6  appleclang 6.3
endif()

if(CMAKE_COMPILER_IS_GNUCC OR CMAKE_C_COMPILER_ID MATCHES "Clang")
  list(APPEND _picky "-Werror-implicit-function-declaration")  # clang 1.0  gcc 2.95
endif()

if(PICKY_COMPILER)
  if(CMAKE_COMPILER_IS_GNUCC OR CMAKE_C_COMPILER_ID MATCHES "Clang")

    # https://clang.llvm.org/docs/DiagnosticsReference.html
    # https://gcc.gnu.org/onlinedocs/gcc/Warning-Options.html

    # _picky_enable = Options we want to enable as-is.
    # _picky_detect = Options we want to test first and enable if available.

    # Prefer the -Wextra alias with clang.
    if(CMAKE_C_COMPILER_ID MATCHES "Clang")
      set(_picky_enable "-Wextra")
    else()
      set(_picky_enable "-W")
    endif()

    list(APPEND _picky_enable
      -Wall -pedantic
    )

    # ----------------------------------
    # Add new options here, if in doubt:
    # ----------------------------------
    set(_picky_detect
    )

    # Assume these options always exist with both clang and gcc.
    # Require clang 3.0 / gcc 2.95 or later.
    list(APPEND _picky_enable
      -Wbad-function-cast                  # clang  2.7  gcc  2.95
      -Wconversion                         # clang  2.7  gcc  2.95
      -Wmissing-declarations               # clang  1.0  gcc  2.7
      -Wmissing-prototypes                 # clang  1.0  gcc  1.0
      -Wnested-externs                     # clang  1.0  gcc  2.7
      -Wno-long-long                       # clang  1.0  gcc  2.95
      -Wno-multichar                       # clang  1.0  gcc  2.95
      -Wpointer-arith                      # clang  1.0  gcc  1.4
      -Wshadow                             # clang  1.0  gcc  2.95
      -Wsign-compare                       # clang  1.0  gcc  2.95
      -Wundef                              # clang  1.0  gcc  2.95
      -Wunused                             # clang  1.1  gcc  2.95
      -Wwrite-strings                      # clang  1.0  gcc  1.4
    )

    # Always enable with clang, version dependent with gcc
    set(_picky_common_old
      -Waddress                            # clang  2.7  gcc  4.3
      -Wattributes                         # clang  2.7  gcc  4.1
      -Wcast-align                         # clang  1.0  gcc  4.2
      -Wdeclaration-after-statement        # clang  1.0  gcc  3.4
      -Wdiv-by-zero                        # clang  2.7  gcc  4.1
      -Wempty-body                         # clang  2.7  gcc  4.3
      -Wendif-labels                       # clang  1.0  gcc  3.3
      -Wfloat-equal                        # clang  1.0  gcc  2.96 (3.0)
      -Wformat-security                    # clang  2.7  gcc  4.1
      -Wignored-qualifiers                 # clang  2.8  gcc  4.3
      -Wmissing-field-initializers         # clang  2.7  gcc  4.1
      -Wmissing-noreturn                   # clang  2.7  gcc  4.1
      -Wno-format-nonliteral               # clang  1.0  gcc  2.96 (3.0)
      -Wno-sign-conversion                 # clang  2.9  gcc  4.3
      -Wno-system-headers                  # clang  1.0  gcc  3.0
    # -Wpadded                             # clang  2.9  gcc  4.1               # Not used: We cannot change public structs
      -Wold-style-definition               # clang  2.7  gcc  3.4
      -Wredundant-decls                    # clang  2.7  gcc  4.1
      -Wstrict-prototypes                  # clang  1.0  gcc  3.3
    # -Wswitch-enum                        # clang  2.7  gcc  4.1               # Not used: It basically disallows default case
      -Wtype-limits                        # clang  2.7  gcc  4.3
      -Wunreachable-code                   # clang  2.7  gcc  4.1
    # -Wunused-macros                      # clang  2.7  gcc  4.1               # Not practical
      -Wunused-parameter                   # clang  2.7  gcc  4.1
      -Wvla                                # clang  2.8  gcc  4.3
    )

    if(CMAKE_C_COMPILER_ID MATCHES "Clang")
      list(APPEND _picky_enable
        ${_picky_common_old}
        -Wshift-sign-overflow              # clang  2.9
        -Wshorten-64-to-32                 # clang  1.0
        -Wformat=2                         # clang  3.0  gcc  4.8
      )
      if(NOT MSVC)
        list(APPEND _picky_enable
          -Wlanguage-extension-token       # clang  3.0
        )
      endif()
      # Enable based on compiler version
      if((CMAKE_C_COMPILER_ID STREQUAL "Clang"      AND NOT CMAKE_C_COMPILER_VERSION VERSION_LESS 3.6) OR
         (CMAKE_C_COMPILER_ID STREQUAL "AppleClang" AND NOT CMAKE_C_COMPILER_VERSION VERSION_LESS 6.3))
        list(APPEND _picky_enable
          -Wdouble-promotion               # clang  3.6  gcc  4.6  appleclang  6.3
          -Wenum-conversion                # clang  3.2  gcc 10.0  appleclang  4.6  g++ 11.0
          -Wheader-guard                   # clang  3.4            appleclang  5.1
          -Wpragmas                        # clang  3.5  gcc  4.1  appleclang  6.0
          -Wsometimes-uninitialized        # clang  3.2            appleclang  4.6
        # -Wunreachable-code-break         # clang  3.5            appleclang  6.0  # Not used: Silent in "unity" builds
          -Wunused-const-variable          # clang  3.4  gcc  6.0  appleclang  5.1
        )
      endif()
      if((CMAKE_C_COMPILER_ID STREQUAL "Clang"      AND NOT CMAKE_C_COMPILER_VERSION VERSION_LESS 3.9) OR
         (CMAKE_C_COMPILER_ID STREQUAL "AppleClang" AND NOT CMAKE_C_COMPILER_VERSION VERSION_LESS 8.3))
        list(APPEND _picky_enable
          -Wcomma                          # clang  3.9            appleclang  8.3
          -Wmissing-variable-declarations  # clang  3.2            appleclang  4.6
        )
      endif()
      if((CMAKE_C_COMPILER_ID STREQUAL "Clang"      AND NOT CMAKE_C_COMPILER_VERSION VERSION_LESS 7.0) OR
         (CMAKE_C_COMPILER_ID STREQUAL "AppleClang" AND NOT CMAKE_C_COMPILER_VERSION VERSION_LESS 10.3))
        list(APPEND _picky_enable
          -Wassign-enum                    # clang  7.0            appleclang 10.3
          -Wextra-semi-stmt                # clang  7.0            appleclang 10.3
        )
      endif()
      if((CMAKE_C_COMPILER_ID STREQUAL "Clang"      AND NOT CMAKE_C_COMPILER_VERSION VERSION_LESS 10.0) OR
         (CMAKE_C_COMPILER_ID STREQUAL "AppleClang" AND NOT CMAKE_C_COMPILER_VERSION VERSION_LESS 12.4))
        list(APPEND _picky_enable
          -Wimplicit-fallthrough           # clang  4.0  gcc  7.0  appleclang 12.4  # We do silencing for clang 10.0 and above only
        )
      endif()
    else()  # gcc
      # Enable based on compiler version
      if(NOT CMAKE_C_COMPILER_VERSION VERSION_LESS 4.3)
        list(APPEND _picky_enable
          ${_picky_common_old}
          -Wclobbered                      #             gcc  4.3
          -Wmissing-parameter-type         #             gcc  4.3
          -Wold-style-declaration          #             gcc  4.3
          -Wpragmas                        # clang  3.5  gcc  4.1  appleclang  6.0
          -Wstrict-aliasing=3              #             gcc  4.0
        )
      endif()
      if(NOT CMAKE_C_COMPILER_VERSION VERSION_LESS 4.5 AND MINGW)
        list(APPEND _picky_enable
          -Wno-pedantic-ms-format          #             gcc  4.5 (MinGW-only)
        )
      endif()
      if(NOT CMAKE_C_COMPILER_VERSION VERSION_LESS 4.8)
        list(APPEND _picky_enable
          -Wdouble-promotion               # clang  3.6  gcc  4.6  appleclang  6.3
          -Wformat=2                       # clang  3.0  gcc  4.8
          -Wtrampolines                    #             gcc  4.6
        )
      endif()
      if(NOT CMAKE_C_COMPILER_VERSION VERSION_LESS 5.0)
        list(APPEND _picky_enable
          -Warray-bounds=2 -ftree-vrp      # clang  3.0  gcc  5.0 (clang default: -Warray-bounds)
        )
      endif()
      if(NOT CMAKE_C_COMPILER_VERSION VERSION_LESS 6.0)
        list(APPEND _picky_enable
          -Wduplicated-cond                #             gcc  6.0
          -Wnull-dereference               # clang  3.0  gcc  6.0 (clang default)
            -fdelete-null-pointer-checks
          -Wshift-negative-value           # clang  3.7  gcc  6.0 (clang default)
          -Wshift-overflow=2               # clang  3.0  gcc  6.0 (clang default: -Wshift-overflow)
          -Wunused-const-variable          # clang  3.4  gcc  6.0  appleclang  5.1
        )
      endif()
      if(NOT CMAKE_C_COMPILER_VERSION VERSION_LESS 7.0)
        list(APPEND _picky_enable
          -Walloc-zero                     #             gcc  7.0
          -Wduplicated-branches            #             gcc  7.0
          -Wformat-truncation=2            #             gcc  7.0
          -Wimplicit-fallthrough           # clang  4.0  gcc  7.0
          -Wrestrict                       #             gcc  7.0
        )
      endif()
      if(NOT CMAKE_C_COMPILER_VERSION VERSION_LESS 10.0)
        list(APPEND _picky_enable
          -Warith-conversion               #             gcc 10.0
          -Wenum-conversion                # clang  3.2  gcc 10.0  appleclang  4.6  g++ 11.0
        )
      endif()
    endif()

    #

    foreach(_ccopt IN LISTS _picky_enable)
      list(APPEND _picky "${_ccopt}")
    endforeach()

    foreach(_ccopt IN LISTS _picky_detect)
      # Use a unique variable name 1. for meaningful log output 2. to have a fresh, undefined variable for each detection
      string(MAKE_C_IDENTIFIER "OPT${_ccopt}" _optvarname)
      # GCC only warns about unknown -Wno- options if there are also other diagnostic messages,
      # so test for the positive form instead
      string(REPLACE "-Wno-" "-W" _ccopt_on "${_ccopt}")
      check_c_compiler_flag(${_ccopt_on} ${_optvarname})
      if(${_optvarname})
        list(APPEND _picky "${_ccopt}")
      endif()
    endforeach()

    if(CMAKE_COMPILER_IS_GNUCC)
      if(CMAKE_C_COMPILER_VERSION VERSION_LESS 4.5)
        # Avoid false positives
        list(APPEND _picky "-Wno-shadow")
        list(APPEND _picky "-Wno-unreachable-code")
      endif()
      if(NOT CMAKE_C_COMPILER_VERSION VERSION_LESS 4.2 AND CMAKE_C_COMPILER_VERSION VERSION_LESS 4.6)
        # GCC <4.6 do not support #pragma to suppress warnings locally. Disable them globally instead.
        list(APPEND _picky "-Wno-overlength-strings")
      endif()
      if(NOT CMAKE_C_COMPILER_VERSION VERSION_LESS 4.0 AND CMAKE_C_COMPILER_VERSION VERSION_LESS 4.7)
        list(APPEND _picky "-Wno-missing-field-initializers")  # https://gcc.gnu.org/bugzilla/show_bug.cgi?id=36750
      endif()
      if(NOT CMAKE_C_COMPILER_VERSION VERSION_LESS 4.3 AND CMAKE_C_COMPILER_VERSION VERSION_LESS 4.8)
        list(APPEND _picky "-Wno-type-limits")  # Avoid false positives
      endif()
    endif()
  endif()
endif()

# clang-cl
if(CMAKE_C_COMPILER_ID STREQUAL "Clang" AND MSVC)
  list(APPEND _picky "-Wno-language-extension-token")  # Allow __int64

  set(_picky_tmp "")
  foreach(_ccopt IN LISTS _picky)
    # Prefix -Wall, otherwise clang-cl interprets it as an MSVC option and translates it to -Weverything
    if(_ccopt MATCHES "^-W" AND NOT _ccopt STREQUAL "-Wall")
      list(APPEND _picky_tmp ${_ccopt})
    else()
      list(APPEND _picky_tmp "-clang:${_ccopt}")
    endif()
  endforeach()
  set(_picky ${_picky_tmp})
endif()

if(_picky)
  string(REPLACE ";" " " _picky "${_picky}")
  string(APPEND CMAKE_C_FLAGS " ${_picky}")
  message(STATUS "Picky compiler options: ${_picky}")
endif()
