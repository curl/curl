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
set(_picky_nocheck "")  # not to pass to feature checks

if(CURL_WERROR)
  if(MSVC)
    list(APPEND _picky_nocheck "-WX")
  else()  # llvm/clang and gcc style options
    list(APPEND _picky_nocheck "-Werror")
  endif()

  if((CMAKE_C_COMPILER_ID STREQUAL "GNU" AND
      NOT DOS AND  # Watt-32 headers use the '#include_next' GCC extension
      CMAKE_C_COMPILER_VERSION VERSION_GREATER_EQUAL 5.0) OR
     CMAKE_C_COMPILER_ID MATCHES "Clang")
    list(APPEND _picky_nocheck "-pedantic-errors")
  endif()
endif()

if(APPLE AND
   (CMAKE_C_COMPILER_ID STREQUAL "Clang"      AND CMAKE_C_COMPILER_VERSION VERSION_GREATER_EQUAL 3.6) OR
   (CMAKE_C_COMPILER_ID STREQUAL "AppleClang" AND CMAKE_C_COMPILER_VERSION VERSION_GREATER_EQUAL 6.3))
  list(APPEND _picky "-Werror=partial-availability")  # clang 3.6  appleclang 6.3
endif()

if(CMAKE_C_COMPILER_ID STREQUAL "GNU" OR CMAKE_C_COMPILER_ID MATCHES "Clang")
  list(APPEND _picky "-Werror-implicit-function-declaration")  # clang 1.0  gcc 2.95
endif()

if(MSVC)
  # Use the highest warning level for Visual Studio.
  string(REGEX REPLACE "[/-]W[0-4]" "" CMAKE_C_FLAGS "${CMAKE_C_FLAGS}")
  list(APPEND _picky "-W4")
elseif(BORLAND)
  list(APPEND _picky "-w-")  # Disable warnings on Borland to avoid changing 3rd party code.
endif()

if(PICKY_COMPILER)
  if(CMAKE_C_COMPILER_ID STREQUAL "GNU" OR CMAKE_C_COMPILER_ID MATCHES "Clang")

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
      -Wcast-qual                          # clang  3.0  gcc  3.4.6
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
    #   -Wno-error=unused-macros           # clang  2.7  gcc  4.1
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
      if((CMAKE_C_COMPILER_ID STREQUAL "Clang"      AND CMAKE_C_COMPILER_VERSION VERSION_GREATER_EQUAL 3.6) OR
         (CMAKE_C_COMPILER_ID STREQUAL "AppleClang" AND CMAKE_C_COMPILER_VERSION VERSION_GREATER_EQUAL 6.3))
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
      if((CMAKE_C_COMPILER_ID STREQUAL "Clang"      AND CMAKE_C_COMPILER_VERSION VERSION_GREATER_EQUAL 3.9) OR
         (CMAKE_C_COMPILER_ID STREQUAL "AppleClang" AND CMAKE_C_COMPILER_VERSION VERSION_GREATER_EQUAL 8.3))
        list(APPEND _picky_enable
          -Wcomma                          # clang  3.9            appleclang  8.3
          -Wmissing-variable-declarations  # clang  3.2            appleclang  4.6
        )
      endif()
      if((CMAKE_C_COMPILER_ID STREQUAL "Clang"      AND CMAKE_C_COMPILER_VERSION VERSION_GREATER_EQUAL 7.0) OR
         (CMAKE_C_COMPILER_ID STREQUAL "AppleClang" AND CMAKE_C_COMPILER_VERSION VERSION_GREATER_EQUAL 10.3))
        list(APPEND _picky_enable
          -Wassign-enum                    # clang  7.0            appleclang 10.3
          -Wextra-semi-stmt                # clang  7.0            appleclang 10.3
        )
      endif()
      if((CMAKE_C_COMPILER_ID STREQUAL "Clang"      AND CMAKE_C_COMPILER_VERSION VERSION_GREATER_EQUAL 10.0) OR
         (CMAKE_C_COMPILER_ID STREQUAL "AppleClang" AND CMAKE_C_COMPILER_VERSION VERSION_GREATER_EQUAL 12.4))
        list(APPEND _picky_enable
          -Wimplicit-fallthrough           # clang  4.0  gcc  7.0  appleclang 12.4  # We do silencing for clang 10.0 and above only
        )
      endif()
    else()  # gcc
      # Enable based on compiler version
      if(CMAKE_C_COMPILER_VERSION VERSION_GREATER_EQUAL 4.3)
        list(APPEND _picky_enable
          ${_picky_common_old}
          -Wclobbered                      #             gcc  4.3
          -Wmissing-parameter-type         #             gcc  4.3
          -Wold-style-declaration          #             gcc  4.3
          -Wpragmas                        # clang  3.5  gcc  4.1  appleclang  6.0
          -Wstrict-aliasing=3              #             gcc  4.0
          -ftree-vrp                       #             gcc  4.3 (required for -Warray-bounds, included in -Wall)
        )
      endif()
      if(CMAKE_C_COMPILER_VERSION VERSION_GREATER_EQUAL 4.5)
        list(APPEND _picky_enable
          -Wjump-misses-init               #             gcc  4.5
        )

        if(MINGW)
          list(APPEND _picky_enable
            -Wno-pedantic-ms-format        #             gcc  4.5 (MinGW-only)
          )
        endif()
      endif()
      if(CMAKE_C_COMPILER_VERSION VERSION_GREATER_EQUAL 4.8)
        list(APPEND _picky_enable
          -Wdouble-promotion               # clang  3.6  gcc  4.6  appleclang  6.3
          -Wformat=2                       # clang  3.0  gcc  4.8
          -Wtrampolines                    #             gcc  4.6
        )
      endif()
      if(CMAKE_C_COMPILER_VERSION VERSION_GREATER_EQUAL 5.0)
        list(APPEND _picky_enable
          -Warray-bounds=2                 # clang  3.0  gcc  5.0 (clang default: -Warray-bounds)
        )
      endif()
      if(CMAKE_C_COMPILER_VERSION VERSION_GREATER_EQUAL 6.0)
        list(APPEND _picky_enable
          -Wduplicated-cond                #             gcc  6.0
          -Wnull-dereference               # clang  3.0  gcc  6.0 (clang default)
            -fdelete-null-pointer-checks
          -Wshift-negative-value           # clang  3.7  gcc  6.0 (clang default)
          -Wshift-overflow=2               # clang  3.0  gcc  6.0 (clang default: -Wshift-overflow)
          -Wunused-const-variable          # clang  3.4  gcc  6.0  appleclang  5.1
        )
      endif()
      if(CMAKE_C_COMPILER_VERSION VERSION_GREATER_EQUAL 7.0)
        list(APPEND _picky_enable
          -Walloc-zero                     #             gcc  7.0
          -Wduplicated-branches            #             gcc  7.0
          -Wformat-truncation=2            #             gcc  7.0
          -Wimplicit-fallthrough           # clang  4.0  gcc  7.0
          -Wrestrict                       #             gcc  7.0
        )
      endif()
      if(CMAKE_C_COMPILER_VERSION VERSION_GREATER_EQUAL 10.0)
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

    if(CMAKE_C_COMPILER_ID STREQUAL "GNU")
      if(CMAKE_C_COMPILER_VERSION VERSION_LESS 4.5)
        # Avoid false positives
        list(APPEND _picky "-Wno-shadow")
        list(APPEND _picky "-Wno-unreachable-code")
      endif()
      if(CMAKE_C_COMPILER_VERSION VERSION_GREATER_EQUAL 4.2 AND CMAKE_C_COMPILER_VERSION VERSION_LESS 4.6)
        # GCC <4.6 do not support #pragma to suppress warnings locally. Disable them globally instead.
        list(APPEND _picky "-Wno-overlength-strings")
      endif()
      if(CMAKE_C_COMPILER_VERSION VERSION_GREATER_EQUAL 4.0 AND CMAKE_C_COMPILER_VERSION VERSION_LESS 4.7)
        list(APPEND _picky "-Wno-missing-field-initializers")  # https://gcc.gnu.org/bugzilla/show_bug.cgi?id=36750
      endif()
      if(CMAKE_C_COMPILER_VERSION VERSION_GREATER_EQUAL 4.3 AND CMAKE_C_COMPILER_VERSION VERSION_LESS 4.8)
        list(APPEND _picky "-Wno-type-limits")  # Avoid false positives
      endif()
      if(CMAKE_C_COMPILER_VERSION VERSION_GREATER_EQUAL 5.1 AND CMAKE_C_COMPILER_VERSION VERSION_LESS 5.5)
        list(APPEND _picky "-Wno-conversion")  # Avoid false positives
      endif()
    endif()
  elseif(MSVC AND MSVC_VERSION LESS_EQUAL 1943)  # Skip for untested/unreleased newer versions
    list(APPEND _picky "-Wall")
    list(APPEND _picky "-wd4061")  # enumerator 'A' in switch of enum 'B' is not explicitly handled by a case label
    list(APPEND _picky "-wd4191")  # 'type cast': unsafe conversion from 'FARPROC' to 'void (__cdecl *)(void)'
    list(APPEND _picky "-wd4255")  # no function prototype given: converting '()' to '(void)' (in winuser.h)
    list(APPEND _picky "-wd4464")  # relative include path contains '..'
    list(APPEND _picky "-wd4548")  # expression before comma has no effect; expected expression with side-effect (in FD_SET())
    list(APPEND _picky "-wd4574")  # 'M' is defined to be '0': did you mean to use '#if M'? (in ws2tcpip.h)
    list(APPEND _picky "-wd4668")  # 'M' is not defined as a preprocessor macro, replacing with '0' for '#if/#elif' (in winbase.h)
    list(APPEND _picky "-wd4710")  # 'snprintf': function not inlined
    list(APPEND _picky "-wd4711")  # function 'A' selected for automatic inline expansion
    list(APPEND _picky "-wd4746")  # volatile access of '<expression>' is subject to /volatile:<iso|ms> setting;
                                   #   consider using __iso_volatile_load/store intrinsic functions (ARM64)
    list(APPEND _picky "-wd4774")  # 'snprintf': format string expected in argument 3 is not a string literal
    list(APPEND _picky "-wd4820")  # 'A': 'N' bytes padding added after data member 'B'
    if(MSVC_VERSION GREATER_EQUAL 1900)
      list(APPEND _picky "-wd5045")  # Compiler will insert Spectre mitigation for memory load if /Qspectre switch specified
    endif()
  endif()
endif()

# clang-cl
if(CMAKE_C_COMPILER_ID STREQUAL "Clang" AND MSVC)
  list(APPEND _picky "-Wno-language-extension-token")  # Allow __int64

  foreach(_wlist IN ITEMS _picky_nocheck _picky)
    set(_picky_tmp "")
    foreach(_ccopt IN LISTS "${_wlist}")
      # Prefix -Wall, otherwise clang-cl interprets it as an MSVC option and translates it to -Weverything
      if(_ccopt MATCHES "^-W" AND NOT _ccopt STREQUAL "-Wall")
        list(APPEND _picky_tmp ${_ccopt})
      else()
        list(APPEND _picky_tmp "-clang:${_ccopt}")
      endif()
    endforeach()
    set("${_wlist}" ${_picky_tmp})
  endforeach()
endif()

if(_picky_nocheck OR _picky)
  set(_picky_tmp "${_picky_nocheck}" "${_picky}")
  string(REPLACE ";" " " _picky_tmp "${_picky_tmp}")
  string(STRIP "${_picky_tmp}" _picky_tmp)
  message(STATUS "Picky compiler options: ${_picky_tmp}")
  set_property(DIRECTORY APPEND PROPERTY COMPILE_OPTIONS "${_picky_nocheck}" "${_picky}")

  # Apply to all feature checks
  string(REPLACE ";" " " _picky_tmp "${_picky}")
  string(APPEND CMAKE_REQUIRED_FLAGS " ${_picky_tmp}")

  unset(_picky)
  unset(_picky_tmp)
endif()
