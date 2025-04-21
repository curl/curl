#!/bin/sh
# Copyright (C) Viktor Szakats
#
# SPDX-License-Identifier: curl

set -eu

cd "$(dirname "$0")"

mode="${1:-all}"

if [ "${mode}" = 'all' ] || [ "${mode}" = 'FetchContent' ]; then
  rm -rf bld-fetchcontent
  cmake -B bld-fetchcontent \
    -DTEST_INTEGRATION_MODE=FetchContent \
    -DFROM_GIT_REPO="${PWD}/../.." \
    -DFROM_GIT_TAG="$(git rev-parse HEAD)"
  cmake --build bld-fetchcontent
fi

if [ "${mode}" = 'all' ] || [ "${mode}" = 'add_subdirectory' ]; then
  rm -rf curl; ln -s ../.. curl
  rm -rf bld-add_subdirectory
  cmake -B bld-add_subdirectory \
    -DTEST_INTEGRATION_MODE=add_subdirectory
  cmake --build bld-add_subdirectory
fi

if [ "${mode}" = 'all' ] || [ "${mode}" = 'find_package' ]; then
  bld='bld-curl'
  rm -rf "${bld}"
  cmake ../.. -B "${bld}" -DCMAKE_INSTALL_PREFIX="${PWD}/${bld}/_pkg" \
    -DBUILD_SHARED_LIBS=ON \
    -DBUILD_STATIC_LIBS=ON
  cmake --build "${bld}"
  cmake --install "${bld}"
  rm -rf bld-find_package
  cmake -B bld-find_package \
    -DTEST_INTEGRATION_MODE=find_package \
    -DCMAKE_PREFIX_PATH="${PWD}/${bld}/_pkg/lib/cmake/CURL"
  cmake --build bld-find_package --verbose
fi
