#!/bin/sh
# Copyright (C) Viktor Szakats
#
# SPDX-License-Identifier: curl

set -eu

cd "$(dirname "$0")"

command -v dpkg >/dev/null && export CMAKE_GENERATOR=Ninja

mode="${1:-all}"
shift

cmake_provider="${CMAKE_PROVIDER:-cmake}"
cmake_consumer="${CMAKE_CONSUMER:-${cmake_provider}}"

src='../..'

if [ "${mode}" = 'all' ] || [ "${mode}" = 'FetchContent' ]; then
  src="${PWD}/${src}"
  bldc='bld-fetchcontent'
  rm -rf "${bldc}"
  "${cmake_consumer}" -B "${bldc}" "$@" \
    -DTEST_INTEGRATION_MODE=FetchContent \
    -DFROM_GIT_REPO="${src}" \
    -DFROM_GIT_TAG="$(git rev-parse HEAD)"
  "${cmake_consumer}" --build "${bldc}" --verbose
fi

if [ "${mode}" = 'all' ] || [ "${mode}" = 'add_subdirectory' ]; then
  rm -rf curl; ln -s "${src}" curl
  bldc='bld-add_subdirectory'
  rm -rf "${bldc}"
  "${cmake_consumer}" -B "${bldc}" "$@" \
    -DTEST_INTEGRATION_MODE=add_subdirectory
  "${cmake_consumer}" --build "${bldc}" --verbose
fi

if [ "${mode}" = 'all' ] || [ "${mode}" = 'find_package' ]; then
  src="${PWD}/${src}"
  bldp='bld-curl'
  prefix="${PWD}/${bldp}/_pkg"
  rm -rf "${bldp}"
  "${cmake_provider}" -B "${bldp}" -S "${src}" -DCMAKE_INSTALL_PREFIX="${prefix}" "$@" \
    -DBUILD_SHARED_LIBS=ON \
    -DBUILD_STATIC_LIBS=ON
  "${cmake_provider}" --build "${bldp}"
  "${cmake_provider}" --install "${bldp}"
  bldc='bld-find_package'
  rm -rf "${bldc}"
  "${cmake_consumer}" -B "${bldc}" "$@" \
    -DTEST_INTEGRATION_MODE=find_package \
    -DCMAKE_PREFIX_PATH="${prefix}/lib/cmake/CURL"
  "${cmake_consumer}" --build "${bldc}" --verbose
fi
