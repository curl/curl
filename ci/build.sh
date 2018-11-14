#!/bin/bash
# by KangLin(kl222@126.com)

set -e

cd $1

PROJECT_DIR=`pwd`

cd ${PROJECT_DIR}
mkdir build
cd build

#TODO: Download or build dependent librarys

case ${BUILD_TARGERT} in
    windows_msvc)
        case ${TOOLCHAIN_VERSION} in
            15)
                PRJ_GEN="Visual Studio 15 2017"
            ;;
            14)
                PRJ_GEN="Visual Studio 14 2015"
            ;;
            12)
                PRJ_GEN="Visual Studio 12 2013"
            ;;
            11)
                PRJ_GEN="Visual Studio 11 2012"
            ;;
            9)
                PRJ_GEN="Visual Studio 9 2008"
                if [ "${Platform}" = "x64" ]; then
                    echo "Don't support Visual Studio 9 2008 for x64 in appveyor"
                    cd ${PROJECT_DIR}
                    exit 0
                fi
            ;;
        esac
        if [ "${Platform}" = "x64" ]; then
            PRJ_GEN="${PRJ_GEN} Win64"
        fi
    ;;
    
esac

# Test cmake
echo "cmake .. -G\"${PRJ_GEN}\" -DCMAKE_USE_OPENSSL=${OPENSSL} -DCMAKE_USE_WINSSL=${WINSSL} -DBUILD_SHARED_LIBS=${SHARED} -DBUILD_TESTING=${TESTING} -DCURL_WERROR=ON -DENABLE_DEBUG=${ENABLE_DEBUG} -DCMAKE_INSTALL_PREFIX="${PROJECT_DIR}/install" -DCMAKE_BUILD_TYPE=${Configuration} ${CMAKE_PARA}"
cmake .. \
    -G"${PRJ_GEN}" \
    -DCMAKE_USE_OPENSSL=${OPENSSL} \
    -DCMAKE_USE_WINSSL=${WINSSL} \
    -DBUILD_SHARED_LIBS=${SHARED} \
    -DBUILD_TESTING=${TESTING} \
    -DCURL_WERROR=ON \
    -DENABLE_DEBUG=${ENABLE_DEBUG} \
    -DCMAKE_INSTALL_PREFIX="${PROJECT_DIR}/install" \
    -DCMAKE_BUILD_TYPE=${Configuration} \
    ${CMAKE_PARA}
cmake --build . --config ${Configuration} --target install --clean-first


cd ${PROJECT_DIR}
