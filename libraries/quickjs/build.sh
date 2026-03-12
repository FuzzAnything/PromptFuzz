#!/bin/bash

source ../common.sh

PROJECT_NAME=quickjs
STALIB_NAME=libquickjs.a
DYNLIB_NAME=libquickjs.so
DIR=$(pwd)

function download() {
    cd $SRC
    git clone --depth 1 https://github.com/bellard/quickjs.git
}

function build_lib() {
    BUILD_DIR=$WORK/build
    rm -rf $BUILD_DIR
    mkdir -p $BUILD_DIR
    cd $SRC/${PROJECT_NAME}
    # Fix common build issues (PRId64, CONFIG_VERSION)
    sed -i '1i#include <inttypes.h>' quickjs.c 2>/dev/null || true
    sed -i 's/CONFIG_VERSION/"unknown"/g' quickjs.c 2>/dev/null || true
    sed -i 's/%" PRId64 "/%lld/g' quickjs.c 2>/dev/null || true
    sed -i 's/%"PRId64"/%lld/g' quickjs.c 2>/dev/null || true
    # -D_GNU_SOURCE needed on glibc for environ, sighandler_t in quickjs-libc.c
    QJ_CFLAGS="-O3 -g -fPIC -D_GNU_SOURCE"
    make clean || true
    make -j$(nproc) CC="$CC" AR="${AR:-ar}" CFLAGS="$QJ_CFLAGS $CFLAGS" libquickjs.a
    # QuickJS Makefile may not build .so; build shared for copy_share_lib
    $CC -shared -fPIC -O3 -g -D_GNU_SOURCE -o libquickjs.so quickjs.c quickjs-libc.c cutils.c -lm 2>/dev/null
    LIB_STORE_DIR=$SRC/${PROJECT_NAME}
}

function build_oss_fuzz() {
    pwd
}

function copy_include() {
    mkdir -p ${LIB_BUILD}/include
    cp $SRC/${PROJECT_NAME}/quickjs.h ${LIB_BUILD}/include/
    cp $SRC/${PROJECT_NAME}/quickjs-libc.h ${LIB_BUILD}/include/
    mkdir -p ${LIB_BUILD}/include/quickjs
    cp $SRC/${PROJECT_NAME}/quickjs.h ${LIB_BUILD}/include/quickjs/ 2>/dev/null || true
    cp $SRC/${PROJECT_NAME}/quickjs-libc.h ${LIB_BUILD}/include/quickjs/ 2>/dev/null || true
}

function build_corpus() {
    mkdir -p ${LIB_BUILD}/corpus
    echo '1+1' > ${LIB_BUILD}/corpus/seed.js
}

function build_dict() {
    echo 'keyword="function"' > ${LIB_BUILD}/fuzzer.dict
}

build_all
