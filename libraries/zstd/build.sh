#!/bin/bash

source ../common.sh

PROJECT_NAME=zstd
STALIB_NAME=libzstd.a
DYNLIB_NAME=libzstd.so
DIR=$(pwd)

function download() {
    cd $SRC
    git clone --depth 1 https://github.com/facebook/zstd.git
}

function build_lib() {
    BUILD_DIR=$WORK/build
    rm -rf $BUILD_DIR
    mkdir -p $BUILD_DIR
    cd $SRC/${PROJECT_NAME}/lib
    make clean || true
    make -j$(nproc) lib
    # zstd make install puts libs in PREFIX/lib
    make install PREFIX="$BUILD_DIR" install-static install-includes
    LIB_STORE_DIR=$BUILD_DIR/lib
}

function build_oss_fuzz() {
    pwd
}

function copy_include() {
    mkdir -p ${LIB_BUILD}/include
    # Public API only: zstd.h, zstd_errors.h, zdict.h (no common/compress/decompress/dictBuilder)
    cp $SRC/${PROJECT_NAME}/lib/zstd.h $SRC/${PROJECT_NAME}/lib/zstd_errors.h $SRC/${PROJECT_NAME}/lib/zdict.h ${LIB_BUILD}/include/
    blue_echo "Headers copied to ${LIB_BUILD}/include (zstd.h, zstd_errors.h, zdict.h)"
}

function build_corpus() {
    mkdir -p ${LIB_BUILD}/corpus
    # minimal zstd frame
    printf '\x28\xb5\x2f\xfd\x00\x00\x00\x00\x01\x00\x00' > ${LIB_BUILD}/corpus/seed
}

function build_dict() {
    echo 'magic="\x28\xb5\x2f\xfd"' > ${LIB_BUILD}/fuzzer.dict
}

build_all
