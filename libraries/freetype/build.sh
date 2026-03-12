#!/bin/bash

source ../common.sh

PROJECT_NAME=freetype
STALIB_NAME=libfreetype.a
DYNLIB_NAME=libfreetype.so
DIR=$(pwd)

function download() {
    if [[ ! -z "${DOCKER_CONTAINER:-}" ]]; then
        apt-get update && apt-get install -y autoconf automake libtool
    fi
    cd $SRC
    git clone --depth 1 https://gitlab.freedesktop.org/freetype/freetype.git
}

function build_lib() {
    BUILD_DIR=$WORK/build
    rm -rf $BUILD_DIR
    mkdir -p $BUILD_DIR
    cd $SRC/${PROJECT_NAME}
    ./autogen.sh
    ./configure \
        --prefix="$BUILD_DIR" \
        --enable-static \
        --enable-shared \
        --with-harfbuzz=no \
        --with-png=no \
        --with-zlib=yes \
        --with-bzip2=no \
        --with-brotli=no 
    make -j$(nproc)
    make install
    
    LIB_STORE_DIR=$BUILD_DIR/lib
}

function build_oss_fuzz() {
    pwd
}

function copy_include() {
    mkdir -p ${LIB_BUILD}/include
    cp -r $SRC/${PROJECT_NAME}/include/* ${LIB_BUILD}/include/
    rm -rf ${LIB_BUILD}/include/freetype/internal
    rm -rf ${LIB_BUILD}/include/dlg
}

function build_corpus() {
    mkdir -p ${LIB_BUILD}/corpus
    # minimal font-like seed
    printf '\x00\x01\x00\x00' > ${LIB_BUILD}/corpus/seed
}

function build_dict() {
    echo 'font=".ttf"' > ${LIB_BUILD}/fuzzer.dict
}

build_all
