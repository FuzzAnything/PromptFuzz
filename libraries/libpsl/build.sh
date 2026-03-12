#!/bin/bash

source ../common.sh

PROJECT_NAME=libpsl
STALIB_NAME=libpsl.a
DYNLIB_NAME=libpsl.so
DIR=$(pwd)

function download() {
    cd $SRC
    apt update && apt install -y git meson ninja-build autoconf autoconf-archive autopoint automake libtool gettext pkg-config gtk-doc-tools libidn-dev

    # clone with submodules so that list/public_suffix_list.dat exists for Meson
    git clone --depth 1 --recursive https://github.com/rockdaboot/libpsl.git
}

function build_lib() {

    cd $SRC/libpsl
    BUILD_DIR=$WORK/build
    rm -rf $BUILD_DIR
    mkdir -p $BUILD_DIR
    ./autogen.sh
    ./configure --prefix="$BUILD_DIR" --enable-static --enable-shared
    make -j$(nproc)
    make install
    LIB_STORE_DIR=$BUILD_DIR/lib
}

function copy_include() {
    mkdir -p ${LIB_BUILD}/include
    # libpsl installs include/libpsl.h (generated from include/psl.h.in)
    if [ -f $WORK/build/include/libpsl.h ]; then
        cp $WORK/build/include/libpsl.h ${LIB_BUILD}/include/
    fi
    # psl.h might not exist in some versions or build modes, libpsl.h is the primary one
    [ -f $WORK/build/include/psl.h ] && cp $WORK/build/include/psl.h ${LIB_BUILD}/include/
    [ -f $SRC/libpsl/include/psl.h ] && cp $SRC/libpsl/include/psl.h ${LIB_BUILD}/include/
    return 0
}

function build_corpus() {
    mkdir -p ${LIB_BUILD}/corpus
    echo 'example.com' > ${LIB_BUILD}/corpus/sample_domain.txt
    echo 'sub.domain.co.uk' >> ${LIB_BUILD}/corpus/sample_domain.txt
}

function build_dict() {
    echo 'domain="example.com"' > ${LIB_BUILD}/fuzzer.dict
    echo 'suffix=".co.uk"' >> ${LIB_BUILD}/fuzzer.dict
}

build_all
