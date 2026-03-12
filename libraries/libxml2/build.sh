#!/bin/bash

source ../common.sh

PROJECT_NAME=libxml2
STALIB_NAME=libxml2.a
DYNLIB_NAME=libxml2.so
DIR=$(pwd)

function download() {
    cd $SRC

    git clone --depth 1 https://gitlab.gnome.org/GNOME/libxml2.git
    
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
        --without-python \
        --without-modules \
        --without-lzma \
        --with-zlib=yes \
        --with-http=no \
        --with-ftp=no 
    make -j$(nproc)
    make install
    LIB_STORE_DIR=$BUILD_DIR/lib
   
}

function build_oss_fuzz() {
    pwd
}

function copy_include() {
    mkdir -p ${LIB_BUILD}/include
    # Headers are installed to $WORK/build/include/libxml2 by make install (source has include/libxml, not include/libxml2)
    cp -r $WORK/build/include/libxml2 ${LIB_BUILD}/include/
}

function build_corpus() {
    mkdir -p ${LIB_BUILD}/corpus
    echo '<?xml version="1.0"?><root>hello</root>' > ${LIB_BUILD}/corpus/sample.xml
}

function build_dict() {
    echo 'element="root"' > ${LIB_BUILD}/fuzzer.dict
}

build_all
