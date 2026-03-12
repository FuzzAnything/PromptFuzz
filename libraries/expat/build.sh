#!/bin/bash

source ../common.sh

PROJECT_NAME=libexpat
STALIB_NAME=libexpat.a
DYNLIB_NAME=libexpat.so
DIR=$(pwd)

function download() {
    cd $SRC
    git clone --depth 1 https://github.com/libexpat/libexpat.git
}

function build_lib() {
    LIB_STORE_DIR=$WORK/build
    rm -rf $LIB_STORE_DIR
    mkdir -p $LIB_STORE_DIR
    cd $LIB_STORE_DIR
    
    # Build Static
    cmake $SRC/${PROJECT_NAME}/expat \
        -DCMAKE_BUILD_TYPE=Release \
        -DEXPAT_SHARED_LIBS=OFF \
        -DEXPAT_BUILD_TOOLS=OFF \
        -DEXPAT_BUILD_EXAMPLES=OFF \
        -DEXPAT_BUILD_TESTS=OFF
    make -j$(nproc)

    # Build Shared
    cmake $SRC/${PROJECT_NAME}/expat -DEXPAT_SHARED_LIBS=ON
    make -j$(nproc)
}

function build_oss_fuzz() {
    pwd
}

function copy_include() {
    mkdir -p ${LIB_BUILD}/include
    cp $SRC/${PROJECT_NAME}/expat/lib/expat.h ${LIB_BUILD}/include/
    cp $SRC/${PROJECT_NAME}/expat/lib/expat_external.h ${LIB_BUILD}/include/
}

function build_corpus() {
    mkdir -p ${LIB_BUILD}/corpus
    echo '<root>hello</root>' > ${LIB_BUILD}/corpus/sample.xml
}

function build_dict() {
    echo 'element="root"' > ${LIB_BUILD}/fuzzer.dict
}

build_all
