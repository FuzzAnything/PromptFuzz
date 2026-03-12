#!/bin/bash

source ../common.sh

PROJECT_NAME=libyaml
STALIB_NAME=libyaml.a
DYNLIB_NAME=libyaml.so
DIR=$(pwd)

function download() {
    cd $SRC
    git clone --depth 1 https://github.com/yaml/libyaml.git
}

function build_lib() {
    BUILD_DIR=$WORK/build
    rm -rf ${BUILD_DIR}
    mkdir -p ${BUILD_DIR}
    cd $BUILD_DIR

    # Build static lib first
    cmake $SRC/libyaml \
        -DCMAKE_BUILD_TYPE=Release \
        -DBUILD_SHARED_LIBS=OFF
    make -j$(nproc)

    # Build shared lib
    cmake $SRC/libyaml -DBUILD_SHARED_LIBS=ON
    make -j$(nproc)
    LIB_STORE_DIR=$BUILD_DIR

}

function copy_include() {
    mkdir -p ${LIB_BUILD}/include
    cp $SRC/libyaml/include/yaml.h ${LIB_BUILD}/include/
    [ -f $WORK/build/include/config.h ] && cp $WORK/build/include/config.h ${LIB_BUILD}/include/
}

function build_corpus() {
    mkdir -p ${LIB_BUILD}/corpus
    echo 'key: value' > ${LIB_BUILD}/corpus/sample.yaml
}

function build_dict() {
    echo 'key="value"' > ${LIB_BUILD}/fuzzer.dict
}

build_all
