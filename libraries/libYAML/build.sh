#!/bin/bash

source ../common.sh

PROJECT_NAME=libYAML
STALIB_NAME=libyaml.a
DYNLIB_NAME=libyaml.so
DIR=$(pwd)

function download() {
    cd $SRC
    if [ -x "$(command -v coscli)" ]; then
        coscli cp cos://sbd-testing-1251316161/bench_archive/LLM_FUZZ/archives/${PROJECT_NAME}.tar.gz ${PROJECT_NAME}.tar.gz
        tar -xvf ${PROJECT_NAME}.tar.gz && rm ${PROJECT_NAME}.tar.gz
    else
        git clone --depth 1 https://github.com/yaml/libyaml.git
    fi
    # keep source dir as libyaml (repo name)
    [ -d libyaml ] && true
}

function build_lib() {
    LIB_STORE_DIR=$WORK/build
    rm -rf ${LIB_STORE_DIR}
    mkdir -p ${LIB_STORE_DIR}
    cd $LIB_STORE_DIR

    # Build static lib first
    cmake $SRC/libyaml \
        -DCMAKE_BUILD_TYPE=Release \
        -DCMAKE_C_FLAGS="${CFLAGS:-} -O3 -g -fPIC" \
        -DBUILD_SHARED_LIBS=OFF
    make -j$(nproc)

    # Build shared lib
    cmake $SRC/libyaml -DBUILD_SHARED_LIBS=ON
    make -j$(nproc)

    # common.sh expects .a and .so in LIB_STORE_DIR (cmake may put in . or lib/)
    if [ -f lib/libyaml.a ]; then cp lib/libyaml.a .; fi
    if [ -f lib/libyaml.so ]; then cp lib/libyaml.so .; fi
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
