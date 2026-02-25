#!/bin/bash

source ../common.sh

PROJECT_NAME=liblouis
STALIB_NAME=liblouis.a
DYNLIB_NAME=liblouis.so
DIR=$(pwd)


function download() {
    if [[ ! -z "${DOCKER_CONTAINER:-}" ]]; then
        apt-get update && apt-get install -y yasm wget gcc
    fi

    cd $SRC
    git clone --depth 1 https://github.com/liblouis/liblouis.git
}

function build_lib() {
    # Build liblouis
    BUILD_DIR=$SRC/build
    rm -rf ${BUILD_DIR}
    mkdir -p ${BUILD_DIR}
    cd $SRC/liblouis
    ./autogen.sh
    ./configure --prefix=$BUILD_DIR --enable-static --enable-shared
    make -j$(nproc)
    make install
    LIB_STORE_DIR=$SRC/build/lib
}

function build_oss_fuzz() {
    pwd
}

function copy_include() {
    mkdir -p $LIB_BUILD/include
    cp -r $SRC/build/include/* $LIB_BUILD/include/
}

function build_corpus() {
    cd ${LIB_BUILD}
    mkdir corpus
    cp $SRC/liblouis/tables/latinLetterDef6Dots.uti corpus/
}

function build_dict() {
    cp $SRC/liblouis/tests/fuzzing/fuzz_translate_generic.dict ${LIB_BUILD}/fuzzer.dict
}


build_all