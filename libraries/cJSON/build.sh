#!/bin/bash

source ../common.sh

PROJECT_NAME=cjson
STALIB_NAME=libcjson.a
DYNLIB_NAME=libcjson.so
DIR=$(pwd)


function download() {
    cd $SRC
    if [ -x "$(command -v coscli)" ]; then
        coscli cp cos://sbd-testing-1251316161/bench_archive/LLM_FUZZ/archives/cJSON.tar.gz cJSON.tar.gz
        tar -xvf cJSON.tar.gz && rm cJSON.tar.gz
    else
        git clone --depth 1 https://github.com/DaveGamble/cJSON.git
    fi
    mv cJSON $PROJECT_NAME
}

function build_lib() {
    LIB_STORE_DIR=$WORK/build
    rm -rf $LIB_STORE_DIR
    mkdir -p $LIB_STORE_DIR
    cd $LIB_STORE_DIR
    cmake -DBUILD_SHARED_AND_STATIC_LIBS=ON -DENABLE_CJSON_TEST=OFF $SRC/cjson
    make -j$(nproc)
}

function build_oss_fuzz() {
    # build fuzzers
    $CXX $CXXFLAGS $SRC/${PROJECT_NAME}/fuzzing/cjson_read_fuzzer.c -I. \
    -o $OUT/cjson_read_fuzzer \
    $LIB_FUZZING_ENGINE $WORK/build/libcjson.a
}

function copy_include() {
    mkdir -p ${LIB_BUILD}/include
    cp ${SRC}/${PROJECT_NAME}/cJSON.h ${LIB_BUILD}/include/cJSON.h
}

function build_corpus() {
    cp $SRC/cjson/fuzzing/inputs ${LIB_BUILD}/corpus -r
    append_terminate_to_corpus ${LIB_BUILD}/corpus
    for FILE in ${LIB_BUILD}/corpus/*; do
        dd if=$FILE of=$FILE.bak bs=1 skip=2 && mv $FILE.bak $FILE
    done
}

function build_dict() {
    cp $SRC/cjson/fuzzing/json.dict ${LIB_BUILD}/fuzzer.dict
}

build_all
