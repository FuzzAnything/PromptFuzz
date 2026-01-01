#!/bin/bash

source ../common.sh

PROJECT_NAME=lcms
STALIB_NAME=liblcms2.a
DYNLIB_NAME=liblcms2.so
DIR=$(pwd)


function download() {
    if [[ ! -z "${DOCKER_CONTAINER:-}" ]]; then
        apt-get update && apt-get install -y make autoconf automake libtool
    fi
    cd $SRC
    if [ -x "$(command -v coscli)" ]; then
        coscli cp cos://sbd-testing-1251316161/bench_archive/LLM_FUZZ/archives/Little-CMS.tar.gz Little-CMS.tar.gz
        tar -xvf Little-CMS.tar.gz && rm Little-CMS.tar.gz
    else
        git clone --depth 1 https://github.com/mm2/Little-CMS.git
        pushd Little-CMS
        wget https://raw.githubusercontent.com/google/oss-fuzz/master/projects/lcms/cmsIT8_load_fuzzer.c
        wget https://raw.githubusercontent.com/google/oss-fuzz/master/projects/lcms/cms_transform_fuzzer.c
        wget https://raw.githubusercontent.com/google/oss-fuzz/master/projects/lcms/cms_overwrite_transform_fuzzer.c
        wget https://raw.githubusercontent.com/google/oss-fuzz/master/projects/lcms/cms_transform_all_fuzzer.c
        wget https://raw.githubusercontent.com/google/oss-fuzz/master/projects/lcms/cms_profile_fuzzer.c
        wget https://raw.githubusercontent.com/google/oss-fuzz/master/projects/lcms/cms_universal_transform_fuzzer.c
        wget https://raw.githubusercontent.com/google/oss-fuzz/master/projects/lcms/cms_transform_extended_fuzzer.c
        popd
    fi
    mv Little-CMS ${PROJECT_NAME}
    SRC=$SRC/$PROJECT_NAME
}

function build_lib() {
    # Build lcms
    LIB_STORE_DIR=$SRC/src/.libs
    cd $SRC
    # build the target.
    ./configure 
    make clean
    make -j$(nproc) all
}

function build_oss_fuzz() {
    cd $SRC
    # build your fuzzer(s)
    FUZZERS="cmsIT8_load_fuzzer            \
            cms_transform_fuzzer           \
            cms_overwrite_transform_fuzzer \
            cms_transform_all_fuzzer       \
            cms_profile_fuzzer             \
            cms_universal_transform_fuzzer \
            cms_transform_extended_fuzzer"

    for F in $FUZZERS; do
        $CC $CFLAGS -c -Iinclude \
            $SRC/$F.c -o $SRC/$F.o
        $CXX $CXXFLAGS \
            $SRC/$F.o -o $OUT/$F \
            $LIB_FUZZING_ENGINE $SRC/src/.libs/liblcms2.a
    done
}

function copy_include() {
    mkdir -p ${LIB_BUILD}/include
    cp ${SRC}/include/lcms2.h ${LIB_BUILD}/include/lcms2.h
    #cp ${SRC}/include/lcms2_plugin.h ${LIB_BUILD}/include/lcms2_plugin.h
}

function build_corpus() {
    mkdir -p ${LIB_BUILD}/corpus && \
    cd ${LIB_BUILD}/corpus && \
    cp $SRC/testbed/bad.icc . && \
    cp $SRC/testbed/toosmall.icc . && \
    cp $SRC/testbed/test1.icc . && \
    cp $SRC/testbed/crayons.icc . && \
    cp $SRC/testbed/ibm-t61.icc .
}

function build_dict() {
    cp ${DIR}/icc.dict ${LIB_BUILD}/fuzzer.dict
}

build_all
