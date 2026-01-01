#!/bin/bash

source ../common.sh

PROJECT_NAME=libpcap
STALIB_NAME=libpcap.a
DYNLIB_NAME=libpcap.so
DIR=$(pwd)


function download() {
    if [[ ! -z "${DOCKER_CONTAINER:-}" ]]; then
        apt-get update && apt-get install -y make cmake flex bison libnl-3-dev
    fi
    cd $SRC
    if [ -x "$(command -v coscli)" ]; then
        coscli cp cos://sbd-testing-1251316161/bench_archive/LLM_FUZZ/archives/libpcap.tar.gz libpcap.tar.gz
        tar -xvf libpcap.tar.gz && rm libpcap.tar.gz
        coscli cp cos://sbd-testing-1251316161/bench_archive/LLM_FUZZ/archives/tcpdump.tar.gz tcpdump.tar.gz
        tar -xvf tcpdump.tar.gz && rm tcpdump.tar.gz
    else
        git clone --depth 1 https://github.com/the-tcpdump-group/libpcap.git libpcap
        git clone --depth=1 https://github.com/the-tcpdump-group/tcpdump.git tcpdump
    fi
}

function build_lib() {
    # Build project
    LIB_STORE_DIR=$WORK/build
    rm -rf $LIB_STORE_DIR
    mkdir -p ${LIB_STORE_DIR}
    cd $LIB_STORE_DIR

    cmake $SRC/libpcap -DBUILD_WITH_LIBNL=off -DENABLE_REMOTE=off -DDISABLE_RDMA=on
    make -j$(nproc)
}

function build_oss_fuzz() {
    cd $SRC/libpcap

    # build fuzz targets
    for target in pcap filter both
    do
        $CC $CFLAGS -I. -c testprogs/fuzz/fuzz_$target.c -o fuzz_$target.o
        $CXX $CXXFLAGS fuzz_$target.o -o $OUT/fuzz_$target $LIB_STORE_DIR/libpcap.a $LIB_FUZZING_ENGINE
    done
    cp testprogs/fuzz/fuzz_*.options $OUT/
}

function copy_include() {
    make_include pcap
}

function build_corpus() {
    mkdir -p ${LIB_BUILD}/corpus
    cd $SRC/tcpdump/
    cp -r tests ${LIB_BUILD}/corpus/
    cd $SRC/libpcap/testprogs/BPF
    ls *.txt | while read i; do tail -1 $i > ${LIB_BUILD}/corpus/$i; done
}

function build_dict() {
    pwd
}

build_all
