#!/bin/bash

source ../common.sh

PROJECT_NAME=protobuf
STALIB_NAME=libprotobuf.a
DYNLIB_NAME=libprotobuf.so
DIR=$(pwd)


function download() {
    if [[ ! -z "${DOCKER_CONTAINER:-}" ]]; then
        apt-get update && apt-get install -y cmake yasm wget zlib1g-dev libabsl-dev
    fi
    cd $SRC

    git clone --depth 1 https://github.com/protocolbuffers/protobuf.git
}

function build_lib() {
    # Build aom
    LIB_STORE_DIR=$WORK/lib
    cd $SRC/${PROJECT_NAME}
    rm -rf build_fuzz
    mkdir -p build_fuzz
    cd build_fuzz
    # Let protobuf fetch its own dependencies (abseil) to ensure compatibility.
    cmake -DCMAKE_INSTALL_PREFIX="$WORK" \
        -DCMAKE_C_COMPILER="$CC" \
        -DCMAKE_CXX_COMPILER="$CXX" \
        -DCMAKE_C_FLAGS="$CFLAGS" \
        -DCMAKE_CXX_FLAGS="$CXXFLAGS" \
        -Dprotobuf_BUILD_TESTS=OFF \
        -Dprotobuf_BUILD_EXAMPLES=OFF \
        -Dprotobuf_BUILD_CONFORMANCE=OFF \
        -Dprotobuf_BUILD_PROTOC_BINARIES=OFF \
        -Dprotobuf_BUILD_LIBPROTOC=OFF \
        -Dprotobuf_BUILD_LIBUPB=ON \
        -Dprotobuf_WITH_ZLIB=ON \
        -Dprotobuf_LOCAL_DEPENDENCIES_ONLY=OFF \
        -Dprotobuf_FORCE_FETCH_DEPENDENCIES=ON \
        -DCMAKE_POSITION_INDEPENDENT_CODE=ON \
        -DBUILD_SHARED_LIBS=OFF \
        "$SRC/${PROJECT_NAME}"

    # Build and install static libraries
    make -j$(nproc)
    make install
    cd $WORK/lib
    clang++ -shared -fPIC -o libprotobuf.so \
            -fuse-ld=lld \
            -Wl,--whole-archive libprotobuf.a -Wl,--no-whole-archive \
            -Wl,--allow-multiple-definition \
            -ldl -lpthread -lz -lm

}

function copy_include() {
    cd ${LIB_BUILD}
    mkdir -p include/google/protobuf
    cp ${WORK}/include/google/protobuf include/google/protobuf -r
}

function build_corpus() {
    cd ${LIB_BUILD}
    cp $SRC/${PROJECT_NAME}/src/google/protobuf/testdata corpus -r
}

function build_dict() {
    ls
}

build_all
