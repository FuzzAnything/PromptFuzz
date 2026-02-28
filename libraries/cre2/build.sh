#!/bin/bash

source ../common.sh

PROJECT_NAME=cre2
STALIB_NAME=libcre2.a
DYNLIB_NAME=libcre2.so
DIR=$(pwd)

set -e
set -x

function download() {
    if [[ ! -z "${DOCKER_CONTAINER:-}" ]]; then
        apt-get update &&
            apt-get -y upgrade &&
            apt-get -y install pkg-config file cmake autoconf automake texinfo libtool libabsl-dev &&
            apt-get clean
    fi
    cd $SRC

    git clone --depth 1 https://github.com/PromptFuzz/cre2
    git clone --depth 1 https://github.com/google/re2.git
    sed -i '1i #include <cstring>' $SRC/cre2/src/cre2.cpp

    git clone --depth 1 https://github.com/abseil/abseil-cpp.git
    cd abseil-cpp
    mkdir build && cd build

    cmake .. \
    -DCMAKE_CXX_STANDARD=17 \
    -DABSL_ENABLE_INSTALL=ON \
    -DCMAKE_POSITION_INDEPENDENT_CODE=ON --trace-expand

    make -j$(nproc)
    make install
}

function build_lib() {
    export INSTALLDIR=$WORK
    mkdir -p $WORK
    LIB_STORE_DIR=$INSTALLDIR/lib
    rm -rf $INSTALLDIR/lib

    export PKG_CONFIG_PATH=$INSTALLDIR/lib/pkgconfig:/usr/local/lib/x86_64-linux-gnu/pkgconfig:/usr/local/lib/pkgconfig:$PKG_CONFIG_PATH

    # build re2
    pushd $SRC/re2
    CXXFLAGS="$CXXFLAGS -fPIC"
    make clean
    make -j$(nproc)
    make install prefix=$INSTALLDIR
    popd

    pushd $SRC/cre2
    ./autogen.sh
    # build cre2
    print "build cre2"
    rm -rf build
    mkdir build
    cd build
    ../configure --enable-maintainer-mode 
    make -j$(nproc)
    make install prefix=$INSTALLDIR

    # merge re2 and cre2
    cd $INSTALLDIR/lib
    ar -x libre2.a
    ar -x libcre2.a
    mkdir -p absl_obj 
    #mv libabsl*.a absl_obj
    #pushd absl_obj
    #for FILE in $(ls libabsl*.a)
    #do
    #    ar -x $FILE
    #done
    #popd
    rm libcre2.a
    #ar -rcs libcre2.a *.o absl_obj/*.o
    ar -rcs libcre2.a *.o
    ${CXX:-g++} ${CXXFLAGS} -fPIC --shared -o libcre2.so *.o
    rm *.o
    popd
}

function build_oss_fuzz() {
    cd $SRC/re2
    $CXX $CXXFLAGS -I. \
        re2/fuzzing/re2_fuzzer.cc -o $OUT/re2_fuzzer \
        $LIB_FUZZING_ENGINE obj/libre2.a -I$INSTALLDIR/include -L$INSTALLDIR/lib/absl_obj -labsl_flags_internal -labsl_flags_marshalling -labsl_flags_reflection -labsl_flags_private_handle_accessor -labsl_flags_commandlineflag -labsl_flags_commandlineflag_internal -labsl_flags_config -labsl_flags_program_name -labsl_cord -labsl_cordz_info -labsl_cord_internal -labsl_cordz_functions -labsl_cordz_handle -labsl_crc_cord_state -labsl_crc32c -labsl_crc_internal -labsl_crc_cpu_detect -labsl_raw_hash_set -labsl_hash -labsl_city -labsl_bad_variant_access -labsl_low_level_hash -labsl_hashtablez_sampler -labsl_exponential_biased -labsl_bad_optional_access -labsl_str_format_internal -labsl_synchronization -labsl_graphcycles_internal -labsl_kernel_timeout_internal -labsl_stacktrace -labsl_symbolize -labsl_debugging_internal -labsl_demangle_internal -labsl_malloc_internal -labsl_time -labsl_civil_time -labsl_strings -labsl_strings_internal -labsl_string_view -labsl_base -lrt -labsl_spinlock_wait -labsl_int128 -labsl_throw_delegate -labsl_raw_logging_internal -labsl_log_severity -labsl_time_zone           
}

function copy_include() {
    mkdir -p $LIB_BUILD/include
    cp $INSTALLDIR/include/cre2.h $LIB_BUILD/include/cre2.h
    sed -i '1s/^/\#include<stddef.h>\n/' $LIB_BUILD/include/cre2.h
}

function build_corpus() {
    # add seed corpus.
    cp $DIR/corpus.tar.gz $LIB_BUILD/corpus.tar.gz
    cd $LIB_BUILD
    tar -xvf corpus.tar.gz
    rm corpus.tar.gz
    pwd
}

function build_dict() {
    wget -qO ${LIB_BUILD}/fuzzer.dict \
    https://raw.githubusercontent.com/google/fuzzing/master/dictionaries/regexp.dict
}

build_all
