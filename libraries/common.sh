#!/bin/bash

BLUE='\033[0;34m'
NC='\033[0m' # No Color
set -Eeo pipefail
set -x

function blue_echo() {
    echo -e "${BLUE}$1.${NC}"
}

function init() {
    mkdir -p ../../output/build
    OUTPUT=$(realpath ../../output/build)
    LIB_BUILD=${OUTPUT}/${PROJECT_NAME}
    rm -rf $LIB_BUILD
    mkdir -p $LIB_BUILD
    SRC=${LIB_BUILD}/src
    WORK=${LIB_BUILD}/work
    OUT=${LIB_BUILD}/out
    rm -rf $SRC
    mkdir -p $SRC
    rm -rf $WORK
    mkdir -p $WORK
    rm -rf $OUT
    mkdir -p $OUT
}

#https://google.github.io/oss-fuzz/getting-started/new-project-guide/#static-and-dynamic-linking-of-libraries
function san_env() {
    blue_echo "set ASan and UBSan env"
    unset CFLAGS
    unset CXXFLAGS
    export CC=clang
    export CXX=clang++
    SANITIZER_FLAGS="-O2 -fsanitize=address,undefined -fsanitize-address-use-after-scope -g "
    export CFLAGS="${CFLAGS:-} $SANITIZER_FLAGS"
    export CXXFLAGS="${CXXFLAGS:-} $SANITIZER_FLAGS"
}

# Set libfuzzer's environment for building library
# Libfuzzer:
# https://releases.llvm.org/5.0.0/docs/LibFuzzer.html
# How fuzzbench use libfuzzer:
# https://github.com/google/fuzzbench/blob/master/fuzzers/libfuzzer/fuzzer.py
function libfuzzer_env() {
    blue_echo "set libfuzzer env"
    export CC=clang
    export CXX=clang++

    unset CFLAGS
    unset CXXFLAGS
    FUZZER_FLAGS="-fsanitize=fuzzer-no-link -fno-omit-frame-pointer -g -DFUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION $SANITIZER_FLAGS"
    export CFLAGS="${CFLAGS:-} $FUZZER_FLAGS"
    export CXXFLAGS="${CXXFLAGS:-} $FUZZER_FLAGS"
    export CUSTOM_FLAGS=${LIBFUZZER_CUSTOM_FLAGS:-}
    export LIB_FUZZING_ENGINE="-fsanitize=fuzzer"
    # With LibFuzzer we use -fsanitize=fuzzer-no-link for build CFLAGS and then
    # /usr/lib/libFuzzer.a as the FUZZER_LIB for the main fuzzing binary. This
    # allows us to link against a version of LibFuzzer that we specify.
    # export LIB_FUZZING_ENGINE='/usr/lib/libFuzzer.a'
}

# Set source-based coverage's environment for building
# https://clang.llvm.org/docs/SourceBasedCodeCoverage.html
# https://github.com/google/fuzzing/issues/41
function coverage_env() {
    unset CFLAGS
    unset CXXFLAGS
    unset LDFLAGS
    blue_echo "set coverage env"
    export CC=clang
    export CXX=clang++
    COVERAGE_FLAGS="-g -fsanitize=fuzzer-no-link -fno-sanitize=undefined -fprofile-instr-generate -fcoverage-mapping -Wl,--no-as-needed -Wl,-ldl -Wl,-lm -Wno-unused-command-line-argument -DFUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION "
    export CFLAGS="${CFLAGS:-} $COVERAGE_FLAGS"
    export CXXFLAGS="${CXXFLAGS:-} $COVERAGE_FLAGS"
}

function build_bc() {
    blue_echo "build bitcode"
    unset CFLAGS
    unset CXXFLAGS
    unset LDFLAGS
    unset CC
    unset CXX
    export LLVM_COMPILER=clang
    export CC=wllvm
    export CXX=wllvm++
    export CFLAGS="-g -O0 "
    export CXXFLAGS="-g -O0 "
    build_lib
    cd $WORK
    extract-bc -b $LIB_STORE_DIR/$STALIB_NAME
    opt -passes=dot-callgraph $LIB_STORE_DIR/${STALIB_NAME}.bc
    mv $LIB_STORE_DIR/${STALIB_NAME}.bc.callgraph.dot callgraph.dot
    sed -i '/^[[:space:]]*label="Call graph:/d' callgraph.dot
    unset CC
    unset CXX
}

function make_include() {
    cd ${LIB_BUILD}
    mkdir -p include/$1
    cp $SRC/${PROJECT_NAME}/$1/*.h include/$1/
}

function copy_lib() {
    cd $LIB_STORE_DIR
    NEW_LIB_NAME=${STALIB_NAME%.a}_${1}.a
    cp ${STALIB_NAME} ${NEW_LIB_NAME}
    mkdir -p ${LIB_BUILD}/lib
    cp ${NEW_LIB_NAME} ${LIB_BUILD}/lib/${NEW_LIB_NAME}
    copy_share_lib $1
}

function copy_share_lib() {
    cd $LIB_STORE_DIR
    NEW_DYNLIB_NAME=${DYNLIB_NAME%.so}_${1}.so
    cp ${DYNLIB_NAME} ${NEW_DYNLIB_NAME}
    patchelf --set-soname ${NEW_DYNLIB_NAME} ${NEW_DYNLIB_NAME}
    mkdir -p ${LIB_BUILD}/lib
    cp ${NEW_DYNLIB_NAME} ${LIB_BUILD}/lib/${NEW_DYNLIB_NAME}
}

function build_san() {
    blue_echo "build sanitizers"
    san_env
    build_lib
    copy_lib san
}

function build_fuzzer() {
    blue_echo "build with fuzzers"
    san_env
    libfuzzer_env
    build_lib
    OLD_OUT=$OUT
    OUT=$OUT/oss_fuzzer
    mkdir -p $OUT
    build_oss_fuzz
    OUT=$OLD_OUT
    copy_lib fuzzer
}

function build_debug_fuzzer() {
    blue_echo "build with fuzzers"
    export CFLAGS="-O0 -g "
    export CXXFLAGS="-O0 -g "
    build_lib
    copy_lib debug
}

function build_cov() {
    blue_echo "build with coverage"
    coverage_env
    build_lib
    copy_lib cov
    OLD_OUT=$OUT
    OUT=$OUT/oss_fuzzer_cov
    mkdir -p $OUT
    build_oss_fuzz
    OUT=$OLD_OUT
}

function write_magicbytes_to_dict() {
    magic="fmagic=\"\xCA\xFE\xBA\""
    echo $magic >> ${LIB_BUILD}/fuzzer.dict
}

function append_terminate_to_corpus() {
    #find "$1" -type f -exec sh -c 'printf "\x00" >> "{}"' \;
    for FILE in $(find "$1" -type f); do
        printf "\x00" >> $FILE
    done
}

function save_flags() {
    OLD_CFLAGS=$CFLAGS
    OLD_CXXFLAGS=$CXXFLAGS
    unset CFLAGS
    unset CXXFLAGS
}

function load_flags() {
    export CFLAGS=$OLD_CFLAGS
    export CXXFLAGS=$OLD_CXXFLAGS
}

function build_all() {
    init && \
    download && \
    #build_san && \
    build_fuzzer && \
    build_debug_fuzzer &&\
    build_corpus && \
    build_dict && \
    build_cov && \
    copy_include && \
    build_bc && \
    write_magicbytes_to_dict 
}
