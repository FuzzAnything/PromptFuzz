source ../common.sh

PROJECT_NAME=c-ares
STALIB_NAME=libcares.a
DYNLIB_NAME=libcares.so

function download() {
    if [[ ! -z "${DOCKER_CONTAINER:-}" ]]; then
        apt-get update && apt-get install -y make autoconf automake libtool
    fi

    cd $SRC
    if [ -x "$(command -v coscli)" ]; then
        coscli cp cos://sbd-testing-1251316161/bench_archive/LLM_FUZZ/archives/${PROJECT_NAME}.tar.gz ${PROJECT_NAME}.tar.gz
        tar -xvf ${PROJECT_NAME}.tar.gz && rm ${PROJECT_NAME}.tar.gz
    else
        git clone --depth 1 https://github.com/c-ares/c-ares.git
    fi
}

function build_lib() {
    LIB_STORE_DIR=$SRC/c-ares/src/lib/.libs
    cd ${SRC}/c-ares
    make distclean
    ./buildconf
    ./configure --enable-debug --disable-tests
    make clean
    make -j$(nproc) V=1 all
}

function build_oss_fuzz() {
    # build fuzzers
    # Build the fuzzers.
    cd ${SRC}/c-ares
    $CC $CFLAGS -Iinclude -Isrc/lib -c $SRC/c-ares/test/ares-test-fuzz.c -o $WORK/ares-test-fuzz.o
    $CXX $CXXFLAGS -std=c++11 $WORK/ares-test-fuzz.o \
        -o $OUT/ares_parse_reply_fuzzer \
        $LIB_FUZZING_ENGINE $SRC/c-ares/src/lib/.libs/libcares.a

    $CC $CFLAGS -Iinclude -Isrc/lib -c $SRC/c-ares/test/ares-test-fuzz-name.c \
        -o $WORK/ares-test-fuzz-name.o
    $CXX $CXXFLAGS -std=c++11 $WORK/ares-test-fuzz-name.o \
        -o $OUT/ares_create_query_fuzzer \
        $LIB_FUZZING_ENGINE $SRC/c-ares/src/lib/.libs/libcares.a
}

function copy_include() {
    mkdir -p ${LIB_BUILD}/include/
    cp $SRC/${PROJECT_NAME}/include/*.h ${LIB_BUILD}/include/$1/
}

function build_corpus() {
    cd ${LIB_BUILD}
    mkdir corpus
    mv $SRC/c-ares/test/fuzzinput/*  $SRC/c-ares/test/fuzznames/* corpus
}

function build_dict() {
    # no dict
    pwd
}

build_all