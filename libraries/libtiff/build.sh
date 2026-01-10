#!/bin/bash

source ../common.sh

PROJECT_NAME=libtiff
STALIB_NAME=libtiff.a
DYNLIB_NAME=libtiff.so
DIR=$(pwd)
set -Eeo pipefail
set -x

function download() {
    if [[ ! -z "${DOCKER_CONTAINER:-}" ]]; then
        apt-get update &&
            apt-get -y upgrade &&
            apt-get -y install yasm liblzma-dev &&
            apt-get clean
    fi
    cd $SRC
    if [ -x "$(command -v coscli)" ]; then
        DOWNLOAD_PROJECT=$PROJECT_NAME
        coscli cp cos://sbd-testing-1251316161/bench_archive/LLM_FUZZ/archives/${DOWNLOAD_PROJECT}.tar.gz ${DOWNLOAD_PROJECT}.tar.gz
        tar -xvf ${DOWNLOAD_PROJECT}.tar.gz && rm ${DOWNLOAD_PROJECT}.tar.gz
        DOWNLOAD_PROJECT=zlib
        coscli cp cos://sbd-testing-1251316161/bench_archive/LLM_FUZZ/archives/${DOWNLOAD_PROJECT}.tar.gz ${DOWNLOAD_PROJECT}.tar.gz
        tar -xvf ${DOWNLOAD_PROJECT}.tar.gz && rm ${DOWNLOAD_PROJECT}.tar.gz
        DOWNLOAD_PROJECT=libjpeg-turbo
        coscli cp cos://sbd-testing-1251316161/bench_archive/LLM_FUZZ/archives/${DOWNLOAD_PROJECT}.tar.gz ${DOWNLOAD_PROJECT}.tar.gz
        tar -xvf ${DOWNLOAD_PROJECT}.tar.gz && rm ${DOWNLOAD_PROJECT}.tar.gz
        DOWNLOAD_PROJECT=jbigkit
        coscli cp cos://sbd-testing-1251316161/bench_archive/LLM_FUZZ/archives/${DOWNLOAD_PROJECT}.tar.gz ${DOWNLOAD_PROJECT}.tar.gz
        tar -xvf ${DOWNLOAD_PROJECT}.tar.gz && rm ${DOWNLOAD_PROJECT}.tar.gz
        coscli cp cos://sbd-testing-1251316161/bench_archive/LLM_FUZZ/archives/zstd.tar.gz zstd.tar.gz
        tar -xvf zstd.tar.gz && rm zstd.tar.gz
    else
        git clone --depth 1 https://gitlab.com/libtiff/libtiff
        git clone --depth 1 https://github.com/madler/zlib
        git clone --depth 1 https://github.com/libjpeg-turbo/libjpeg-turbo
        git clone https://www.cl.cam.ac.uk/~mgk25/git/jbigkit
        git clone --depth 1 https://github.com/facebook/zstd.git
        wget https://raw.githubusercontent.com/google/AFL/debe27037b9444bbf090a0ffbd5d24889bb887ae/dictionaries/tiff.dict
        cp tiff.dict ${PROJECT_NAME}/tiff.dict
    fi
    sed -i 's/TIFF \*TIFFOpen(const char \*, const char \*);/TIFF \*TIFFOpen(const char \*filename, const char \*mode);/g' $SRC/$PROJECT_NAME/$PROJECT_NAME/tiffio.h
    sed -i 's/TIFF \*TIFFOpenExt(const char \*, const char \*, TIFFOpenOptions \*opts)/TIFF \*TIFFOpenExt(const char \*filename, const char \*mode, TIFFOpenOptions \*opts)/g' $SRC/$PROJECT_NAME/$PROJECT_NAME/tiffio.h
    sed -i 's/TIFF \*TIFFFdOpen(int, const char \*, const char \*)/TIFF \*TIFFFdOpen(int ifd, const char \*filename, const char \*mode)/g' $SRC/$PROJECT_NAME/$PROJECT_NAME/tiffio.h
    sed -i 's/TIFF \*TIFFFdOpenExt(int, const char \*, const char \*,/TIFF \*TIFFFdOpenExt(int ifd, const char \*filename, const char \*mode,/g' $SRC/$PROJECT_NAME/$PROJECT_NAME/tiffio.h
    sed -i 's/-Wno-unused-result/-Wno-unused-result -fPIC/g' $SRC/jbigkit/Makefile
}

function build_zlib() {
    save_flags
    export CFLAGS="$CFLAGS -fPIC"
    export CXXFLAGS="$CXXFLAGS -fPIC"
    pushd "$SRC/zlib"
    ./configure --static --prefix="$WORK" --libdir=$WORK/lib
    make -j$(nproc)
    make install
    popd
    load_flags
}

function build_libjpeg() {
    save_flags
    export CFLAGS="$CFLAGS -fPIC"
    export CXXFLAGS="$CXXFLAGS -fPIC"
    pushd "$SRC/libjpeg-turbo"
    cmake . -DCMAKE_INSTALL_PREFIX=$WORK -DENABLE_STATIC=on -DENABLE_SHARED=off -DCMAKE_INSTALL_LIBDIR=$WORK/lib
    make -j$(nproc)
    make install
    popd
    load_flags
}

function build_libjbig() {
    save_flags
    pushd "$SRC/jbigkit"
    if [ "$ARCHITECTURE" = "i386" ]; then
        echo "#!/bin/bash" > gcc
        echo "clang -m32 -fPIC \$*" >> gcc
        chmod +x gcc
        PATH=$PWD:$PATH make lib
    else
        echo "#!/bin/bash" > gcc
        echo "clang -fPIC \$*" >> gcc
        chmod +x gcc
        PATH=$PWD:$PATH make lib
    fi
    mv "$SRC"/jbigkit/libjbig/*.a "$WORK/lib/"
    mv "$SRC"/jbigkit/libjbig/*.h "$WORK/include/"
    popd
    load_flags
}

function build_zstd() {
    save_flags
    pushd $ZSTD_DIR
    rm -rf fuzz_build
    cmake -DCMAKE_INSTALL_PREFIX=$INSTALL_DIR -DCMAKE_INSTALL_LIBDIR=$INSTALL_DIR/lib -B fuzz_build -S build/cmake
    cd fuzz_build
    make -j$(nproc)
    make install
    popd
    load_flags
}

function build_lib() {
    INSTALL_DIR=$WORK
    ZSTD_DIR=$SRC/zstd
    # Build project
    if [ ! -d $INSTALL_DIR/lib ]; then
        build_zlib
        build_libjpeg
        build_libjbig
        build_zstd
    fi

    cd $SRC/${PROJECT_NAME}
    LIB_STORE_DIR=$SRC/${PROJECT_NAME}/${PROJECT_NAME}/.libs
    rm -rf $LIB_STORE_DIR

    ./autogen.sh
    ./configure --prefix=$WORK --libdir=$WORK/lib --enable-shared=yes --enable-static=yes \
        --with-zlib-include-dir=$WORK/include --with-zlib-lib-dir=$WORK/lib \
        --with-jpeg-include-dir=$WORK/include --with-jpeg-lib-dir=$WORK/lib \
        --with-jbig-include-dir=$WORK/include --with-jbig-lib-dir=$WORK/lib

    make clean
    make -j$(nproc)
    make install
}

function build_oss_fuzz() {
    if [ "$ARCHITECTURE" = "i386" ]; then
        $CXX $CXXFLAGS -std=c++11 -I$WORK/include \
            $SRC/libtiff/contrib/oss-fuzz/tiff_read_rgba_fuzzer.cc -o $OUT/tiff_read_rgba_fuzzer \
            $LIB_FUZZING_ENGINE $WORK/lib/libtiffxx.a $WORK/lib/libtiff.a $WORK/lib/libz.a $WORK/lib/libjpeg.a \
            $WORK/lib/libjbig.a $WORK/lib/libjbig85.a
    else
        $CXX $CXXFLAGS -std=c++11 -I$WORK/include \
            $SRC/libtiff/contrib/oss-fuzz/tiff_read_rgba_fuzzer.cc -o $OUT/tiff_read_rgba_fuzzer \
            $LIB_FUZZING_ENGINE $WORK/lib/libtiffxx.a $WORK/lib/libtiff.a $WORK/lib/libz.a $WORK/lib/libjpeg.a \
            $WORK/lib/libjbig.a $WORK/lib/libjbig85.a -llzma #-Wl,-Bstatic -llzma -Wl,-Bdynamic
    fi
}

function copy_include() {
    mkdir -p ${LIB_BUILD}/include
    cp $WORK/include/tiff.h ${LIB_BUILD}/include/
    cp $WORK/include/tiffconf.h ${LIB_BUILD}/include/
    cp $WORK/include/tiffio.h ${LIB_BUILD}/include/
    cp $WORK/include/tiffvers.h ${LIB_BUILD}/include/
    cp $WORK/include/tiffio.hxx ${LIB_BUILD}/include
}

function build_corpus() {
    cd $SRC
    wget https://lcamtuf.coredump.cx/afl/demo/afl_testcases.tgz
    mkdir afl_testcases
    (cd afl_testcases; tar xf "$SRC/afl_testcases.tgz")
    mkdir tif
    find afl_testcases -type f -name '*.tif' -exec mv -n {} tif/ \;
    mv tif ${LIB_BUILD}/corpus
}

function build_dict() {
    cp $SRC/$PROJECT_NAME/tiff.dict $LIB_BUILD/fuzzer.dict
}

build_all
rm $WORK/lib/libtiffxx.so